"""
Background scan worker process.

Polls the Redis queue for scan jobs, runs the 4-stage pipeline,
persists results to PostgreSQL, and publishes real-time progress
via Redis pub/sub → WebSocket.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session, engine
from app.models.host import Host
from app.models.port import Port
from app.models.scan import Scan, ScanLog, ScanStatus
from app.services.scanner import DiscoveredHost, run_full_pipeline
from app.services.scheduler import ScanScheduler, scheduler
from app.utils.logging import configure_logging, get_logger

configure_logging(settings.log_level)
log = get_logger("worker")


async def _add_log(db: AsyncSession, scan_id: uuid.UUID, stage: int, message: str, level: str = "info"):
    """Persist a log entry for a scan."""
    entry = ScanLog(scan_id=scan_id, stage=stage, message=message, level=level)
    db.add(entry)
    await db.flush()


async def _persist_results(db: AsyncSession, scan: Scan, hosts: list[DiscoveredHost]):
    """Upsert discovered hosts (keyed by MAC) and ports to the database."""
    total_ports = 0

    for dh in hosts:
        # Generate a deterministic MAC for hosts without one
        mac = dh.mac or f"00:00:{dh.ip.replace('.', ':')[:8]}"

        # Upsert: check if device already exists by MAC
        result = await db.execute(select(Host).where(Host.mac_address == mac))
        host = result.scalar_one_or_none()

        if host is None:
            host = Host(mac_address=mac)
            db.add(host)

        # Update fields from latest scan
        host.scan_id = scan.id
        host.ip_address = dh.ip
        host.hostname = dh.hostname or host.hostname
        host.vendor = dh.vendor or host.vendor
        host.os_name = dh.os_name or host.os_name
        host.os_family = dh.os_family or host.os_family
        host.os_accuracy = dh.os_accuracy if dh.os_accuracy else host.os_accuracy
        host.os_cpe = dh.os_cpe or host.os_cpe
        host.is_up = dh.is_up
        host.response_time_ms = dh.response_time_ms
        host.nmap_raw_xml = dh.nmap_xml or host.nmap_raw_xml
        host.last_seen = datetime.now(timezone.utc)
        host.open_port_count = len(dh.open_ports)

        await db.flush()

        # Delete old ports for this host and write fresh ones
        from sqlalchemy import delete
        await db.execute(delete(Port).where(Port.host_id == mac))

        # Ports from deep scan services
        for port_num, svc in dh.services.items():
            port = Port(
                host_id=mac,
                port_number=svc.get("port", port_num),
                protocol=svc.get("protocol", "tcp"),
                state=svc.get("state", "open"),
                service_name=svc.get("name"),
                service_version=svc.get("version"),
                service_product=svc.get("product"),
                service_extra_info=svc.get("extra_info"),
                service_cpe=svc.get("cpe"),
                scripts_output=svc.get("scripts"),
            )
            db.add(port)
            total_ports += 1

        # If no deep scan data, still record open ports
        if not dh.services and dh.open_ports:
            for pn in dh.open_ports:
                port = Port(
                    host_id=mac,
                    port_number=pn,
                    protocol="tcp",
                    state="open",
                )
                db.add(port)
                total_ports += 1

    await db.flush()
    return total_ports


async def _load_existing_hosts(db: AsyncSession) -> dict[str, int]:
    """Load MAC → open_port_count mapping from existing host table for stage-4 skip."""
    result = await db.execute(select(Host.mac_address, Host.open_port_count))
    return {row[0]: row[1] for row in result.all()}


async def _process_scan(scan_id_str: str):
    """Execute the full pipeline for one scan job."""
    scan_id = uuid.UUID(scan_id_str)
    log.info("processing_scan", scan_id=scan_id_str)

    stage_labels = [
        "Ping Sweep",
        "ARP MAC Lookup",
        "Port Scanning",
        "Deep Scan (SYN + Version + Scripts + OS)",
    ]
    current_stage = [0]  # mutable container for closure

    async def on_progress(message: str, data: dict):
        """Progress callback — updates DB + publishes to Redis."""
        for i, label in enumerate(stage_labels):
            if f"Stage {i + 1}" in message:
                current_stage[0] = i + 1
                break

        if await scheduler.is_cancelled(scan_id):
            raise asyncio.CancelledError("Scan cancelled by user")

        try:
            async with async_session() as progress_db:
                result = await progress_db.execute(select(Scan).where(Scan.id == scan_id))
                s = result.scalar_one_or_none()
                if s:
                    s.current_stage = current_stage[0]
                    s.stage_label = stage_labels[current_stage[0] - 1] if current_stage[0] > 0 else "Initializing"
                    await _add_log(progress_db, scan_id, current_stage[0], message)
                    await progress_db.commit()
        except Exception as e:
            log.warning("progress_db_error", error=str(e))

        await scheduler.publish_progress(scan_id_str, {
            "type": "scan_progress",
            "scan_id": scan_id_str,
            "stage": current_stage[0],
            "stage_label": stage_labels[current_stage[0] - 1] if current_stage[0] > 0 else "Initializing",
            "message": message,
            "data": data,
        })

    try:
        # Load scan from DB and mark as running
        async with async_session() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()

            if not scan:
                log.error("scan_not_found", scan_id=scan_id_str)
                return

            if scan.status == ScanStatus.CANCELLED:
                log.info("scan_already_cancelled", scan_id=scan_id_str)
                return

            target = scan.target

            # Load existing device inventory for stage-4 skip optimization
            existing_hosts = await _load_existing_hosts(db)

            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(timezone.utc)
            scan.current_stage = 0
            await db.commit()
            log.info("scan_marked_running", scan_id=scan_id_str, target=target, known_devices=len(existing_hosts))

        # Execute the 4-stage pipeline (existing_hosts enables stage-4 skip)
        hosts = await run_full_pipeline(target, on_progress=on_progress, existing_hosts=existing_hosts)
        log.info("pipeline_done", scan_id=scan_id_str, hosts=len(hosts))

        # Persist results in a new session
        async with async_session() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                log.error("scan_vanished", scan_id=scan_id_str)
                return

            total_ports = await _persist_results(db, scan, hosts)

            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.current_stage = 4
            scan.stage_label = "Completed"
            scan.hosts_discovered = len(hosts)
            scan.live_hosts = sum(1 for h in hosts if h.is_up)
            scan.open_ports_found = total_ports
            await _add_log(db, scan_id, 4, f"Scan completed: {len(hosts)} hosts, {total_ports} ports")
            await db.commit()

        await scheduler.publish_progress(scan_id_str, {
            "type": "scan_completed",
            "scan_id": scan_id_str,
            "hosts": len(hosts),
            "ports": total_ports,
        })
        log.info("scan_completed", scan_id=scan_id_str, hosts=len(hosts), ports=total_ports)

    except asyncio.CancelledError:
        async with async_session() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.CANCELLED
                scan.completed_at = datetime.now(timezone.utc)
                await _add_log(db, scan_id, current_stage[0], "Scan cancelled by user", level="warning")
                await db.commit()
        await scheduler.clear_cancel(scan_id)
        log.info("scan_cancelled", scan_id=scan_id_str)

    except Exception as e:
        log.error("scan_failed", scan_id=scan_id_str, error=str(e), exc_info=True)
        try:
            async with async_session() as db:
                result = await db.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.completed_at = datetime.now(timezone.utc)
                    scan.error_message = str(e)[:2000]
                    await _add_log(db, scan_id, current_stage[0], f"Scan failed: {e}", level="error")
                    await db.commit()
        except Exception as db_err:
            log.error("scan_fail_persist_error", error=str(db_err))

        await scheduler.publish_progress(scan_id_str, {
            "type": "scan_failed",
            "scan_id": scan_id_str,
            "error": str(e)[:500],
        })


async def worker_loop():
    """Main worker loop — dequeue and process scans."""
    log.info("worker_starting", concurrency=settings.worker_concurrency)
    await scheduler.start()

    active_tasks: set[asyncio.Task] = set()

    while True:
        try:
            scan_id = await scheduler.dequeue_scan(timeout=2)
            if scan_id:
                log.info("scan_dequeued", scan_id=scan_id)
                task = asyncio.create_task(_process_scan(scan_id))
                active_tasks.add(task)
                task.add_done_callback(active_tasks.discard)
            else:
                await asyncio.sleep(0.5)
        except Exception as e:
            log.error("worker_loop_error", error=str(e), exc_info=True)
            await asyncio.sleep(2)


def main():
    """Entry point for `python -m app.worker.main`."""
    asyncio.run(worker_loop())


if __name__ == "__main__":
    main()
