"""
Firmware analysis pipeline — orchestrates the 3-stage process:
  Stage A: Download firmware from fw_url
  Stage B: Run EMBA on downloaded .bin
  Stage C: AI triage EMBA findings → risk report

This module is called by the worker process for background execution.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.models.firmware import FirmwareAnalysis, FirmwareStatus
from app.models.host import Host
from app.services.firmware_download import download_firmware
from app.services.emba_scanner import run_emba
from app.services.ai_triage import run_triage
from app.services.scheduler import scheduler
from app.utils.logging import get_logger

log = get_logger("firmware.pipeline")

# Redis queue key for firmware analysis jobs
FW_QUEUE_KEY = "soc:firmware_queue"
FW_CANCEL_SET = "soc:firmware_cancel"


async def _update_analysis(
    db: AsyncSession,
    analysis_id: uuid.UUID,
    **kwargs,
):
    """Update a FirmwareAnalysis record."""
    result = await db.execute(
        select(FirmwareAnalysis).where(FirmwareAnalysis.id == analysis_id)
    )
    analysis = result.scalar_one_or_none()
    if analysis:
        for k, v in kwargs.items():
            setattr(analysis, k, v)
        await db.flush()
    return analysis


async def _update_host_firmware(
    db: AsyncSession,
    mac: str,
    **kwargs,
):
    """Update the cached firmware fields on the Host record."""
    result = await db.execute(select(Host).where(Host.mac_address == mac))
    host = result.scalar_one_or_none()
    if host:
        for k, v in kwargs.items():
            setattr(host, k, v)
        await db.flush()


async def run_firmware_pipeline(
    analysis_id: str,
    on_progress: Callable[[str, dict], None] | None = None,
):
    """
    Execute the full firmware analysis pipeline for one device.

    Stages:
        1. Download firmware from fw_url
        2. Run EMBA on the downloaded binary
        3. AI triage the EMBA findings via Ollama
    """
    aid = uuid.UUID(analysis_id)
    log.info("fw_pipeline_start", analysis_id=analysis_id)

    stage_labels = [
        "Downloading Firmware",
        "Running EMBA Analysis",
        "AI Triage & Risk Scoring",
    ]

    async def progress(msg: str, stage: int = 0):
        if on_progress:
            await on_progress(msg, {
                "stage": stage,
                "stage_label": stage_labels[stage - 1] if stage > 0 else "Initializing",
            })

    try:
        # ── Load analysis record ────────────────
        async with async_session() as db:
            result = await db.execute(
                select(FirmwareAnalysis).where(FirmwareAnalysis.id == aid)
            )
            analysis = result.scalar_one_or_none()
            if not analysis:
                log.error("analysis_not_found", analysis_id=analysis_id)
                return

            if analysis.status == FirmwareStatus.CANCELLED:
                log.info("analysis_already_cancelled", analysis_id=analysis_id)
                return

            host_mac = analysis.host_mac
            fw_url = analysis.fw_url

            # Load host info for triage context
            host_result = await db.execute(
                select(Host).where(Host.mac_address == host_mac)
            )
            host = host_result.scalar_one_or_none()
            if not host:
                log.error("host_not_found", mac=host_mac)
                return

            ip = host.ip_address
            vendor = host.vendor or "Unknown"
            # Build ports string from host's open ports
            ports_list = [str(p.port_number) for p in (host.ports or [])]
            ports_str = ", ".join(ports_list) if ports_list else "none"

            # Mark as running
            analysis.status = FirmwareStatus.DOWNLOADING
            analysis.started_at = datetime.now(timezone.utc)
            analysis.current_stage = 1
            analysis.stage_label = stage_labels[0]
            await db.commit()

        await progress(f"Starting firmware pipeline for {ip} ({host_mac})", 1)

        # ── Stage A: Download Firmware ──────────
        if not fw_url:
            raise ValueError(f"No firmware URL configured for device {host_mac}")

        async def download_progress(msg: str):
            await progress(msg, 1)

        fw_path, fw_hash, fw_size = await download_firmware(
            url=fw_url,
            ip=ip,
            mac=host_mac,
            on_progress=lambda msg: None,  # sync shim
        )

        # Persist Stage A results
        async with async_session() as db:
            await _update_analysis(
                db, aid,
                fw_path=str(fw_path),
                fw_hash=fw_hash,
                fw_size_bytes=fw_size,
                status=FirmwareStatus.DOWNLOADED,
                current_stage=1,
                stage_label="Firmware Downloaded",
            )
            await _update_host_firmware(
                db, host_mac,
                fw_path=str(fw_path),
                fw_hash=fw_hash,
                firmware_status=FirmwareStatus.DOWNLOADED.value,
            )
            await db.commit()

        await progress(f"Firmware downloaded: {fw_path.name} ({fw_size:,} bytes)", 1)

        # Check cancellation
        if await scheduler.is_cancelled_firmware(aid):
            raise CancelledError("Analysis cancelled by user")

        # ── Stage B: EMBA Scan ──────────────────
        async with async_session() as db:
            await _update_analysis(
                db, aid,
                status=FirmwareStatus.EMBA_RUNNING,
                current_stage=2,
                stage_label=stage_labels[1],
            )
            await _update_host_firmware(
                db, host_mac,
                firmware_status=FirmwareStatus.EMBA_RUNNING.value,
            )
            await db.commit()

        await progress(f"Starting EMBA analysis on {fw_path.name}", 2)

        emba_log_dir = await run_emba(
            fw_path=str(fw_path),
            device_id=str(aid)[:8],
            ip=ip,
            on_progress=lambda msg: None,  # sync shim
        )

        # Persist Stage B results
        async with async_session() as db:
            await _update_analysis(
                db, aid,
                emba_log_dir=emba_log_dir,
                status=FirmwareStatus.EMBA_DONE,
                current_stage=2,
                stage_label="EMBA Analysis Complete",
            )
            await _update_host_firmware(
                db, host_mac,
                emba_log_dir=emba_log_dir,
                firmware_status=FirmwareStatus.EMBA_DONE.value,
            )
            await db.commit()

        await progress(f"EMBA analysis complete for {ip}", 2)

        # Check cancellation
        if await scheduler.is_cancelled_firmware(aid):
            raise CancelledError("Analysis cancelled by user")

        # ── Stage C: AI Triage ──────────────────
        async with async_session() as db:
            await _update_analysis(
                db, aid,
                status=FirmwareStatus.TRIAGING,
                current_stage=3,
                stage_label=stage_labels[2],
            )
            await _update_host_firmware(
                db, host_mac,
                firmware_status=FirmwareStatus.TRIAGING.value,
            )
            await db.commit()

        await progress(f"Running AI triage on EMBA results for {ip}", 3)

        report, risk_score, findings_count, critical_count, high_count = await run_triage(
            emba_log_dir=emba_log_dir,
            ip=ip,
            vendor=vendor,
            ports=ports_str,
            mac=host_mac,
            on_progress=lambda msg: None,  # sync shim
        )

        # Persist Stage C results + mark completed
        async with async_session() as db:
            await _update_analysis(
                db, aid,
                risk_report=report,
                risk_score=risk_score,
                findings_count=findings_count,
                critical_count=critical_count,
                high_count=high_count,
                status=FirmwareStatus.COMPLETED,
                current_stage=3,
                stage_label="Completed",
                completed_at=datetime.now(timezone.utc),
            )
            await _update_host_firmware(
                db, host_mac,
                risk_report=report,
                risk_score=risk_score,
                firmware_status=FirmwareStatus.COMPLETED.value,
            )
            await db.commit()

        await progress(
            f"Firmware analysis complete for {ip} — "
            f"Risk: {risk_score}/10, {findings_count} findings",
            3,
        )
        log.info(
            "fw_pipeline_done",
            analysis_id=analysis_id,
            risk_score=risk_score,
            findings=findings_count,
        )

    except CancelledError:
        async with async_session() as db:
            await _update_analysis(
                db, aid,
                status=FirmwareStatus.CANCELLED,
                completed_at=datetime.now(timezone.utc),
            )
            await _update_host_firmware(
                db, host_mac,
                firmware_status=FirmwareStatus.CANCELLED.value,
            )
            await db.commit()
        await scheduler.clear_cancel_firmware(aid)
        log.info("fw_pipeline_cancelled", analysis_id=analysis_id)

    except Exception as e:
        log.error("fw_pipeline_failed", analysis_id=analysis_id, error=str(e), exc_info=True)
        try:
            async with async_session() as db:
                await _update_analysis(
                    db, aid,
                    status=FirmwareStatus.FAILED,
                    error_message=str(e)[:2000],
                    completed_at=datetime.now(timezone.utc),
                )
                await _update_host_firmware(
                    db, host_mac,
                    firmware_status=FirmwareStatus.FAILED.value,
                )
                await db.commit()
        except Exception as db_err:
            log.error("fw_pipeline_fail_persist_error", error=str(db_err))

        if on_progress:
            await on_progress(f"Firmware analysis failed for {ip}: {e}", {
                "stage": 0,
                "error": str(e)[:500],
            })


class CancelledError(Exception):
    """Firmware analysis was cancelled by user."""
    pass
