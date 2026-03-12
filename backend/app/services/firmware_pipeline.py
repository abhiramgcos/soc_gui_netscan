"""
Firmware analysis pipeline — orchestrates the full 8-stage process:

  Stage 0:  Orchestrator       — global timeout wrapper + cleanup
  Stage A:  Download           — fetch binary with retries + validation
  Stage B:  EMBA Prep          — CVE DB refresh, IoT profile generation
  Stage C:  EMBA Scan          — run EMBA, stream logs, detect completion by exit code
  Stage D:  Post-process       — validate expected output files exist
  Stage E:  AI Triage          — extract findings, send to Ollama, produce risk report
  Stage F:  DB Persist         — write results to database
  Stage G:  Alert              — Slack/email dispatch (fire-and-forget)

This module is called by the worker process for background execution.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid
from asyncio import CancelledError
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.models.firmware import FirmwareAnalysis, FirmwareStatus
from app.models.host import Host
from app.services.alerting import send_alert
from app.services.firmware_download import download_firmware
from app.services.emba_scanner import run_emba, validate_emba_output
from app.services.ai_triage import run_triage
from app.services.scheduler import scheduler
from app.config import settings
from app.utils.logging import get_logger

log = get_logger("firmware.pipeline")

# Redis queue key for firmware analysis jobs
FW_QUEUE_KEY = "soc:firmware_queue"
FW_CANCEL_SET = "soc:firmware_cancel"


@dataclasses.dataclass
class PipelineResult:
    """Carries the outcome of a completed (or failed) pipeline run."""

    status: str                         # "COMPLETED" | "FAILED" | "CANCELLED" | "TIMEOUT"
    ip: str = "unknown"
    analysis_id: str = ""
    risk_score: float | None = None
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    report: str = ""
    stage_failed: str | None = None     # label of the stage that raised, if any
    error: str | None = None


# ── Helpers ─────────────────────────────────────────────────────────────────

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


async def _set_status(
    aid: uuid.UUID,
    host_mac: str,
    status: FirmwareStatus,
    stage: int,
    label: str,
) -> None:
    """Single-call helper to update both FirmwareAnalysis and Host in one transaction."""
    async with async_session() as db:
        await _update_analysis(
            db, aid,
            status=status,
            current_stage=stage,
            stage_label=label,
        )
        await _update_host_firmware(
            db, host_mac,
            firmware_status=status.value,
        )
        await db.commit()


async def _persist_results(
    aid: uuid.UUID,
    host_mac: str,
    result: "PipelineResult",
) -> None:
    """Stage F — write final analysis results to DB."""
    async with async_session() as db:
        await _update_analysis(
            db, aid,
            risk_report=result.report,
            risk_score=result.risk_score,
            findings_count=result.findings_count,
            critical_count=result.critical_count,
            high_count=result.high_count,
            status=FirmwareStatus.COMPLETED,
            current_stage=5,
            stage_label="Completed",
            completed_at=datetime.now(timezone.utc),
        )
        await _update_host_firmware(
            db, host_mac,
            risk_report=result.report,
            risk_score=result.risk_score,
            firmware_status=FirmwareStatus.COMPLETED.value,
        )
        await db.commit()


# ── Core pipeline ────────────────────────────────────────────────────────────

async def _pipeline_core(
    analysis_id: str,
    aid: uuid.UUID,
    on_progress: Callable[[str, dict], None] | None,
) -> "PipelineResult":
    """Run all pipeline stages and return a PipelineResult."""

    stage_labels = [
        "Downloading Firmware",          # 1
        "Running EMBA Analysis",         # 2
        "Validating EMBA Output",        # 3
        "AI Triage & Risk Scoring",      # 4
    ]

    ip = "unknown"
    host_mac = ""

    async def progress(msg: str, stage: int = 0):
        if on_progress:
            await on_progress(msg, {
                "stage": stage,
                "stage_label": stage_labels[stage - 1] if 1 <= stage <= len(stage_labels) else "Initializing",
            })

    # ── Load analysis record ─────────────────────────────────────────────
    async with async_session() as db:
        result = await db.execute(
            select(FirmwareAnalysis).where(FirmwareAnalysis.id == aid)
        )
        analysis = result.scalar_one_or_none()
        if not analysis:
            log.error("analysis_not_found", analysis_id=analysis_id)
            return PipelineResult(status="FAILED", error="Analysis record not found")

        if analysis.status == FirmwareStatus.CANCELLED:
            log.info("analysis_already_cancelled", analysis_id=analysis_id)
            return PipelineResult(status="CANCELLED")

        host_mac = analysis.host_mac
        fw_url = analysis.fw_url

        host_result = await db.execute(select(Host).where(Host.mac_address == host_mac))
        host = host_result.scalar_one_or_none()
        if not host:
            log.error("host_not_found", mac=host_mac)
            return PipelineResult(status="FAILED", error=f"Host {host_mac} not found")

        ip = host.ip_address
        vendor = host.vendor or "Unknown"
        ports_list = [str(p.port_number) for p in (host.ports or [])]
        ports_str = ", ".join(ports_list) if ports_list else "none"

        analysis.status = FirmwareStatus.DOWNLOADING
        analysis.started_at = datetime.now(timezone.utc)
        analysis.current_stage = 1
        analysis.stage_label = stage_labels[0]
        await db.commit()

    await progress(f"Starting firmware pipeline for {ip} ({host_mac})", 1)

    if not fw_url:
        raise ValueError(f"No firmware URL configured for device {host_mac}")

    # ── Stage A: Download + Validate ─────────────────────────────────────
    fw_path, fw_hash, fw_size = await download_firmware(
        url=fw_url,
        ip=ip,
        mac=host_mac,
        on_progress=lambda msg: progress(msg, 1),
    )

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

    await progress(f"Firmware downloaded & validated: {fw_path.name} ({fw_size:,} bytes)", 1)

    if await scheduler.is_cancelled_firmware(aid):
        raise CancelledError("Analysis cancelled by user")

    # ── Stage B/C: EMBA Prep + Scan ──────────────────────────────────────
    await _set_status(aid, host_mac, FirmwareStatus.EMBA_PREP, 2, "EMBA Preparation")
    await progress(f"Preparing EMBA environment for {fw_path.name}", 2)

    await _set_status(aid, host_mac, FirmwareStatus.EMBA_RUNNING, 2, stage_labels[1])
    await progress(f"Starting EMBA analysis on {fw_path.name}", 2)

    emba_log_dir = await run_emba(
        fw_path=str(fw_path),
        device_id=str(aid)[:8],
        ip=ip,
        on_progress=lambda msg: progress(msg, 2),
    )

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

    # ── Stage D: Post-process validation ─────────────────────────────────
    await _set_status(aid, host_mac, FirmwareStatus.POST_PROCESSING, 3, stage_labels[2])
    await progress("Validating EMBA output files", 3)

    output_check = validate_emba_output(emba_log_dir)
    if not output_check["valid"]:
        missing = [k for k, v in output_check["files"].items() if not v]
        await progress(f"EMBA output incomplete — missing: {missing}; proceeding with available data", 3)
    else:
        await progress("EMBA output validation passed", 3)

    if await scheduler.is_cancelled_firmware(aid):
        raise CancelledError("Analysis cancelled by user")

    # ── Stage E: AI Triage ───────────────────────────────────────────────
    await _set_status(aid, host_mac, FirmwareStatus.TRIAGING, 4, stage_labels[3])
    await progress(f"Running AI triage on EMBA results for {ip}", 4)

    report, risk_score, findings_count, critical_count, high_count = await run_triage(
        emba_log_dir=emba_log_dir,
        ip=ip,
        vendor=vendor,
        ports=ports_str,
        mac=host_mac,
        on_progress=lambda msg: progress(msg, 4),
    )

    pipeline_result = PipelineResult(
        status="COMPLETED",
        ip=ip,
        analysis_id=analysis_id,
        risk_score=risk_score,
        findings_count=findings_count,
        critical_count=critical_count,
        high_count=high_count,
        report=report,
    )

    # ── Stage F: DB Persist ──────────────────────────────────────────────
    await _persist_results(aid, host_mac, pipeline_result)

    await progress(
        f"Firmware analysis complete for {ip} — "
        f"Risk: {risk_score}/10, {findings_count} findings",
        4,
    )

    log.info(
        "fw_pipeline_done",
        analysis_id=analysis_id,
        risk_score=risk_score,
        findings=findings_count,
    )

    return pipeline_result


# ── Public entry point ───────────────────────────────────────────────────────

async def run_firmware_pipeline(
    analysis_id: str,
    on_progress: Callable[[str, dict], None] | None = None,
) -> None:
    """
    Execute the full firmware analysis pipeline for one device.

    Wraps ``_pipeline_core`` in a global timeout (``settings.pipeline_timeout``).
    All failures are caught here. Dispatches alerts via Stage G on failure or
    high-risk completion.
    """
    aid = uuid.UUID(analysis_id)
    log.info("fw_pipeline_start", analysis_id=analysis_id)

    ip = "unknown"

    async def progress(msg: str, meta: dict | None = None):
        if on_progress:
            await on_progress(msg, meta or {"stage": 0, "stage_label": "Initializing"})

    try:
        result = await asyncio.wait_for(
            _pipeline_core(analysis_id, aid, on_progress),
            timeout=settings.pipeline_timeout,
        )

    except asyncio.TimeoutError:
        log.error("fw_pipeline_timeout", analysis_id=analysis_id, timeout=settings.pipeline_timeout)
        try:
            async with async_session() as db:
                await _update_analysis(
                    db, aid,
                    status=FirmwareStatus.FAILED,
                    error_message=f"Pipeline exceeded global timeout of {settings.pipeline_timeout}s",
                    completed_at=datetime.now(timezone.utc),
                )
                await db.commit()
        except Exception as db_err:
            log.error("fw_pipeline_timeout_persist_error", error=str(db_err))

        await send_alert(
            level="TIMEOUT",
            device_ip=ip,
            analysis_id=analysis_id,
            error=f"Pipeline exceeded {settings.pipeline_timeout}s",
        )
        await progress(
            f"Pipeline timed out after {settings.pipeline_timeout}s",
            {"stage": 0, "error": "timeout"},
        )
        return

    except CancelledError:
        log.info("fw_pipeline_cancelled", analysis_id=analysis_id)
        try:
            async with async_session() as db:
                await _update_analysis(
                    db, aid,
                    status=FirmwareStatus.CANCELLED,
                    completed_at=datetime.now(timezone.utc),
                )
                await db.commit()
        except Exception:
            pass
        await scheduler.clear_cancel_firmware(aid)
        return

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
                await db.commit()
        except Exception as db_err:
            log.error("fw_pipeline_fail_persist_error", error=str(db_err))

        await send_alert(
            level="FAILED",
            device_ip=ip,
            analysis_id=analysis_id,
            error=str(e)[:500],
        )
        await progress(
            f"Firmware analysis failed: {e}",
            {"stage": 0, "error": str(e)[:500]},
        )
        return

    # ── Stage G: Alert ───────────────────────────────────────────────────
    if (
        result.status == "COMPLETED"
        and result.risk_score is not None
        and result.risk_score >= settings.alert_risk_threshold
    ):
        async with async_session() as db:
            await _update_analysis(
                db, aid,
                status=FirmwareStatus.ALERTING,
                stage_label="Dispatching Alerts",
            )
            await db.commit()

        await send_alert(
            level="HIGH_RISK",
            device_ip=result.ip,
            analysis_id=analysis_id,
            risk_score=result.risk_score,
            findings_count=result.findings_count,
        )

        async with async_session() as db:
            await _update_analysis(
                db, aid,
                status=FirmwareStatus.COMPLETED,
                stage_label="Completed",
            )
            await db.commit()
