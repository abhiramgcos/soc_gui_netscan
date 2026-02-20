"""Firmware analysis endpoints — trigger, monitor, and retrieve results."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.firmware import FirmwareAnalysis, FirmwareStatus
from app.models.host import Host
from app.schemas.firmware import (
    FirmwareAnalysisBatchCreate,
    FirmwareAnalysisCreate,
    FirmwareAnalysisListOut,
    FirmwareAnalysisOut,
    FirmwareAnalysisSummary,
)
from app.services.scheduler import scheduler
from app.utils.logging import get_logger

log = get_logger("api.firmware")

router = APIRouter(prefix="/firmware", tags=["firmware"])


@router.post("", response_model=FirmwareAnalysisOut, status_code=201)
async def start_firmware_analysis(
    body: FirmwareAnalysisCreate,
    db: AsyncSession = Depends(get_db),
):
    """Start firmware analysis pipeline for a single host."""
    # Validate host exists
    result = await db.execute(
        select(Host).where(Host.mac_address == body.host_mac)
    )
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

    # Determine firmware URL
    fw_url = body.fw_url or host.firmware_url
    if not fw_url:
        raise HTTPException(
            400,
            "No firmware URL provided. Set firmware_url on the host or include fw_url in the request.",
        )

    # Check if there's already a running analysis for this host
    running_q = select(FirmwareAnalysis).where(
        FirmwareAnalysis.host_mac == body.host_mac,
        FirmwareAnalysis.status.in_([
            FirmwareStatus.PENDING,
            FirmwareStatus.DOWNLOADING,
            FirmwareStatus.DOWNLOADED,
            FirmwareStatus.EMBA_RUNNING,
            FirmwareStatus.TRIAGING,
        ]),
    )
    existing = (await db.execute(running_q)).scalar_one_or_none()
    if existing:
        raise HTTPException(
            409,
            f"Analysis {existing.id} is already in progress for this host (status: {existing.status.value})",
        )

    # Create the analysis record
    analysis = FirmwareAnalysis(
        host_mac=body.host_mac,
        fw_url=fw_url,
        status=FirmwareStatus.PENDING,
    )
    db.add(analysis)
    await db.flush()

    # Update host firmware_url if a new one was provided
    if body.fw_url and body.fw_url != host.firmware_url:
        host.firmware_url = body.fw_url

    host.firmware_status = FirmwareStatus.PENDING.value
    await db.commit()
    await db.refresh(analysis)

    # Enqueue for background processing
    await scheduler.enqueue_firmware(analysis.id)
    log.info("firmware_analysis_created", analysis_id=str(analysis.id), host=body.host_mac)

    return FirmwareAnalysisOut.model_validate(analysis)


@router.post("/batch", response_model=list[FirmwareAnalysisOut], status_code=201)
async def start_batch_firmware_analysis(
    body: FirmwareAnalysisBatchCreate,
    db: AsyncSession = Depends(get_db),
):
    """Start firmware analysis for multiple hosts (or all hosts with firmware URLs)."""
    if body.host_macs:
        # Specific hosts
        result = await db.execute(
            select(Host).where(
                Host.mac_address.in_(body.host_macs),
                Host.firmware_url.isnot(None),
            )
        )
    else:
        # All hosts with firmware URLs that haven't been analysed
        result = await db.execute(
            select(Host).where(
                Host.firmware_url.isnot(None),
                (Host.firmware_status.is_(None)) | (Host.firmware_status.in_(["failed", "cancelled"])),
            )
        )

    hosts = result.scalars().all()
    if not hosts:
        raise HTTPException(404, "No eligible hosts found with firmware URLs")

    analyses = []
    for host in hosts:
        # Skip hosts with running analyses
        running = (await db.execute(
            select(FirmwareAnalysis).where(
                FirmwareAnalysis.host_mac == host.mac_address,
                FirmwareAnalysis.status.in_([
                    FirmwareStatus.PENDING, FirmwareStatus.DOWNLOADING,
                    FirmwareStatus.DOWNLOADED, FirmwareStatus.EMBA_RUNNING,
                    FirmwareStatus.TRIAGING,
                ]),
            )
        )).scalar_one_or_none()

        if running:
            continue

        analysis = FirmwareAnalysis(
            host_mac=host.mac_address,
            fw_url=host.firmware_url,
            status=FirmwareStatus.PENDING,
        )
        db.add(analysis)
        host.firmware_status = FirmwareStatus.PENDING.value
        analyses.append(analysis)

    await db.flush()
    await db.commit()

    # Enqueue all
    for a in analyses:
        await db.refresh(a)
        await scheduler.enqueue_firmware(a.id)

    log.info("batch_firmware_enqueued", count=len(analyses))
    return [FirmwareAnalysisOut.model_validate(a) for a in analyses]


@router.get("", response_model=FirmwareAnalysisListOut)
async def list_firmware_analyses(
    host_mac: str | None = None,
    status: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """List firmware analyses with optional filtering."""
    query = select(FirmwareAnalysis)
    count_query = select(func.count()).select_from(FirmwareAnalysis)

    if host_mac:
        query = query.where(FirmwareAnalysis.host_mac == host_mac)
        count_query = count_query.where(FirmwareAnalysis.host_mac == host_mac)
    if status:
        query = query.where(FirmwareAnalysis.status == status)
        count_query = count_query.where(FirmwareAnalysis.status == status)

    total = (await db.execute(count_query)).scalar() or 0
    query = (
        query
        .order_by(FirmwareAnalysis.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(query)
    analyses = result.scalars().all()

    return FirmwareAnalysisListOut(
        items=[FirmwareAnalysisOut.model_validate(a) for a in analyses],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/summary", response_model=FirmwareAnalysisSummary)
async def firmware_summary(db: AsyncSession = Depends(get_db)):
    """Get aggregate firmware analysis statistics."""
    total = (await db.execute(select(func.count(FirmwareAnalysis.id)))).scalar() or 0

    pending = (await db.execute(
        select(func.count(FirmwareAnalysis.id)).where(
            FirmwareAnalysis.status == FirmwareStatus.PENDING
        )
    )).scalar() or 0

    running = (await db.execute(
        select(func.count(FirmwareAnalysis.id)).where(
            FirmwareAnalysis.status.in_([
                FirmwareStatus.DOWNLOADING, FirmwareStatus.DOWNLOADED,
                FirmwareStatus.EMBA_RUNNING, FirmwareStatus.EMBA_DONE,
                FirmwareStatus.TRIAGING,
            ])
        )
    )).scalar() or 0

    completed = (await db.execute(
        select(func.count(FirmwareAnalysis.id)).where(
            FirmwareAnalysis.status == FirmwareStatus.COMPLETED
        )
    )).scalar() or 0

    failed = (await db.execute(
        select(func.count(FirmwareAnalysis.id)).where(
            FirmwareAnalysis.status == FirmwareStatus.FAILED
        )
    )).scalar() or 0

    avg_risk = (await db.execute(
        select(func.avg(FirmwareAnalysis.risk_score)).where(
            FirmwareAnalysis.risk_score.isnot(None)
        )
    )).scalar()

    max_risk = (await db.execute(
        select(func.max(FirmwareAnalysis.risk_score)).where(
            FirmwareAnalysis.risk_score.isnot(None)
        )
    )).scalar()

    total_critical = (await db.execute(
        select(func.coalesce(func.sum(FirmwareAnalysis.critical_count), 0))
    )).scalar() or 0

    total_high = (await db.execute(
        select(func.coalesce(func.sum(FirmwareAnalysis.high_count), 0))
    )).scalar() or 0

    hosts_with_fw = (await db.execute(
        select(func.count(Host.mac_address)).where(Host.firmware_url.isnot(None))
    )).scalar() or 0

    hosts_analysed = (await db.execute(
        select(func.count(distinct(FirmwareAnalysis.host_mac))).where(
            FirmwareAnalysis.status == FirmwareStatus.COMPLETED
        )
    )).scalar() or 0

    return FirmwareAnalysisSummary(
        total=total,
        pending=pending,
        running=running,
        completed=completed,
        failed=failed,
        avg_risk_score=round(avg_risk, 1) if avg_risk else None,
        max_risk_score=round(max_risk, 1) if max_risk else None,
        total_critical=total_critical,
        total_high=total_high,
        hosts_with_firmware_url=hosts_with_fw,
        hosts_analysed=hosts_analysed,
    )


@router.get("/{analysis_id}", response_model=FirmwareAnalysisOut)
async def get_firmware_analysis(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a single firmware analysis by ID."""
    result = await db.execute(
        select(FirmwareAnalysis).where(FirmwareAnalysis.id == analysis_id)
    )
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(404, "Firmware analysis not found")
    return FirmwareAnalysisOut.model_validate(analysis)


@router.post("/{analysis_id}/cancel", response_model=FirmwareAnalysisOut)
async def cancel_firmware_analysis(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Cancel a running firmware analysis."""
    result = await db.execute(
        select(FirmwareAnalysis).where(FirmwareAnalysis.id == analysis_id)
    )
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(404, "Firmware analysis not found")

    if analysis.status in (FirmwareStatus.COMPLETED, FirmwareStatus.CANCELLED):
        raise HTTPException(400, f"Cannot cancel analysis in {analysis.status.value} state")

    await scheduler.cancel_firmware(analysis_id)
    analysis.status = FirmwareStatus.CANCELLED
    await db.commit()
    await db.refresh(analysis)
    return FirmwareAnalysisOut.model_validate(analysis)


@router.delete("/{analysis_id}", status_code=204)
async def delete_firmware_analysis(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete a firmware analysis record."""
    result = await db.execute(
        select(FirmwareAnalysis).where(FirmwareAnalysis.id == analysis_id)
    )
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(404, "Firmware analysis not found")

    await db.delete(analysis)
    await db.commit()


@router.get("/{analysis_id}/report")
async def get_firmware_report(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get the AI triage report for a firmware analysis."""
    result = await db.execute(
        select(FirmwareAnalysis).where(FirmwareAnalysis.id == analysis_id)
    )
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(404, "Firmware analysis not found")
    if not analysis.risk_report:
        raise HTTPException(404, "No report available yet")

    return {
        "analysis_id": str(analysis.id),
        "host_mac": analysis.host_mac,
        "risk_score": analysis.risk_score,
        "findings_count": analysis.findings_count,
        "critical_count": analysis.critical_count,
        "high_count": analysis.high_count,
        "report": analysis.risk_report,
    }
