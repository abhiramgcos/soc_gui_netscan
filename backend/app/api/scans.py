"""Scan CRUD and lifecycle endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.scan import Scan, ScanStatus
from app.schemas.scan import ScanCreate, ScanDetailOut, ScanListOut, ScanOut, ScanUpdate
from app.services.scheduler import scheduler
from app.utils.logging import get_logger

router = APIRouter(prefix="/scans", tags=["scans"])
log = get_logger("api.scans")


@router.get("", response_model=ScanListOut)
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: ScanStatus | None = None,
    search: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List scans with optional filtering and pagination."""
    query = select(Scan)
    count_query = select(func.count(Scan.id))

    if status:
        query = query.where(Scan.status == status)
        count_query = count_query.where(Scan.status == status)
    if search:
        pattern = f"%{search}%"
        query = query.where(Scan.target.ilike(pattern) | Scan.name.ilike(pattern))
        count_query = count_query.where(Scan.target.ilike(pattern) | Scan.name.ilike(pattern))

    total = (await db.execute(count_query)).scalar() or 0
    query = query.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    scans = result.scalars().all()

    return ScanListOut(items=[ScanOut.model_validate(s) for s in scans], total=total, page=page, page_size=page_size)


@router.post("", response_model=ScanOut, status_code=201)
async def create_scan(
    body: ScanCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new scan job and enqueue it for processing."""
    scan = Scan(
        target=body.target,
        scan_type=body.scan_type,
        name=body.name or f"Scan {body.target}",
        description=body.description,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Enqueue the scan for the worker
    await scheduler.enqueue_scan(scan.id)
    log.info("scan_created", scan_id=str(scan.id), target=body.target)
    return ScanOut.model_validate(scan)


@router.get("/{scan_id}", response_model=ScanDetailOut)
async def get_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Get full scan details including logs."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return ScanDetailOut.model_validate(scan)


@router.patch("/{scan_id}", response_model=ScanOut)
async def update_scan(scan_id: uuid.UUID, body: ScanUpdate, db: AsyncSession = Depends(get_db)):
    """Update scan metadata."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    if body.name is not None:
        scan.name = body.name
    if body.description is not None:
        scan.description = body.description
    await db.flush()
    await db.refresh(scan)
    return ScanOut.model_validate(scan)


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Delete a scan and all associated data."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    await db.delete(scan)
    log.info("scan_deleted", scan_id=str(scan_id))


@router.post("/{scan_id}/cancel", response_model=ScanOut)
async def cancel_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Cancel a running or pending scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(400, f"Cannot cancel scan in '{scan.status}' state")

    scan.status = ScanStatus.CANCELLED
    await scheduler.cancel_scan(scan.id)
    await db.flush()
    await db.refresh(scan)
    log.info("scan_cancelled", scan_id=str(scan_id))
    return ScanOut.model_validate(scan)
