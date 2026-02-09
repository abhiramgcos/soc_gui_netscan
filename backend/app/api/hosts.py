"""Host listing, filtering, searching, and tagging endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.host import Host
from app.models.port import Port
from app.models.tag import Tag, host_tags
from app.schemas.host import HostDetailOut, HostFilter, HostListOut, HostOut

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("", response_model=HostListOut)
async def list_hosts(
    scan_id: uuid.UUID | None = None,
    ip_address: str | None = None,
    os_family: str | None = None,
    is_up: bool | None = None,
    has_open_ports: bool | None = None,
    tag_name: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """List and filter hosts across all scans."""
    query = select(Host).options(selectinload(Host.tags))
    count_query = select(func.count(Host.id))

    # ── Filters ─────────────────────────────────
    if scan_id:
        query = query.where(Host.scan_id == scan_id)
        count_query = count_query.where(Host.scan_id == scan_id)
    if ip_address:
        query = query.where(Host.ip_address.ilike(f"%{ip_address}%"))
        count_query = count_query.where(Host.ip_address.ilike(f"%{ip_address}%"))
    if os_family:
        query = query.where(Host.os_family.ilike(f"%{os_family}%"))
        count_query = count_query.where(Host.os_family.ilike(f"%{os_family}%"))
    if is_up is not None:
        query = query.where(Host.is_up == is_up)
        count_query = count_query.where(Host.is_up == is_up)
    if has_open_ports is not None:
        if has_open_ports:
            sub = select(Port.host_id).where(Port.state == "open").distinct().subquery()
            query = query.where(Host.id.in_(select(sub.c.host_id)))
            count_query = count_query.where(Host.id.in_(select(sub.c.host_id)))
    if tag_name:
        query = query.join(host_tags).join(Tag).where(Tag.name.ilike(f"%{tag_name}%"))
        count_query = count_query.join(host_tags).join(Tag).where(Tag.name.ilike(f"%{tag_name}%"))
    if search:
        pattern = f"%{search}%"
        query = query.where(
            Host.ip_address.ilike(pattern)
            | Host.hostname.ilike(pattern)
            | Host.os_name.ilike(pattern)
            | Host.vendor.ilike(pattern)
            | Host.mac_address.ilike(pattern)
        )
        count_query = count_query.where(
            Host.ip_address.ilike(pattern)
            | Host.hostname.ilike(pattern)
            | Host.os_name.ilike(pattern)
            | Host.vendor.ilike(pattern)
            | Host.mac_address.ilike(pattern)
        )

    total = (await db.execute(count_query)).scalar() or 0
    query = query.order_by(Host.discovered_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    hosts = result.scalars().unique().all()

    return HostListOut(items=[HostOut.model_validate(h) for h in hosts], total=total, page=page, page_size=page_size)


@router.get("/{host_id}", response_model=HostDetailOut)
async def get_host(host_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Get host details with all ports."""
    result = await db.execute(
        select(Host).where(Host.id == host_id).options(selectinload(Host.ports), selectinload(Host.tags))
    )
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")
    return HostDetailOut.model_validate(host)


@router.post("/{host_id}/tags/{tag_id}", status_code=204)
async def add_tag_to_host(host_id: uuid.UUID, tag_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Attach a tag to a host."""
    host = (await db.execute(select(Host).where(Host.id == host_id).options(selectinload(Host.tags)))).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")
    tag = (await db.execute(select(Tag).where(Tag.id == tag_id))).scalar_one_or_none()
    if not tag:
        raise HTTPException(404, "Tag not found")
    if tag not in host.tags:
        host.tags.append(tag)


@router.delete("/{host_id}/tags/{tag_id}", status_code=204)
async def remove_tag_from_host(host_id: uuid.UUID, tag_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Remove a tag from a host."""
    host = (await db.execute(select(Host).where(Host.id == host_id).options(selectinload(Host.tags)))).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")
    tag = (await db.execute(select(Tag).where(Tag.id == tag_id))).scalar_one_or_none()
    if not tag:
        raise HTTPException(404, "Tag not found")
    if tag in host.tags:
        host.tags.remove(tag)
