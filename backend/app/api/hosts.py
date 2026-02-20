"""Host listing, filtering, editing, import/export, and tagging endpoints."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.host import Host
from app.models.port import Port
from app.models.tag import Tag, host_tags
from app.schemas.host import HostDetailOut, HostFilter, HostListOut, HostOut, HostUpdate

router = APIRouter(prefix="/hosts", tags=["hosts"])

# ── db/devices directory for git-backed export ──
DEVICES_DIR = Path("/app/db_devices")
DEVICES_DIR.mkdir(parents=True, exist_ok=True)


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
    count_query = select(func.count()).select_from(Host)

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
            query = query.where(Host.open_port_count > 0)
            count_query = count_query.where(Host.open_port_count > 0)
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
    query = query.order_by(Host.last_seen.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    hosts = result.scalars().unique().all()

    return HostListOut(items=[HostOut.model_validate(h) for h in hosts], total=total, page=page, page_size=page_size)


@router.get("/{mac}", response_model=HostDetailOut)
async def get_host(mac: str, db: AsyncSession = Depends(get_db)):
    """Get host details with all ports."""
    result = await db.execute(
        select(Host)
        .where(Host.mac_address == mac)
        .options(selectinload(Host.ports), selectinload(Host.tags))
    )
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")
    return HostDetailOut.model_validate(host)


@router.patch("/{mac}", response_model=HostOut)
async def update_host(mac: str, body: HostUpdate, db: AsyncSession = Depends(get_db)):
    """Edit host fields (hostname, vendor, OS, firmware URL, IP)."""
    result = await db.execute(
        select(Host).where(Host.mac_address == mac).options(selectinload(Host.tags))
    )
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")

    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(host, field, value)

    await db.commit()
    await db.refresh(host)
    return HostOut.model_validate(host)


# ── Tagging ─────────────────────────────────────

@router.post("/{mac}/tags/{tag_id}", status_code=204)
async def add_tag_to_host(mac: str, tag_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Attach a tag to a host."""
    host = (await db.execute(select(Host).where(Host.mac_address == mac).options(selectinload(Host.tags)))).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")
    tag = (await db.execute(select(Tag).where(Tag.id == tag_id))).scalar_one_or_none()
    if not tag:
        raise HTTPException(404, "Tag not found")
    if tag not in host.tags:
        host.tags.append(tag)
        await db.commit()


@router.delete("/{mac}/tags/{tag_id}", status_code=204)
async def remove_tag_from_host(mac: str, tag_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Remove a tag from a host."""
    host = (await db.execute(select(Host).where(Host.mac_address == mac).options(selectinload(Host.tags)))).scalar_one_or_none()
    if not host:
        raise HTTPException(404, "Host not found")
    tag = (await db.execute(select(Tag).where(Tag.id == tag_id))).scalar_one_or_none()
    if not tag:
        raise HTTPException(404, "Tag not found")
    if tag in host.tags:
        host.tags.remove(tag)
        await db.commit()


# ── Export / Import — db/devices/ ───────────────

def _host_to_dict(host: Host) -> dict:
    """Serialize a host to a plain dict for JSON export."""
    return {
        "mac_address": host.mac_address,
        "ip_address": host.ip_address,
        "hostname": host.hostname,
        "vendor": host.vendor,
        "os_name": host.os_name,
        "os_family": host.os_family,
        "os_accuracy": host.os_accuracy,
        "os_cpe": host.os_cpe,
        "is_up": host.is_up,
        "response_time_ms": host.response_time_ms,
        "firmware_url": host.firmware_url,
        "open_port_count": host.open_port_count,
        "fw_path": host.fw_path,
        "fw_hash": host.fw_hash,
        "emba_log_dir": host.emba_log_dir,
        "risk_score": host.risk_score,
        "firmware_status": host.firmware_status,
        "discovered_at": host.discovered_at.isoformat() if host.discovered_at else None,
        "last_seen": host.last_seen.isoformat() if host.last_seen else None,
        "tags": [t.name for t in host.tags] if host.tags else [],
        "ports": [
            {
                "port_number": p.port_number,
                "protocol": p.protocol,
                "state": p.state,
                "service_name": p.service_name,
                "service_version": p.service_version,
                "service_product": p.service_product,
                "service_cpe": p.service_cpe,
            }
            for p in (host.ports or [])
        ],
    }


@router.post("/export", status_code=200)
async def export_devices(db: AsyncSession = Depends(get_db)):
    """Export all hosts to db/devices/ as individual JSON files + a combined devices.json."""
    result = await db.execute(
        select(Host).options(selectinload(Host.ports), selectinload(Host.tags))
    )
    hosts = result.scalars().unique().all()

    all_devices = []
    for host in hosts:
        data = _host_to_dict(host)
        all_devices.append(data)
        # Per-device file keyed by MAC (replace colons for filename safety)
        safe_mac = host.mac_address.replace(":", "-")
        (DEVICES_DIR / f"{safe_mac}.json").write_text(json.dumps(data, indent=2))

    # Combined file
    (DEVICES_DIR / "devices.json").write_text(json.dumps(all_devices, indent=2))

    return {"exported": len(all_devices), "path": str(DEVICES_DIR)}


@router.post("/import", status_code=200)
async def import_devices(db: AsyncSession = Depends(get_db)):
    """Import hosts from db/devices/devices.json into the database (upsert by MAC)."""
    combined = DEVICES_DIR / "devices.json"
    if not combined.exists():
        raise HTTPException(404, "No devices.json found in db/devices/")

    devices = json.loads(combined.read_text())
    imported = 0

    for dev in devices:
        mac = dev.get("mac_address")
        if not mac:
            continue

        result = await db.execute(select(Host).where(Host.mac_address == mac))
        host = result.scalar_one_or_none()

        if host is None:
            host = Host(mac_address=mac)
            db.add(host)

        # Update fields from import (but don't overwrite user edits with None)
        for field in ["ip_address", "hostname", "vendor", "os_name", "os_family",
                       "os_accuracy", "os_cpe", "firmware_url"]:
            val = dev.get(field)
            if val is not None:
                setattr(host, field, val)

        host.is_up = dev.get("is_up", True)
        host.open_port_count = dev.get("open_port_count", 0)

        if dev.get("last_seen"):
            try:
                host.last_seen = datetime.fromisoformat(dev["last_seen"])
            except (ValueError, TypeError):
                pass

        imported += 1

    await db.commit()
    return {"imported": imported}
