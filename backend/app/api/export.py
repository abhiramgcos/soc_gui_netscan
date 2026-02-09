"""Export endpoints — CSV and JSON for scan results and host data."""

from __future__ import annotations

import csv
import io
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.host import Host
from app.models.scan import Scan

router = APIRouter(prefix="/export", tags=["export"])


@router.get("/scans/{scan_id}")
async def export_scan(
    scan_id: uuid.UUID,
    format: str = Query("csv", regex="^(csv|json)$"),
    db: AsyncSession = Depends(get_db),
):
    """Export all hosts and ports discovered in a scan."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")

    host_result = await db.execute(
        select(Host).where(Host.scan_id == scan_id).options(selectinload(Host.ports), selectinload(Host.tags))
    )
    hosts = host_result.scalars().unique().all()

    if format == "json":
        import orjson
        data = []
        for h in hosts:
            data.append({
                "ip_address": h.ip_address,
                "mac_address": h.mac_address,
                "hostname": h.hostname,
                "vendor": h.vendor,
                "os_name": h.os_name,
                "os_family": h.os_family,
                "os_accuracy": h.os_accuracy,
                "is_up": h.is_up,
                "discovered_at": h.discovered_at.isoformat() if h.discovered_at else None,
                "tags": [t.name for t in h.tags],
                "ports": [
                    {
                        "port": p.port_number,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service": p.service_name,
                        "version": p.service_version,
                        "product": p.service_product,
                    }
                    for p in h.ports
                ],
            })
        content = orjson.dumps({"scan_target": scan.target, "scan_id": str(scan.id), "hosts": data})
        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.json"},
        )

    # CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "IP Address", "MAC Address", "Hostname", "Vendor", "OS", "OS Family",
        "OS Accuracy", "Status", "Port", "Protocol", "State", "Service",
        "Version", "Product", "Tags", "Discovered At",
    ])
    for h in hosts:
        if h.ports:
            for p in h.ports:
                writer.writerow([
                    h.ip_address, h.mac_address, h.hostname, h.vendor,
                    h.os_name, h.os_family, h.os_accuracy,
                    "up" if h.is_up else "down",
                    p.port_number, p.protocol, p.state, p.service_name,
                    p.service_version, p.service_product,
                    "; ".join(t.name for t in h.tags),
                    h.discovered_at.isoformat() if h.discovered_at else "",
                ])
        else:
            writer.writerow([
                h.ip_address, h.mac_address, h.hostname, h.vendor,
                h.os_name, h.os_family, h.os_accuracy,
                "up" if h.is_up else "down",
                "", "", "", "", "", "",
                "; ".join(t.name for t in h.tags),
                h.discovered_at.isoformat() if h.discovered_at else "",
            ])

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"},
    )


@router.get("/hosts")
async def export_all_hosts(
    format: str = Query("csv", regex="^(csv|json)$"),
    db: AsyncSession = Depends(get_db),
):
    """Export all discovered hosts."""
    result = await db.execute(
        select(Host).options(selectinload(Host.ports), selectinload(Host.tags)).order_by(Host.discovered_at.desc())
    )
    hosts = result.scalars().unique().all()

    if format == "json":
        import orjson
        data = []
        for h in hosts:
            data.append({
                "ip_address": h.ip_address,
                "mac_address": h.mac_address,
                "hostname": h.hostname,
                "vendor": h.vendor,
                "os_name": h.os_name,
                "os_family": h.os_family,
                "is_up": h.is_up,
                "discovered_at": h.discovered_at.isoformat() if h.discovered_at else None,
                "tags": [t.name for t in h.tags],
                "ports_count": len(h.ports),
            })
        content = orjson.dumps({"total": len(data), "hosts": data})
        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=hosts_export.json"},
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP Address", "MAC Address", "Hostname", "Vendor", "OS", "OS Family", "Status", "Open Ports", "Tags", "Discovered At"])
    for h in hosts:
        open_ports = [p for p in h.ports if p.state == "open"]
        writer.writerow([
            h.ip_address, h.mac_address, h.hostname, h.vendor,
            h.os_name, h.os_family, "up" if h.is_up else "down",
            len(open_ports),
            "; ".join(t.name for t in h.tags),
            h.discovered_at.isoformat() if h.discovered_at else "",
        ])
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=hosts_export.csv"},
    )
