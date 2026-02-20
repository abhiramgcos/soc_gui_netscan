"""Dashboard aggregate statistics endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.host import Host
from app.models.port import Port
from app.models.scan import Scan, ScanStatus
from app.models.firmware import FirmwareAnalysis, FirmwareStatus

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
async def dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Return aggregate statistics for the dashboard."""
    total_scans = (await db.execute(select(func.count(Scan.id)))).scalar() or 0
    running_scans = (await db.execute(select(func.count(Scan.id)).where(Scan.status == ScanStatus.RUNNING))).scalar() or 0
    completed_scans = (await db.execute(select(func.count(Scan.id)).where(Scan.status == ScanStatus.COMPLETED))).scalar() or 0
    failed_scans = (await db.execute(select(func.count(Scan.id)).where(Scan.status == ScanStatus.FAILED))).scalar() or 0

    total_hosts = (await db.execute(select(func.count(Host.mac_address)))).scalar() or 0
    live_hosts = (await db.execute(select(func.count(Host.mac_address)).where(Host.is_up == True))).scalar() or 0  # noqa: E712
    unique_ips = (await db.execute(select(func.count(distinct(Host.ip_address))))).scalar() or 0

    total_ports = (await db.execute(select(func.count(Port.id)))).scalar() or 0
    open_ports = (await db.execute(select(func.count(Port.id)).where(Port.state == "open"))).scalar() or 0

    # Top services
    top_services_q = (
        select(Port.service_name, func.count(Port.id).label("count"))
        .where(Port.service_name.isnot(None))
        .group_by(Port.service_name)
        .order_by(func.count(Port.id).desc())
        .limit(10)
    )
    top_services_result = await db.execute(top_services_q)
    top_services = [{"name": row[0], "count": row[1]} for row in top_services_result.all()]

    # Top ports
    top_ports_q = (
        select(Port.port_number, func.count(Port.id).label("count"))
        .where(Port.state == "open")
        .group_by(Port.port_number)
        .order_by(func.count(Port.id).desc())
        .limit(10)
    )
    top_ports_result = await db.execute(top_ports_q)
    top_ports = [{"port": row[0], "count": row[1]} for row in top_ports_result.all()]

    # OS distribution
    os_dist_q = (
        select(Host.os_family, func.count(Host.mac_address).label("count"))
        .where(Host.os_family.isnot(None))
        .group_by(Host.os_family)
        .order_by(func.count(Host.mac_address).desc())
        .limit(10)
    )
    os_dist_result = await db.execute(os_dist_q)
    os_distribution = [{"os": row[0], "count": row[1]} for row in os_dist_result.all()]

    # Recent scans
    recent_q = select(Scan).order_by(Scan.created_at.desc()).limit(5)
    recent_result = await db.execute(recent_q)
    recent_scans = []
    for s in recent_result.scalars().all():
        recent_scans.append({
            "id": str(s.id),
            "target": s.target,
            "status": s.status.value,
            "hosts_discovered": s.hosts_discovered,
            "open_ports_found": s.open_ports_found,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        })

    return {
        "scans": {
            "total": total_scans,
            "running": running_scans,
            "completed": completed_scans,
            "failed": failed_scans,
        },
        "hosts": {
            "total": total_hosts,
            "live": live_hosts,
            "unique_ips": unique_ips,
        },
        "ports": {
            "total": total_ports,
            "open": open_ports,
        },
        "firmware": await _firmware_stats(db),
        "top_services": top_services,
        "top_ports": top_ports,
        "os_distribution": os_distribution,
        "recent_scans": recent_scans,
    }


async def _firmware_stats(db: AsyncSession) -> dict:
    """Compute firmware analysis aggregate stats for the dashboard."""
    total = (await db.execute(select(func.count(FirmwareAnalysis.id)))).scalar() or 0
    completed = (await db.execute(
        select(func.count(FirmwareAnalysis.id)).where(
            FirmwareAnalysis.status == FirmwareStatus.COMPLETED
        )
    )).scalar() or 0
    running = (await db.execute(
        select(func.count(FirmwareAnalysis.id)).where(
            FirmwareAnalysis.status.in_([
                FirmwareStatus.DOWNLOADING, FirmwareStatus.EMBA_RUNNING,
                FirmwareStatus.TRIAGING, FirmwareStatus.PENDING,
            ])
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
    hosts_with_fw = (await db.execute(
        select(func.count(Host.mac_address)).where(Host.firmware_url.isnot(None))
    )).scalar() or 0

    return {
        "total": total,
        "completed": completed,
        "running": running,
        "avg_risk_score": round(avg_risk, 1) if avg_risk else None,
        "max_risk_score": round(max_risk, 1) if max_risk else None,
        "hosts_with_firmware_url": hosts_with_fw,
    }
