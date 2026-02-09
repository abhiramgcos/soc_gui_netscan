"""
Seed data script — populates the database with default tags
and (optionally) sample scan data for development.

Usage:
    python seed_data.py          # tags only
    python seed_data.py --demo   # tags + demo scan data
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

# Ensure app is importable
sys.path.insert(0, ".")

from app.database import async_session, engine, Base
from app.models import Scan, ScanLog, Host, Port, Tag
from app.models.scan import ScanStatus, ScanType


DEFAULT_TAGS = [
    {"name": "Critical", "color": "#ef4444", "description": "Critical infrastructure or vulnerability"},
    {"name": "Production", "color": "#f59e0b", "description": "Production environment host"},
    {"name": "Development", "color": "#3b82f6", "description": "Development / staging host"},
    {"name": "Database", "color": "#8b5cf6", "description": "Database server"},
    {"name": "Web Server", "color": "#10b981", "description": "Web / HTTP server"},
    {"name": "Firewall", "color": "#f97316", "description": "Firewall / gateway device"},
    {"name": "IoT", "color": "#06b6d4", "description": "IoT / embedded device"},
    {"name": "Printer", "color": "#64748b", "description": "Network printer"},
    {"name": "Monitored", "color": "#22c55e", "description": "Under active monitoring"},
    {"name": "Quarantine", "color": "#dc2626", "description": "Quarantined / isolated host"},
]


async def seed_tags():
    """Insert default tags if they don't exist."""
    async with async_session() as db:
        for tag_data in DEFAULT_TAGS:
            existing = (await db.execute(select(Tag).where(Tag.name == tag_data["name"]))).scalar_one_or_none()
            if not existing:
                db.add(Tag(**tag_data))
                print(f"  + Tag: {tag_data['name']}")
        await db.commit()
    print("Tags seeded.")


async def seed_demo_data():
    """Insert a sample completed scan with hosts and ports."""
    async with async_session() as db:
        scan = Scan(
            target="192.168.1.0/24",
            scan_type=ScanType.SUBNET,
            status=ScanStatus.COMPLETED,
            name="Demo Network Scan",
            description="Sample scan for development and testing",
            current_stage=4,
            total_stages=4,
            stage_label="Completed",
            hosts_discovered=5,
            live_hosts=5,
            open_ports_found=12,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        await db.flush()

        demo_hosts = [
            {
                "ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:01",
                "hostname": "gateway.local", "vendor": "Cisco Systems",
                "os_name": "Cisco IOS 15.x", "os_family": "IOS", "os_accuracy": 95,
                "ports": [(22, "ssh", "OpenSSH 8.9", "open"), (80, "http", "nginx 1.24", "open"), (443, "https", "nginx 1.24", "open")],
            },
            {
                "ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:10",
                "hostname": "web-server.local", "vendor": "Dell Inc",
                "os_name": "Ubuntu 22.04", "os_family": "Linux", "os_accuracy": 98,
                "ports": [(22, "ssh", "OpenSSH 8.9", "open"), (80, "http", "Apache 2.4.57", "open"), (443, "https", "Apache 2.4.57", "open"), (3306, "mysql", "MySQL 8.0.35", "open")],
            },
            {
                "ip": "192.168.1.20", "mac": "AA:BB:CC:DD:EE:20",
                "hostname": "db-primary.local", "vendor": "HP Inc",
                "os_name": "CentOS 8", "os_family": "Linux", "os_accuracy": 90,
                "ports": [(22, "ssh", "OpenSSH 7.4", "open"), (5432, "postgresql", "PostgreSQL 16.1", "open")],
            },
            {
                "ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:50",
                "hostname": "workstation-01.local", "vendor": "Apple Inc",
                "os_name": "macOS Ventura", "os_family": "macOS", "os_accuracy": 85,
                "ports": [(22, "ssh", "OpenSSH 9.0", "open"), (5900, "vnc", "Apple Remote Desktop", "open")],
            },
            {
                "ip": "192.168.1.100", "mac": "AA:BB:CC:DD:EE:FF",
                "hostname": "printer-floor2.local", "vendor": "HP Inc",
                "os_name": "HP JetDirect", "os_family": "Embedded", "os_accuracy": 70,
                "ports": [(80, "http", "HP Embedded Web Server", "open"), (9100, "jetdirect", None, "open")],
            },
        ]

        for hd in demo_hosts:
            host = Host(
                scan_id=scan.id,
                ip_address=hd["ip"],
                mac_address=hd["mac"],
                hostname=hd["hostname"],
                vendor=hd["vendor"],
                os_name=hd["os_name"],
                os_family=hd["os_family"],
                os_accuracy=hd["os_accuracy"],
            )
            db.add(host)
            await db.flush()

            for port_num, service, version, state in hd["ports"]:
                port = Port(
                    host_id=host.id,
                    port_number=port_num,
                    protocol="tcp",
                    state=state,
                    service_name=service,
                    service_version=version,
                )
                db.add(port)

        # Add scan logs
        for stage, msg in enumerate([
            "Ping sweep found 5 hosts",
            "ARP resolved 5/5 MACs",
            "Port scan found 12 open ports",
            "Deep scan completed for 5 hosts",
        ], 1):
            db.add(ScanLog(scan_id=scan.id, stage=stage, message=msg))

        await db.commit()
    print("Demo data seeded.")


async def main():
    demo = "--demo" in sys.argv
    print("Seeding database...")
    await seed_tags()
    if demo:
        await seed_demo_data()
    print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
