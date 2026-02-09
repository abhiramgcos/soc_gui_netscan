"""ORM model unit tests."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.host import Host
from app.models.port import Port
from app.models.scan import Scan, ScanLog, ScanStatus, ScanType
from app.models.tag import Tag


@pytest.mark.asyncio
class TestScanModel:
    async def test_create_scan(self, db_session: AsyncSession):
        scan = Scan(target="10.0.0.0/24", scan_type=ScanType.SUBNET, name="Unit Test Scan")
        db_session.add(scan)
        await db_session.flush()
        assert scan.id is not None
        assert scan.status == ScanStatus.PENDING
        assert scan.current_stage == 0

    async def test_scan_relationships(self, db_session: AsyncSession):
        scan = Scan(target="10.0.0.1", scan_type=ScanType.SINGLE_HOST)
        db_session.add(scan)
        await db_session.flush()

        host = Host(scan_id=scan.id, ip_address="10.0.0.1", is_up=True)
        db_session.add(host)
        await db_session.flush()

        log_entry = ScanLog(scan_id=scan.id, stage=1, message="Test log")
        db_session.add(log_entry)
        await db_session.flush()

        result = await db_session.execute(select(Scan).where(Scan.id == scan.id))
        loaded = result.scalar_one()
        assert len(loaded.hosts) == 1
        assert len(loaded.logs) == 1


@pytest.mark.asyncio
class TestHostModel:
    async def test_create_host(self, db_session: AsyncSession):
        scan = Scan(target="10.0.0.1", scan_type=ScanType.SINGLE_HOST)
        db_session.add(scan)
        await db_session.flush()

        host = Host(
            scan_id=scan.id,
            ip_address="10.0.0.1",
            mac_address="AA:BB:CC:DD:EE:FF",
            hostname="test.local",
            vendor="Test Vendor",
            os_name="Linux",
            os_family="Linux",
            os_accuracy=95,
        )
        db_session.add(host)
        await db_session.flush()
        assert host.id is not None
        assert host.is_up is True

    async def test_host_with_ports(self, db_session: AsyncSession):
        scan = Scan(target="10.0.0.1", scan_type=ScanType.SINGLE_HOST)
        db_session.add(scan)
        await db_session.flush()

        host = Host(scan_id=scan.id, ip_address="10.0.0.1")
        db_session.add(host)
        await db_session.flush()

        port = Port(host_id=host.id, port_number=80, protocol="tcp", state="open", service_name="http")
        db_session.add(port)
        await db_session.flush()

        result = await db_session.execute(select(Host).where(Host.id == host.id))
        loaded = result.scalar_one()
        assert len(loaded.ports) == 1
        assert loaded.ports[0].port_number == 80


@pytest.mark.asyncio
class TestTagModel:
    async def test_create_tag(self, db_session: AsyncSession):
        tag = Tag(name="TestTag", color="#ff0000")
        db_session.add(tag)
        await db_session.flush()
        assert tag.id is not None

    async def test_tag_host_relationship(self, db_session: AsyncSession):
        scan = Scan(target="10.0.0.0/24", scan_type=ScanType.SUBNET)
        db_session.add(scan)
        await db_session.flush()

        host = Host(scan_id=scan.id, ip_address="10.0.0.5")
        tag = Tag(name="Important", color="#ef4444")
        db_session.add_all([host, tag])
        await db_session.flush()

        host.tags.append(tag)
        await db_session.flush()

        result = await db_session.execute(select(Host).where(Host.id == host.id))
        loaded = result.scalar_one()
        assert len(loaded.tags) == 1
        assert loaded.tags[0].name == "Important"
