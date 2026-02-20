"""Host Pydantic schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.schemas.port import PortOut


class TagBrief(BaseModel):
    id: uuid.UUID
    name: str
    color: str

    model_config = {"from_attributes": True}


class HostOut(BaseModel):
    """Host response."""
    mac_address: str
    scan_id: uuid.UUID | None = None
    ip_address: str
    hostname: str | None = None
    vendor: str | None = None
    os_name: str | None = None
    os_family: str | None = None
    os_accuracy: int | None = None
    os_cpe: str | None = None
    is_up: bool = True
    response_time_ms: int | None = None
    firmware_url: str | None = None
    open_port_count: int = 0
    # Firmware analysis fields
    fw_path: str | None = None
    fw_hash: str | None = None
    emba_log_dir: str | None = None
    risk_report: str | None = None
    risk_score: float | None = None
    firmware_status: str | None = None
    discovered_at: datetime
    last_seen: datetime
    tags: list[TagBrief] = []

    model_config = {"from_attributes": True}


class HostDetailOut(HostOut):
    """Host with ports."""
    ports: list[PortOut] = []

    model_config = {"from_attributes": True}


class HostUpdate(BaseModel):
    """Editable fields for a host."""
    hostname: str | None = None
    vendor: str | None = None
    os_name: str | None = None
    os_family: str | None = None
    firmware_url: str | None = None
    ip_address: str | None = None


class HostListOut(BaseModel):
    """Paginated host list."""
    items: list[HostOut]
    total: int
    page: int
    page_size: int


class HostFilter(BaseModel):
    """Query parameters for filtering hosts."""
    scan_id: uuid.UUID | None = None
    ip_address: str | None = None
    os_family: str | None = None
    is_up: bool | None = None
    has_open_ports: bool | None = None
    tag_name: str | None = None
    search: str | None = None
    page: int = 1
    page_size: int = 50
