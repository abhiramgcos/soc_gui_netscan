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
    id: uuid.UUID
    scan_id: uuid.UUID
    ip_address: str
    mac_address: str | None
    hostname: str | None
    vendor: str | None
    os_name: str | None
    os_family: str | None
    os_accuracy: int | None
    os_cpe: str | None
    is_up: bool
    response_time_ms: int | None
    discovered_at: datetime
    last_seen: datetime
    tags: list[TagBrief] = []

    model_config = {"from_attributes": True}


class HostDetailOut(HostOut):
    """Host with ports."""
    ports: list[PortOut] = []

    model_config = {"from_attributes": True}


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
