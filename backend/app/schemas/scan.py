"""Scan Pydantic schemas for request validation and response serialization."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.scan import ScanStatus, ScanType


class ScanCreate(BaseModel):
    """Request body to create a new scan."""
    target: str = Field(..., min_length=1, max_length=512, description="IP, CIDR, or hostname")
    scan_type: ScanType = ScanType.SUBNET
    name: str | None = Field(None, max_length=256)
    description: str | None = None


class ScanUpdate(BaseModel):
    """Fields that can be updated on a scan."""
    name: str | None = None
    description: str | None = None


class ScanLogOut(BaseModel):
    id: uuid.UUID
    stage: int
    level: str
    message: str
    timestamp: datetime

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    """Full scan response."""
    id: uuid.UUID
    target: str
    scan_type: ScanType
    status: ScanStatus
    name: str | None
    description: str | None
    current_stage: int
    total_stages: int
    stage_label: str | None
    hosts_discovered: int
    live_hosts: int
    open_ports_found: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None

    model_config = {"from_attributes": True}


class ScanListOut(BaseModel):
    """Paginated scan list."""
    items: list[ScanOut]
    total: int
    page: int
    page_size: int


class ScanDetailOut(ScanOut):
    """Scan with nested hosts and logs."""
    logs: list[ScanLogOut] = []

    model_config = {"from_attributes": True}
