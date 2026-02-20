"""Firmware analysis Pydantic schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel


class FirmwareAnalysisCreate(BaseModel):
    """Request to start firmware analysis for a host."""
    host_mac: str
    fw_url: str | None = None  # Override firmware URL; if omitted, uses host.firmware_url


class FirmwareAnalysisBatchCreate(BaseModel):
    """Request to start firmware analysis for multiple hosts."""
    host_macs: list[str] | None = None  # If None, analyse all hosts with firmware_url


class FirmwareAnalysisOut(BaseModel):
    """Firmware analysis response."""
    id: uuid.UUID
    host_mac: str
    status: str
    current_stage: int
    total_stages: int
    stage_label: str | None = None
    fw_url: str | None = None
    fw_path: str | None = None
    fw_hash: str | None = None
    fw_size_bytes: int | None = None
    emba_log_dir: str | None = None
    risk_report: str | None = None
    risk_score: float | None = None
    findings_count: int | None = None
    critical_count: int | None = None
    high_count: int | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None

    model_config = {"from_attributes": True}


class FirmwareAnalysisListOut(BaseModel):
    """Paginated firmware analysis list."""
    items: list[FirmwareAnalysisOut]
    total: int
    page: int
    page_size: int


class FirmwareAnalysisSummary(BaseModel):
    """Summary stats for the firmware analysis dashboard."""
    total: int
    pending: int
    running: int
    completed: int
    failed: int
    avg_risk_score: float | None = None
    max_risk_score: float | None = None
    total_critical: int
    total_high: int
    hosts_with_firmware_url: int
    hosts_analysed: int
