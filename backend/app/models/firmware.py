"""Firmware analysis ORM model — tracks the 3-stage firmware pipeline per host."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class FirmwareStatus(str, enum.Enum):
    """Status of the firmware analysis pipeline."""
    PENDING = "pending"
    DOWNLOADING = "downloading"
    DOWNLOADED = "downloaded"
    EMBA_QUEUED = "emba_queued"
    EMBA_RUNNING = "emba_running"
    EMBA_DONE = "emba_done"
    TRIAGING = "triaging"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FirmwareAnalysis(Base):
    """Tracks a firmware analysis run (download → EMBA → AI triage) for a device."""
    __tablename__ = "firmware_analyses"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    host_mac: Mapped[str] = mapped_column(
        String(17), ForeignKey("hosts.mac_address", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    status: Mapped[FirmwareStatus] = mapped_column(
        Enum(FirmwareStatus, values_callable=lambda x: [e.value for e in x]),
        nullable=False, default=FirmwareStatus.PENDING, index=True,
    )

    # Pipeline progress (stages 0-3)
    current_stage: Mapped[int] = mapped_column(Integer, default=0)
    total_stages: Mapped[int] = mapped_column(Integer, default=3)
    stage_label: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # ── Stage A: Download ───────────────────────
    fw_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    fw_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    fw_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fw_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ── Stage B: EMBA ───────────────────────────
    emba_log_dir: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # ── Stage C: AI Triage ──────────────────────
    risk_report: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    findings_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    critical_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    high_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ── Timestamps ──────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Relationships ───────────────────────────
    host: Mapped["Host"] = relationship("Host", back_populates="firmware_analyses")  # noqa: F821

    def __repr__(self) -> str:
        return f"<FirmwareAnalysis {self.id} host={self.host_mac} status={self.status}>"
