"""Scan and ScanLog ORM models."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, enum.Enum):
    SINGLE_HOST = "single_host"
    SUBNET = "subnet"
    RANGE = "range"
    CUSTOM = "custom"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType, values_callable=lambda x: [e.value for e in x]), nullable=False, default=ScanType.SUBNET)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus, values_callable=lambda x: [e.value for e in x]), nullable=False, default=ScanStatus.PENDING, index=True)
    name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Pipeline progress
    current_stage: Mapped[int] = mapped_column(Integer, default=0)  # 0-4
    total_stages: Mapped[int] = mapped_column(Integer, default=4)
    stage_label: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Stats
    hosts_discovered: Mapped[int] = mapped_column(Integer, default=0)
    live_hosts: Mapped[int] = mapped_column(Integer, default=0)
    open_ports_found: Mapped[int] = mapped_column(Integer, default=0)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Error info
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    hosts: Mapped[list["Host"]] = relationship("Host", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")  # noqa: F821
    logs: Mapped[list["ScanLog"]] = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")

    def __repr__(self) -> str:
        return f"<Scan {self.id} target={self.target} status={self.status}>"


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    stage: Mapped[int] = mapped_column(Integer, nullable=False)
    level: Mapped[str] = mapped_column(String(16), default="info")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped["Scan"] = relationship("Scan", back_populates="logs")

    def __repr__(self) -> str:
        return f"<ScanLog scan={self.scan_id} stage={self.stage} level={self.level}>"
