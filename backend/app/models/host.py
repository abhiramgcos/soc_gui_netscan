"""Host ORM model — MAC address is the primary key (device inventory)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Host(Base):
    __tablename__ = "hosts"

    # MAC is the natural primary key for device identity
    mac_address: Mapped[str] = mapped_column(String(17), primary_key=True)

    # Latest scan that touched this device
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True,
    )

    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    hostname: Mapped[str | None] = mapped_column(String(256), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # OS fingerprinting
    os_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    os_family: Mapped[str | None] = mapped_column(String(128), nullable=True)
    os_accuracy: Mapped[int | None] = mapped_column(Integer, nullable=True)
    os_cpe: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Status
    is_up: Mapped[bool] = mapped_column(default=True)
    response_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Deep scan raw output
    nmap_raw_xml: Mapped[str | None] = mapped_column(Text, nullable=True)

    # User-editable fields
    firmware_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # Port count cache — used to decide whether to skip stage 4
    open_port_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="hosts")  # noqa: F821
    ports: Mapped[list["Port"]] = relationship(  # noqa: F821
        "Port", back_populates="host", cascade="all, delete-orphan", lazy="selectin",
    )
    tags: Mapped[list["Tag"]] = relationship(  # noqa: F821
        "Tag", secondary="host_tags", back_populates="hosts", lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<Host {self.mac_address} ip={self.ip_address} os={self.os_name}>"
