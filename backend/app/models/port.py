"""Port ORM model."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)

    port_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="open")

    # Service detection
    service_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    service_version: Mapped[str | None] = mapped_column(String(256), nullable=True)
    service_product: Mapped[str | None] = mapped_column(String(256), nullable=True)
    service_extra_info: Mapped[str | None] = mapped_column(String(512), nullable=True)
    service_cpe: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Script output
    scripts_output: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Banner
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    host: Mapped["Host"] = relationship("Host", back_populates="ports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<Port {self.port_number}/{self.protocol} state={self.state} service={self.service_name}>"
