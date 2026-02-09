"""Tag ORM model and association table."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, String, Table, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

# ── Many-to-many association ────────────────────
host_tags = Table(
    "host_tags",
    Base.metadata,
    Column("host_id", String(17), ForeignKey("hosts.mac_address", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", UUID(as_uuid=True), ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    color: Mapped[str] = mapped_column(String(7), nullable=False, default="#3b82f6")  # hex color
    description: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    hosts: Mapped[list["Host"]] = relationship("Host", secondary=host_tags, back_populates="tags", lazy="selectin")  # noqa: F821

    def __repr__(self) -> str:
        return f"<Tag {self.name} color={self.color}>"
