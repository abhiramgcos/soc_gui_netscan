"""MAC address as host primary key, add firmware_url + open_port_count

Revision ID: 002
Revises: 001
Create Date: 2026-02-09
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Drop dependent tables first (foreign keys reference hosts.id)
    op.drop_table("host_tags")
    op.drop_table("ports")
    op.drop_table("hosts")

    # ── Recreate hosts with mac_address as PK ────
    op.create_table(
        "hosts",
        sa.Column("mac_address", sa.String(17), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("ip_address", sa.String(45), nullable=False, index=True),
        sa.Column("hostname", sa.String(256), nullable=True),
        sa.Column("vendor", sa.String(256), nullable=True),
        sa.Column("os_name", sa.String(256), nullable=True),
        sa.Column("os_family", sa.String(128), nullable=True),
        sa.Column("os_accuracy", sa.Integer, nullable=True),
        sa.Column("os_cpe", sa.String(512), nullable=True),
        sa.Column("is_up", sa.Boolean, default=True),
        sa.Column("response_time_ms", sa.Integer, nullable=True),
        sa.Column("firmware_url", sa.String(1024), nullable=True),
        sa.Column("open_port_count", sa.Integer, default=0),
        sa.Column("nmap_raw_xml", sa.Text, nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Recreate ports referencing hosts.mac_address ──
    op.create_table(
        "ports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("host_id", sa.String(17), sa.ForeignKey("hosts.mac_address", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("port_number", sa.Integer, nullable=False, index=True),
        sa.Column("protocol", sa.String(10), nullable=False, default="tcp"),
        sa.Column("state", sa.String(32), nullable=False, default="open"),
        sa.Column("service_name", sa.String(128), nullable=True),
        sa.Column("service_version", sa.String(256), nullable=True),
        sa.Column("service_product", sa.String(256), nullable=True),
        sa.Column("service_extra_info", sa.String(512), nullable=True),
        sa.Column("service_cpe", sa.String(512), nullable=True),
        sa.Column("scripts_output", sa.Text, nullable=True),
        sa.Column("banner", sa.Text, nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Recreate host_tags referencing hosts.mac_address ──
    op.create_table(
        "host_tags",
        sa.Column("host_id", sa.String(17), sa.ForeignKey("hosts.mac_address", ondelete="CASCADE"), primary_key=True),
        sa.Column("tag_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
    )


def downgrade() -> None:
    # Drop new tables
    op.drop_table("host_tags")
    op.drop_table("ports")
    op.drop_table("hosts")

    # Recreate old hosts with UUID PK
    op.create_table(
        "hosts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("ip_address", sa.String(45), nullable=False, index=True),
        sa.Column("mac_address", sa.String(17), nullable=True),
        sa.Column("hostname", sa.String(256), nullable=True),
        sa.Column("vendor", sa.String(256), nullable=True),
        sa.Column("os_name", sa.String(256), nullable=True),
        sa.Column("os_family", sa.String(128), nullable=True),
        sa.Column("os_accuracy", sa.Integer, nullable=True),
        sa.Column("os_cpe", sa.String(512), nullable=True),
        sa.Column("is_up", sa.Boolean, default=True),
        sa.Column("response_time_ms", sa.Integer, nullable=True),
        sa.Column("nmap_raw_xml", sa.Text, nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "ports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("port_number", sa.Integer, nullable=False, index=True),
        sa.Column("protocol", sa.String(10), nullable=False, default="tcp"),
        sa.Column("state", sa.String(32), nullable=False, default="open"),
        sa.Column("service_name", sa.String(128), nullable=True),
        sa.Column("service_version", sa.String(256), nullable=True),
        sa.Column("service_product", sa.String(256), nullable=True),
        sa.Column("service_extra_info", sa.String(512), nullable=True),
        sa.Column("service_cpe", sa.String(512), nullable=True),
        sa.Column("scripts_output", sa.Text, nullable=True),
        sa.Column("banner", sa.Text, nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "host_tags",
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("tag_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
    )
