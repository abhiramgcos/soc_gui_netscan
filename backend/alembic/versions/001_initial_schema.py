"""Initial schema — scans, hosts, ports, tags

Revision ID: 001
Revises: None
Create Date: 2026-02-08
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── scans ────────────────────────────────
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("target", sa.String(512), nullable=False, index=True),
        sa.Column("scan_type", sa.Enum("single_host", "subnet", "range", "custom", name="scantype"), nullable=False),
        sa.Column("status", sa.Enum("pending", "running", "completed", "failed", "cancelled", name="scanstatus"), nullable=False, index=True),
        sa.Column("name", sa.String(256), nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("current_stage", sa.Integer, default=0),
        sa.Column("total_stages", sa.Integer, default=4),
        sa.Column("stage_label", sa.String(128), nullable=True),
        sa.Column("hosts_discovered", sa.Integer, default=0),
        sa.Column("live_hosts", sa.Integer, default=0),
        sa.Column("open_ports_found", sa.Integer, default=0),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
    )

    # ── scan_logs ────────────────────────────
    op.create_table(
        "scan_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("stage", sa.Integer, nullable=False),
        sa.Column("level", sa.String(16), default="info"),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── hosts ────────────────────────────────
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

    # ── ports ────────────────────────────────
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

    # ── tags ─────────────────────────────────
    op.create_table(
        "tags",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("color", sa.String(7), nullable=False, default="#3b82f6"),
        sa.Column("description", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── host_tags (many-to-many) ─────────────
    op.create_table(
        "host_tags",
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("tag_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
    )


def downgrade() -> None:
    op.drop_table("host_tags")
    op.drop_table("tags")
    op.drop_table("ports")
    op.drop_table("hosts")
    op.drop_table("scan_logs")
    op.drop_table("scans")
    op.execute("DROP TYPE IF EXISTS scantype")
    op.execute("DROP TYPE IF EXISTS scanstatus")
