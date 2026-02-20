"""add firmware analysis tables and host columns

Revision ID: 003
Revises: 002
Create Date: 2026-02-20 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision = '003_firmware_analysis'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Create firmware_analyses table ──────────
    op.create_table(
        'firmware_analyses',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('host_mac', sa.String(17), sa.ForeignKey('hosts.mac_address', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('status', sa.Enum(
            'pending', 'downloading', 'downloaded', 'emba_queued',
            'emba_running', 'emba_done', 'triaging', 'completed',
            'failed', 'cancelled',
            name='firmwarestatus',
        ), nullable=False, default='pending', index=True),
        sa.Column('current_stage', sa.Integer(), default=0),
        sa.Column('total_stages', sa.Integer(), default=3),
        sa.Column('stage_label', sa.String(128), nullable=True),
        # Stage A
        sa.Column('fw_url', sa.String(1024), nullable=True),
        sa.Column('fw_path', sa.String(1024), nullable=True),
        sa.Column('fw_hash', sa.String(64), nullable=True),
        sa.Column('fw_size_bytes', sa.Integer(), nullable=True),
        # Stage B
        sa.Column('emba_log_dir', sa.String(1024), nullable=True),
        # Stage C
        sa.Column('risk_report', sa.Text(), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('findings_count', sa.Integer(), nullable=True),
        sa.Column('critical_count', sa.Integer(), nullable=True),
        sa.Column('high_count', sa.Integer(), nullable=True),
        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
    )

    # ── Add firmware columns to hosts table ─────
    op.add_column('hosts', sa.Column('fw_path', sa.String(1024), nullable=True))
    op.add_column('hosts', sa.Column('fw_hash', sa.String(64), nullable=True))
    op.add_column('hosts', sa.Column('emba_log_dir', sa.String(1024), nullable=True))
    op.add_column('hosts', sa.Column('risk_report', sa.Text(), nullable=True))
    op.add_column('hosts', sa.Column('risk_score', sa.Float(), nullable=True))
    op.add_column('hosts', sa.Column('firmware_status', sa.String(32), nullable=True))


def downgrade() -> None:
    # ── Remove host firmware columns ────────────
    op.drop_column('hosts', 'firmware_status')
    op.drop_column('hosts', 'risk_score')
    op.drop_column('hosts', 'risk_report')
    op.drop_column('hosts', 'emba_log_dir')
    op.drop_column('hosts', 'fw_hash')
    op.drop_column('hosts', 'fw_path')

    # ── Drop firmware_analyses table ────────────
    op.drop_table('firmware_analyses')

    # ── Drop the enum type ──────────────────────
    op.execute("DROP TYPE IF EXISTS firmwarestatus")
