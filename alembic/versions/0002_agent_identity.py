"""Add agent identity columns to events table.

Revision ID: 0002
Revises: 0001
Create Date: 2026-02-23
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("events", sa.Column("agent_id", sa.String(128), nullable=True))
    op.add_column("events", sa.Column("agent_is_registered", sa.Boolean, nullable=True, server_default="false"))
    op.create_index("ix_events_agent_id", "events", ["agent_id"])

    # Backfill existing rows with a placeholder
    op.execute("UPDATE events SET agent_id = 'legacy-unknown', agent_is_registered = false WHERE agent_id IS NULL")

    # Make non-nullable now that rows are filled
    op.alter_column("events", "agent_id", nullable=False)
    op.alter_column("events", "agent_is_registered", nullable=False)


def downgrade() -> None:
    op.drop_index("ix_events_agent_id", "events")
    op.drop_column("events", "agent_is_registered")
    op.drop_column("events", "agent_id")
