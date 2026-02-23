"""Initial schema: sessions + events tables.

Revision ID: 0001
Revises:
Create Date: 2026-02-22
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sessions",
        sa.Column("session_id", sa.String(64), primary_key=True),
        sa.Column("agent_goal", sa.Text, nullable=False),
        sa.Column("framework", sa.String(64), nullable=False, default="unknown"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("total_events", sa.Integer, nullable=False, default=0),
        sa.Column("blocked_events", sa.Integer, nullable=False, default=0),
    )

    op.create_table(
        "events",
        sa.Column("event_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id", sa.String(64), nullable=False),
        sa.Column("agent_goal", sa.Text, nullable=False),
        sa.Column("framework", sa.String(64), nullable=False),
        sa.Column("action_id", sa.String(64), nullable=False),
        sa.Column("action_type", sa.String(32), nullable=False),
        sa.Column("tool_name", sa.String(256), nullable=False),
        sa.Column("parameters", JSONB, nullable=False),
        sa.Column("raw_payload", JSONB, nullable=False),
        sa.Column("risk_score", sa.Float, nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("indicators", JSONB, nullable=False),
        sa.Column("is_goal_aligned", sa.String(8), nullable=False),
        sa.Column("analyzer_model", sa.String(64), nullable=False),
        sa.Column("latency_ms", sa.Float, nullable=False),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("policy_rule", sa.String(128), nullable=True),
        sa.Column("policy_detail", sa.Text, nullable=True),
        sa.Column("provenance", JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        # pgvector column — uncomment when pgvector is available
        # sa.Column("reason_embedding", Vector(1536), nullable=True),
    )

    op.create_index("ix_events_session_id", "events", ["session_id"])
    op.create_index("ix_events_decision", "events", ["decision"])
    op.create_index("ix_events_risk_score", "events", ["risk_score"])
    op.create_index("ix_events_created_at", "events", ["created_at"])
    op.create_index("ix_events_action_type", "events", ["action_type"])
    op.create_index("ix_events_session_decision", "events", ["session_id", "decision"])


def downgrade() -> None:
    op.drop_table("events")
    op.drop_table("sessions")
