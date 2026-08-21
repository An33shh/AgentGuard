"""Create the missing guardrail_events table, and fix is_goal_aligned's type drift.

Two independent schema-drift bugs found during a full-codebase audit:

1. `agentguard.guardrail.db.GuardrailEventRecord` (table "guardrail_events")
   has existed since the guardrail subsystem was added, but no migration
   ever created it — env.py's target_metadata only tracked
   agentguard.ledger.db.Base, never agentguard.guardrail.db.GuardrailBase,
   and nothing in the API startup path calls
   PostgresGuardrailLedger.create_tables() (only the SQLite dev branch of
   the main EventLedger gets an auto-create). On any real Postgres
   deployment (docker-compose's `migrate` service running `alembic upgrade
   head`), every guardrail scan's ledger write fails with
   UndefinedTable — silently, since guardrail.py's _log_event() catches
   and only warns, so scans keep returning correct verdicts while their
   entire audit trail is discarded. Same root cause class as 0004: the
   test suite's SQLite/create_all path never exercises the real migration
   chain.

2. `events.is_goal_aligned` was created as sa.String(8) in 0001, but
   agentguard.ledger.db.EventRecord has always declared it as
   Boolean/Mapped[bool]. On a database built via `alembic upgrade head`,
   every insert binds a Python bool against a varchar(8) column, which
   asyncpg rejects at bind time.

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-13
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE events ALTER COLUMN is_goal_aligned TYPE boolean "
        "USING (is_goal_aligned::boolean)"
    )

    op.create_table(
        "guardrail_events",
        sa.Column("event_id", sa.String(64), primary_key=True),
        sa.Column("session_id", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(128), nullable=False, server_default=""),
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("context_type", sa.String(32), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("analyzer_model", sa.String(64), nullable=False, server_default="local_scanner"),
        sa.Column("latency_ms", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("detections", JSONB, nullable=False),
        sa.Column("text_hash", sa.String(64), nullable=False),
        sa.Column("text_length", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_guardrail_events_session_id", "guardrail_events", ["session_id"])
    op.create_index("ix_guardrail_events_verdict", "guardrail_events", ["verdict"])
    op.create_index("ix_guardrail_session_verdict", "guardrail_events", ["session_id", "verdict"])
    op.create_index("ix_guardrail_created_at", "guardrail_events", ["created_at"])
    op.create_index("ix_guardrail_text_hash", "guardrail_events", ["text_hash"])


def downgrade() -> None:
    op.drop_table("guardrail_events")
    op.execute(
        "ALTER TABLE events ALTER COLUMN is_goal_aligned TYPE varchar(8) "
        "USING (is_goal_aligned::varchar)"
    )
