"""Add correlation_id, initiating_principal, and paper-2 hardening columns
(approval_id, event_hash, prev_event_hash) to the events table.

These columns have existed on agentguard.ledger.db.EventRecord (and the
Event Pydantic model) since before this migration chain started, but were
never added by any prior migration — every query selecting the full row
(the ORM's default behavior) fails with UndefinedColumnError against any
Postgres database created via `alembic upgrade head` rather than
`Base.metadata.create_all()`. Discovered running the real API against a
freshly-migrated database (test suites use SQLite/create_all, which derive
schema directly from the current models and never exercised this drift).

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-12
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("events", sa.Column("correlation_id", sa.String(64), nullable=False, server_default=""))
    op.add_column("events", sa.Column("initiating_principal", sa.String(256), nullable=False, server_default=""))
    op.add_column("events", sa.Column("approval_id", sa.String(64), nullable=False, server_default=""))
    op.add_column("events", sa.Column("event_hash", sa.String(64), nullable=False, server_default=""))
    op.add_column("events", sa.Column("prev_event_hash", sa.String(64), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("events", "prev_event_hash")
    op.drop_column("events", "event_hash")
    op.drop_column("events", "approval_id")
    op.drop_column("events", "initiating_principal")
    op.drop_column("events", "correlation_id")
