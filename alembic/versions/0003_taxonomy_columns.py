"""Add policy_violation and attack_taxonomy JSONB columns to events table.

Revision ID: 0003
Revises: 0002
Create Date: 2026-03-19
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("events", sa.Column("policy_violation", JSONB(), nullable=True))
    op.add_column("events", sa.Column("attack_taxonomy", JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("events", "attack_taxonomy")
    op.drop_column("events", "policy_violation")
