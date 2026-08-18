"""Verifies `alembic upgrade head` against a REAL PostgreSQL instance
produces a schema matching the SQLAlchemy models used at runtime.

The rest of the test suite runs against SQLite via Base.metadata.create_all
(see test_ledger_sqlite.py), which never touches the Alembic migration
chain at all. That gap is exactly how migration 0004 shipped missing 5
EventRecord columns (correlation_id, initiating_principal, approval_id,
event_hash, prev_event_hash) undetected — only a live smoke test against
real Postgres caught it. This test is that check, made permanent.

Skipped by default (requires a real Postgres instance); the CI
"test-migrations" job sets AGENTGUARD_TEST_DATABASE_URL after running
`alembic upgrade head` against a Postgres service container.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine

from agentguard.guardrail.db import GuardrailBase
from agentguard.ledger.db import Base

DATABASE_URL = os.getenv("AGENTGUARD_TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="requires AGENTGUARD_TEST_DATABASE_URL pointing at a real, migrated Postgres instance",
)


def _model_columns(declarative_base: type) -> dict[str, set[str]]:
    return {table.name: {c.name for c in table.columns} for table in declarative_base.metadata.tables.values()}


async def test_migrated_schema_matches_models() -> None:
    expected = {**_model_columns(Base), **_model_columns(GuardrailBase)}
    engine = create_async_engine(DATABASE_URL)
    try:
        async with engine.connect() as conn:
            actual = await conn.run_sync(
                lambda sync_conn: {
                    table: {col["name"] for col in inspect(sync_conn).get_columns(table)}
                    for table in expected
                    if inspect(sync_conn).has_table(table)
                }
            )
    finally:
        await engine.dispose()

    missing_tables = set(expected) - set(actual)
    assert not missing_tables, f"alembic upgrade head never created tables the models expect: {missing_tables}"

    missing_columns = {
        table: expected[table] - actual[table]
        for table in expected
        if expected[table] - actual[table]
    }
    assert not missing_columns, f"alembic upgrade head produced a schema missing columns the models expect: {missing_columns}"
