"""Alembic environment configuration."""

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from agentguard.guardrail.db import GuardrailBase
from agentguard.ledger.db import Base
from alembic import context

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# DATABASE_URL (set by docker-compose and deployment envs) overrides
# alembic.ini's static local-dev default so migrations target the same
# database the app connects to, without editing alembic.ini per environment.
if database_url := os.getenv("DATABASE_URL"):
    config.set_main_option("sqlalchemy.url", database_url)

# Two independent DeclarativeBase hierarchies (event ledger + guardrail
# ledger) both need to be tracked here — a single-base target_metadata is
# exactly how guardrail_events went unmigrated for the entire lifetime of
# the guardrail subsystem (0005 fixes that, this line prevents a repeat).
target_metadata = [Base.metadata, GuardrailBase.metadata]


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # Alembic requires a sync driver — strip +asyncpg so psycopg2 is used
    cfg = config.get_section(config.config_ini_section, {})
    if "sqlalchemy.url" in cfg:
        cfg["sqlalchemy.url"] = cfg["sqlalchemy.url"].replace("+asyncpg", "")
    connectable = engine_from_config(
        cfg,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
