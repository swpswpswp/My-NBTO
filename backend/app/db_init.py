from __future__ import annotations

from app.config import AUTO_CREATE_TABLES
from app.db import engine
from app.models import Base


async def maybe_create_tables() -> None:
    if not AUTO_CREATE_TABLES:
        return
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # Incremental patching for early-stage development:
        # - create_all doesn't add new columns to existing tables
        # - this keeps local DB usable without forcing drop/recreate
        await conn.exec_driver_sql("ALTER TABLE IF EXISTS company_assets ADD COLUMN IF NOT EXISTS carbon_balance INTEGER NOT NULL DEFAULT 0;")
        await conn.exec_driver_sql("ALTER TABLE IF EXISTS ledger_entries ADD COLUMN IF NOT EXISTS carbon_delta INTEGER NOT NULL DEFAULT 0;")
        await conn.exec_driver_sql("ALTER TABLE IF EXISTS companies ADD COLUMN IF NOT EXISTS equity_value INTEGER NOT NULL DEFAULT 0;")
        await conn.exec_driver_sql("ALTER TABLE IF EXISTS companies ADD COLUMN IF NOT EXISTS liability_value INTEGER NOT NULL DEFAULT 0;")
        await conn.exec_driver_sql("ALTER TABLE IF EXISTS recipes ADD COLUMN IF NOT EXISTS company_id VARCHAR(36);")
