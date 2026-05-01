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
        # decimal quantities for materials (2dp)
        await conn.exec_driver_sql("ALTER TABLE IF EXISTS inventories ALTER COLUMN qty TYPE NUMERIC(12,2) USING qty::numeric;")
        await conn.exec_driver_sql("ALTER TABLE IF EXISTS trade_requests ALTER COLUMN qty TYPE NUMERIC(12,2) USING qty::numeric;")
        await conn.exec_driver_sql("ALTER TABLE IF EXISTS ledger_entries ALTER COLUMN material_delta TYPE NUMERIC(12,2) USING material_delta::numeric;")
        await conn.exec_driver_sql("ALTER TABLE IF EXISTS recipe_items ALTER COLUMN qty TYPE NUMERIC(12,2) USING qty::numeric;")
        # rush order recipe hash columns
        await conn.exec_driver_sql("ALTER TABLE IF EXISTS rush_orders ADD COLUMN IF NOT EXISTS craft_code VARCHAR(64);")
        await conn.exec_driver_sql("ALTER TABLE IF EXISTS rush_orders ADD COLUMN IF NOT EXISTS recipe_items_json VARCHAR(2000);")
        await conn.exec_driver_sql("ALTER TABLE IF EXISTS rush_orders ADD COLUMN IF NOT EXISTS recipe_hash VARCHAR(64);")
        await conn.exec_driver_sql("ALTER TABLE IF EXISTS rush_order_submissions ADD COLUMN IF NOT EXISTS product_code VARCHAR(16);")
        await conn.exec_driver_sql("ALTER TABLE IF EXISTS rush_order_submissions ADD COLUMN IF NOT EXISTS recipe_hash VARCHAR(64);")
