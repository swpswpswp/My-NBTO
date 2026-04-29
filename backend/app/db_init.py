from __future__ import annotations

from app.config import AUTO_CREATE_TABLES
from app.db import engine
from app.models import Base


async def maybe_create_tables() -> None:
    if not AUTO_CREATE_TABLES:
        return
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
