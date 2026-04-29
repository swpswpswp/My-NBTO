from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AuditLog,
    Company,
    CompanyAsset,
    CompanyMember,
    Inventory,
    LedgerEntry,
    Match,
    MatchAdmin,
    SystemAdmin,
    TradeRequest,
    User,
)
from app.security import hash_password, verify_password


def now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


MATERIALS = ("R1", "R2", "R3")


async def get_match_by_key(s: AsyncSession, match_key: str) -> Match | None:
    r = await s.execute(select(Match).where(Match.key == match_key))
    return r.scalar_one_or_none()


async def ensure_company_assets(s: AsyncSession, match_id: str, company_id: str) -> None:
    r = await s.execute(select(CompanyAsset).where(and_(CompanyAsset.match_id == match_id, CompanyAsset.company_id == company_id)))
    a = r.scalar_one_or_none()
    if not a:
        s.add(CompanyAsset(match_id=match_id, company_id=company_id, gold_balance=0))
    for m in MATERIALS:
        r2 = await s.execute(
            select(Inventory).where(and_(Inventory.match_id == match_id, Inventory.company_id == company_id, Inventory.material == m))
        )
        if not r2.scalar_one_or_none():
            s.add(Inventory(match_id=match_id, company_id=company_id, material=m, qty=0))


async def create_user(s: AsyncSession, username: str, password: str) -> User:
    username = username.strip()
    if len(username) < 3:
        raise ValueError("username_too_short")
    if len(password) < 6:
        raise ValueError("password_too_short")
    r = await s.execute(select(User).where(User.username == username))
    if r.scalar_one_or_none():
        raise ValueError("username_taken")
    u = User(username=username, password_hash=hash_password(password), created_at=now_utc())
    s.add(u)
    await s.flush()
    return u


async def verify_user_password(s: AsyncSession, username: str, password: str) -> User | None:
    r = await s.execute(select(User).where(User.username == username.strip()))
    u = r.scalar_one_or_none()
    if not u:
        return None
    if not verify_password(password, u.password_hash):
        return None
    return u


async def is_system_admin(s: AsyncSession, user_id: str) -> bool:
    r = await s.execute(select(SystemAdmin).where(SystemAdmin.user_id == user_id))
    return r.scalar_one_or_none() is not None


async def is_match_admin(s: AsyncSession, match_id: str, user_id: str) -> bool:
    r = await s.execute(select(MatchAdmin).where(and_(MatchAdmin.match_id == match_id, MatchAdmin.user_id == user_id)))
    return r.scalar_one_or_none() is not None


async def create_match(s: AsyncSession, key: str, name: str, created_by_user_id: str) -> Match:
    key = key.strip()
    if len(key) < 2:
        raise ValueError("match_key_too_short")
    r = await s.execute(select(Match).where(Match.key == key))
    if r.scalar_one_or_none():
        raise ValueError("match_key_taken")
    m = Match(key=key, name=name.strip() or key, is_active=True, created_at=now_utc())
    s.add(m)
    await s.flush()
    s.add(MatchAdmin(match_id=m.id, user_id=created_by_user_id, created_at=now_utc()))
    s.add(
        AuditLog(
            match_id=m.id,
            actor_user_id=created_by_user_id,
            actor_role="system_admin",
            action="match_create",
            message=f"key={m.key}",
            created_at=now_utc(),
        )
    )
    return m


async def import_company(s: AsyncSession, match_id: str, name: str, join_password: str, actor_user_id: str) -> Company:
    if len(name.strip()) < 2:
        raise ValueError("company_name_too_short")
    if len(join_password) < 4:
        raise ValueError("join_password_too_short")
    c = Company(match_id=match_id, name=name.strip(), join_password_hash=hash_password(join_password), created_at=now_utc())
    s.add(c)
    await s.flush()
    await ensure_company_assets(s, match_id, c.id)
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=actor_user_id,
            actor_role="match_admin",
            action="company_import",
            subject_company_id=c.id,
            message=c.name,
            created_at=now_utc(),
        )
    )
    return c


async def list_companies(s: AsyncSession, match_id: str) -> list[dict]:
    r = await s.execute(select(Company).where(Company.match_id == match_id).order_by(Company.name.asc()))
    rows = r.scalars().all()
    return [{"id": c.id, "name": c.name} for c in rows]


async def join_company(s: AsyncSession, match_id: str, user_id: str, company_id: str, join_password: str) -> None:
    r = await s.execute(select(CompanyMember).where(and_(CompanyMember.match_id == match_id, CompanyMember.user_id == user_id)))
    if r.scalar_one_or_none():
        raise ValueError("already_in_company")
    r2 = await s.execute(select(Company).where(and_(Company.match_id == match_id, Company.id == company_id)))
    c = r2.scalar_one_or_none()
    if not c:
        raise ValueError("company_not_found")
    if not verify_password(join_password, c.join_password_hash):
        raise ValueError("join_password_invalid")
    s.add(CompanyMember(match_id=match_id, company_id=c.id, user_id=user_id, created_at=now_utc()))
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=user_id,
            actor_role="student",
            action="company_join",
            subject_company_id=c.id,
            created_at=now_utc(),
        )
    )


async def get_user_company_id(s: AsyncSession, match_id: str, user_id: str) -> str | None:
    r = await s.execute(select(CompanyMember).where(and_(CompanyMember.match_id == match_id, CompanyMember.user_id == user_id)))
    m = r.scalar_one_or_none()
    return m.company_id if m else None


async def lock_company_asset(s: AsyncSession, match_id: str, company_id: str) -> CompanyAsset:
    q = select(CompanyAsset).where(and_(CompanyAsset.match_id == match_id, CompanyAsset.company_id == company_id)).with_for_update()
    r = await s.execute(q)
    a = r.scalar_one_or_none()
    if not a:
        raise ValueError("company_asset_not_found")
    return a


async def lock_inventory(s: AsyncSession, match_id: str, company_id: str, material: str) -> Inventory:
    q = (
        select(Inventory)
        .where(and_(Inventory.match_id == match_id, Inventory.company_id == company_id, Inventory.material == material))
        .with_for_update()
    )
    r = await s.execute(q)
    inv = r.scalar_one_or_none()
    if not inv:
        raise ValueError("inventory_not_found")
    return inv


async def gold_transfer(s: AsyncSession, match_id: str, from_user_id: str, to_company_id: str, amount: int, idem: str) -> dict:
    if amount <= 0:
        raise ValueError("amount_must_be_positive")
    from_company_id = await get_user_company_id(s, match_id, from_user_id)
    if not from_company_id:
        raise ValueError("user_not_in_company")
    if from_company_id == to_company_id:
        raise ValueError("cannot_transfer_to_self")

    # idempotency: if ledger exists, return success-like response
    r = await s.execute(
        select(LedgerEntry).where(and_(LedgerEntry.match_id == match_id, LedgerEntry.company_id == from_company_id, LedgerEntry.idempotency_key == idem))
    )
    if r.scalar_one_or_none():
        return {"from_company_id": from_company_id, "to_company_id": to_company_id, "amount": amount, "cached": True}

    ref_id = str(uuid.uuid4())
    a_from = await lock_company_asset(s, match_id, from_company_id)
    a_to = await lock_company_asset(s, match_id, to_company_id)

    if a_from.gold_balance < amount:
        raise ValueError("gold_balance_insufficient")
    a_from.gold_balance -= amount
    a_to.gold_balance += amount

    s.add(
        LedgerEntry(
            match_id=match_id,
            company_id=from_company_id,
            kind="transfer_out",
            gold_delta=-amount,
            counterparty_company_id=to_company_id,
            reference_type="transfer",
            reference_id=ref_id,
            idempotency_key=idem,
            created_at=now_utc(),
            actor_user_id=from_user_id,
        )
    )
    s.add(
        LedgerEntry(
            match_id=match_id,
            company_id=to_company_id,
            kind="transfer_in",
            gold_delta=amount,
            counterparty_company_id=from_company_id,
            reference_type="transfer",
            reference_id=ref_id,
            idempotency_key=f"{idem}:in",
            created_at=now_utc(),
            actor_user_id=from_user_id,
        )
    )
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=from_user_id,
            actor_role="student",
            action="gold_transfer",
            subject_company_id=from_company_id,
            target_company_id=to_company_id,
            reference_type="transfer",
            reference_id=ref_id,
            message=str(amount),
            created_at=now_utc(),
        )
    )
    return {"from_company_id": from_company_id, "to_company_id": to_company_id, "amount": amount, "transfer_id": ref_id}


async def create_trade_request(
    s: AsyncSession,
    match_id: str,
    from_user_id: str,
    to_company_id: str,
    material: str,
    qty: int,
    unit_price_gold: int,
    idem: str,
) -> TradeRequest:
    if material not in MATERIALS:
        raise ValueError("unknown_material")
    if qty <= 0 or unit_price_gold <= 0:
        raise ValueError("qty_and_price_must_be_positive")
    from_company_id = await get_user_company_id(s, match_id, from_user_id)
    if not from_company_id:
        raise ValueError("user_not_in_company")
    if from_company_id == to_company_id:
        raise ValueError("cannot_trade_with_self")
    r = await s.execute(select(TradeRequest).where(and_(TradeRequest.match_id == match_id, TradeRequest.idempotency_key == idem)))
    tr = r.scalar_one_or_none()
    if tr:
        return tr
    tr = TradeRequest(
        match_id=match_id,
        from_company_id=from_company_id,
        to_company_id=to_company_id,
        material=material,
        qty=qty,
        unit_price_gold=unit_price_gold,
        status="pending",
        idempotency_key=idem,
        created_at=now_utc(),
    )
    s.add(tr)
    await s.flush()
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=from_user_id,
            actor_role="student",
            action="trade_request_create",
            subject_company_id=from_company_id,
            target_company_id=to_company_id,
            reference_type="trade_request",
            reference_id=tr.id,
            message=f"{material} qty={qty} price={unit_price_gold}",
            created_at=now_utc(),
        )
    )
    return tr


async def decide_trade_request(
    s: AsyncSession,
    match_id: str,
    user_id: str,
    trade_request_id: str,
    decision: str,  # accept/reject
    idem: str,
) -> TradeRequest:
    if decision not in ("accept", "reject"):
        raise ValueError("invalid_decision")
    my_company_id = await get_user_company_id(s, match_id, user_id)
    if not my_company_id:
        raise ValueError("user_not_in_company")

    q = select(TradeRequest).where(and_(TradeRequest.match_id == match_id, TradeRequest.id == trade_request_id)).with_for_update()
    r = await s.execute(q)
    tr = r.scalar_one_or_none()
    if not tr:
        raise ValueError("trade_request_not_found")
    if tr.to_company_id != my_company_id:
        raise ValueError("not_request_receiver")
    if tr.status != "pending":
        return tr

    tr.status = "accepted" if decision == "accept" else "rejected"
    tr.decided_at = now_utc()
    tr.decided_by_user_id = user_id

    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=user_id,
            actor_role="student",
            action="trade_request_decide",
            subject_company_id=tr.to_company_id,
            target_company_id=tr.from_company_id,
            reference_type="trade_request",
            reference_id=tr.id,
            message=decision,
            created_at=now_utc(),
        )
    )
    if decision == "accept":
        await settle_trade_request(s, match_id, user_id, tr, idem)
    return tr


async def settle_trade_request(s: AsyncSession, match_id: str, actor_user_id: str, tr: TradeRequest, idem: str) -> None:
    # Assumption: trade is "from_company sells material to to_company for gold"
    if tr.status not in ("accepted", "settled"):
        raise ValueError("trade_not_accepted")
    if tr.status == "settled":
        return

    seller_id = tr.from_company_id
    buyer_id = tr.to_company_id
    total = tr.qty * tr.unit_price_gold
    ref_id = str(uuid.uuid4())

    # lock rows in stable order to reduce deadlocks
    first, second = (seller_id, buyer_id) if seller_id < buyer_id else (buyer_id, seller_id)
    a1 = await lock_company_asset(s, match_id, first)
    a2 = await lock_company_asset(s, match_id, second)
    _ = a1, a2

    inv_seller = await lock_inventory(s, match_id, seller_id, tr.material)
    inv_buyer = await lock_inventory(s, match_id, buyer_id, tr.material)
    a_seller = await lock_company_asset(s, match_id, seller_id)
    a_buyer = await lock_company_asset(s, match_id, buyer_id)

    if inv_seller.qty < tr.qty:
        raise ValueError("seller_stock_insufficient")
    if a_buyer.gold_balance < total:
        raise ValueError("buyer_gold_insufficient")

    inv_seller.qty -= tr.qty
    inv_buyer.qty += tr.qty
    a_buyer.gold_balance -= total
    a_seller.gold_balance += total

    # ledger entries with idempotency
    s.add(
        LedgerEntry(
            match_id=match_id,
            company_id=seller_id,
            kind="trade_sell",
            gold_delta=total,
            material=tr.material,
            material_delta=-tr.qty,
            counterparty_company_id=buyer_id,
            reference_type="trade",
            reference_id=ref_id,
            idempotency_key=f"{idem}:seller",
            created_at=now_utc(),
            actor_user_id=actor_user_id,
        )
    )
    s.add(
        LedgerEntry(
            match_id=match_id,
            company_id=buyer_id,
            kind="trade_buy",
            gold_delta=-total,
            material=tr.material,
            material_delta=tr.qty,
            counterparty_company_id=seller_id,
            reference_type="trade",
            reference_id=ref_id,
            idempotency_key=f"{idem}:buyer",
            created_at=now_utc(),
            actor_user_id=actor_user_id,
        )
    )

    tr.status = "settled"
    tr.settled_at = now_utc()

    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=actor_user_id,
            actor_role="student",
            action="trade_settle",
            subject_company_id=seller_id,
            target_company_id=buyer_id,
            reference_type="trade",
            reference_id=ref_id,
            message=f"{tr.material} qty={tr.qty} total={total}",
            created_at=now_utc(),
        )
    )
