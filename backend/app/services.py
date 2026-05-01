from __future__ import annotations

import csv
import io
import uuid
import json
import hashlib
import json
import hashlib
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timezone

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AuditLog,
    Company,
    CompanyAsset,
    CompanyFacility,
    CompanyMember,
    Contract,
    FacilityType,
    Inventory,
    LedgerEntry,
    Match,
    MatchAdmin,
    MatchSetting,
    Product,
    ProductListing,
    RushOrder,
    RushOrderSubmission,
    Recipe,
    RecipeItem,
    SystemAdmin,
    TradeRequest,
    User,
)
from app.security import hash_password, verify_password


def now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)

QTY_QUANT = Decimal("0.01")


def parse_qty_2dp(v: object) -> Decimal:
    try:
        d = Decimal(str(v))
    except Exception:
        raise ValueError("invalid_qty")
    d = d.quantize(QTY_QUANT, rounding=ROUND_HALF_UP)
    if d <= 0:
        raise ValueError("qty_must_be_positive")
    return d


MATERIALS = ("R1", "R2", "R3")

CRAFT_TYPES: list[dict[str, str]] = [
    {"code": "CRAFT_A", "name": "工艺A"},
    {"code": "CRAFT_B", "name": "工艺B"},
]
_CRAFT_CODE_SET = {x["code"] for x in CRAFT_TYPES}


def validate_craft_code(craft_code: str) -> str:
    cc = (craft_code or "").strip()
    if not cc:
        raise ValueError("craft_required")
    if cc not in _CRAFT_CODE_SET:
        raise ValueError("invalid_craft")
    return cc


def recipe_fingerprint(craft_code: str, items: list[dict]) -> tuple[str, str]:
    """
    Strict match:
    - craft_code exactly equal
    - materials set exactly equal (no extra/missing)
    - qty exactly equal at 2dp (Decimal quantized)
    Returns (recipe_hash, canonical_items_json).
    """
    cc = validate_craft_code(craft_code)
    norm: list[dict[str, str]] = []
    seen: set[str] = set()
    for it in (items or []):
        m = str((it or {}).get("material") or "").strip()
        if not m:
            raise ValueError("recipe_item_material_required")
        if m in seen:
            raise ValueError("duplicate_material")
        seen.add(m)
        q = parse_qty_2dp((it or {}).get("qty"))
        norm.append({"material": m, "qty": format(q, "f")})
    if not norm:
        raise ValueError("recipe_items_required")
    norm.sort(key=lambda x: x["material"])
    canon = json.dumps({"craft": cc, "items": norm}, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    h = hashlib.sha256(canon.encode("utf-8")).hexdigest()
    return h, json.dumps(norm, ensure_ascii=False, separators=(",", ":"))

# 设施目录：(code, 显示名, 关联原料或 None, gold_cost, carbon_cost)
# 成本占位：后续统一在库里改 FacilityType 即可；导出「设施价值」按 gold_cost * 持有数量全价计入
FACILITY_CATALOG: list[tuple[str, str, str | None, int, int]] = [
    ("mine_r1", "R1矿场", "R1", 100, 100),
    ("mine_r2", "R2矿场", "R2", 100, 100),
    ("mine_r3", "R3矿场", "R3", 100, 100),
    # 成本先统一设置为相同值（后续可在 FacilityType 表里统一调整）
    ("quarry", "采石场", None, 100, 100),
    ("forest", "林场", None, 100, 100),
    ("farm", "农场", None, 100, 100),
    ("ranch", "养殖场", None, 100, 100),
    ("fishery", "渔场", None, 100, 100),
    ("chemical_plant", "化工场", None, 100, 100),
    ("explorer_camp", "探险者营地", None, 100, 100),
    ("product_factory", "产品制造工厂", None, 100, 100),
    ("department_store", "百货大楼", None, 100, 100),
    ("news_center", "新闻中心", None, 100, 100),
]
MINE_UNIT_GOLD_COST = {"R1": 10, "R2": 20, "R3": 30}  # 黄金成本；碳排成本=黄金成本（规则）


async def get_match_by_key(s: AsyncSession, match_key: str) -> Match | None:
    r = await s.execute(select(Match).where(Match.key == match_key))
    return r.scalar_one_or_none()


async def ensure_company_assets(s: AsyncSession, match_id: str, company_id: str) -> None:
    r = await s.execute(select(CompanyAsset).where(and_(CompanyAsset.match_id == match_id, CompanyAsset.company_id == company_id)))
    a = r.scalar_one_or_none()
    if not a:
        s.add(CompanyAsset(match_id=match_id, company_id=company_id, gold_balance=0, carbon_balance=0))
    for m in MATERIALS:
        r2 = await s.execute(
            select(Inventory).where(and_(Inventory.match_id == match_id, Inventory.company_id == company_id, Inventory.material == m))
        )
        if not r2.scalar_one_or_none():
            s.add(Inventory(match_id=match_id, company_id=company_id, material=m, qty=Decimal("0.00")))


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
        MatchSetting(
            match_id=m.id,
            initial_gold=0,
            initial_carbon=0,
            material_r1_price=10,
            material_r2_price=20,
            material_r3_price=30,
            updated_at=now_utc(),
        )
    )
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


async def get_match_setting(s: AsyncSession, match_id: str) -> MatchSetting:
    r = await s.execute(select(MatchSetting).where(MatchSetting.match_id == match_id))
    ms = r.scalar_one_or_none()
    if not ms:
        ms = MatchSetting(
            match_id=match_id,
            initial_gold=0,
            initial_carbon=0,
            material_r1_price=10,
            material_r2_price=20,
            material_r3_price=30,
            updated_at=now_utc(),
        )
        s.add(ms)
        await s.flush()
    return ms


async def upsert_facility_catalog_for_match(s: AsyncSession, match_id: str) -> None:
    """确保赛场设施类型齐全（缺则插入，不覆盖已有成本）。"""
    existing = (await s.execute(select(FacilityType).where(FacilityType.match_id == match_id))).scalars().all()
    have = {x.code for x in existing}
    for code, name, material, gold_cost, carbon_cost in FACILITY_CATALOG:
        if code in have:
            continue
        s.add(
            FacilityType(
                match_id=match_id,
                code=code,
                name=name,
                material=material,
                gold_cost=gold_cost,
                carbon_cost=carbon_cost,
                created_at=now_utc(),
            )
        )


def encode_balance_sheet_csv(rows: list[dict[str, int | str]]) -> bytes:
    """UTF-8 BOM，便于 Excel 打开中文不乱码。"""
    headers = ["公司名", "黄金", "设施价值", "原料价值", "股权价值", "负债价值", "总资产"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(headers)
    for r in rows:
        w.writerow(
            [
                r["company_name"],
                r["gold"],
                r["facility_value"],
                r["material_value"],
                r["equity_value"],
                r["liability_value"],
                r["total_assets"],
            ]
        )
    return buf.getvalue().encode("utf-8-sig")


async def match_balance_sheet_export_rows(s: AsyncSession, match_id: str) -> list[dict[str, int | str]]:
    """总资产 = 黄金 + 设施（全价）+ 原料（半价）+ 股权 - 负债；原料价取赛场 MatchSetting 基准价。"""
    ms = await get_match_setting(s, match_id)
    price_map = {"R1": ms.material_r1_price, "R2": ms.material_r2_price, "R3": ms.material_r3_price}
    companies = (await s.execute(select(Company).where(Company.match_id == match_id).order_by(Company.name.asc()))).scalars().all()
    assets = (await s.execute(select(CompanyAsset).where(CompanyAsset.match_id == match_id))).scalars().all()
    asset_by_c = {a.company_id: a for a in assets}
    inv_rows = (await s.execute(select(Inventory).where(Inventory.match_id == match_id))).scalars().all()
    inv_by_c: dict[str, list[Inventory]] = {}
    for inv in inv_rows:
        inv_by_c.setdefault(inv.company_id, []).append(inv)
    q = (
        select(CompanyFacility, FacilityType)
        .join(FacilityType, CompanyFacility.facility_type_id == FacilityType.id)
        .where(CompanyFacility.match_id == match_id)
    )
    fac_rows = (await s.execute(q)).all()
    fac_val_by_c: dict[str, int] = {}
    for cf, ft in fac_rows:
        fac_val_by_c[cf.company_id] = fac_val_by_c.get(cf.company_id, 0) + int(ft.gold_cost) * int(cf.qty)

    out: list[dict[str, int | str]] = []
    for c in companies:
        a = asset_by_c.get(c.id)
        gold = int(a.gold_balance) if a else 0
        material_val = 0
        for inv in inv_by_c.get(c.id, []):
            p = int(price_map.get(inv.material, 0))
            material_val += (int(inv.qty) * p) // 2
        facility_val = int(fac_val_by_c.get(c.id, 0))
        equity = int(c.equity_value)
        liability = int(c.liability_value)
        total = gold + facility_val + material_val + equity - liability
        out.append(
            {
                "company_name": c.name,
                "gold": gold,
                "facility_value": facility_val,
                "material_value": material_val,
                "equity_value": equity,
                "liability_value": liability,
                "total_assets": total,
            }
        )
    return out



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


async def carbon_transfer(s: AsyncSession, match_id: str, from_user_id: str, to_company_id: str, amount: int, idem: str) -> dict:
    if amount <= 0:
        raise ValueError("amount_must_be_positive")
    from_company_id = await get_user_company_id(s, match_id, from_user_id)
    if not from_company_id:
        raise ValueError("user_not_in_company")
    if from_company_id == to_company_id:
        raise ValueError("cannot_transfer_to_self")

    r = await s.execute(
        select(LedgerEntry).where(and_(LedgerEntry.match_id == match_id, LedgerEntry.company_id == from_company_id, LedgerEntry.idempotency_key == idem))
    )
    if r.scalar_one_or_none():
        return {"from_company_id": from_company_id, "to_company_id": to_company_id, "amount": amount, "cached": True}

    ref_id = str(uuid.uuid4())
    a_from = await lock_company_asset(s, match_id, from_company_id)
    a_to = await lock_company_asset(s, match_id, to_company_id)

    if a_from.carbon_balance < amount:
        raise ValueError("carbon_balance_insufficient")
    a_from.carbon_balance -= amount
    a_to.carbon_balance += amount

    s.add(
        LedgerEntry(
            match_id=match_id,
            company_id=from_company_id,
            kind="carbon_transfer_out",
            gold_delta=0,
            carbon_delta=-amount,
            counterparty_company_id=to_company_id,
            reference_type="carbon_transfer",
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
            kind="carbon_transfer_in",
            gold_delta=0,
            carbon_delta=amount,
            counterparty_company_id=from_company_id,
            reference_type="carbon_transfer",
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
            action="carbon_transfer",
            subject_company_id=from_company_id,
            target_company_id=to_company_id,
            reference_type="carbon_transfer",
            reference_id=ref_id,
            message=str(amount),
            created_at=now_utc(),
        )
    )
    return {"from_company_id": from_company_id, "to_company_id": to_company_id, "amount": amount, "transfer_id": ref_id}


async def buy_facility(s: AsyncSession, match_id: str, user_id: str, facility_code: str, qty: int, idem: str) -> dict:
    if qty <= 0:
        raise ValueError("qty_must_be_positive")
    company_id = await get_user_company_id(s, match_id, user_id)
    if not company_id:
        raise ValueError("user_not_in_company")
    r = await s.execute(
        select(LedgerEntry).where(and_(LedgerEntry.match_id == match_id, LedgerEntry.company_id == company_id, LedgerEntry.idempotency_key == idem))
    )
    if r.scalar_one_or_none():
        return {"company_id": company_id, "facility_code": facility_code, "qty": qty, "cached": True}

    ft = (
        await s.execute(select(FacilityType).where(and_(FacilityType.match_id == match_id, FacilityType.code == facility_code)))
    ).scalar_one_or_none()
    if not ft:
        raise ValueError("facility_not_found")
    total_gold = ft.gold_cost * qty
    total_carbon = ft.carbon_cost * qty

    a = await lock_company_asset(s, match_id, company_id)
    if a.gold_balance < total_gold:
        raise ValueError("gold_balance_insufficient")
    if a.carbon_balance < total_carbon:
        raise ValueError("carbon_balance_insufficient")
    a.gold_balance -= total_gold
    a.carbon_balance -= total_carbon

    existing = (
        await s.execute(
            select(CompanyFacility).where(
                and_(CompanyFacility.match_id == match_id, CompanyFacility.company_id == company_id, CompanyFacility.facility_type_id == ft.id)
            )
        )
    ).scalar_one_or_none()
    if existing:
        existing.qty += qty
    else:
        s.add(CompanyFacility(match_id=match_id, company_id=company_id, facility_type_id=ft.id, qty=qty, created_at=now_utc()))

    ref_id = str(uuid.uuid4())
    s.add(
        LedgerEntry(
            match_id=match_id,
            company_id=company_id,
            kind="facility_buy",
            gold_delta=-total_gold,
            carbon_delta=-total_carbon,
            reference_type="facility",
            reference_id=ref_id,
            idempotency_key=idem,
            created_at=now_utc(),
            actor_user_id=user_id,
        )
    )
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=user_id,
            actor_role="student",
            action="facility_buy",
            subject_company_id=company_id,
            reference_type="facility",
            reference_id=ref_id,
            message=f"{facility_code} x{qty}",
            created_at=now_utc(),
        )
    )
    return {"company_id": company_id, "facility_code": facility_code, "qty": qty, "gold_cost": total_gold, "carbon_cost": total_carbon}


async def list_my_facilities(s: AsyncSession, match_id: str, user_id: str) -> list[dict]:
    company_id = await get_user_company_id(s, match_id, user_id)
    if not company_id:
        raise ValueError("user_not_in_company")
    q = (
        select(CompanyFacility, FacilityType)
        .join(FacilityType, CompanyFacility.facility_type_id == FacilityType.id)
        .where(and_(CompanyFacility.match_id == match_id, CompanyFacility.company_id == company_id))
    )
    rows = (await s.execute(q)).all()
    return [
        {"facility_code": ft.code, "name": ft.name, "material": ft.material, "qty": cf.qty, "gold_cost": ft.gold_cost, "carbon_cost": ft.carbon_cost}
        for (cf, ft) in rows
    ]


async def list_facility_types(s: AsyncSession, match_id: str) -> list[dict]:
    await upsert_facility_catalog_for_match(s, match_id)
    r = await s.execute(select(FacilityType).where(FacilityType.match_id == match_id).order_by(FacilityType.code.asc()))
    rows = r.scalars().all()
    return [
        {
            "code": x.code,
            "name": x.name,
            "material": x.material,
            "gold_cost": x.gold_cost,
            "carbon_cost": x.carbon_cost,
        }
        for x in rows
    ]


async def admin_list_company_facilities(s: AsyncSession, match_id: str) -> list[dict]:
    """全场设施列表：按公司汇总当前持有设施。"""
    await upsert_facility_catalog_for_match(s, match_id)
    companies = (await s.execute(select(Company).where(Company.match_id == match_id).order_by(Company.name.asc()))).scalars().all()
    q = (
        select(CompanyFacility, FacilityType)
        .join(FacilityType, CompanyFacility.facility_type_id == FacilityType.id)
        .where(CompanyFacility.match_id == match_id)
    )
    rows = (await s.execute(q)).all()
    by_company: dict[str, list[dict]] = {}
    for cf, ft in rows:
        by_company.setdefault(cf.company_id, []).append({"code": ft.code, "name": ft.name, "qty": cf.qty})
    out: list[dict] = []
    for c in companies:
        facs = sorted(by_company.get(c.id, []), key=lambda x: x["code"])
        out.append({"company_id": c.id, "company_name": c.name, "facilities": facs})
    return out


async def mine_material(s: AsyncSession, match_id: str, user_id: str, material: str, qty: int, idem: str) -> dict:
    if material not in MATERIALS:
        raise ValueError("unknown_material")
    if qty <= 0:
        raise ValueError("qty_must_be_positive")
    company_id = await get_user_company_id(s, match_id, user_id)
    if not company_id:
        raise ValueError("user_not_in_company")

    # facility requirement: must own mine for this material
    code = f"mine_{material.lower()}"
    q = (
        select(CompanyFacility)
        .join(FacilityType, CompanyFacility.facility_type_id == FacilityType.id)
        .where(and_(CompanyFacility.match_id == match_id, CompanyFacility.company_id == company_id, FacilityType.code == code))
    )
    if (await s.execute(q)).scalar_one_or_none() is None:
        raise ValueError("facility_required")

    # idempotency via ledger
    r = await s.execute(
        select(LedgerEntry).where(and_(LedgerEntry.match_id == match_id, LedgerEntry.company_id == company_id, LedgerEntry.idempotency_key == idem))
    )
    if r.scalar_one_or_none():
        return {"company_id": company_id, "material": material, "qty": qty, "cached": True}

    unit_gold = MINE_UNIT_GOLD_COST[material]
    cost_gold = unit_gold * qty
    cost_carbon = cost_gold  # rule: carbon consumption equals gold paid

    a = await lock_company_asset(s, match_id, company_id)
    if a.gold_balance < cost_gold:
        raise ValueError("gold_balance_insufficient")
    if a.carbon_balance < cost_carbon:
        raise ValueError("carbon_balance_insufficient")
    a.gold_balance -= cost_gold
    a.carbon_balance -= cost_carbon
    inv = await lock_inventory(s, match_id, company_id, material)
    inv.qty += qty

    ref_id = str(uuid.uuid4())
    s.add(
        LedgerEntry(
            match_id=match_id,
            company_id=company_id,
            kind="mine",
            gold_delta=-cost_gold,
            carbon_delta=-cost_carbon,
            material=material,
            material_delta=qty,
            reference_type="mine",
            reference_id=ref_id,
            idempotency_key=idem,
            created_at=now_utc(),
            actor_user_id=user_id,
        )
    )
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=user_id,
            actor_role="student",
            action="mine",
            subject_company_id=company_id,
            reference_type="mine",
            reference_id=ref_id,
            message=f"{material} x{qty}",
            created_at=now_utc(),
        )
    )
    return {"company_id": company_id, "material": material, "qty": qty, "cost_gold": cost_gold, "cost_carbon": cost_carbon}


async def admin_update_match_setting(
    s: AsyncSession,
    match_id: str,
    actor_user_id: str,
    initial_gold: int | None = None,
    initial_carbon: int | None = None,
    material_prices: dict[str, int] | None = None,
) -> dict:
    ms = await get_match_setting(s, match_id)
    if initial_gold is not None:
        if initial_gold < 0:
            raise ValueError("initial_gold_must_be_nonnegative")
        ms.initial_gold = int(initial_gold)
    if initial_carbon is not None:
        if initial_carbon < 0:
            raise ValueError("initial_carbon_must_be_nonnegative")
        ms.initial_carbon = int(initial_carbon)
    if material_prices is not None:
        for k, v in material_prices.items():
            if k not in MATERIALS:
                raise ValueError("unknown_material")
            if int(v) < 0:
                raise ValueError("material_price_must_be_nonnegative")
        if "R1" in material_prices:
            ms.material_r1_price = int(material_prices["R1"])
        if "R2" in material_prices:
            ms.material_r2_price = int(material_prices["R2"])
        if "R3" in material_prices:
            ms.material_r3_price = int(material_prices["R3"])
    ms.updated_at = now_utc()
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=actor_user_id,
            actor_role="match_admin",
            action="match_setting_update",
            reference_type="match_setting",
            reference_id=ms.id,
            message=f"initial_gold={ms.initial_gold} initial_carbon={ms.initial_carbon}",
            created_at=now_utc(),
        )
    )
    return {
        "initial_gold": ms.initial_gold,
        "initial_carbon": ms.initial_carbon,
        "material_prices": {"R1": ms.material_r1_price, "R2": ms.material_r2_price, "R3": ms.material_r3_price},
    }


async def admin_issue_initial_assets_to_all_companies(s: AsyncSession, match_id: str, actor_user_id: str, idem: str) -> dict:
    if not idem:
        raise ValueError("idempotency_key_required")
    ms = await get_match_setting(s, match_id)
    r = await s.execute(select(Company.id).where(Company.match_id == match_id))
    company_ids = [x[0] for x in r.all()]
    issued = 0
    skipped = 0
    for cid in company_ids:
        key = f"{idem}:{cid}"
        r2 = await s.execute(select(LedgerEntry).where(and_(LedgerEntry.match_id == match_id, LedgerEntry.company_id == cid, LedgerEntry.idempotency_key == key)))
        if r2.scalar_one_or_none():
            skipped += 1
            continue
        a = await lock_company_asset(s, match_id, cid)
        a.gold_balance += ms.initial_gold
        a.carbon_balance += ms.initial_carbon
        ref_id = str(uuid.uuid4())
        s.add(
            LedgerEntry(
                match_id=match_id,
                company_id=cid,
                kind="initial_issue",
                gold_delta=ms.initial_gold,
                carbon_delta=ms.initial_carbon,
                counterparty_company_id=None,
                reference_type="initial_issue",
                reference_id=ref_id,
                idempotency_key=key,
                created_at=now_utc(),
                actor_user_id=actor_user_id,
            )
        )
        issued += 1
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=actor_user_id,
            actor_role="match_admin",
            action="initial_issue_all",
            reference_type="initial_issue",
            reference_id=idem,
            message=f"issued={issued} skipped={skipped}",
            created_at=now_utc(),
        )
    )
    return {"issued": issued, "skipped": skipped, "initial_gold": ms.initial_gold, "initial_carbon": ms.initial_carbon}


async def create_contract(
    s: AsyncSession, match_id: str, actor_user_id: str, to_company_id: str, title: str, content: str, idem: str
) -> Contract:
    if not title.strip():
        raise ValueError("title_required")
    if len(title) > 128:
        raise ValueError("title_too_long")
    if not content.strip():
        raise ValueError("content_required")
    if len(content) > 2000:
        raise ValueError("content_too_long")
    from_company_id = await get_user_company_id(s, match_id, actor_user_id)
    if not from_company_id:
        raise ValueError("user_not_in_company")
    if from_company_id == to_company_id:
        raise ValueError("cannot_contract_to_self")
    r = await s.execute(select(Contract).where(and_(Contract.match_id == match_id, Contract.idempotency_key == idem)))
    c0 = r.scalar_one_or_none()
    if c0:
        return c0
    c = Contract(
        match_id=match_id,
        from_company_id=from_company_id,
        to_company_id=to_company_id,
        title=title.strip(),
        content=content.strip(),
        status="pending",
        idempotency_key=idem,
        created_at=now_utc(),
        decided_at=None,
        decided_by_user_id=None,
    )
    s.add(c)
    await s.flush()
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=actor_user_id,
            actor_role="student",
            action="contract_create",
            subject_company_id=from_company_id,
            target_company_id=to_company_id,
            reference_type="contract",
            reference_id=c.id,
            message=c.title,
            created_at=now_utc(),
        )
    )
    return c


async def list_contracts_inbox(s: AsyncSession, match_id: str, user_id: str) -> list[dict]:
    company_id = await get_user_company_id(s, match_id, user_id)
    if not company_id:
        raise ValueError("user_not_in_company")
    r = await s.execute(select(Contract).where(and_(Contract.match_id == match_id, Contract.to_company_id == company_id)).order_by(Contract.created_at.desc()))
    rows = r.scalars().all()
    return [
        {
            "id": x.id,
            "from_company_id": x.from_company_id,
            "to_company_id": x.to_company_id,
            "title": x.title,
            "content": x.content,
            "status": x.status,
            "created_at": x.created_at.isoformat() if x.created_at else None,
        }
        for x in rows
    ]


async def list_contracts_outbox(s: AsyncSession, match_id: str, user_id: str) -> list[dict]:
    company_id = await get_user_company_id(s, match_id, user_id)
    if not company_id:
        raise ValueError("user_not_in_company")
    r = await s.execute(select(Contract).where(and_(Contract.match_id == match_id, Contract.from_company_id == company_id)).order_by(Contract.created_at.desc()))
    rows = r.scalars().all()
    return [
        {
            "id": x.id,
            "from_company_id": x.from_company_id,
            "to_company_id": x.to_company_id,
            "title": x.title,
            "content": x.content,
            "status": x.status,
            "created_at": x.created_at.isoformat() if x.created_at else None,
        }
        for x in rows
    ]


async def decide_contract(s: AsyncSession, match_id: str, user_id: str, contract_id: str, decision: str, idem: str) -> Contract:
    company_id = await get_user_company_id(s, match_id, user_id)
    if not company_id:
        raise ValueError("user_not_in_company")
    if decision not in ("accept", "reject"):
        raise ValueError("invalid_decision")
    # idempotency on receiver ledger-like uniqueness: contract has uq on idem only, so we use idem for decision log as audit only
    q = select(Contract).where(and_(Contract.match_id == match_id, Contract.id == contract_id)).with_for_update()
    c = (await s.execute(q)).scalar_one_or_none()
    if not c:
        raise ValueError("contract_not_found")
    if c.to_company_id != company_id:
        raise ValueError("not_contract_receiver")
    if c.status != "pending":
        return c
    c.status = "accepted" if decision == "accept" else "rejected"
    c.decided_at = now_utc()
    c.decided_by_user_id = user_id
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=user_id,
            actor_role="student",
            action="contract_decide",
            subject_company_id=c.to_company_id,
            target_company_id=c.from_company_id,
            reference_type="contract",
            reference_id=c.id,
            message=c.status,
            created_at=now_utc(),
        )
    )
    return c


async def lock_inventory(s: AsyncSession, match_id: str, company_id: str, material: str) -> Inventory:
    q = (
        select(Inventory)
        .where(and_(Inventory.match_id == match_id, Inventory.company_id == company_id, Inventory.material == material))
        .with_for_update()
    )
    r = await s.execute(q)
    inv = r.scalar_one_or_none()
    if inv:
        return inv
    # create-on-demand (products or new material codes)
    s.add(Inventory(match_id=match_id, company_id=company_id, material=material, qty=Decimal("0.00")))
    await s.flush()
    r2 = await s.execute(q)
    inv2 = r2.scalar_one_or_none()
    if not inv2:
        raise ValueError("inventory_not_found")
    return inv2


async def admin_query_ledger(
    s: AsyncSession,
    match_id: str,
    company_id: str | None = None,
    kind: str | None = None,
    since_iso: str | None = None,
    until_iso: str | None = None,
    limit: int = 200,
) -> list[dict]:
    from datetime import datetime

    q = select(LedgerEntry).where(LedgerEntry.match_id == match_id)
    if company_id:
        q = q.where(LedgerEntry.company_id == company_id)
    if kind:
        q = q.where(LedgerEntry.kind == kind)
    if since_iso:
        q = q.where(LedgerEntry.created_at >= datetime.fromisoformat(since_iso))
    if until_iso:
        q = q.where(LedgerEntry.created_at <= datetime.fromisoformat(until_iso))
    q = q.order_by(LedgerEntry.created_at.desc()).limit(max(1, min(int(limit), 1000)))
    rows = (await s.execute(q)).scalars().all()
    return [
        {
            "id": x.id,
            "company_id": x.company_id,
            "kind": x.kind,
            "gold_delta": x.gold_delta,
            "carbon_delta": x.carbon_delta,
            "material": x.material,
            "material_delta": x.material_delta,
            "counterparty_company_id": x.counterparty_company_id,
            "reference_type": x.reference_type,
            "reference_id": x.reference_id,
            "idempotency_key": x.idempotency_key,
            "created_at": x.created_at.isoformat() if x.created_at else None,
            "actor_user_id": x.actor_user_id,
        }
        for x in rows
    ]


async def admin_query_audit_logs(
    s: AsyncSession,
    match_id: str,
    action: str | None = None,
    actor_user_id: str | None = None,
    subject_company_id: str | None = None,
    target_company_id: str | None = None,
    since_iso: str | None = None,
    until_iso: str | None = None,
    limit: int = 200,
) -> list[dict]:
    from datetime import datetime

    q = select(AuditLog).where(AuditLog.match_id == match_id)
    if action:
        q = q.where(AuditLog.action == action)
    if actor_user_id:
        q = q.where(AuditLog.actor_user_id == actor_user_id)
    if subject_company_id:
        q = q.where(AuditLog.subject_company_id == subject_company_id)
    if target_company_id:
        q = q.where(AuditLog.target_company_id == target_company_id)
    if since_iso:
        q = q.where(AuditLog.created_at >= datetime.fromisoformat(since_iso))
    if until_iso:
        q = q.where(AuditLog.created_at <= datetime.fromisoformat(until_iso))
    q = q.order_by(AuditLog.created_at.desc()).limit(max(1, min(int(limit), 1000)))
    rows = (await s.execute(q)).scalars().all()
    return [
        {
            "id": x.id,
            "actor_user_id": x.actor_user_id,
            "actor_role": x.actor_role,
            "action": x.action,
            "subject_company_id": x.subject_company_id,
            "target_company_id": x.target_company_id,
            "reference_type": x.reference_type,
            "reference_id": x.reference_id,
            "message": x.message,
            "created_at": x.created_at.isoformat() if x.created_at else None,
        }
        for x in rows
    ]


def encode_csv_utf8_bom(headers: list[str], rows: list[list[object]]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(headers)
    for r in rows:
        w.writerow([("" if x is None else x) for x in r])
    return buf.getvalue().encode("utf-8-sig")


async def admin_publish_rush_order(
    s: AsyncSession,
    match_id: str,
    actor_user_id: str,
    product_code: str,
    craft_code: str,
    recipe_items: list[dict],
    recipe_text: str,
    demand_qty: int,
    unit_price_gold: int,
    settlement_at: datetime,
    idem: str,
) -> RushOrder:
    product_code = product_code.strip()
    if not product_code:
        raise ValueError("product_code_required")
    if len(product_code) > 16:
        raise ValueError("product_code_too_long")
    recipe_text = (recipe_text or "").strip()
    if len(recipe_text) > 512:
        raise ValueError("recipe_too_long")
    recipe_hash, recipe_items_json = recipe_fingerprint(craft_code, recipe_items or [])
    if demand_qty <= 0 or unit_price_gold <= 0:
        raise ValueError("qty_and_price_must_be_positive")
    r0 = await s.execute(select(RushOrder).where(and_(RushOrder.match_id == match_id, RushOrder.idempotency_key == idem)))
    ro0 = r0.scalar_one_or_none()
    if ro0:
        return ro0
    ro = RushOrder(
        match_id=match_id,
        created_by_user_id=actor_user_id,
        product_code=product_code,
        craft_code=validate_craft_code(craft_code),
        recipe_items_json=recipe_items_json,
        recipe_hash=recipe_hash,
        recipe_text=recipe_text,
        demand_qty=demand_qty,
        unit_price_gold=unit_price_gold,
        settlement_at=settlement_at,
        status="open",
        idempotency_key=idem,
        created_at=now_utc(),
        settled_at=None,
    )
    s.add(ro)
    await s.flush()
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=actor_user_id,
            actor_role="match_admin",
            action="rush_order_publish",
            reference_type="rush_order",
            reference_id=ro.id,
            message=f"{product_code} craft={ro.craft_code} hash={ro.recipe_hash[:10]} demand={demand_qty} price={unit_price_gold} settle={settlement_at.isoformat()}",
            created_at=now_utc(),
        )
    )
    return ro


async def list_rush_orders(s: AsyncSession, match_id: str, status: str | None = None) -> list[dict]:
    q = select(RushOrder).where(RushOrder.match_id == match_id)
    if status:
        q = q.where(RushOrder.status == status)
    q = q.order_by(RushOrder.created_at.desc()).limit(200)
    rows = (await s.execute(q)).scalars().all()
    return [
        {
            "id": x.id,
            "product_code": x.product_code,
            "craft_code": x.craft_code,
            "recipe_hash": x.recipe_hash,
            "recipe_items": (json.loads(x.recipe_items_json) if (x.recipe_items_json or "").strip() else []),
            "recipe_text": x.recipe_text,
            "demand_qty": x.demand_qty,
            "unit_price_gold": x.unit_price_gold,
            "settlement_at": x.settlement_at.isoformat() if x.settlement_at else None,
            "status": x.status,
            "created_at": x.created_at.isoformat() if x.created_at else None,
            "settled_at": x.settled_at.isoformat() if x.settled_at else None,
        }
        for x in rows
    ]


async def student_submit_rush_order(
    s: AsyncSession,
    match_id: str,
    actor_user_id: str,
    rush_order_id: str,
    product_code: str,
    qty: int,
    idem: str,
) -> RushOrderSubmission:
    if qty <= 0:
        raise ValueError("qty_must_be_positive")
    company_id = await get_user_company_id(s, match_id, actor_user_id)
    if not company_id:
        raise ValueError("user_not_in_company")
    # idempotency
    r0 = await s.execute(
        select(RushOrderSubmission).where(
            and_(
                RushOrderSubmission.match_id == match_id,
                RushOrderSubmission.rush_order_id == rush_order_id,
                RushOrderSubmission.company_id == company_id,
                RushOrderSubmission.idempotency_key == idem,
            )
        )
    )
    sub0 = r0.scalar_one_or_none()
    if sub0:
        return sub0

    q = select(RushOrder).where(and_(RushOrder.match_id == match_id, RushOrder.id == rush_order_id)).with_for_update()
    ro = (await s.execute(q)).scalar_one_or_none()
    if not ro:
        raise ValueError("rush_order_not_found")
    if ro.status != "open":
        raise ValueError("rush_order_not_open")
    if ro.settlement_at and now_utc() >= ro.settlement_at:
        raise ValueError("rush_order_closed")

    if not ro.recipe_hash:
        raise ValueError("rush_order_recipe_not_configured")
    _craft, recipe_hash = await get_company_recipe_fingerprint_for_product_code(s, match_id, company_id, product_code)
    if recipe_hash != ro.recipe_hash:
        raise ValueError("rush_order_recipe_mismatch")

    # consume products immediately (no return)
    inv = await lock_inventory(s, match_id, company_id, product_code)
    if inv.qty < qty:
        raise ValueError("product_insufficient")
    inv.qty -= qty

    sub = RushOrderSubmission(
        match_id=match_id,
        rush_order_id=ro.id,
        company_id=company_id,
        product_code=product_code,
        recipe_hash=recipe_hash,
        qty_submitted=qty,
        submitted_at=now_utc(),
        idempotency_key=idem,
        status="submitted",
        qty_accepted=0,
        settled_at=None,
    )
    s.add(sub)
    await s.flush()
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=actor_user_id,
            actor_role="student",
            action="rush_order_submit",
            subject_company_id=company_id,
            reference_type="rush_order",
            reference_id=ro.id,
            message=f"product={product_code} qty={qty}",
            created_at=now_utc(),
        )
    )
    return sub


async def admin_settle_rush_order(s: AsyncSession, match_id: str, actor_user_id: str, rush_order_id: str, force: bool = False) -> dict:
    q = select(RushOrder).where(and_(RushOrder.match_id == match_id, RushOrder.id == rush_order_id)).with_for_update()
    ro = (await s.execute(q)).scalar_one_or_none()
    if not ro:
        raise ValueError("rush_order_not_found")
    if ro.status != "open":
        return {"id": ro.id, "status": ro.status, "cached": True}
    if (not force) and ro.settlement_at and now_utc() < ro.settlement_at:
        raise ValueError("settlement_time_not_reached")

    # lock all submissions and settle earliest first
    subs = (
        await s.execute(
            select(RushOrderSubmission)
            .where(and_(RushOrderSubmission.match_id == match_id, RushOrderSubmission.rush_order_id == ro.id))
            .order_by(RushOrderSubmission.submitted_at.asc())
            .with_for_update()
        )
    ).scalars().all()

    remaining = int(ro.demand_qty)
    accepted_total = 0
    rejected_total = 0
    paid_total = 0

    # lock assets for all involved companies (stable order)
    company_ids = sorted({x.company_id for x in subs})
    for cid in company_ids:
        _ = await lock_company_asset(s, match_id, cid)

    for sub in subs:
        if sub.status != "submitted":
            continue
        accept = 0
        if remaining > 0:
            accept = min(int(sub.qty_submitted), remaining)
        if accept > 0:
            sub.status = "accepted"
            sub.qty_accepted = accept
            remaining -= accept
            accepted_total += accept
            payout = accept * int(ro.unit_price_gold)
            paid_total += payout
            a = await lock_company_asset(s, match_id, sub.company_id)
            a.gold_balance += payout
            # ledger for accepted
            s.add(
                LedgerEntry(
                    match_id=match_id,
                    company_id=sub.company_id,
                    kind="rush_order_sell",
                    gold_delta=payout,
                    carbon_delta=0,
                    material=sub.product_code,
                    material_delta=-accept,
                    counterparty_company_id=None,
                    reference_type="rush_order",
                    reference_id=ro.id,
                    idempotency_key=f"rush:{ro.id}:{sub.id}:sell",
                    created_at=now_utc(),
                    actor_user_id=actor_user_id,
                )
            )
        else:
            sub.status = "rejected"
            sub.qty_accepted = 0
            rejected_total += int(sub.qty_submitted)
        sub.settled_at = now_utc()

    ro.status = "settled"
    ro.settled_at = now_utc()
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=actor_user_id,
            actor_role="match_admin",
            action="rush_order_settle",
            reference_type="rush_order",
            reference_id=ro.id,
            message=f"accepted={accepted_total} rejected={rejected_total} paid={paid_total}",
            created_at=now_utc(),
        )
    )
    return {
        "id": ro.id,
        "status": ro.status,
        "accepted_total": accepted_total,
        "rejected_total": rejected_total,
        "paid_total": paid_total,
        "demand_qty": ro.demand_qty,
    }


async def upsert_company_recipe(
    s: AsyncSession,
    match_id: str,
    actor_user_id: str,
    company_id: str,
    product_code: str,
    product_name: str,
    craft: str,
    items: list[dict],
) -> dict:
    product_code = product_code.strip()
    if not product_code:
        raise ValueError("product_code_required")
    if len(product_code) > 64:
        raise ValueError("product_code_too_long")
    if not product_name.strip():
        raise ValueError("product_name_required")
    if len(product_name) > 128:
        raise ValueError("product_name_too_long")
    craft = (craft or "").strip()
    craft = validate_craft_code(craft)
    if not isinstance(items, list) or not items:
        raise ValueError("recipe_items_required")

    r = await s.execute(select(Product).where(and_(Product.match_id == match_id, Product.code == product_code)))
    p = r.scalar_one_or_none()
    if not p:
        p = Product(match_id=match_id, code=product_code, name=product_name.strip(), created_at=now_utc())
        s.add(p)
        await s.flush()
    else:
        p.name = product_name.strip()

    r2 = await s.execute(select(Recipe).where(and_(Recipe.match_id == match_id, Recipe.company_id == company_id, Recipe.product_id == p.id)))
    rec = r2.scalar_one_or_none()
    if not rec:
        rec = Recipe(match_id=match_id, company_id=company_id, product_id=p.id, craft=craft, created_at=now_utc(), updated_at=now_utc())
        s.add(rec)
        await s.flush()
    else:
        rec.craft = craft
        rec.updated_at = now_utc()

    # replace items
    from sqlalchemy import delete

    await s.execute(delete(RecipeItem).where(RecipeItem.recipe_id == rec.id))
    for it in items:
        mat = str(it.get("material") or "").strip()
        try:
            qty = parse_qty_2dp(it.get("qty"))
        except ValueError as e:
            raise ValueError(str(e))
        if not mat:
            raise ValueError("recipe_item_material_required")
        s.add(RecipeItem(recipe_id=rec.id, material=mat, qty=qty))

    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=actor_user_id,
            actor_role="student",
            action="recipe_upsert",
            subject_company_id=company_id,
            reference_type="recipe",
            reference_id=rec.id,
            message=f"{product_code}:{product_name}",
            created_at=now_utc(),
        )
    )
    return {"product_code": p.code, "product_name": p.name, "craft": rec.craft}


async def list_company_recipes(s: AsyncSession, match_id: str, company_id: str) -> list[dict]:
    q = (
        select(Product, Recipe)
        .join(Recipe, and_(Recipe.match_id == Product.match_id, Recipe.product_id == Product.id))
        .where(and_(Product.match_id == match_id, Recipe.company_id == company_id))
        .order_by(Product.code.asc())
    )
    rows = (await s.execute(q)).all()
    out: list[dict] = []
    for p, rcp in rows:
        items = (await s.execute(select(RecipeItem).where(RecipeItem.recipe_id == rcp.id).order_by(RecipeItem.material.asc()))).scalars().all()
        out.append(
            {
                "product_code": p.code,
                "product_name": p.name,
                "craft": rcp.craft,
                "items": [{"material": x.material, "qty": x.qty} for x in items],
                "updated_at": rcp.updated_at.isoformat() if rcp.updated_at else None,
            }
        )
    return out


async def get_company_recipe_fingerprint_for_product_code(
    s: AsyncSession, match_id: str, company_id: str, product_code: str
) -> tuple[str, str]:
    product_code = (product_code or "").strip()
    if not product_code:
        raise ValueError("product_code_required")
    p = (
        await s.execute(select(Product).where(and_(Product.match_id == match_id, Product.code == product_code)))
    ).scalar_one_or_none()
    if not p:
        raise ValueError("product_not_found")
    rec = (
        await s.execute(select(Recipe).where(and_(Recipe.match_id == match_id, Recipe.company_id == company_id, Recipe.product_id == p.id)))
    ).scalar_one_or_none()
    if not rec:
        raise ValueError("recipe_not_found_for_product")
    items = (
        await s.execute(select(RecipeItem).where(RecipeItem.recipe_id == rec.id).order_by(RecipeItem.material.asc()))
    ).scalars().all()
    h, _canon_items_json = recipe_fingerprint(rec.craft, [{"material": x.material, "qty": x.qty} for x in items])
    return validate_craft_code(rec.craft), h


async def manufacture_product(
    s: AsyncSession,
    match_id: str,
    actor_user_id: str,
    product_code: str,
    qty: int,
    idem: str,
) -> dict:
    if qty <= 0:
        raise ValueError("qty_must_be_positive")
    company_id = await get_user_company_id(s, match_id, actor_user_id)
    if not company_id:
        raise ValueError("user_not_in_company")
    # idempotency via ledger
    r0 = await s.execute(
        select(LedgerEntry).where(and_(LedgerEntry.match_id == match_id, LedgerEntry.company_id == company_id, LedgerEntry.idempotency_key == idem))
    )
    if r0.scalar_one_or_none():
        return {"company_id": company_id, "product_code": product_code, "qty": qty, "cached": True}

    await upsert_facility_catalog_for_match(s, match_id)
    # require product_factory
    qf = (
        select(CompanyFacility)
        .join(FacilityType, CompanyFacility.facility_type_id == FacilityType.id)
        .where(and_(CompanyFacility.match_id == match_id, CompanyFacility.company_id == company_id, FacilityType.code == "product_factory"))
    )
    if (await s.execute(qf)).scalar_one_or_none() is None:
        raise ValueError("facility_required_product_factory")

    pr = (await s.execute(select(Product).where(and_(Product.match_id == match_id, Product.code == product_code.strip())))).scalar_one_or_none()
    if not pr:
        raise ValueError("product_not_found")
    rcp = (await s.execute(select(Recipe).where(and_(Recipe.match_id == match_id, Recipe.product_id == pr.id)))).scalar_one_or_none()
    if not rcp:
        raise ValueError("recipe_not_found")
    items = (await s.execute(select(RecipeItem).where(RecipeItem.recipe_id == rcp.id))).scalars().all()
    if not items:
        raise ValueError("recipe_items_required")

    # lock all inventories involved
    inv_need: list[tuple[str, int]] = [(x.material, int(x.qty) * qty) for x in items]
    for mat, need in inv_need:
        inv = await lock_inventory(s, match_id, company_id, mat)
        if inv.qty < need:
            raise ValueError("material_insufficient")

    # apply updates
    for mat, need in inv_need:
        inv = await lock_inventory(s, match_id, company_id, mat)
        inv.qty -= need
        s.add(
            LedgerEntry(
                match_id=match_id,
                company_id=company_id,
                kind="manufacture_consume",
                gold_delta=0,
                carbon_delta=0,
                material=mat,
                material_delta=-need,
                counterparty_company_id=None,
                reference_type="manufacture",
                reference_id=pr.id,
                idempotency_key=f"{idem}:{mat}",
                created_at=now_utc(),
                actor_user_id=actor_user_id,
            )
        )

    inv_p = await lock_inventory(s, match_id, company_id, pr.code)
    inv_p.qty += qty
    s.add(
        LedgerEntry(
            match_id=match_id,
            company_id=company_id,
            kind="manufacture_product",
            gold_delta=0,
            carbon_delta=0,
            material=pr.code,
            material_delta=qty,
            counterparty_company_id=None,
            reference_type="manufacture",
            reference_id=pr.id,
            idempotency_key=idem,
            created_at=now_utc(),
            actor_user_id=actor_user_id,
        )
    )
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=actor_user_id,
            actor_role="student",
            action="manufacture",
            subject_company_id=company_id,
            reference_type="product",
            reference_id=pr.id,
            message=f"{pr.code} x{qty}",
            created_at=now_utc(),
        )
    )
    return {"company_id": company_id, "product_code": pr.code, "product_name": pr.name, "qty": qty}


async def create_product_listing(
    s: AsyncSession,
    match_id: str,
    actor_user_id: str,
    product_code: str,
    qty: int,
    unit_price_gold: int,
    idem: str,
) -> ProductListing:
    # 规则：上架固定消耗 1 件库存（不返还）
    qty = 1
    if unit_price_gold <= 0:
        raise ValueError("qty_and_price_must_be_positive")
    product_code = product_code.strip()
    if not product_code:
        raise ValueError("product_code_required")
    if len(product_code) > 16:
        raise ValueError("product_code_too_long")
    company_id = await get_user_company_id(s, match_id, actor_user_id)
    if not company_id:
        raise ValueError("user_not_in_company")

    await upsert_facility_catalog_for_match(s, match_id)
    # require department_store
    qf = (
        select(CompanyFacility)
        .join(FacilityType, CompanyFacility.facility_type_id == FacilityType.id)
        .where(and_(CompanyFacility.match_id == match_id, CompanyFacility.company_id == company_id, FacilityType.code == "department_store"))
    )
    if (await s.execute(qf)).scalar_one_or_none() is None:
        raise ValueError("facility_required_department_store")

    r0 = await s.execute(select(ProductListing).where(and_(ProductListing.match_id == match_id, ProductListing.idempotency_key == idem)))
    pl0 = r0.scalar_one_or_none()
    if pl0:
        return pl0

    inv = await lock_inventory(s, match_id, company_id, product_code)
    if inv.qty < 1:
        raise ValueError("product_insufficient")
    inv.qty -= 1  # consume on listing (no return)

    pl = ProductListing(
        match_id=match_id,
        seller_company_id=company_id,
        product_code=product_code,
        qty=1,
        unit_price_gold=unit_price_gold,
        status="active",
        idempotency_key=idem,
        created_at=now_utc(),
        updated_at=now_utc(),
        rating_score=None,
        rating_comment=None,
        rated_by_user_id=None,
        rated_at=None,
    )
    s.add(pl)
    await s.flush()
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=actor_user_id,
            actor_role="student",
            action="product_listing_create",
            subject_company_id=company_id,
            reference_type="product_listing",
            reference_id=pl.id,
            message=f"{product_code} qty=1 price={unit_price_gold}",
            created_at=now_utc(),
        )
    )
    return pl


async def list_product_listings(s: AsyncSession, match_id: str, status: str | None = "active") -> list[dict]:
    q = select(ProductListing).where(ProductListing.match_id == match_id)
    if status:
        q = q.where(ProductListing.status == status)
    q = q.order_by(ProductListing.created_at.desc()).limit(500)
    rows = (await s.execute(q)).scalars().all()
    return [
        {
            "id": x.id,
            "seller_company_id": x.seller_company_id,
            "product_code": x.product_code,
            "qty": x.qty,
            "unit_price_gold": x.unit_price_gold,
            "status": x.status,
            "rating_score": x.rating_score,
            "rating_comment": x.rating_comment,
            "created_at": x.created_at.isoformat() if x.created_at else None,
        }
        for x in rows
    ]


async def cancel_product_listing(s: AsyncSession, match_id: str, actor_user_id: str, listing_id: str, idem: str) -> ProductListing:
    company_id = await get_user_company_id(s, match_id, actor_user_id)
    if not company_id:
        raise ValueError("user_not_in_company")
    q = select(ProductListing).where(and_(ProductListing.match_id == match_id, ProductListing.id == listing_id)).with_for_update()
    pl = (await s.execute(q)).scalar_one_or_none()
    if not pl:
        raise ValueError("listing_not_found")
    if pl.seller_company_id != company_id:
        raise ValueError("not_listing_owner")
    if pl.status != "active":
        return pl
    # idempotency via audit/ledger not needed; use idem only for client retry; safe by status
    # 规则：上架已消耗库存，不返还
    pl.status = "cancelled"
    pl.updated_at = now_utc()
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=actor_user_id,
            actor_role="student",
            action="product_listing_cancel",
            subject_company_id=company_id,
            reference_type="product_listing",
            reference_id=pl.id,
            message=idem,
            created_at=now_utc(),
        )
    )
    return pl


async def buy_product_listing(
    s: AsyncSession,
    match_id: str,
    actor_user_id: str,
    listing_id: str,
    qty: int,
    idem: str,
) -> dict:
    if qty <= 0:
        raise ValueError("qty_must_be_positive")
    buyer_company_id = await get_user_company_id(s, match_id, actor_user_id)
    if not buyer_company_id:
        raise ValueError("user_not_in_company")

    # idempotency via buyer ledger
    r0 = await s.execute(
        select(LedgerEntry).where(and_(LedgerEntry.match_id == match_id, LedgerEntry.company_id == buyer_company_id, LedgerEntry.idempotency_key == idem))
    )
    if r0.scalar_one_or_none():
        return {"buyer_company_id": buyer_company_id, "listing_id": listing_id, "qty": qty, "cached": True}

    q = select(ProductListing).where(and_(ProductListing.match_id == match_id, ProductListing.id == listing_id)).with_for_update()
    pl = (await s.execute(q)).scalar_one_or_none()
    if not pl:
        raise ValueError("listing_not_found")
    if pl.status != "active":
        raise ValueError("listing_not_active")
    if pl.seller_company_id == buyer_company_id:
        raise ValueError("cannot_buy_own_listing")
    if pl.qty < qty:
        raise ValueError("listing_qty_insufficient")

    total = int(pl.unit_price_gold) * qty
    # lock assets stable order
    first, second = (pl.seller_company_id, buyer_company_id) if pl.seller_company_id < buyer_company_id else (buyer_company_id, pl.seller_company_id)
    _ = await lock_company_asset(s, match_id, first)
    _ = await lock_company_asset(s, match_id, second)
    a_seller = await lock_company_asset(s, match_id, pl.seller_company_id)
    a_buyer = await lock_company_asset(s, match_id, buyer_company_id)
    if a_buyer.gold_balance < total:
        raise ValueError("buyer_gold_insufficient")
    a_buyer.gold_balance -= total
    a_seller.gold_balance += total

    inv_buyer = await lock_inventory(s, match_id, buyer_company_id, pl.product_code)
    inv_buyer.qty += qty

    pl.qty -= qty
    if pl.qty == 0:
        pl.status = "sold_out"
    pl.updated_at = now_utc()

    ref_id = str(uuid.uuid4())
    s.add(
        LedgerEntry(
            match_id=match_id,
            company_id=buyer_company_id,
            kind="product_buy",
            gold_delta=-total,
            carbon_delta=0,
            material=pl.product_code,
            material_delta=qty,
            counterparty_company_id=pl.seller_company_id,
            reference_type="product_listing",
            reference_id=pl.id,
            idempotency_key=idem,
            created_at=now_utc(),
            actor_user_id=actor_user_id,
        )
    )
    s.add(
        LedgerEntry(
            match_id=match_id,
            company_id=pl.seller_company_id,
            kind="product_sell",
            gold_delta=total,
            carbon_delta=0,
            material=pl.product_code,
            material_delta=-qty,
            counterparty_company_id=buyer_company_id,
            reference_type="product_listing",
            reference_id=pl.id,
            idempotency_key=f"{idem}:seller",
            created_at=now_utc(),
            actor_user_id=actor_user_id,
        )
    )
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=actor_user_id,
            actor_role="student",
            action="product_listing_buy",
            subject_company_id=buyer_company_id,
            target_company_id=pl.seller_company_id,
            reference_type="product_listing",
            reference_id=pl.id,
            message=f"qty={qty} total={total} ref={ref_id}",
            created_at=now_utc(),
        )
    )
    return {"buyer_company_id": buyer_company_id, "seller_company_id": pl.seller_company_id, "listing_id": pl.id, "qty": qty, "total_gold": total}


async def sell_product_to_consumers(
    s: AsyncSession,
    match_id: str,
    actor_user_id: str,
    product_code: str,
    qty: int,
    unit_price_gold: int,
    idem: str,
) -> dict:
    """卖给消费者：必须评分后才能卖；售价=标价×(score/100)，线性系数。"""
    # 兼容：product_code 参数改为 listing_id 使用（前端会传 listing_id）
    listing_id = product_code.strip()
    if not listing_id:
        raise ValueError("listing_id_required")
    if qty <= 0:
        raise ValueError("qty_must_be_positive")
    if unit_price_gold <= 0:
        raise ValueError("unit_price_gold_required")
    company_id = await get_user_company_id(s, match_id, actor_user_id)
    if not company_id:
        raise ValueError("user_not_in_company")

    # idempotency on company ledger
    r0 = await s.execute(
        select(LedgerEntry).where(and_(LedgerEntry.match_id == match_id, LedgerEntry.company_id == company_id, LedgerEntry.idempotency_key == idem))
    )
    if r0.scalar_one_or_none():
        return {"company_id": company_id, "product_code": product_code, "qty": qty, "cached": True}

    q = select(ProductListing).where(and_(ProductListing.match_id == match_id, ProductListing.id == listing_id)).with_for_update()
    pl = (await s.execute(q)).scalar_one_or_none()
    if not pl:
        raise ValueError("listing_not_found")
    if pl.seller_company_id != company_id:
        raise ValueError("not_listing_owner")
    if pl.status != "active":
        raise ValueError("listing_not_active")
    if pl.rating_score is None:
        raise ValueError("rating_required")

    # linear coefficient
    coef = max(0.0, min(1.0, float(pl.rating_score) / 100.0))
    # each sale consumes real inventory; listing acts as "rated product design"
    inv = await lock_inventory(s, match_id, company_id, pl.product_code)
    if inv.qty < qty:
        raise ValueError("product_insufficient")
    inv.qty -= qty

    unit_final = int(round(float(pl.unit_price_gold) * coef))
    total = unit_final * qty
    a = await lock_company_asset(s, match_id, company_id)
    a.gold_balance += total
    pl.updated_at = now_utc()

    ref_id = str(uuid.uuid4())
    s.add(
        LedgerEntry(
            match_id=match_id,
            company_id=company_id,
            kind="consumer_sell",
            gold_delta=total,
            carbon_delta=0,
            material=pl.product_code,
            material_delta=-qty,
            counterparty_company_id=None,
            reference_type="consumer_sell",
            reference_id=ref_id,
            idempotency_key=idem,
            created_at=now_utc(),
            actor_user_id=actor_user_id,
        )
    )
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=actor_user_id,
            actor_role="student",
            action="consumer_sell",
            subject_company_id=company_id,
            reference_type="consumer_sell",
            reference_id=ref_id,
            message=f"{pl.product_code} listing={pl.id} score={pl.rating_score} coef={coef:.2f} unit={unit_final} qty={qty} total={total}",
            created_at=now_utc(),
        )
    )
    return {
        "company_id": company_id,
        "listing_id": pl.id,
        "product_code": pl.product_code,
        "qty": qty,
        "unit_price_gold": unit_final,
        "total_gold": total,
        "coef": coef,
    }


async def admin_rate_product_listing(
    s: AsyncSession,
    match_id: str,
    actor_user_id: str,
    listing_id: str,
    score: int,
    comment: str | None,
) -> ProductListing:
    if score < 0 or score > 100:
        raise ValueError("score_out_of_range")
    q = select(ProductListing).where(and_(ProductListing.match_id == match_id, ProductListing.id == listing_id)).with_for_update()
    pl = (await s.execute(q)).scalar_one_or_none()
    if not pl:
        raise ValueError("listing_not_found")
    pl.rating_score = int(score)
    pl.rating_comment = (comment or "").strip()[:256] or None
    pl.rated_by_user_id = actor_user_id
    pl.rated_at = now_utc()
    pl.updated_at = now_utc()
    s.add(
        AuditLog(
            match_id=match_id,
            actor_user_id=actor_user_id,
            actor_role="match_admin",
            action="product_listing_rate",
            subject_company_id=pl.seller_company_id,
            reference_type="product_listing",
            reference_id=pl.id,
            message=f"score={score}",
            created_at=now_utc(),
        )
    )
    return pl


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
            carbon_delta=0,
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
            carbon_delta=0,
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
    material = material.strip()
    if not material:
        raise ValueError("material_required")
    if len(material) > 16:
        # TradeRequest.material column is String(16) for now; keep constraint explicit
        raise ValueError("material_too_long")
    qty_d = parse_qty_2dp(qty)
    if unit_price_gold <= 0:
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
        qty=qty_d,
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
            message=f"{material} qty={qty_d} price={unit_price_gold}",
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
    total = int((Decimal(str(tr.qty)) * Decimal(int(tr.unit_price_gold))).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
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

    if Decimal(str(inv_seller.qty)) < Decimal(str(tr.qty)):
        raise ValueError("seller_stock_insufficient")
    if a_buyer.gold_balance < total:
        raise ValueError("buyer_gold_insufficient")

    inv_seller.qty = Decimal(str(inv_seller.qty)) - Decimal(str(tr.qty))
    inv_buyer.qty = Decimal(str(inv_buyer.qty)) + Decimal(str(tr.qty))
    a_buyer.gold_balance -= total
    a_seller.gold_balance += total

    # ledger entries with idempotency
    s.add(
        LedgerEntry(
            match_id=match_id,
            company_id=seller_id,
            kind="trade_sell",
            gold_delta=total,
            carbon_delta=0,
            material=tr.material,
            material_delta=-(Decimal(str(tr.qty))),
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
            carbon_delta=0,
            material=tr.material,
            material_delta=Decimal(str(tr.qty)),
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
