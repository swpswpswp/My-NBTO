"""
MVP 内存态：黄金账本、三原料、开采、原料市场（挂单/撤单/买入）。
重启后数据清空。后续可替换为 PostgreSQL。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

MINE_UNIT_COST = {"R1": 10, "R2": 20, "R3": 30}
MATERIALS = ("R1", "R2", "R3")

# company_id -> {name, created_by_user_id}
companies: dict[str, dict[str, Any]] = {}
# user_id -> company_id
user_company: dict[str, str] = {}

# 黄金：余额 + 冻结（真相仍以 ledger 为准时可双写；MVP 双写 balance/frozen + ledger）
gold_balance: dict[str, int] = {}
gold_frozen: dict[str, int] = {}
# company_id -> list of ledger rows
gold_ledger: dict[str, list[dict[str, Any]]] = {}

# company_id -> material -> {qty, frozen}
inventory: dict[str, dict[str, dict[str, int]]] = {}

# listing_id -> row
listings: dict[str, dict[str, Any]] = {}
trades: list[dict[str, Any]] = []

# 幂等：key -> True
idempotency_done: set[str] = {}

# 开采整笔幂等结果（与 ledger 行里的 idempotency_key 区分）
mine_done: dict[str, dict[str, Any]] = {}

# 转账整笔幂等结果
transfer_done: dict[str, dict[str, Any]] = {}


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _ensure_company_assets(company_id: str) -> None:
    if company_id not in gold_balance:
        gold_balance[company_id] = 0
        gold_frozen[company_id] = 0
        gold_ledger[company_id] = []
    if company_id not in inventory:
        inventory[company_id] = {m: {"qty": 0, "frozen": 0} for m in MATERIALS}


def get_company_for_user(user_id: str) -> str | None:
    return user_company.get(user_id)


def create_company(user_id: str, name: str) -> dict[str, Any]:
    if user_id in user_company:
        raise ValueError("already_in_company")
    for c in companies.values():
        if c["name"] == name:
            raise ValueError("company_name_taken")
    cid = str(uuid.uuid4())
    companies[cid] = {"id": cid, "name": name, "created_by_user_id": user_id}
    user_company[user_id] = cid
    _ensure_company_assets(cid)
    return companies[cid]


def _post_gold(company_id: str, amount: int, reason: str, ref_type: str, ref_id: str, idem: str, actor_user_id: str | None) -> None:
    if idem in idempotency_done:
        return
    _ensure_company_assets(company_id)
    gold_balance[company_id] += amount
    if gold_balance[company_id] < 0:
        gold_balance[company_id] -= amount
        raise ValueError("gold_balance_insufficient")
    gold_ledger[company_id].append(
        {
            "id": str(uuid.uuid4()),
            "amount": amount,
            "reason": reason,
            "reference_type": ref_type,
            "reference_id": ref_id,
            "created_at": _now_iso(),
            "created_by_user_id": actor_user_id,
            "idempotency_key": idem,
        }
    )
    idempotency_done.add(idem)


def grant_gold(company_id: str, amount: int, idem: str, actor_user_id: str | None) -> None:
    if amount <= 0:
        raise ValueError("amount_must_be_positive")
    if company_id not in companies:
        raise ValueError("company_not_found")
    rid = str(uuid.uuid4())
    _post_gold(company_id, amount, "admin_grant", "admin_grant", rid, f"{idem}:gold", actor_user_id)


def gold_snapshot(company_id: str) -> dict[str, Any]:
    _ensure_company_assets(company_id)
    return {"company_id": company_id, "balance": gold_balance[company_id], "frozen": gold_frozen[company_id]}


def gold_ledger_list(company_id: str, limit: int) -> list[dict[str, Any]]:
    _ensure_company_assets(company_id)
    rows = list(reversed(gold_ledger[company_id]))
    return rows[:limit]


def freeze_gold(company_id: str, amount: int) -> None:
    _ensure_company_assets(company_id)
    avail = gold_balance[company_id] - gold_frozen[company_id]
    if avail < amount:
        raise ValueError("gold_available_insufficient")
    gold_frozen[company_id] += amount


def unfreeze_gold(company_id: str, amount: int) -> None:
    _ensure_company_assets(company_id)
    if gold_frozen[company_id] < amount:
        raise ValueError("gold_frozen_insufficient")
    gold_frozen[company_id] -= amount


def mine(user_id: str, material: str, qty: int, idem: str) -> dict[str, Any]:
    if idem in mine_done:
        return {**mine_done[idem], "cached": True}
    if material not in MINE_UNIT_COST:
        raise ValueError("unknown_material")
    if qty <= 0:
        raise ValueError("qty_must_be_positive")
    cid = get_company_for_user(user_id)
    if not cid:
        raise ValueError("user_not_in_company")
    unit = MINE_UNIT_COST[material]
    cost = qty * unit
    rid = str(uuid.uuid4())
    _post_gold(cid, -cost, "mine", "mining", rid, f"mine:{idem}:gold", user_id)
    _ensure_company_assets(cid)
    inventory[cid][material]["qty"] += qty
    out = {"mining_record_id": rid, "cost_gold": cost}
    mine_done[idem] = out
    return out


def inventory_list(company_id: str) -> list[dict[str, Any]]:
    _ensure_company_assets(company_id)
    return [{"material": m, **inventory[company_id][m]} for m in MATERIALS]


def list_companies() -> list[dict[str, Any]]:
    rows = list(companies.values())
    rows.sort(key=lambda c: c["name"])
    return rows


def transfer_gold(from_user_id: str, to_company_id: str, amount: int, idem: str) -> dict[str, Any]:
    """
    公司之间黄金转账：扣款方/收款方各记一条账本记录。
    - 幂等：同 idem 重试不会重复转账
    - 禁止自转
    """
    if idem in transfer_done:
        return {**transfer_done[idem], "cached": True}
    if amount <= 0:
        raise ValueError("amount_must_be_positive")
    from_c = get_company_for_user(from_user_id)
    if not from_c:
        raise ValueError("user_not_in_company")
    if to_company_id not in companies:
        raise ValueError("company_not_found")
    if to_company_id == from_c:
        raise ValueError("cannot_transfer_to_self")

    tid = str(uuid.uuid4())
    # 先校验再双边入账，避免半成功
    _ensure_company_assets(from_c)
    _ensure_company_assets(to_company_id)

    _post_gold(from_c, -amount, "transfer_out", "transfer", tid, f"{idem}:out", from_user_id)
    _post_gold(to_company_id, amount, "transfer_in", "transfer", tid, f"{idem}:in", from_user_id)
    out = {"transfer_id": tid, "from_company_id": from_c, "to_company_id": to_company_id, "amount": amount}
    transfer_done[idem] = out
    return out


def _freeze_stock(company_id: str, material: str, qty: int) -> None:
    _ensure_company_assets(company_id)
    inv = inventory[company_id][material]
    avail = inv["qty"] - inv["frozen"]
    if avail < qty:
        raise ValueError("stock_available_insufficient")
    inv["frozen"] += qty


def _unfreeze_stock(company_id: str, material: str, qty: int) -> None:
    _ensure_company_assets(company_id)
    inv = inventory[company_id][material]
    if inv["frozen"] < qty:
        raise ValueError("stock_frozen_insufficient")
    inv["frozen"] -= qty


def _transfer_stock(from_c: str, to_c: str, material: str, qty: int) -> None:
    """从卖方冻结库存交割给买方（不经过买方冻结）。"""
    _ensure_company_assets(from_c)
    _ensure_company_assets(to_c)
    finv = inventory[from_c][material]
    if finv["frozen"] < qty:
        raise ValueError("stock_frozen_insufficient")
    finv["frozen"] -= qty
    finv["qty"] -= qty
    if finv["qty"] < 0:
        raise ValueError("stock_negative")
    inventory[to_c][material]["qty"] += qty


def create_listing(seller_user_id: str, material: str, qty: int, unit_price: int, idem: str) -> dict[str, Any]:
    if idem in idempotency_done:
        for lid, L in listings.items():
            if L.get("idempotency_key") == idem:
                return L
        raise ValueError("idempotency_conflict")
    cid = get_company_for_user(seller_user_id)
    if not cid:
        raise ValueError("user_not_in_company")
    if material not in MINE_UNIT_COST:
        raise ValueError("unknown_material")
    if qty <= 0 or unit_price <= 0:
        raise ValueError("qty_and_price_must_be_positive")
    _freeze_stock(cid, material, qty)
    lid = str(uuid.uuid4())
    row = {
        "id": lid,
        "seller_company_id": cid,
        "material": material,
        "qty": qty,
        "filled_qty": 0,
        "unit_price": unit_price,
        "status": "open",
        "idempotency_key": idem,
        "created_by_user_id": seller_user_id,
        "created_at": _now_iso(),
    }
    listings[lid] = row
    idempotency_done.add(idem)
    return row


def list_open_listings(material: str | None) -> list[dict[str, Any]]:
    out = []
    for L in listings.values():
        if L["status"] != "open":
            continue
        if material and L["material"] != material:
            continue
        out.append(L)
    out.sort(key=lambda x: x["created_at"], reverse=True)
    return out[:200]


def cancel_listing(seller_user_id: str, listing_id: str, idem: str) -> dict[str, Any]:
    if idem in idempotency_done:
        L = listings.get(listing_id)
        if not L:
            raise ValueError("listing_not_found")
        return L
    L = listings.get(listing_id)
    if not L:
        raise ValueError("listing_not_found")
    cid = get_company_for_user(seller_user_id)
    if cid != L["seller_company_id"]:
        raise ValueError("listing_not_owner")
    if L["status"] in ("cancelled", "filled"):
        idempotency_done.add(idem)
        return L
    remaining = L["qty"] - L["filled_qty"]
    if remaining > 0:
        _unfreeze_stock(cid, L["material"], remaining)
    L["status"] = "cancelled"
    idempotency_done.add(idem)
    return L


def buy_listing(buyer_user_id: str, listing_id: str, qty: int, idem: str) -> dict[str, Any]:
    if idem in idempotency_done:
        for t in reversed(trades):
            if t.get("idempotency_key") == idem:
                return t
        raise ValueError("idempotency_conflict")
    L = listings.get(listing_id)
    if not L or L["status"] != "open":
        raise ValueError("listing_not_open")
    buyer_c = get_company_for_user(buyer_user_id)
    if not buyer_c:
        raise ValueError("user_not_in_company")
    if buyer_c == L["seller_company_id"]:
        raise ValueError("cannot_buy_own_listing")
    remaining = L["qty"] - L["filled_qty"]
    if remaining < qty or qty <= 0:
        raise ValueError("listing_insufficient_remaining")
    total = qty * L["unit_price"]
    freeze_gold(buyer_c, total)
    try:
        _transfer_stock(L["seller_company_id"], buyer_c, L["material"], qty)
        unfreeze_gold(buyer_c, total)
        tid = str(uuid.uuid4())
        _post_gold(buyer_c, -total, "trade_buy", "trade", tid, f"{idem}:buyer", buyer_user_id)
        _post_gold(L["seller_company_id"], total, "trade_sell", "trade", tid, f"{idem}:seller", buyer_user_id)
        trade = {
            "id": tid,
            "listing_id": listing_id,
            "buyer_company_id": buyer_c,
            "seller_company_id": L["seller_company_id"],
            "material": L["material"],
            "qty": qty,
            "unit_price": L["unit_price"],
            "total_price": total,
            "idempotency_key": idem,
            "created_at": _now_iso(),
        }
        trades.append(trade)
        L["filled_qty"] += qty
        if L["filled_qty"] >= L["qty"]:
            L["status"] = "filled"
        idempotency_done.add(idem)
        return trade
    except Exception:
        try:
            unfreeze_gold(buyer_c, total)
        except Exception:
            pass
        raise


def my_listings(company_id: str) -> list[dict[str, Any]]:
    rows = [L for L in listings.values() if L["seller_company_id"] == company_id]
    rows.sort(key=lambda x: x["created_at"], reverse=True)
    return rows[:200]


def my_trades(company_id: str) -> list[dict[str, Any]]:
    rows = [t for t in trades if t["buyer_company_id"] == company_id or t["seller_company_id"] == company_id]
    rows.sort(key=lambda x: x["created_at"], reverse=True)
    return rows[:200]
