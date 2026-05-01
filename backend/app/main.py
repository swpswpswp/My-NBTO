from datetime import datetime, timedelta, timezone
import uuid

from jose import JWTError, jwt
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from app import game_store as gs
from app.db import session_scope
from app.db_init import maybe_create_tables
from app import services as svc
from app import security as sec
from app.config import JWT_ALGO as CFG_JWT_ALGO, JWT_SECRET as CFG_JWT_SECRET

JWT_SECRET = CFG_JWT_SECRET
JWT_ALGO = CFG_JWT_ALGO
ACCESS_MINUTES = 60 * 12

USERS = {
    "admin": {
        "id": str(uuid.uuid4()),
        "username": "admin",
        "role": "admin",
        "password": "admin123",
    },
    "student1": {
        "id": str(uuid.uuid4()),
        "username": "student1",
        "role": "student",
        "password": "student123",
    },
    "student": {
        "id": str(uuid.uuid4()),
        "username": "student",
        "role": "student",
        "password": "student123",
    },
    "student2": {
        "id": str(uuid.uuid4()),
        "username": "student2",
        "role": "student",
        "password": "student123",
    },
}

USERS_BY_LOWERNAME = {u["username"].lower(): u for u in USERS.values()}


def token_of(user: dict) -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": user["id"],
        "username": user["username"],
        "role": user["role"],
        "iat": int(now.timestamp()),
        "exp": now + timedelta(minutes=ACCESS_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def bearer_token(request: Request) -> str:
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return ""


def auth_user(request: Request) -> dict | None:
    token = bearer_token(request)
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except JWTError:
        return None
    return {
        "id": payload.get("sub"),
        "username": payload.get("username"),
        "role": payload.get("role"),
    }


async def health(_: Request) -> JSONResponse:
    return JSONResponse({"ok": True})


# -----------------------------
# V2: PostgreSQL + 多赛场 API
# Base path: /m/{match_key}/...
# -----------------------------


def _match_key(request: Request) -> str:
    return str(request.path_params.get("match_key") or "").strip()


async def v2_register(request: Request) -> JSONResponse:
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    async with session_scope() as s:
        try:
            u = await svc.create_user(s, username, password)
            await s.commit()
            return JSONResponse({"ok": True, "user_id": u.id, "username": u.username})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_login(request: Request) -> JSONResponse:
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    async with session_scope() as s:
        u = await svc.verify_user_password(s, username, password)
        if not u:
            return JSONResponse({"detail": "invalid_username_or_password"}, status_code=400)
        role = "system_admin" if await svc.is_system_admin(s, u.id) else "student"
        return JSONResponse({"access_token": sec.encode_token(u.id, u.username, role), "token_type": "bearer"})


async def v2_match_create(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    if u.get("role") != "system_admin":
        return JSONResponse({"detail": "system_admin_required"}, status_code=403)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    key = str(data.get("key") or "")
    name = str(data.get("name") or key)
    async with session_scope() as s:
        try:
            m = await svc.create_match(s, key, name, u["id"])
            await s.commit()
            return JSONResponse({"id": m.id, "key": m.key, "name": m.name})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_system_admin_bootstrap(request: Request) -> JSONResponse:
    """
    开发期便捷：把指定 user 设为 system_admin（只用于本地/比赛前初始化）。
    """
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    username = (data.get("username") or "").strip()
    async with session_scope() as s:
        from sqlalchemy import select
        from app.models import User, SystemAdmin

        r = await s.execute(select(User).where(User.username == username))
        usr = r.scalar_one_or_none()
        if not usr:
            return JSONResponse({"detail": "user_not_found"}, status_code=404)
        r2 = await s.execute(select(SystemAdmin).where(SystemAdmin.user_id == usr.id))
        if not r2.scalar_one_or_none():
            s.add(SystemAdmin(user_id=usr.id))
            await s.commit()
        return JSONResponse({"ok": True, "user_id": usr.id, "username": usr.username})


async def v2_companies(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        return JSONResponse(await svc.list_companies(s, m.id))


async def v2_join_company(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    company_id = str(data.get("company_id") or "")
    join_password = str(data.get("join_password") or "")
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            await svc.join_company(s, m.id, u["id"], company_id, join_password)
            await s.commit()
            return JSONResponse({"ok": True})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_me(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        cid = await svc.get_user_company_id(s, m.id, u["id"])
        return JSONResponse({"id": u["id"], "username": u["username"], "role": u["role"], "match_key": mk, "company_id": cid})


async def v2_gold_balance(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        cid = await svc.get_user_company_id(s, m.id, u["id"])
        if not cid:
            return JSONResponse({"detail": "user_not_in_company"}, status_code=400)
        # load asset
        from sqlalchemy import and_, select
        from app.models import CompanyAsset

        r = await s.execute(select(CompanyAsset).where(and_(CompanyAsset.match_id == m.id, CompanyAsset.company_id == cid)))
        a = r.scalar_one_or_none()
        if not a:
            return JSONResponse({"detail": "company_asset_not_found"}, status_code=400)
        return JSONResponse({"company_id": cid, "balance": a.gold_balance})

async def v2_carbon_balance(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        cid = await svc.get_user_company_id(s, m.id, u["id"])
        if not cid:
            return JSONResponse({"detail": "user_not_in_company"}, status_code=400)
        from sqlalchemy import and_, select
        from app.models import CompanyAsset

        r = await s.execute(select(CompanyAsset).where(and_(CompanyAsset.match_id == m.id, CompanyAsset.company_id == cid)))
        a = r.scalar_one_or_none()
        if not a:
            return JSONResponse({"detail": "company_asset_not_found"}, status_code=400)
        return JSONResponse({"company_id": cid, "balance": a.carbon_balance})


async def v2_ledger(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        limit = int(request.query_params.get("limit") or "50")
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 200))
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        cid = await svc.get_user_company_id(s, m.id, u["id"])
        if not cid:
            return JSONResponse({"detail": "user_not_in_company"}, status_code=400)
        from sqlalchemy import and_, select
        from app.models import LedgerEntry

        r = await s.execute(
            select(LedgerEntry)
            .where(and_(LedgerEntry.match_id == m.id, LedgerEntry.company_id == cid))
            .order_by(LedgerEntry.created_at.desc())
            .limit(limit)
        )
        rows = r.scalars().all()
        return JSONResponse(
            [
                {
                    "id": x.id,
                    "kind": x.kind,
                    "gold_delta": x.gold_delta,
                    "carbon_delta": x.carbon_delta,
                    "material": x.material,
                    "material_delta": float(x.material_delta) if x.material_delta is not None else None,
                    "counterparty_company_id": x.counterparty_company_id,
                    "reference_type": x.reference_type,
                    "reference_id": x.reference_id,
                    "idempotency_key": x.idempotency_key,
                    "created_at": x.created_at.isoformat() if x.created_at else None,
                }
                for x in rows
            ]
        )


async def v2_gold_transfer(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    to_company_id = str(data.get("to_company_id") or "")
    try:
        amount = int(data.get("amount"))
    except Exception:
        return JSONResponse({"detail": "invalid_amount"}, status_code=400)
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            r = await svc.gold_transfer(s, m.id, u["id"], to_company_id, amount, idem)
            await s.commit()
            return JSONResponse({"ok": True, **r})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)

async def v2_carbon_transfer(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    to_company_id = str(data.get("to_company_id") or "")
    try:
        amount = int(data.get("amount"))
    except Exception:
        return JSONResponse({"detail": "invalid_amount"}, status_code=400)
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            r = await svc.carbon_transfer(s, m.id, u["id"], to_company_id, amount, idem)
            await s.commit()
            return JSONResponse({"ok": True, **r})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)

async def v2_student_facilities(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            rows = await svc.list_my_facilities(s, m.id, u["id"])
            return JSONResponse(rows)
        except ValueError as e:
            return JSONResponse({"detail": str(e)}, status_code=400)

async def v2_student_facility_types(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        return JSONResponse(await svc.list_facility_types(s, m.id))


async def v2_admin_company_facilities(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        return JSONResponse(await svc.admin_list_company_facilities(s, m.id))


async def v2_admin_rush_orders(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    status = (request.query_params.get("status") or "").strip() or None
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        return JSONResponse(await svc.list_rush_orders(s, m.id, status=status))


async def v2_admin_rush_order_publish(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    product_code = str(data.get("product_code") or "")
    craft_code = str(data.get("craft_code") or "")
    recipe_items = data.get("recipe_items") or []
    recipe_text = str(data.get("recipe_text") or "")
    try:
        demand_qty = int(data.get("demand_qty"))
    except Exception:
        return JSONResponse({"detail": "invalid_demand_qty"}, status_code=400)
    try:
        unit_price_gold = int(data.get("unit_price_gold"))
    except Exception:
        return JSONResponse({"detail": "invalid_unit_price_gold"}, status_code=400)
    settlement_at = str(data.get("settlement_at") or "")
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    from datetime import datetime

    try:
        settle_dt = datetime.fromisoformat(settlement_at)
    except Exception:
        return JSONResponse({"detail": "invalid_settlement_at"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        try:
            ro = await svc.admin_publish_rush_order(
                s, m.id, u["id"], product_code, craft_code, recipe_items, recipe_text, demand_qty, unit_price_gold, settle_dt, idem
            )
            await s.commit()
            return JSONResponse({"ok": True, "id": ro.id, "status": ro.status})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_admin_rush_order_settle(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    rush_order_id = str(request.path_params.get("rush_order_id") or "")
    try:
        data = await request.json()
    except Exception:
        data = {}
    force = bool((data or {}).get("force") or False)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        try:
            r = await svc.admin_settle_rush_order(s, m.id, u["id"], rush_order_id, force=force)
            await s.commit()
            return JSONResponse({"ok": True, **r})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_student_rush_orders(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    status = (request.query_params.get("status") or "open").strip()
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        return JSONResponse(await svc.list_rush_orders(s, m.id, status=status))


async def v2_student_rush_order_submit(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    rush_order_id = str(request.path_params.get("rush_order_id") or "")
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    product_code = str(data.get("product_code") or "")
    try:
        qty = int(data.get("qty"))
    except Exception:
        return JSONResponse({"detail": "invalid_qty"}, status_code=400)
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            sub = await svc.student_submit_rush_order(s, m.id, u["id"], rush_order_id, product_code, qty, idem)
            await s.commit()
            return JSONResponse({"ok": True, "id": sub.id, "status": sub.status, "qty_submitted": sub.qty_submitted})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_craft_types(request: Request) -> JSONResponse:
    # public enough; used by frontend dropdowns
    return JSONResponse(svc.CRAFT_TYPES)
async def v2_student_buy_facility(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    facility_code = str(data.get("facility_code") or "")
    try:
        qty = int(data.get("qty"))
    except Exception:
        qty = 1
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        await svc.upsert_facility_catalog_for_match(s, m.id)
        try:
            r = await svc.buy_facility(s, m.id, u["id"], facility_code, qty, idem)
            await s.commit()
            return JSONResponse({"ok": True, **r})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)

async def v2_student_mine(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    material = str(data.get("material") or "")
    try:
        qty = int(data.get("qty"))
    except Exception:
        return JSONResponse({"detail": "invalid_qty"}, status_code=400)
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        await svc.upsert_facility_catalog_for_match(s, m.id)
        try:
            r = await svc.mine_material(s, m.id, u["id"], material, qty, idem)
            await s.commit()
            return JSONResponse({"ok": True, **r})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_trade_request_create(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    to_company_id = str(data.get("to_company_id") or "")
    material = str(data.get("material") or "")
    try:
        qty = data.get("qty")
        unit_price_gold = int(data.get("unit_price"))
    except Exception:
        return JSONResponse({"detail": "invalid_params"}, status_code=400)
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            tr = await svc.create_trade_request(s, m.id, u["id"], to_company_id, material, qty, unit_price_gold, idem)
            await s.commit()
            return JSONResponse(
                {
                    "id": tr.id,
                    "from_company_id": tr.from_company_id,
                    "to_company_id": tr.to_company_id,
                    "material": tr.material,
                    "qty": float(tr.qty),
                    "unit_price_gold": tr.unit_price_gold,
                    "status": tr.status,
                }
            )
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_trade_requests_outbox(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        cid = await svc.get_user_company_id(s, m.id, u["id"])
        if not cid:
            return JSONResponse({"detail": "user_not_in_company"}, status_code=400)
        from sqlalchemy import and_, select
        from app.models import TradeRequest

        r = await s.execute(
            select(TradeRequest)
            .where(and_(TradeRequest.match_id == m.id, TradeRequest.from_company_id == cid))
            .order_by(TradeRequest.created_at.desc())
            .limit(200)
        )
        rows = r.scalars().all()
        return JSONResponse(
            [
                {
                    "id": x.id,
                    "from_company_id": x.from_company_id,
                    "to_company_id": x.to_company_id,
                    "material": x.material,
                    "qty": float(x.qty),
                    "unit_price_gold": x.unit_price_gold,
                    "status": x.status,
                    "created_at": x.created_at.isoformat() if x.created_at else None,
                }
                for x in rows
            ]
        )


async def v2_trade_requests_inbox(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        cid = await svc.get_user_company_id(s, m.id, u["id"])
        if not cid:
            return JSONResponse({"detail": "user_not_in_company"}, status_code=400)
        from sqlalchemy import and_, select
        from app.models import TradeRequest

        r = await s.execute(
            select(TradeRequest)
            .where(and_(TradeRequest.match_id == m.id, TradeRequest.to_company_id == cid))
            .order_by(TradeRequest.created_at.desc())
            .limit(200)
        )
        rows = r.scalars().all()
        return JSONResponse(
            [
                {
                    "id": x.id,
                    "from_company_id": x.from_company_id,
                    "to_company_id": x.to_company_id,
                    "material": x.material,
                    "qty": float(x.qty),
                    "unit_price_gold": x.unit_price_gold,
                    "status": x.status,
                    "created_at": x.created_at.isoformat() if x.created_at else None,
                }
                for x in rows
            ]
        )


async def v2_trade_request_decide(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    trade_request_id = str(request.path_params.get("trade_request_id"))
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    decision = str(data.get("decision") or "")
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            tr = await svc.decide_trade_request(s, m.id, u["id"], trade_request_id, decision, idem)
            await s.commit()
            return JSONResponse({"ok": True, "id": tr.id, "status": tr.status})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_admin_import_company(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    name = str(data.get("name") or "").strip()
    join_password = str(data.get("join_password") or "")
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        try:
            c = await svc.import_company(s, m.id, name, join_password, u["id"])
            await s.commit()
            return JSONResponse({"id": c.id, "name": c.name})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_admin_grant_gold(request: Request) -> JSONResponse:
    """开发/比赛管理：给公司发放黄金。"""
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    company_id = str(request.path_params.get("company_id") or "")
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    try:
        amount = int(data.get("amount"))
    except Exception:
        return JSONResponse({"detail": "invalid_amount"}, status_code=400)
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    if amount <= 0:
        return JSONResponse({"detail": "amount_must_be_positive"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        try:
            # reuse transfer path: match admin is actor, "from" is virtual faucet
            from sqlalchemy import and_, select
            from app.models import CompanyAsset, LedgerEntry, AuditLog

            ref_id = str(uuid.uuid4())
            # idempotency on company ledger
            r = await s.execute(
                select(LedgerEntry).where(and_(LedgerEntry.match_id == m.id, LedgerEntry.company_id == company_id, LedgerEntry.idempotency_key == idem))
            )
            if r.scalar_one_or_none():
                return JSONResponse({"ok": True, "cached": True})
            q = select(CompanyAsset).where(and_(CompanyAsset.match_id == m.id, CompanyAsset.company_id == company_id)).with_for_update()
            a = (await s.execute(q)).scalar_one_or_none()
            if not a:
                return JSONResponse({"detail": "company_asset_not_found"}, status_code=400)
            a.gold_balance += amount
            s.add(
                LedgerEntry(
                    match_id=m.id,
                    company_id=company_id,
                    kind="admin_grant_gold",
                    gold_delta=amount,
                    carbon_delta=0,
                    counterparty_company_id=None,
                    reference_type="admin_grant",
                    reference_id=ref_id,
                    idempotency_key=idem,
                    created_at=datetime.now(tz=timezone.utc),
                    actor_user_id=u["id"],
                )
            )
            s.add(
                AuditLog(
                    match_id=m.id,
                    actor_user_id=u["id"],
                    actor_role=u.get("role") or "match_admin",
                    action="admin_grant_gold",
                    subject_company_id=company_id,
                    reference_type="admin_grant",
                    reference_id=ref_id,
                    message=str(amount),
                    created_at=datetime.now(tz=timezone.utc),
                )
            )
            await s.commit()
            return JSONResponse({"ok": True})
        except Exception as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_admin_grant_material(request: Request) -> JSONResponse:
    """开发/比赛管理：给公司发放原料（后续会被“地块开采”替代）。"""
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    company_id = str(request.path_params.get("company_id") or "")
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    material = str(data.get("material") or "")
    try:
        qty = int(data.get("qty"))
    except Exception:
        return JSONResponse({"detail": "invalid_qty"}, status_code=400)
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    if qty <= 0:
        return JSONResponse({"detail": "qty_must_be_positive"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        try:
            from sqlalchemy import and_, select
            from app.models import AuditLog, Inventory, LedgerEntry

            if material not in svc.MATERIALS:
                return JSONResponse({"detail": "unknown_material"}, status_code=400)
            ref_id = str(uuid.uuid4())
            # idempotency via ledger
            r = await s.execute(
                select(LedgerEntry).where(and_(LedgerEntry.match_id == m.id, LedgerEntry.company_id == company_id, LedgerEntry.idempotency_key == idem))
            )
            if r.scalar_one_or_none():
                return JSONResponse({"ok": True, "cached": True})
            inv = await svc.lock_inventory(s, m.id, company_id, material)
            inv.qty += qty
            s.add(
                LedgerEntry(
                    match_id=m.id,
                    company_id=company_id,
                    kind="admin_grant_material",
                    gold_delta=0,
                    carbon_delta=0,
                    material=material,
                    material_delta=qty,
                    counterparty_company_id=None,
                    reference_type="admin_grant",
                    reference_id=ref_id,
                    idempotency_key=idem,
                    created_at=datetime.now(tz=timezone.utc),
                    actor_user_id=u["id"],
                )
            )
            s.add(
                AuditLog(
                    match_id=m.id,
                    actor_user_id=u["id"],
                    actor_role=u.get("role") or "match_admin",
                    action="admin_grant_material",
                    subject_company_id=company_id,
                    reference_type="admin_grant",
                    reference_id=ref_id,
                    message=f"{material}:{qty}",
                    created_at=datetime.now(tz=timezone.utc),
                )
            )
            await s.commit()
            return JSONResponse({"ok": True})
        except Exception as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_admin_grant_carbon(request: Request) -> JSONResponse:
    """比赛管理：给公司发放碳排放指标（只有系统/管理员发放）。"""
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    company_id = str(request.path_params.get("company_id") or "")
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    try:
        amount = int(data.get("amount"))
    except Exception:
        return JSONResponse({"detail": "invalid_amount"}, status_code=400)
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    if amount <= 0:
        return JSONResponse({"detail": "amount_must_be_positive"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        try:
            from sqlalchemy import and_, select
            from app.models import AuditLog, CompanyAsset, LedgerEntry

            ref_id = str(uuid.uuid4())
            r = await s.execute(
                select(LedgerEntry).where(and_(LedgerEntry.match_id == m.id, LedgerEntry.company_id == company_id, LedgerEntry.idempotency_key == idem))
            )
            if r.scalar_one_or_none():
                return JSONResponse({"ok": True, "cached": True})
            q = select(CompanyAsset).where(and_(CompanyAsset.match_id == m.id, CompanyAsset.company_id == company_id)).with_for_update()
            a = (await s.execute(q)).scalar_one_or_none()
            if not a:
                return JSONResponse({"detail": "company_asset_not_found"}, status_code=400)
            a.carbon_balance += amount
            s.add(
                LedgerEntry(
                    match_id=m.id,
                    company_id=company_id,
                    kind="admin_grant_carbon",
                    gold_delta=0,
                    carbon_delta=amount,
                    counterparty_company_id=None,
                    reference_type="admin_grant",
                    reference_id=ref_id,
                    idempotency_key=idem,
                    created_at=datetime.now(tz=timezone.utc),
                    actor_user_id=u["id"],
                )
            )
            s.add(
                AuditLog(
                    match_id=m.id,
                    actor_user_id=u["id"],
                    actor_role=u.get("role") or "match_admin",
                    action="admin_grant_carbon",
                    subject_company_id=company_id,
                    reference_type="admin_grant",
                    reference_id=ref_id,
                    message=str(amount),
                    created_at=datetime.now(tz=timezone.utc),
                )
            )
            await s.commit()
            return JSONResponse({"ok": True})
        except Exception as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_admin_match_settings_get(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        ms = await svc.get_match_setting(s, m.id)
        return JSONResponse(
            {
                "initial_gold": ms.initial_gold,
                "initial_carbon": ms.initial_carbon,
                "material_prices": {"R1": ms.material_r1_price, "R2": ms.material_r2_price, "R3": ms.material_r3_price},
                "updated_at": ms.updated_at.isoformat() if ms.updated_at else None,
            }
        )


async def v2_admin_match_settings_update(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    initial_gold = data.get("initial_gold", None)
    initial_carbon = data.get("initial_carbon", None)
    material_prices = data.get("material_prices", None)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        try:
            r = await svc.admin_update_match_setting(
                s,
                m.id,
                u["id"],
                initial_gold=int(initial_gold) if initial_gold is not None else None,
                initial_carbon=int(initial_carbon) if initial_carbon is not None else None,
                material_prices={str(k): int(v) for (k, v) in (material_prices or {}).items()} if material_prices is not None else None,
            )
            await s.commit()
            return JSONResponse({"ok": True, **r})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_admin_issue_initial(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    idem = str(data.get("idempotency_key") or "")
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        try:
            r = await svc.admin_issue_initial_assets_to_all_companies(s, m.id, u["id"], idem)
            await s.commit()
            return JSONResponse({"ok": True, **r})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_admin_export_balance_sheet(request: Request) -> Response:
    """导出资产负债表 CSV：UTF-8 BOM，Excel 可直接打开不乱码。"""
    import re

    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        rows = await svc.match_balance_sheet_export_rows(s, m.id)
    body = svc.encode_balance_sheet_csv(rows)
    safe_key = re.sub(r"[^\w\-.]+", "_", mk)[:64] or "match"
    return Response(
        body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="balance-sheet-{safe_key}.csv"'},
    )


async def v2_admin_ledger_query(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    company_id = (request.query_params.get("company_id") or "").strip() or None
    kind = (request.query_params.get("kind") or "").strip() or None
    since = (request.query_params.get("since") or "").strip() or None
    until = (request.query_params.get("until") or "").strip() or None
    try:
        limit = int(request.query_params.get("limit") or "200")
    except Exception:
        limit = 200
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        try:
            rows = await svc.admin_query_ledger(s, m.id, company_id=company_id, kind=kind, since_iso=since, until_iso=until, limit=limit)
            return JSONResponse(rows)
        except Exception as e:
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_admin_audit_query(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    action = (request.query_params.get("action") or "").strip() or None
    actor_user_id = (request.query_params.get("actor_user_id") or "").strip() or None
    subject_company_id = (request.query_params.get("subject_company_id") or "").strip() or None
    target_company_id = (request.query_params.get("target_company_id") or "").strip() or None
    since = (request.query_params.get("since") or "").strip() or None
    until = (request.query_params.get("until") or "").strip() or None
    try:
        limit = int(request.query_params.get("limit") or "200")
    except Exception:
        limit = 200
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        try:
            rows = await svc.admin_query_audit_logs(
                s,
                m.id,
                action=action,
                actor_user_id=actor_user_id,
                subject_company_id=subject_company_id,
                target_company_id=target_company_id,
                since_iso=since,
                until_iso=until,
                limit=limit,
            )
            return JSONResponse(rows)
        except Exception as e:
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_admin_ledger_export_csv(request: Request) -> Response:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    company_id = (request.query_params.get("company_id") or "").strip() or None
    kind = (request.query_params.get("kind") or "").strip() or None
    since = (request.query_params.get("since") or "").strip() or None
    until = (request.query_params.get("until") or "").strip() or None
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        rows = await svc.admin_query_ledger(s, m.id, company_id=company_id, kind=kind, since_iso=since, until_iso=until, limit=1000)
    body = svc.encode_csv_utf8_bom(
        ["时间", "公司ID", "类型", "对手方", "黄金", "碳排", "物品", "数量", "actor_user_id", "reference"],
        [
            [
                r.get("created_at"),
                r.get("company_id"),
                r.get("kind"),
                r.get("counterparty_company_id"),
                r.get("gold_delta"),
                r.get("carbon_delta"),
                r.get("material"),
                r.get("material_delta"),
                r.get("actor_user_id"),
                f'{r.get("reference_type")}:{r.get("reference_id")}',
            ]
            for r in rows
        ],
    )
    return Response(body, media_type="text/csv; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="ledger.csv"'})


async def v2_admin_audit_export_csv(request: Request) -> Response:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    action = (request.query_params.get("action") or "").strip() or None
    subject_company_id = (request.query_params.get("subject_company_id") or "").strip() or None
    target_company_id = (request.query_params.get("target_company_id") or "").strip() or None
    since = (request.query_params.get("since") or "").strip() or None
    until = (request.query_params.get("until") or "").strip() or None
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        rows = await svc.admin_query_audit_logs(
            s,
            m.id,
            action=action,
            subject_company_id=subject_company_id,
            target_company_id=target_company_id,
            since_iso=since,
            until_iso=until,
            limit=1000,
        )
    body = svc.encode_csv_utf8_bom(
        ["时间", "角色", "动作", "actor_user_id", "主体公司", "目标公司", "reference", "备注"],
        [
            [
                r.get("created_at"),
                r.get("actor_role"),
                r.get("action"),
                r.get("actor_user_id"),
                r.get("subject_company_id"),
                r.get("target_company_id"),
                f'{r.get("reference_type")}:{r.get("reference_id")}',
                r.get("message"),
            ]
            for r in rows
        ],
    )
    return Response(body, media_type="text/csv; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="audit.csv"'})


async def v2_student_recipe_upsert(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    product_code = str(data.get("product_code") or "")
    product_name = str(data.get("product_name") or "")
    craft = str(data.get("craft") or "")
    items = data.get("items") or []
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        company_id = await svc.get_user_company_id(s, m.id, u["id"])
        if not company_id:
            return JSONResponse({"detail": "user_not_in_company"}, status_code=400)
        try:
            r = await svc.upsert_company_recipe(s, m.id, u["id"], company_id, product_code, product_name, craft, items)
            await s.commit()
            return JSONResponse({"ok": True, **r})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_student_recipe_list(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        company_id = await svc.get_user_company_id(s, m.id, u["id"])
        if not company_id:
            return JSONResponse({"detail": "user_not_in_company"}, status_code=400)
        return JSONResponse(await svc.list_company_recipes(s, m.id, company_id))


async def v2_student_manufacture(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    product_code = str(data.get("product_code") or "")
    try:
        qty = int(data.get("qty"))
    except Exception:
        return JSONResponse({"detail": "invalid_qty"}, status_code=400)
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            r = await svc.manufacture_product(s, m.id, u["id"], product_code, qty, idem)
            await s.commit()
            return JSONResponse({"ok": True, **r})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_student_product_listings(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    status = (request.query_params.get("status") or "active").strip()
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        return JSONResponse(await svc.list_product_listings(s, m.id, status=status))


async def v2_student_product_listing_create(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    product_code = str(data.get("product_code") or "")
    try:
        unit_price_gold = int(data.get("unit_price_gold"))
    except Exception:
        return JSONResponse({"detail": "invalid_unit_price_gold"}, status_code=400)
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            pl = await svc.create_product_listing(s, m.id, u["id"], product_code, 1, unit_price_gold, idem)
            await s.commit()
            return JSONResponse({"ok": True, "id": pl.id, "status": pl.status})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_student_product_listing_cancel(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    listing_id = str(request.path_params.get("listing_id") or "")
    try:
        data = await request.json()
    except Exception:
        data = {}
    idem = str((data or {}).get("idempotency_key") or "")
    if not idem:
        idem = "cancel"
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            pl = await svc.cancel_product_listing(s, m.id, u["id"], listing_id, idem)
            await s.commit()
            return JSONResponse({"ok": True, "id": pl.id, "status": pl.status})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_student_product_listing_buy(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    listing_id = str(request.path_params.get("listing_id") or "")
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    try:
        qty = int(data.get("qty"))
    except Exception:
        return JSONResponse({"detail": "invalid_qty"}, status_code=400)
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            r = await svc.buy_product_listing(s, m.id, u["id"], listing_id, qty, idem)
            await s.commit()
            return JSONResponse({"ok": True, **r})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_student_consumer_sell(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    listing_id = str(data.get("listing_id") or "")
    try:
        qty = int(data.get("qty"))
    except Exception:
        return JSONResponse({"detail": "invalid_qty"}, status_code=400)
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            r = await svc.sell_product_to_consumers(s, m.id, u["id"], listing_id, qty, 1, idem)
            await s.commit()
            return JSONResponse({"ok": True, **r})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_admin_product_listing_rate(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    listing_id = str(request.path_params.get("listing_id") or "")
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    try:
        score = int(data.get("score"))
    except Exception:
        return JSONResponse({"detail": "invalid_score"}, status_code=400)
    comment = str(data.get("comment") or "")
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        is_admin = (u.get("role") == "system_admin") or (await svc.is_match_admin(s, m.id, u["id"]))
        if not is_admin:
            return JSONResponse({"detail": "match_admin_required"}, status_code=403)
        try:
            pl = await svc.admin_rate_product_listing(s, m.id, u["id"], listing_id, score, comment)
            await s.commit()
            return JSONResponse({"ok": True, "id": pl.id, "rating_score": pl.rating_score})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_contract_create(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    to_company_id = str(data.get("to_company_id") or "")
    title = str(data.get("title") or "")
    content = str(data.get("content") or "")
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            c = await svc.create_contract(s, m.id, u["id"], to_company_id, title, content, idem)
            await s.commit()
            return JSONResponse({"ok": True, "id": c.id, "status": c.status})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_contracts_inbox(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            rows = await svc.list_contracts_inbox(s, m.id, u["id"])
            return JSONResponse(rows)
        except ValueError as e:
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_contracts_outbox(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            rows = await svc.list_contracts_outbox(s, m.id, u["id"])
            return JSONResponse(rows)
        except ValueError as e:
            return JSONResponse({"detail": str(e)}, status_code=400)


async def v2_contract_decide(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    contract_id = str(request.path_params.get("contract_id"))
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    decision = str(data.get("decision") or "")
    idem = str(data.get("idempotency_key") or "")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        try:
            c = await svc.decide_contract(s, m.id, u["id"], contract_id, decision, idem)
            await s.commit()
            return JSONResponse({"ok": True, "id": c.id, "status": c.status})
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)

async def v2_inventory(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    mk = _match_key(request)
    async with session_scope() as s:
        m = await svc.get_match_by_key(s, mk)
        if not m:
            return JSONResponse({"detail": "match_not_found"}, status_code=404)
        cid = await svc.get_user_company_id(s, m.id, u["id"])
        if not cid:
            return JSONResponse({"detail": "user_not_in_company"}, status_code=400)
        from sqlalchemy import and_, select
        from app.models import Inventory

        r = await s.execute(
            select(Inventory).where(and_(Inventory.match_id == m.id, Inventory.company_id == cid)).order_by(Inventory.material.asc())
        )
        rows = r.scalars().all()
        raw = [{"material": x.material, "qty": float(x.qty)} for x in rows if x.material in svc.MATERIALS]
        products = [{"material": x.material, "qty": float(x.qty)} for x in rows if x.material not in svc.MATERIALS]
        return JSONResponse({"raw": raw, "products": products})



async def login(request: Request) -> JSONResponse:
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    user = USERS_BY_LOWERNAME.get(username.lower())
    if not user or password != user["password"]:
        return JSONResponse({"detail": "invalid_username_or_password"}, status_code=400)

    return JSONResponse({"access_token": token_of(user), "token_type": "bearer"})


async def me(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    return JSONResponse({"id": u["id"], "username": u["username"], "role": u["role"]})


async def student_company_create(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    name = request.query_params.get("name")
    if not name:
        try:
            body = await request.json()
            name = body.get("name")
        except Exception:
            name = None
    if not name or not str(name).strip():
        return JSONResponse({"detail": "name_required"}, status_code=400)
    try:
        c = gs.create_company(u["id"], str(name).strip())
        return JSONResponse({"company_id": c["id"], "name": c["name"]})
    except ValueError as e:
        return JSONResponse({"detail": str(e)}, status_code=400)


async def student_gold_balance(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    cid = gs.get_company_for_user(u["id"])
    if not cid:
        return JSONResponse({"detail": "user_not_in_company"}, status_code=400)
    return JSONResponse(gs.gold_snapshot(cid))


async def student_gold_ledger(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    cid = gs.get_company_for_user(u["id"])
    if not cid:
        return JSONResponse({"detail": "user_not_in_company"}, status_code=400)
    try:
        limit = int(request.query_params.get("limit") or "50")
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 200))
    return JSONResponse(gs.gold_ledger_list(cid, limit))


async def student_mine(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    try:
        r = gs.mine(u["id"], str(data.get("material")), int(data.get("qty")), str(data.get("idempotency_key")))
        return JSONResponse({"ok": True, **r})
    except (ValueError, TypeError) as e:
        return JSONResponse({"detail": str(e)}, status_code=400)


async def student_inventory(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    cid = gs.get_company_for_user(u["id"])
    if not cid:
        return JSONResponse({"detail": "user_not_in_company"}, status_code=400)
    return JSONResponse(gs.inventory_list(cid))


async def student_my_listings(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    cid = gs.get_company_for_user(u["id"])
    if not cid:
        return JSONResponse({"detail": "user_not_in_company"}, status_code=400)
    return JSONResponse(gs.my_listings(cid))


async def student_my_trades(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    cid = gs.get_company_for_user(u["id"])
    if not cid:
        return JSONResponse({"detail": "user_not_in_company"}, status_code=400)
    return JSONResponse(gs.my_trades(cid))


async def student_companies(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    return JSONResponse(gs.list_companies())


async def student_transfer_gold(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    try:
        to_company_id = str(data.get("to_company_id"))
        amount = int(data.get("amount"))
        idem = str(data.get("idempotency_key"))
    except (TypeError, ValueError):
        return JSONResponse({"detail": "invalid_params"}, status_code=400)
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    try:
        r = gs.transfer_gold(u["id"], to_company_id, amount, idem)
        return JSONResponse({"ok": True, **r})
    except (ValueError, TypeError) as e:
        return JSONResponse({"detail": str(e)}, status_code=400)


async def market_listings(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    m = request.query_params.get("material") or None
    return JSONResponse(gs.list_open_listings(m))


async def market_create_listing(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    try:
        row = gs.create_listing(
            u["id"],
            str(data.get("material")),
            int(data.get("qty")),
            int(data.get("unit_price")),
            str(data.get("idempotency_key")),
        )
        return JSONResponse(row)
    except (ValueError, TypeError) as e:
        return JSONResponse({"detail": str(e)}, status_code=400)


async def market_cancel(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    lid = request.path_params["listing_id"]
    idem = request.query_params.get("idempotency_key")
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    try:
        return JSONResponse(gs.cancel_listing(u["id"], lid, idem))
    except ValueError as e:
        return JSONResponse({"detail": str(e)}, status_code=400)


async def market_buy(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u:
        return JSONResponse({"detail": "invalid_token"}, status_code=401)
    lid = request.path_params["listing_id"]
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    try:
        t = gs.buy_listing(u["id"], lid, int(data.get("qty")), str(data.get("idempotency_key")))
        return JSONResponse(t)
    except (ValueError, TypeError) as e:
        return JSONResponse({"detail": str(e)}, status_code=400)


async def admin_create_company(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u or u.get("role") != "admin":
        return JSONResponse({"detail": "admin_required"}, status_code=403)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid_json"}, status_code=400)
    name = (data.get("name") or "").strip()
    if len(name) < 2:
        return JSONResponse({"detail": "name_too_short"}, status_code=400)
    cid = str(uuid.uuid4())
    gs.companies[cid] = {"id": cid, "name": name, "created_by_user_id": u["id"]}
    gs._ensure_company_assets(cid)
    return JSONResponse({"id": cid, "name": name})


async def admin_grant_gold(request: Request) -> JSONResponse:
    u = auth_user(request)
    if not u or u.get("role") != "admin":
        return JSONResponse({"detail": "admin_required"}, status_code=403)
    cid = request.path_params["company_id"]
    try:
        amount = int(request.query_params.get("amount"))
        idem = str(request.query_params.get("idempotency_key"))
    except (TypeError, ValueError):
        return JSONResponse({"detail": "invalid_params"}, status_code=400)
    if not idem:
        return JSONResponse({"detail": "idempotency_key_required"}, status_code=400)
    try:
        gs.grant_gold(cid, amount, idem, u["id"])
        return JSONResponse({"ok": True})
    except ValueError as e:
        return JSONResponse({"detail": str(e)}, status_code=400)


app = Starlette(
    debug=True,
    routes=[
        Route("/health", health, methods=["GET"]),
        # v2 auth (PostgreSQL)
        Route("/v2/auth/register", v2_register, methods=["POST"]),
        Route("/v2/auth/login", v2_login, methods=["POST"]),
        Route("/v2/craft-types", v2_craft_types, methods=["GET"]),
        Route("/v2/system/bootstrap-admin", v2_system_admin_bootstrap, methods=["POST"]),
        Route("/v2/matches", v2_match_create, methods=["POST"]),
        # v2 match-scoped
        Route("/m/{match_key:str}/student/me", v2_me, methods=["GET"]),
        Route("/m/{match_key:str}/student/companies", v2_companies, methods=["GET"]),
        Route("/m/{match_key:str}/student/company/join", v2_join_company, methods=["POST"]),
        Route("/m/{match_key:str}/student/gold/balance", v2_gold_balance, methods=["GET"]),
        Route("/m/{match_key:str}/student/carbon/balance", v2_carbon_balance, methods=["GET"]),
        Route("/m/{match_key:str}/student/ledger", v2_ledger, methods=["GET"]),
        Route("/m/{match_key:str}/student/inventory", v2_inventory, methods=["GET"]),
        Route("/m/{match_key:str}/student/gold/transfer", v2_gold_transfer, methods=["POST"]),
        Route("/m/{match_key:str}/student/carbon/transfer", v2_carbon_transfer, methods=["POST"]),
        Route("/m/{match_key:str}/student/facilities", v2_student_facilities, methods=["GET"]),
        Route("/m/{match_key:str}/student/facility-types", v2_student_facility_types, methods=["GET"]),
        Route("/m/{match_key:str}/student/facilities/buy", v2_student_buy_facility, methods=["POST"]),
        Route("/m/{match_key:str}/student/mine", v2_student_mine, methods=["POST"]),
        Route("/m/{match_key:str}/trade/request", v2_trade_request_create, methods=["POST"]),
        Route("/m/{match_key:str}/trade/requests/outbox", v2_trade_requests_outbox, methods=["GET"]),
        Route("/m/{match_key:str}/trade/requests/inbox", v2_trade_requests_inbox, methods=["GET"]),
        Route("/m/{match_key:str}/trade/request/{trade_request_id:str}/decide", v2_trade_request_decide, methods=["POST"]),
        Route("/m/{match_key:str}/contract", v2_contract_create, methods=["POST"]),
        Route("/m/{match_key:str}/contracts/outbox", v2_contracts_outbox, methods=["GET"]),
        Route("/m/{match_key:str}/contracts/inbox", v2_contracts_inbox, methods=["GET"]),
        Route("/m/{match_key:str}/contract/{contract_id:str}/decide", v2_contract_decide, methods=["POST"]),
        Route("/m/{match_key:str}/admin/companies", v2_admin_import_company, methods=["POST"]),
        Route("/m/{match_key:str}/admin/companies/{company_id:str}/grant-gold", v2_admin_grant_gold, methods=["POST"]),
        Route("/m/{match_key:str}/admin/companies/{company_id:str}/grant-carbon", v2_admin_grant_carbon, methods=["POST"]),
        Route("/m/{match_key:str}/admin/companies/{company_id:str}/grant-material", v2_admin_grant_material, methods=["POST"]),
        Route("/m/{match_key:str}/admin/settings", v2_admin_match_settings_get, methods=["GET"]),
        Route("/m/{match_key:str}/admin/settings", v2_admin_match_settings_update, methods=["POST"]),
        Route("/m/{match_key:str}/admin/issue-initial", v2_admin_issue_initial, methods=["POST"]),
        Route("/m/{match_key:str}/admin/export/balance-sheet.csv", v2_admin_export_balance_sheet, methods=["GET"]),
        Route("/m/{match_key:str}/admin/ledger", v2_admin_ledger_query, methods=["GET"]),
        Route("/m/{match_key:str}/admin/audit", v2_admin_audit_query, methods=["GET"]),
        Route("/m/{match_key:str}/admin/export/ledger.csv", v2_admin_ledger_export_csv, methods=["GET"]),
        Route("/m/{match_key:str}/admin/export/audit.csv", v2_admin_audit_export_csv, methods=["GET"]),
        Route("/m/{match_key:str}/admin/facilities/companies", v2_admin_company_facilities, methods=["GET"]),
        Route("/m/{match_key:str}/admin/rush/orders", v2_admin_rush_orders, methods=["GET"]),
        Route("/m/{match_key:str}/admin/rush/order", v2_admin_rush_order_publish, methods=["POST"]),
        Route("/m/{match_key:str}/admin/rush/order/{rush_order_id:str}/settle", v2_admin_rush_order_settle, methods=["POST"]),
        Route("/m/{match_key:str}/student/recipes", v2_student_recipe_list, methods=["GET"]),
        Route("/m/{match_key:str}/student/recipe", v2_student_recipe_upsert, methods=["POST"]),
        Route("/m/{match_key:str}/student/manufacture", v2_student_manufacture, methods=["POST"]),
        Route("/m/{match_key:str}/student/product/listings", v2_student_product_listings, methods=["GET"]),
        Route("/m/{match_key:str}/student/product/listing", v2_student_product_listing_create, methods=["POST"]),
        Route("/m/{match_key:str}/student/product/listing/{listing_id:str}/cancel", v2_student_product_listing_cancel, methods=["POST"]),
        Route("/m/{match_key:str}/student/product/listing/{listing_id:str}/buy", v2_student_product_listing_buy, methods=["POST"]),
        Route("/m/{match_key:str}/student/product/consumer-sell", v2_student_consumer_sell, methods=["POST"]),
        Route("/m/{match_key:str}/admin/product/listing/{listing_id:str}/rate", v2_admin_product_listing_rate, methods=["POST"]),
        Route("/m/{match_key:str}/student/rush/orders", v2_student_rush_orders, methods=["GET"]),
        Route("/m/{match_key:str}/student/rush/order/{rush_order_id:str}/submit", v2_student_rush_order_submit, methods=["POST"]),
        # legacy routes (in-memory MVP) kept for now
        Route("/auth/login", login, methods=["POST"]),
        Route("/student/me", me, methods=["GET"]),
        Route("/student/company/create", student_company_create, methods=["POST"]),
        Route("/student/gold/balance", student_gold_balance, methods=["GET"]),
        Route("/student/gold/ledger", student_gold_ledger, methods=["GET"]),
        Route("/student/mine", student_mine, methods=["POST"]),
        Route("/student/inventory", student_inventory, methods=["GET"]),
        Route("/student/my/listings", student_my_listings, methods=["GET"]),
        Route("/student/my/trades", student_my_trades, methods=["GET"]),
        Route("/student/companies", student_companies, methods=["GET"]),
        Route("/student/gold/transfer", student_transfer_gold, methods=["POST"]),
        Route("/market/listings", market_listings, methods=["GET"]),
        Route("/market/listings", market_create_listing, methods=["POST"]),
        Route("/market/listings/{listing_id}/cancel", market_cancel, methods=["POST"]),
        Route("/market/listings/{listing_id}/buy", market_buy, methods=["POST"]),
        Route("/admin/companies", admin_create_company, methods=["POST"]),
        Route("/admin/companies/{company_id}/grant-gold", admin_grant_gold, methods=["POST"]),
    ],
)


@app.on_event("startup")
async def _startup() -> None:
    import asyncio
    import logging

    try:
        await asyncio.wait_for(maybe_create_tables(), timeout=5)
    except Exception as e:
        logging.getLogger("uvicorn.error").warning("DB init skipped (db unreachable?): %s", e)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_headers=["*"],
    allow_methods=["*"],
    allow_credentials=True,
)
