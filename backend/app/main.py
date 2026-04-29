from datetime import datetime, timedelta, timezone
import uuid

from jose import JWTError, jwt
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
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
        qty = int(data.get("qty"))
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
                    "qty": tr.qty,
                    "unit_price_gold": tr.unit_price_gold,
                    "status": tr.status,
                }
            )
        except ValueError as e:
            await s.rollback()
            return JSONResponse({"detail": str(e)}, status_code=400)


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
        # v2 match-scoped
        Route("/m/{match_key:str}/student/me", v2_me, methods=["GET"]),
        Route("/m/{match_key:str}/student/companies", v2_companies, methods=["GET"]),
        Route("/m/{match_key:str}/student/company/join", v2_join_company, methods=["POST"]),
        Route("/m/{match_key:str}/student/gold/balance", v2_gold_balance, methods=["GET"]),
        Route("/m/{match_key:str}/student/gold/transfer", v2_gold_transfer, methods=["POST"]),
        Route("/m/{match_key:str}/trade/request", v2_trade_request_create, methods=["POST"]),
        Route("/m/{match_key:str}/trade/request/{trade_request_id:str}/decide", v2_trade_request_decide, methods=["POST"]),
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
