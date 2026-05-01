from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Numeric, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class Match(Base):
    __tablename__ = "matches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class MatchSetting(Base):
    __tablename__ = "match_settings"
    __table_args__ = (UniqueConstraint("match_id", name="uq_match_setting_match"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    initial_gold: Mapped[int] = mapped_column(Integer, default=0)
    initial_carbon: Mapped[int] = mapped_column(Integer, default=0)
    # material base price for valuation/export; keys R1/R2/R3...
    material_r1_price: Mapped[int] = mapped_column(Integer, default=10)
    material_r2_price: Mapped[int] = mapped_column(Integer, default=20)
    material_r3_price: Mapped[int] = mapped_column(Integer, default=30)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    match: Mapped[Match] = relationship(Match)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SystemAdmin(Base):
    __tablename__ = "system_admins"

    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    user: Mapped[User] = relationship(User)


class MatchAdmin(Base):
    __tablename__ = "match_admins"

    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    match: Mapped[Match] = relationship(Match)
    user: Mapped[User] = relationship(User)


class Company(Base):
    __tablename__ = "companies"
    __table_args__ = (UniqueConstraint("match_id", "name", name="uq_company_match_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    join_password_hash: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # 总资产导出用；后续可由管理员录入或从合同/报表同步
    equity_value: Mapped[int] = mapped_column(Integer, default=0)
    liability_value: Mapped[int] = mapped_column(Integer, default=0)

    match: Mapped[Match] = relationship(Match)


class CompanyMember(Base):
    __tablename__ = "company_members"
    __table_args__ = (UniqueConstraint("match_id", "user_id", name="uq_member_match_user"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    company_id: Mapped[str] = mapped_column(String(36), ForeignKey("companies.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    company: Mapped[Company] = relationship(Company)
    user: Mapped[User] = relationship(User)


class CompanyAsset(Base):
    __tablename__ = "company_assets"
    __table_args__ = (UniqueConstraint("match_id", "company_id", name="uq_asset_match_company"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    company_id: Mapped[str] = mapped_column(String(36), ForeignKey("companies.id", ondelete="CASCADE"), index=True)
    gold_balance: Mapped[int] = mapped_column(Integer, default=0)
    carbon_balance: Mapped[int] = mapped_column(Integer, default=0)

    company: Mapped[Company] = relationship(Company)


class Inventory(Base):
    __tablename__ = "inventories"
    __table_args__ = (UniqueConstraint("match_id", "company_id", "material", name="uq_inv_match_company_material"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    company_id: Mapped[str] = mapped_column(String(36), ForeignKey("companies.id", ondelete="CASCADE"), index=True)
    material: Mapped[str] = mapped_column(String(16))
    qty: Mapped[float] = mapped_column(Numeric(12, 2, asdecimal=True), default=0)


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"
    __table_args__ = (UniqueConstraint("match_id", "company_id", "idempotency_key", name="uq_ledger_idem"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    company_id: Mapped[str] = mapped_column(String(36), ForeignKey("companies.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(64))  # transfer_out, transfer_in, trade_out, trade_in ...
    gold_delta: Mapped[int] = mapped_column(Integer, default=0)
    carbon_delta: Mapped[int] = mapped_column(Integer, default=0)
    material: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    material_delta: Mapped[Optional[float]] = mapped_column(Numeric(12, 2, asdecimal=True), nullable=True)
    counterparty_company_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    reference_type: Mapped[str] = mapped_column(String(64))
    reference_id: Mapped[str] = mapped_column(String(36))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor_user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    actor_user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    actor_role: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(64))
    subject_company_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    target_company_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    reference_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    reference_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    message: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class TradeRequest(Base):
    __tablename__ = "trade_requests"
    __table_args__ = (UniqueConstraint("match_id", "idempotency_key", name="uq_trade_idem"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    from_company_id: Mapped[str] = mapped_column(String(36), ForeignKey("companies.id", ondelete="CASCADE"), index=True)
    to_company_id: Mapped[str] = mapped_column(String(36), ForeignKey("companies.id", ondelete="CASCADE"), index=True)
    material: Mapped[str] = mapped_column(String(16))
    qty: Mapped[float] = mapped_column(Numeric(12, 2, asdecimal=True))
    unit_price_gold: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))  # pending/accepted/rejected/settled
    idempotency_key: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by_user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    settled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class FacilityType(Base):
    __tablename__ = "facility_types"
    __table_args__ = (UniqueConstraint("match_id", "code", name="uq_facility_match_code"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    code: Mapped[str] = mapped_column(String(64))  # e.g. mine_r1
    name: Mapped[str] = mapped_column(String(128))
    material: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)  # for mines
    gold_cost: Mapped[int] = mapped_column(Integer, default=0)
    carbon_cost: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CompanyFacility(Base):
    __tablename__ = "company_facilities"
    __table_args__ = (UniqueConstraint("match_id", "company_id", "facility_type_id", name="uq_company_facility"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    company_id: Mapped[str] = mapped_column(String(36), ForeignKey("companies.id", ondelete="CASCADE"), index=True)
    facility_type_id: Mapped[str] = mapped_column(String(36), ForeignKey("facility_types.id", ondelete="CASCADE"), index=True)
    qty: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Contract(Base):
    __tablename__ = "contracts"
    __table_args__ = (UniqueConstraint("match_id", "idempotency_key", name="uq_contract_idem"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    from_company_id: Mapped[str] = mapped_column(String(36), ForeignKey("companies.id", ondelete="CASCADE"), index=True)
    to_company_id: Mapped[str] = mapped_column(String(36), ForeignKey("companies.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(128))
    content: Mapped[str] = mapped_column(String(2000))
    status: Mapped[str] = mapped_column(String(16))  # pending/accepted/rejected
    idempotency_key: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by_user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)


class Product(Base):
    __tablename__ = "products"
    __table_args__ = (UniqueConstraint("match_id", "code", name="uq_product_match_code"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    code: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Recipe(Base):
    __tablename__ = "recipes"
    __table_args__ = (UniqueConstraint("match_id", "company_id", "product_id", name="uq_recipe_match_company_product"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    company_id: Mapped[str] = mapped_column(String(36), ForeignKey("companies.id", ondelete="CASCADE"), index=True)
    product_id: Mapped[str] = mapped_column(String(36), ForeignKey("products.id", ondelete="CASCADE"), index=True)
    craft: Mapped[str] = mapped_column(String(512))  # 工艺/流程（先用文本，后续可结构化）
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RecipeItem(Base):
    __tablename__ = "recipe_items"
    __table_args__ = (UniqueConstraint("recipe_id", "material", name="uq_recipe_item_material"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    recipe_id: Mapped[str] = mapped_column(String(36), ForeignKey("recipes.id", ondelete="CASCADE"), index=True)
    material: Mapped[str] = mapped_column(String(64))  # 原料 code（可扩展）
    qty: Mapped[float] = mapped_column(Numeric(12, 2, asdecimal=True))


class ProductListing(Base):
    __tablename__ = "product_listings"
    __table_args__ = (UniqueConstraint("match_id", "idempotency_key", name="uq_product_listing_idem"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    seller_company_id: Mapped[str] = mapped_column(String(36), ForeignKey("companies.id", ondelete="CASCADE"), index=True)
    product_code: Mapped[str] = mapped_column(String(16))
    qty: Mapped[int] = mapped_column(Integer)
    unit_price_gold: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))  # active/sold_out/cancelled
    idempotency_key: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    rating_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rating_comment: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    rated_by_user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    rated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class RushOrder(Base):
    __tablename__ = "rush_orders"
    __table_args__ = (UniqueConstraint("match_id", "idempotency_key", name="uq_rush_order_idem"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    created_by_user_id: Mapped[str] = mapped_column(String(36))
    product_code: Mapped[str] = mapped_column(String(16))
    craft_code: Mapped[str] = mapped_column(String(64))
    recipe_items_json: Mapped[str] = mapped_column(String(2000))  # 结构化原料清单（json string）
    recipe_hash: Mapped[str] = mapped_column(String(64))
    recipe_text: Mapped[str] = mapped_column(String(512))  # 说明（可选，展示用）
    demand_qty: Mapped[int] = mapped_column(Integer)
    unit_price_gold: Mapped[int] = mapped_column(Integer)
    settlement_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16))  # open/settled/cancelled
    idempotency_key: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    settled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class RushOrderSubmission(Base):
    __tablename__ = "rush_order_submissions"
    __table_args__ = (
        UniqueConstraint("match_id", "rush_order_id", "company_id", "idempotency_key", name="uq_rush_submit_idem"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    match_id: Mapped[str] = mapped_column(String(36), ForeignKey("matches.id", ondelete="CASCADE"), index=True)
    rush_order_id: Mapped[str] = mapped_column(String(36), ForeignKey("rush_orders.id", ondelete="CASCADE"), index=True)
    company_id: Mapped[str] = mapped_column(String(36), ForeignKey("companies.id", ondelete="CASCADE"), index=True)
    product_code: Mapped[str] = mapped_column(String(16))
    recipe_hash: Mapped[str] = mapped_column(String(64))
    qty_submitted: Mapped[int] = mapped_column(Integer)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16))  # submitted/accepted/rejected
    qty_accepted: Mapped[int] = mapped_column(Integer, default=0)
    settled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
