"""Network role, subsidiary registry, and employee/device inventory migrations.

Implements B01, B08, and B09 schema migration logic, baseline subsidiary seeding,
and legacy alias resolution.
"""

from __future__ import annotations

import logging
import uuid
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import db

logger = logging.getLogger(__name__)

# Canonical baseline subsidiaries derived from verified specifications (HANDBOOK.md §2).
# 'Others' is intentionally excluded as an authorized tenant (HANDBOOK.md §2).
INITIAL_SUBSIDIARIES: list[dict[str, str]] = [
    {"code": "lezzgo_boracay", "display_name": "Lezzgo Boracay"},
    {"code": "lezzgo_cebu", "display_name": "Lezzgo Cebu"},
    {"code": "topline", "display_name": "Topline Business Development Corporation"},
    {"code": "light_fuels", "display_name": "Light Fuels Corporation"},
    {"code": "commercial_fuel_trade", "display_name": "Commercial Fuel Trade"},
    {"code": "bay_mall", "display_name": "Bay Mall"},
    {"code": "bmead", "display_name": "BMEAD"},
]

# Explicit legacy aliases mapping to canonical codes. Unknown or ambiguous values return None.
LEGACY_SUBSIDIARY_ALIASES: dict[str, str] = {
    "lezzgo boracay": "lezzgo_boracay",
    "lezzgo-boracay": "lezzgo_boracay",
    "lezzgo_boracay": "lezzgo_boracay",
    "lezzgo cebu": "lezzgo_cebu",
    "lezzgo-cebu": "lezzgo_cebu",
    "lezzgo_cebu": "lezzgo_cebu",
    "topline business development corporation": "topline",
    "topline": "topline",
    "topline business": "topline",
    "light fuels corporation": "light_fuels",
    "light fuels": "light_fuels",
    "light-fuels": "light_fuels",
    "light_fuels": "light_fuels",
    "commercial fuel trade": "commercial_fuel_trade",
    "commercial-fuel-trade": "commercial_fuel_trade",
    "commercial_fuel_trade": "commercial_fuel_trade",
    "cft": "commercial_fuel_trade",
    "bay mall": "bay_mall",
    "bay-mall": "bay_mall",
    "bay_mall": "bay_mall",
    "bmead": "bmead",
}

_NETWORK_CERTIFICATE_MIGRATIONS = [
    ("subsidiary_id", "VARCHAR"),
    ("department_id", "VARCHAR"),
    ("network_role_id", "VARCHAR"),
    ("employee_id", "VARCHAR"),
    ("device_id", "VARCHAR"),
    ("identity_schema_version", "INTEGER DEFAULT 1"),
    ("issuance_policy_snapshot", "TEXT"),
    ("request_fingerprint", "VARCHAR"),
]


def get_deterministic_subsidiary_id(code: str) -> str:
    """Generate a stable UUID5 for initial seed records to ensure environment reproducibility."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"subsidiary.radius.{code}"))


def resolve_subsidiary_alias(raw: str | None) -> str | None:
    """Resolves a legacy free-text subsidiary string to its canonical code.
    
    Returns None if unknown, blank, or 'Others' (which requires operator review).
    """
    if not raw:
        return None
    cleaned = raw.strip().lower()
    return LEGACY_SUBSIDIARY_ALIASES.get(cleaned)


def seed_baseline_subsidiaries(engine) -> list[str]:
    """Idempotently seeds baseline subsidiaries into the database."""
    inserted = []
    with Session(engine) as session:
        existing_codes = set(
            session.scalars(select(db.Subsidiary.code)).all()
        )
        for item in INITIAL_SUBSIDIARIES:
            code = item["code"]
            if code not in existing_codes:
                sub_id = get_deterministic_subsidiary_id(code)
                sub = db.Subsidiary(
                    id=sub_id,
                    code=code,
                    display_name=item["display_name"],
                    is_active=True,
                )
                session.add(sub)
                inserted.append(code)
        if inserted:
            session.commit()
            logger.info("Seeded %d baseline subsidiaries: %s", len(inserted), inserted)
    return inserted


def run_network_migrations(engine) -> None:
    """Runs all schema updates, additive column migrations, and baseline data seeding."""
    # Ensure all new and existing tables are created
    db.Base.metadata.create_all(engine)
    
    # Ensure additive certificate columns exist on existing databases
    db._migrate_columns(engine, "certificates", _NETWORK_CERTIFICATE_MIGRATIONS)
    
    # Seed baseline subsidiaries idempotently
    seed_baseline_subsidiaries(engine)
