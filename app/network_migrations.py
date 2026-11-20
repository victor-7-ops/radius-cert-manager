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
#
# This list is a one-time seed, not a hardcoded ceiling: the real admin UI
# (/subsidiaries, app/routes/web_subsidiaries.py) can create, rename, and
# delete subsidiaries freely now — delete the ones you don't need rather
# than removing them from here, which would also strip dozens of other
# tests' fixture data that assumes these rows exist.
INITIAL_SUBSIDIARIES: list[dict[str, str]] = [
    {"code": "lezzgo_boracay", "display_name": "Lezzgo Boracay"},
    {"code": "lezzgo_cebu", "display_name": "Lezzgo Cebu"},
    {"code": "topline", "display_name": "Topline (Main Office)"},
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

# Real department/role structure for Topline's own corporate rollout
# (HANDOFF-SESSION-2026-11-19.md Task C, approved 20 Nov 2026). Only
# "topline" has real org-chart departments today -- the other subsidiary
# codes in INITIAL_SUBSIDIARIES are placeholder tenants with no live
# structure of their own yet, so this seed is deliberately scoped to
# "topline" rather than applied generically to every subsidiary.
#
# "IT" uses the department code "topline_it_dept", not "it" -- the live
# DB already has a placeholder department with code "it" and 9 certs/8
# devices attached, which stays untouched (handoff task K, 20 Nov 2026).
# All codes here carry a "topline_" prefix to stay out of the generic
# short-code namespace ("hr", "finance", "acct"...) that ad-hoc test
# fixtures elsewhere in this suite use for the same "topline" subsidiary.
# The fallback VLAN (99) and these roles' real VLANs are configured per
# site via SiteRoleBinding at switch cutover, not here -- both sites are
# authenticate-only today and seeding a binding now would be premature.
TOPLINE_SUBSIDIARY_CODE = "topline"

TOPLINE_DEPARTMENTS: list[dict[str, str]] = [
    {"code": "topline_admin", "display_name": "Admin"},
    {"code": "topline_head", "display_name": "Head"},
    {"code": "topline_properties", "display_name": "Properties"},
    {"code": "topline_hr", "display_name": "HR"},
    {"code": "topline_cft", "display_name": "CFT"},
    {"code": "topline_accounting", "display_name": "Accounting"},
    {"code": "topline_treasury", "display_name": "Treasury"},
    {"code": "topline_marketing", "display_name": "Marketing"},
    {"code": "topline_it_dept", "display_name": "IT"},
    {"code": "topline_consultant", "display_name": "Consultant"},
]

TOPLINE_NETWORK_ROLES: list[dict[str, str]] = [
    {"code": "topline_standard", "display_name": "Standard"},
    {"code": "topline_finance", "display_name": "Finance"},
    {"code": "topline_marketing_role", "display_name": "Marketing"},
    {"code": "topline_it_role", "display_name": "IT"},
    {"code": "topline_external", "display_name": "External"},
]

# department code -> role code
TOPLINE_DEPARTMENT_ROLE_MAP: dict[str, str] = {
    "topline_admin": "topline_standard",
    "topline_head": "topline_standard",
    "topline_properties": "topline_standard",
    "topline_hr": "topline_standard",
    "topline_cft": "topline_standard",
    "topline_accounting": "topline_finance",
    "topline_treasury": "topline_finance",
    "topline_marketing": "topline_marketing_role",
    "topline_it_dept": "topline_it_role",
    "topline_consultant": "topline_external",
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


def seed_topline_network_roles(engine) -> dict[str, list[str]]:
    """Idempotently seeds Topline's real departments/roles (handoff task K,
    20 Nov 2026). Only touches the "topline" subsidiary; does nothing if
    that subsidiary doesn't exist (e.g. a throwaway test DB)."""
    inserted = {"departments": [], "network_roles": [], "department_roles": []}
    with Session(engine) as session:
        sub = session.scalar(
            select(db.Subsidiary).where(db.Subsidiary.code == TOPLINE_SUBSIDIARY_CODE)
        )
        if not sub:
            return inserted

        existing_dept_codes = set(
            session.scalars(
                select(db.Department.code).where(db.Department.subsidiary_id == sub.id)
            ).all()
        )
        dept_by_code: dict[str, db.Department] = {
            d.code: d
            for d in session.scalars(
                select(db.Department).where(db.Department.subsidiary_id == sub.id)
            ).all()
        }
        for item in TOPLINE_DEPARTMENTS:
            if item["code"] not in existing_dept_codes:
                dept = db.Department(
                    subsidiary_id=sub.id, code=item["code"], display_name=item["display_name"],
                )
                session.add(dept)
                session.flush()
                dept_by_code[item["code"]] = dept
                inserted["departments"].append(item["code"])

        existing_role_codes = set(
            session.scalars(
                select(db.NetworkRole.code).where(db.NetworkRole.subsidiary_id == sub.id)
            ).all()
        )
        role_by_code: dict[str, db.NetworkRole] = {
            r.code: r
            for r in session.scalars(
                select(db.NetworkRole).where(db.NetworkRole.subsidiary_id == sub.id)
            ).all()
        }
        for item in TOPLINE_NETWORK_ROLES:
            if item["code"] not in existing_role_codes:
                role = db.NetworkRole(
                    subsidiary_id=sub.id, code=item["code"], display_name=item["display_name"],
                )
                session.add(role)
                session.flush()
                role_by_code[item["code"]] = role
                inserted["network_roles"].append(item["code"])

        existing_links = {
            (link.department_id, link.network_role_id)
            for link in session.scalars(
                select(db.DepartmentRole).where(
                    db.DepartmentRole.department_id.in_(d.id for d in dept_by_code.values())
                )
            ).all()
        }
        for dept_code, role_code in TOPLINE_DEPARTMENT_ROLE_MAP.items():
            dept = dept_by_code[dept_code]
            role = role_by_code[role_code]
            if (dept.id, role.id) not in existing_links:
                session.add(db.DepartmentRole(department_id=dept.id, network_role_id=role.id))
                inserted["department_roles"].append(f"{dept_code}->{role_code}")

        if any(inserted.values()):
            session.commit()
            logger.info("Seeded Topline network roles: %s", inserted)
    return inserted


def run_network_migrations(engine) -> None:
    """Runs all schema updates, additive column migrations, and baseline data seeding."""
    # Ensure all new and existing tables are created
    db.Base.metadata.create_all(engine)
    
    # Ensure additive certificate columns exist on existing databases
    db._migrate_columns(engine, "certificates", _NETWORK_CERTIFICATE_MIGRATIONS)
    
    # One-time seed, not idempotent-by-code: seed_baseline_subsidiaries on
    # its own re-inserts any code missing from the table, which includes
    # one an admin deliberately deleted through the real UI
    # (app/routes/web_subsidiaries.py) -- every app restart (every
    # deploy) was silently resurrecting it. db.run_once gates this to the
    # very first boot ever, recorded in the migration_flags table, so a
    # real delete stays deleted.
    db.run_once(engine, "baseline_subsidiaries_seed", lambda: seed_baseline_subsidiaries(engine))

    # Same gating as above: an admin deleting one of these through the
    # real UI must stay deleted, not get resurrected on the next boot.
    db.run_once(engine, "topline_network_roles_seed", lambda: seed_topline_network_roles(engine))
