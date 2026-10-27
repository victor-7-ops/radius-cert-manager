"""Tests for B01/B08/B09 network migrations, schema constraints, and alias resolution.

Verifies:
- Migration runs twice idempotently
- Legacy alias mapping
- Baseline subsidiary seeding
- Uniqueness and foreign key enforcement
- Cross-tenant isolation
"""

import pytest
import sqlite3
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import db
from app.network_migrations import (
    INITIAL_SUBSIDIARIES,
    LEGACY_SUBSIDIARY_ALIASES,
    get_deterministic_subsidiary_id,
    resolve_subsidiary_alias,
    run_network_migrations,
    seed_baseline_subsidiaries,
)


def test_baseline_subsidiaries_seeded_idempotently(tmp_path):
    db_file = tmp_path / "test_net.db"
    engine = db.make_engine(str(db_file))

    # Run first time
    db.init_db(engine)

    with Session(engine) as session:
        subs = session.scalars(select(db.Subsidiary)).all()
        assert len(subs) == len(INITIAL_SUBSIDIARIES)
        codes = {s.code for s in subs}
        expected_codes = {s["code"] for s in INITIAL_SUBSIDIARIES}
        assert codes == expected_codes
        # "Others" is not a seeded tenant
        assert "others" not in codes
        assert "Others" not in codes

        # Verify deterministic IDs
        for sub in subs:
            assert sub.id == get_deterministic_subsidiary_id(sub.code)
            assert sub.is_active is True

    # Run second time - should be completely idempotent
    db.init_db(engine)

    with Session(engine) as session:
        subs_after = session.scalars(select(db.Subsidiary)).all()
        assert len(subs_after) == len(INITIAL_SUBSIDIARIES)


def test_legacy_subsidiary_alias_resolution():
    assert resolve_subsidiary_alias("Topline Business Development Corporation") == "topline"
    assert resolve_subsidiary_alias("topline") == "topline"
    assert resolve_subsidiary_alias("Lezzgo Boracay") == "lezzgo_boracay"
    assert resolve_subsidiary_alias("lezzgo-cebu") == "lezzgo_cebu"
    assert resolve_subsidiary_alias("commercial fuel trade") == "commercial_fuel_trade"
    assert resolve_subsidiary_alias("CFT") == "commercial_fuel_trade"
    assert resolve_subsidiary_alias("Light Fuels Corporation") == "light_fuels"
    assert resolve_subsidiary_alias("Bay Mall") == "bay_mall"
    assert resolve_subsidiary_alias("BMEAD") == "bmead"

    # Unresolved / Unknown / Blanks
    assert resolve_subsidiary_alias(None) is None
    assert resolve_subsidiary_alias("") is None
    assert resolve_subsidiary_alias("   ") is None
    assert resolve_subsidiary_alias("Others") is None
    assert resolve_subsidiary_alias("Unknown Company Inc") is None


def test_department_and_role_constraints(tmp_path):
    db_file = tmp_path / "test_dept_role.db"
    engine = db.make_engine(str(db_file))
    db.init_db(engine)

    with Session(engine) as session:
        sub_a = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        sub_b = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "lezzgo_cebu"))
        assert sub_a is not None and sub_b is not None

        # Department creation
        dept_a = db.Department(subsidiary_id=sub_a.id, code="acct", display_name="Accounting")
        session.add(dept_a)
        session.commit()

        # Same department code in another subsidiary is allowed
        dept_b = db.Department(subsidiary_id=sub_b.id, code="acct", display_name="Accounting")
        session.add(dept_b)
        session.commit()

        # Duplicate department code in same subsidiary violates uniqueness
        dept_dup = db.Department(subsidiary_id=sub_a.id, code="acct", display_name="Accounting Duplicate")
        session.add(dept_dup)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        # Foreign key violation for non-existent subsidiary
        dept_bad_fk = db.Department(subsidiary_id="non-existent-sub", code="it", display_name="IT")
        session.add(dept_bad_fk)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_network_role_constraints(tmp_path):
    db_file = tmp_path / "test_roles.db"
    engine = db.make_engine(str(db_file))
    db.init_db(engine)

    with Session(engine) as session:
        sub_a = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        sub_b = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "lezzgo_boracay"))

        role_a = db.NetworkRole(
            subsidiary_id=sub_a.id,
            code="finance",
            display_name="Finance Access",
            is_active=True,
            is_privileged=False,
        )
        session.add(role_a)
        session.commit()

        # Same role code in another subsidiary is allowed
        role_b = db.NetworkRole(
            subsidiary_id=sub_b.id,
            code="finance",
            display_name="Finance Access",
            is_active=True,
            is_privileged=False,
        )
        session.add(role_b)
        session.commit()

        # Duplicate role code in same subsidiary violates uniqueness
        role_dup = db.NetworkRole(
            subsidiary_id=sub_a.id,
            code="finance",
            display_name="Duplicate Finance",
        )
        session.add(role_dup)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_site_role_binding_constraints(tmp_path):
    db_file = tmp_path / "test_bindings.db"
    engine = db.make_engine(str(db_file))
    db.init_db(engine)

    with Session(engine) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        role = db.NetworkRole(subsidiary_id=sub.id, code="eng", display_name="Engineering")
        session.add(role)
        session.flush()

        site = db.Site(
            name="HQ",
            radius_cn="radius-hq.internal",
            auth_token_hash="dummyhash",
        )
        session.add(site)
        session.flush()

        binding = db.SiteRoleBinding(
            site_id=site.id,
            subsidiary_id=sub.id,
            network_role_id=role.id,
            vlan_id=30,
            fallback_vlan_id=99,
            platform_enabled=True,
            tenant_enabled=True,
        )
        session.add(binding)
        session.commit()

        # Duplicate binding tuple violates uniqueness
        dup_binding = db.SiteRoleBinding(
            site_id=site.id,
            subsidiary_id=sub.id,
            network_role_id=role.id,
            vlan_id=31,
            fallback_vlan_id=99,
        )
        session.add(dup_binding)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_employee_and_device_inventory_models(tmp_path):
    db_file = tmp_path / "test_emp_dev.db"
    engine = db.make_engine(str(db_file))
    db.init_db(engine)

    with Session(engine) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        dept = db.Department(subsidiary_id=sub.id, code="eng", display_name="Engineering")
        role = db.NetworkRole(subsidiary_id=sub.id, code="dev", display_name="Developer Access")
        session.add_all([dept, role])
        session.flush()

        emp1 = db.Employee(
            subsidiary_id=sub.id,
            employee_number="EMP-001",
            display_name="Alice Smith",
            department_id=dept.id,
            status="active",
        )
        session.add(emp1)
        session.commit()

        # Duplicate employee_number in same subsidiary
        emp_dup = db.Employee(
            subsidiary_id=sub.id,
            employee_number="EMP-001",
            display_name="Alice Duplicate",
            department_id=dept.id,
        )
        session.add(emp_dup)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        # Add two devices to employee
        dev1 = db.Device(
            subsidiary_id=sub.id,
            employee_id=emp1.id,
            display_name="Alice Laptop",
            device_type="Laptop",
            department_id=dept.id,
            network_role_id=role.id,
            status="active",
        )
        dev2 = db.Device(
            subsidiary_id=sub.id,
            employee_id=emp1.id,
            display_name="Alice Phone",
            device_type="Phone",
            department_id=dept.id,
            network_role_id=role.id,
            status="active",
        )
        session.add_all([dev1, dev2])
        session.commit()

        # Verify device relationship
        reloaded_emp = session.get(db.Employee, emp1.id)
        assert len(reloaded_emp.devices) == 2


def test_certificate_additive_columns_on_legacy_db(tmp_path):
    """Simulate a legacy database created before the B01 migration and verify additive columns."""
    db_file = tmp_path / "legacy.db"
    
    # Create an old schema table directly via raw SQL without the new columns
    raw_conn = sqlite3.connect(str(db_file))
    raw_conn.execute("""
        CREATE TABLE certificates (
            id VARCHAR PRIMARY KEY,
            cn VARCHAR,
            serial VARCHAR UNIQUE,
            issued_at DATETIME,
            expires_at DATETIME,
            status VARCHAR,
            reason VARCHAR,
            status_changed_at DATETIME,
            issued_by VARCHAR,
            status_changed_by VARCHAR,
            supersedes_id VARCHAR,
            request_id VARCHAR UNIQUE,
            note VARCHAR,
            batch_id VARCHAR
        )
    """)
    raw_conn.commit()
    raw_conn.close()

    # Now run init_db which includes column migration
    engine = db.make_engine(str(db_file))
    db.init_db(engine)

    # Verify new columns exist
    with engine.connect() as conn:
        cols = {row[1] for row in conn.execute(db.text("PRAGMA table_info(certificates)"))}
        assert "subsidiary_id" in cols
        assert "department_id" in cols
        assert "network_role_id" in cols
        assert "employee_id" in cols
        assert "device_id" in cols
        assert "identity_schema_version" in cols
        assert "issuance_policy_snapshot" in cols
        assert "request_fingerprint" in cols
