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
    TOPLINE_DEPARTMENT_ROLE_MAP,
    TOPLINE_DEPARTMENT_ROLE_MAP_V2,
    TOPLINE_DEPARTMENTS,
    TOPLINE_DEPARTMENTS_V2,
    TOPLINE_FALLBACK_VLAN,
    TOPLINE_NETWORK_ROLES,
    TOPLINE_ROLE_VLAN,
    get_deterministic_subsidiary_id,
    mark_topline_standard_as_default,
    resolve_subsidiary_alias,
    run_network_migrations,
    seed_baseline_subsidiaries,
    seed_topline_network_roles,
    seed_topline_real_org_v2,
    seed_topline_site_role_bindings,
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


def test_topline_network_roles_seeded_idempotently(tmp_path):
    db_file = tmp_path / "test_topline_roles.db"
    engine = db.make_engine(str(db_file))
    db.init_db(engine)

    with Session(engine) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))

        depts = {d.code: d for d in session.scalars(
            select(db.Department).where(db.Department.subsidiary_id == sub.id)
        ).all()}
        roles = {r.code: r for r in session.scalars(
            select(db.NetworkRole).where(db.NetworkRole.subsidiary_id == sub.id)
        ).all()}
        # init_db also runs seed_topline_real_org_v2 now (both gated
        # run_once calls fire on a fresh DB), so depts is a superset of
        # the original ten, not an exact match.
        assert {d["code"] for d in TOPLINE_DEPARTMENTS}.issubset(depts.keys())
        assert set(roles.keys()) == {r["code"] for r in TOPLINE_NETWORK_ROLES}

        links = session.scalars(select(db.DepartmentRole)).all()
        link_pairs = {(depts[d.code].id, roles[r.code].id) for d in depts.values() for r in roles.values()
                      if any(link.department_id == d.id and link.network_role_id == r.id for link in links)}
        for dept_code, role_code in TOPLINE_DEPARTMENT_ROLE_MAP.items():
            assert (depts[dept_code].id, roles[role_code].id) in link_pairs

        dept_count_before = len(depts)
        role_count_before = len(roles)
        link_count_before = len(links)

    # Re-run is a no-op: run_network_migrations is already gated by
    # db.run_once, same pattern as baseline_subsidiaries_seed.
    run_network_migrations(engine)

    with Session(engine) as session:
        assert session.query(db.Department).count() == dept_count_before
        assert session.query(db.NetworkRole).count() == role_count_before
        assert session.query(db.DepartmentRole).count() == link_count_before


def test_topline_consultant_has_contractor_constraint_description(tmp_path):
    """R3, 26 Nov 2026: topline_consultant is the only department mapped to
    topline_external (VLAN 90), the contractor role, and the real
    sponsor/cert-validity controls don't exist yet. The constraint must be
    visible at issuance time, not just in a handoff doc."""
    db_file = tmp_path / "test_consultant_description.db"
    engine = db.make_engine(str(db_file))
    db.init_db(engine)

    with Session(engine) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        consultant = session.scalar(
            select(db.Department).where(
                db.Department.subsidiary_id == sub.id, db.Department.code == "topline_consultant",
            )
        )
        assert consultant is not None
        assert consultant.description
        assert "sponsor" in consultant.description.lower()


def test_department_description_backfills_on_rerun_without_overwriting(tmp_path):
    """The run_once gate around seed_topline_network_roles already fired on
    the live hub before "description" existed -- calling the seed function
    directly (bypassing run_once, same as a one-off hub fix) must fill a
    blank description without touching one an admin set by hand."""
    db_file = tmp_path / "test_description_backfill.db"
    engine = db.make_engine(str(db_file))
    db.init_db(engine)

    with Session(engine) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        consultant = session.scalar(
            select(db.Department).where(
                db.Department.subsidiary_id == sub.id, db.Department.code == "topline_consultant",
            )
        )
        consultant.description = None  # simulate a pre-R3 row, seeded before this column existed
        other = session.scalar(
            select(db.Department).where(
                db.Department.subsidiary_id == sub.id, db.Department.code == "topline_cft",
            )
        )
        other.description = "admin wrote this by hand"
        session.commit()

    seed_topline_network_roles(engine)

    with Session(engine) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        consultant = session.scalar(
            select(db.Department).where(
                db.Department.subsidiary_id == sub.id, db.Department.code == "topline_consultant",
            )
        )
        other = session.scalar(
            select(db.Department).where(
                db.Department.subsidiary_id == sub.id, db.Department.code == "topline_cft",
            )
        )
        assert consultant.description  # backfilled
        assert other.description == "admin wrote this by hand"  # untouched


def test_topline_network_roles_seed_leaves_existing_placeholder_data_alone(tmp_path):
    """handoff task K, 20 Nov 2026: the seed must never touch a
    pre-existing department/role that already has real data on it --
    it only adds the new ones, by code, next to whatever is already
    there."""
    db_file = tmp_path / "test_topline_placeholder.db"
    engine = db.make_engine(str(db_file))
    db.init_db(engine)

    with Session(engine) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        sub_id = sub.id
        placeholder_it = db.Department(subsidiary_id=sub.id, code="it", display_name="IT")
        session.add(placeholder_it)
        session.commit()
        placeholder_id = placeholder_it.id

    seed_topline_network_roles(engine)

    with Session(engine) as session:
        still_there = session.get(db.Department, placeholder_id)
        assert still_there is not None
        assert still_there.code == "it"

        # The new seeded IT department uses a different code, not "it".
        new_it = session.scalar(
            select(db.Department).where(
                db.Department.subsidiary_id == sub_id, db.Department.code == "topline_it_dept"
            )
        )
        assert new_it is not None
        assert new_it.id != placeholder_id


def test_topline_real_org_v2_adds_without_touching_old_seed(tmp_path):
    """deploy/TENANT-AND-VLAN-PLAN.md: additive only -- the old ten
    departments (0 certs/0 employees live on the hub when checked, 25
    Nov 2026) stay untouched, the real 19-department org chart's missing
    ten get added next to them under distinct codes. Calls
    seed_topline_network_roles (the old seed) directly instead of
    db.init_db, so this exercises seed_topline_real_org_v2 itself from a
    clean slate rather than the already-seeded state init_db leaves."""
    db_file = tmp_path / "test_real_org_v2.db"
    engine = db.make_engine(str(db_file))
    db.Base.metadata.create_all(engine)
    seed_baseline_subsidiaries(engine)
    seed_topline_network_roles(engine)

    with Session(engine) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        sub_id = sub.id
        old_dept_codes = {d.code for d in session.scalars(
            select(db.Department).where(db.Department.subsidiary_id == sub.id)
        ).all()}

    inserted = seed_topline_real_org_v2(engine)
    assert set(inserted["departments"]) == {d["code"] for d in TOPLINE_DEPARTMENTS_V2}

    with Session(engine) as session:
        all_dept_codes = {d.code for d in session.scalars(
            select(db.Department).where(db.Department.subsidiary_id == sub_id)
        ).all()}
        # old departments still present
        assert old_dept_codes.issubset(all_dept_codes)
        # new ones added
        assert all_dept_codes == old_dept_codes | {d["code"] for d in TOPLINE_DEPARTMENTS_V2}

        depts_by_code = {d.code: d for d in session.scalars(
            select(db.Department).where(db.Department.subsidiary_id == sub_id)
        ).all()}
        roles_by_code = {r.code: r for r in session.scalars(
            select(db.NetworkRole).where(db.NetworkRole.subsidiary_id == sub_id)
        ).all()}
        links = session.scalars(select(db.DepartmentRole)).all()
        link_pairs = {(link.department_id, link.network_role_id) for link in links}
        for dept_code, role_code in TOPLINE_DEPARTMENT_ROLE_MAP_V2.items():
            assert (depts_by_code[dept_code].id, roles_by_code[role_code].id) in link_pairs

    # Re-run is idempotent -- no new inserts
    again = seed_topline_real_org_v2(engine)
    assert again["departments"] == []
    assert again["department_roles"] == []


def test_mark_topline_standard_as_default(tmp_path):
    db_file = tmp_path / "test_default_role.db"
    engine = db.make_engine(str(db_file))
    db.Base.metadata.create_all(engine)
    seed_baseline_subsidiaries(engine)
    seed_topline_network_roles(engine)

    with Session(engine) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        role = session.scalar(
            select(db.NetworkRole).where(
                db.NetworkRole.subsidiary_id == sub.id, db.NetworkRole.code == "topline_standard",
            )
        )
        assert role.is_default_fallback is False

    assert mark_topline_standard_as_default(engine) is True

    with Session(engine) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        role = session.scalar(
            select(db.NetworkRole).where(
                db.NetworkRole.subsidiary_id == sub.id, db.NetworkRole.code == "topline_standard",
            )
        )
        assert role.is_default_fallback is True


def test_seed_topline_site_role_bindings_requires_site_authorization(tmp_path):
    """No-op until SiteSubsidiary authorizes a site for topline -- both
    boxes were authenticate-only as of 20 Nov 2026, so this seed must not
    invent authorization that doesn't exist yet."""
    db_file = tmp_path / "test_site_bindings_seed.db"
    engine = db.make_engine(str(db_file))
    db.init_db(engine)

    assert seed_topline_site_role_bindings(engine) == []

    with Session(engine) as session:
        assert session.query(db.SiteRoleBinding).count() == 0


def test_seed_topline_site_role_bindings_binds_authorized_sites(tmp_path):
    db_file = tmp_path / "test_site_bindings_seed2.db"
    engine = db.make_engine(str(db_file))
    db.init_db(engine)

    with Session(engine) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        site = db.Site(name="HQ", radius_cn="radius-hq.internal", auth_token_hash="x")
        session.add(site)
        session.flush()
        session.add(db.SiteSubsidiary(site_id=site.id, subsidiary_id=sub.id, is_active=True))
        session.commit()
        site_id, sub_id = site.id, sub.id

    inserted = seed_topline_site_role_bindings(engine)
    assert len(inserted) == len(TOPLINE_ROLE_VLAN)

    with Session(engine) as session:
        bindings = session.scalars(
            select(db.SiteRoleBinding).where(db.SiteRoleBinding.site_id == site_id)
        ).all()
        assert len(bindings) == len(TOPLINE_ROLE_VLAN)
        roles_by_id = {r.id: r for r in session.scalars(
            select(db.NetworkRole).where(db.NetworkRole.subsidiary_id == sub_id)
        ).all()}
        for b in bindings:
            assert b.vlan_id == TOPLINE_ROLE_VLAN[roles_by_id[b.network_role_id].code]
            assert b.fallback_vlan_id == TOPLINE_FALLBACK_VLAN

    # Idempotent re-run
    again = seed_topline_site_role_bindings(engine)
    assert again == []


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
