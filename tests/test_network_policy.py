"""Unit tests for B02/B08 network policy domain logic, permissions, and switch decisions.

Verifies:
- Scoped permissions (Platform superadmin, Subsidiary superadmin, Ordinary admin, Viewer)
- Unscoped subsidiary superadmin rejection
- Cross-tenant isolation
- Assignment validation (Department-Role pairing, admin grants)
- Binding resolution decision tree:
    - Normal VLAN when ON
    - Configured fallback VLAN when tenant switch is OFF
    - REJECT on platform block (never fallback)
    - REJECT on invalid, revoked, inactive, or missing fallback
"""

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import db
from app.network_policy import (
    ConflictError,
    ForbiddenError,
    PolicyValidationError,
    ResourceNotFoundError,
    assert_can_manage_subsidiary,
    authorize_site_subsidiary,
    configure_site_role_binding,
    create_department,
    create_network_role,
    create_subsidiary,
    deauthorize_site_subsidiary,
    delete_department,
    delete_network_role,
    delete_subsidiary,
    grant_role,
    link_department_role,
    resolve_binding,
    set_network_role_tenant_state,
    set_site_binding_platform_state,
    set_site_binding_tenant_state,
    unlink_department_role,
    update_department,
    update_network_role,
    update_subsidiary,
    validate_assignment,
)


@pytest.fixture
def policy_db(tmp_path):
    db_file = tmp_path / "test_policy.db"
    engine = db.make_engine(str(db_file))
    db.init_db(engine)
    return engine


def _make_admin(session, username, role, scope=None):
    admin = db.Admin(
        username=username,
        password_hash="dummyhash",
        role=role,
        subsidiary_scope=scope,
        is_active=True,
    )
    session.add(admin)
    session.flush()
    return admin


def test_permission_matrix_and_tenant_superadmin_scope(policy_db):
    with Session(policy_db) as session:
        sub_topline = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        sub_lezzgo = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "lezzgo_boracay"))

        platform_super = _make_admin(session, "p_super", db.AdminRole.super_admin, None)
        sub_super_topline = _make_admin(session, "s_super_topline", db.AdminRole.subsidiary_super_admin, "topline")
        sub_super_unscoped = _make_admin(session, "s_super_unscoped", db.AdminRole.subsidiary_super_admin, None)
        ord_admin = _make_admin(session, "ord_admin", db.AdminRole.admin, "topline")
        viewer = _make_admin(session, "viewer", db.AdminRole.viewer, "topline")

        # 1. Unscoped subsidiary superadmin is rejected
        with pytest.raises(ForbiddenError):
            assert_can_manage_subsidiary(sub_super_unscoped, sub_topline.id, session)

        # 2. Subsidiary superadmin cannot manage another subsidiary
        with pytest.raises(ForbiddenError):
            assert_can_manage_subsidiary(sub_super_topline, sub_lezzgo.id, session)

        # 3. Subsidiary superadmin CAN manage their own subsidiary
        assert_can_manage_subsidiary(sub_super_topline, sub_topline.id, session)

        # 4. Platform superadmin can manage any subsidiary
        assert_can_manage_subsidiary(platform_super, sub_topline.id, session)
        assert_can_manage_subsidiary(platform_super, sub_lezzgo.id, session)

        # 5. Ordinary admin and Viewer cannot manage subsidiary settings
        with pytest.raises(ForbiddenError):
            assert_can_manage_subsidiary(ord_admin, sub_topline.id, session)
        with pytest.raises(ForbiddenError):
            assert_can_manage_subsidiary(viewer, sub_topline.id, session)


def test_department_and_role_creation_and_linking(policy_db):
    with Session(policy_db) as session:
        sub_topline = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        sub_lezzgo = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "lezzgo_boracay"))
        sub_super = _make_admin(session, "s_super", db.AdminRole.subsidiary_super_admin, "topline")

        # Create department and role in own tenant
        dept = create_department(sub_super, sub_topline.id, "fin", "Finance Dept", session)
        role = create_network_role(sub_super, sub_topline.id, "fin_access", "Finance Access", "Desc", False, session)
        assert dept.code == "fin"
        assert role.code == "fin_access"

        # Link department and role
        dep_role = link_department_role(sub_super, dept.id, role.id, session)
        assert dep_role.department_id == dept.id
        assert dep_role.network_role_id == role.id

        # Linking cross-subsidiary is strictly forbidden
        role_lezzgo = db.NetworkRole(subsidiary_id=sub_lezzgo.id, code="guest", display_name="Guest")
        session.add(role_lezzgo)
        session.flush()

        with pytest.raises(PolicyValidationError):
            link_department_role(sub_super, dept.id, role_lezzgo.id, session)


def test_role_grants_for_ordinary_admins(policy_db):
    with Session(policy_db) as session:
        sub_topline = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        sub_super = _make_admin(session, "s_super", db.AdminRole.subsidiary_super_admin, "topline")
        ord_admin = _make_admin(session, "ord_admin", db.AdminRole.admin, "topline")
        other_admin = _make_admin(session, "other_admin", db.AdminRole.admin, "lezzgo_boracay")

        role = create_network_role(sub_super, sub_topline.id, "audit", "Auditor Access", None, False, session)

        # Grant role to scoped admin in same tenant
        grant = grant_role(sub_super, ord_admin.id, role.id, session)
        assert grant.admin_id == ord_admin.id
        assert grant.network_role_id == role.id

        # Cannot grant to admin from different subsidiary scope
        with pytest.raises(PolicyValidationError):
            grant_role(sub_super, other_admin.id, role.id, session)


def test_assignment_validation_rules(policy_db):
    with Session(policy_db) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        dept = db.Department(subsidiary_id=sub.id, code="acct", display_name="Accounting")
        dept_other = db.Department(subsidiary_id=sub.id, code="hr", display_name="HR")
        role = db.NetworkRole(subsidiary_id=sub.id, code="fin", display_name="Finance Access")
        session.add_all([dept, dept_other, role])
        session.flush()

        # Link acct -> fin
        session.add(db.DepartmentRole(department_id=dept.id, network_role_id=role.id))

        # Add a site binding so role is ready
        site = db.Site(name="HQ", radius_cn="radius-hq.internal", auth_token_hash="hash")
        session.add(site)
        session.flush()
        session.add(
            db.SiteRoleBinding(
                site_id=site.id,
                subsidiary_id=sub.id,
                network_role_id=role.id,
                vlan_id=30,
                fallback_vlan_id=99,
            )
        )
        session.commit()

        platform_super = _make_admin(session, "p_super", db.AdminRole.super_admin)
        ord_admin = _make_admin(session, "ord_admin", db.AdminRole.admin, "topline")

        # 1. Ordinary admin without grant fails
        with pytest.raises(ForbiddenError, match="has not been granted"):
            validate_assignment(ord_admin, sub.id, dept.id, role.id, session)

        # 2. Grant role to ordinary admin -> succeeds
        grant_role(platform_super, ord_admin.id, role.id, session)
        validate_assignment(ord_admin, sub.id, dept.id, role.id, session)

        # 3. Department not eligible for role (hr -> fin is not linked) -> fails
        with pytest.raises(PolicyValidationError, match="not authorized"):
            validate_assignment(ord_admin, sub.id, dept_other.id, role.id, session)

        # 4. Role without site binding -> fails
        role_unbound = db.NetworkRole(subsidiary_id=sub.id, code="unbound", display_name="Unbound")
        session.add(role_unbound)
        session.flush()
        session.add(db.DepartmentRole(department_id=dept.id, network_role_id=role_unbound.id))
        grant_role(platform_super, ord_admin.id, role_unbound.id, session)
        with pytest.raises(PolicyValidationError, match="no active site bindings"):
            validate_assignment(ord_admin, sub.id, dept.id, role_unbound.id, session)


def test_resolve_binding_decision_tree_authoritative(policy_db):
    """Verifies all branches of normal/fallback/reject decision tree."""
    with Session(policy_db) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        role = db.NetworkRole(subsidiary_id=sub.id, code="fin", display_name="Finance Access", is_active=True)
        site = db.Site(name="HQ", radius_cn="radius-hq.internal", auth_token_hash="hash")
        session.add_all([role, site])
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

        # Branch 1: Both switches ON -> PRIMARY VLAN 30
        decision = resolve_binding(site.id, sub.id, role.id, session)
        assert decision.outcome == "primary"
        assert decision.vlan_id == 30

        # Branch 2: Tenant-wide role switch is OFF -> FALLBACK VLAN 99
        role.is_active = False
        session.commit()
        decision = resolve_binding(site.id, sub.id, role.id, session)
        assert decision.outcome == "fallback"
        assert decision.vlan_id == 99

        # Restore role.is_active, turn site-specific tenant switch OFF -> FALLBACK VLAN 99
        role.is_active = True
        binding.tenant_enabled = False
        session.commit()
        decision = resolve_binding(site.id, sub.id, role.id, session)
        assert decision.outcome == "fallback"
        assert decision.vlan_id == 99

        # Branch 3: Fallback VLAN missing when switch is OFF -> REJECT (never guess a VLAN)
        binding.fallback_vlan_id = None
        session.commit()
        decision = resolve_binding(site.id, sub.id, role.id, session)
        assert decision.outcome == "reject"
        assert decision.vlan_id is None
        assert "no valid approved fallback VLAN" in decision.reason

        # Branch 4: Platform block -> ALWAYS REJECT (never fallback)
        binding.fallback_vlan_id = 99
        binding.platform_enabled = False
        session.commit()
        decision = resolve_binding(site.id, sub.id, role.id, session)
        assert decision.outcome == "reject"
        assert decision.vlan_id is None
        assert "Platform administration has disabled" in decision.reason

        # Branch 5: Inactive subsidiary -> REJECT
        binding.platform_enabled = True
        sub.is_active = False
        session.commit()
        decision = resolve_binding(site.id, sub.id, role.id, session)
        assert decision.outcome == "reject"
        assert decision.vlan_id is None


def test_vlan_infrastructure_configuration_permissions(policy_db):
    with Session(policy_db) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        role = db.NetworkRole(subsidiary_id=sub.id, code="ops", display_name="Ops")
        site = db.Site(name="Branch", radius_cn="radius-branch.internal", auth_token_hash="hash")
        session.add_all([role, site])
        session.flush()

        platform_super = _make_admin(session, "p_super", db.AdminRole.super_admin)
        sub_super = _make_admin(session, "s_super", db.AdminRole.subsidiary_super_admin, "topline")

        # Subsidiary superadmin CANNOT configure VLAN numbers
        with pytest.raises(ForbiddenError, match="Only platform superadmins"):
            configure_site_role_binding(sub_super, site.id, sub.id, role.id, vlan_id=20, fallback_vlan_id=99, session=session)

        # Platform superadmin CAN configure VLAN numbers
        b = configure_site_role_binding(platform_super, site.id, sub.id, role.id, vlan_id=20, fallback_vlan_id=99, session=session)
        assert b.vlan_id == 20
        assert b.fallback_vlan_id == 99

        # Reject identical fallback VLAN and primary VLAN
        with pytest.raises(PolicyValidationError, match="identical"):
            configure_site_role_binding(platform_super, site.id, sub.id, role.id, vlan_id=20, fallback_vlan_id=20, session=session)

        # Reject invalid VLAN number out of 1-4094
        with pytest.raises(PolicyValidationError, match="between 1 and 4094"):
            configure_site_role_binding(platform_super, site.id, sub.id, role.id, vlan_id=5000, fallback_vlan_id=99, session=session)


def test_site_subsidiary_authorization(policy_db):
    with Session(policy_db) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        site = db.Site(name="Branch", radius_cn="radius-branch2.internal", auth_token_hash="hash")
        session.add(site)
        session.flush()

        platform_super = _make_admin(session, "p_super", db.AdminRole.super_admin)
        sub_super = _make_admin(session, "s_super", db.AdminRole.subsidiary_super_admin, "topline")

        # Subsidiary superadmin cannot authorize a site -- same platform-only
        # restriction as VLAN infrastructure (both control what a site's
        # compiled policy.json can contain, not subsidiary-internal state).
        with pytest.raises(ForbiddenError, match="Only platform superadmins"):
            authorize_site_subsidiary(sub_super, site.id, sub.id, session)

        link = authorize_site_subsidiary(platform_super, site.id, sub.id, session)
        assert link.is_active is True

        # Idempotent: authorizing again reactivates rather than duplicating
        link_again = authorize_site_subsidiary(platform_super, site.id, sub.id, session)
        assert link_again.id == link.id

        deauthorize_site_subsidiary(platform_super, site.id, sub.id, session)
        session.refresh(link)
        assert link.is_active is False

        with pytest.raises(ForbiddenError, match="Only platform superadmins"):
            deauthorize_site_subsidiary(sub_super, site.id, sub.id, session)

        with pytest.raises(ResourceNotFoundError):
            authorize_site_subsidiary(platform_super, "nonexistent-site", sub.id, session)


def test_subsidiary_rename_and_delete(policy_db):
    with Session(policy_db) as session:
        platform_super = _make_admin(session, "p_super", db.AdminRole.super_admin)
        sub_super = _make_admin(session, "s_super", db.AdminRole.subsidiary_super_admin, "topline")

        new_sub = create_subsidiary(platform_super, "acme", "Acme Corp", session)

        with pytest.raises(ForbiddenError):
            update_subsidiary(sub_super, new_sub.id, "Acme Corp Renamed", session)

        renamed = update_subsidiary(platform_super, new_sub.id, "Acme Corp Renamed", session)
        assert renamed.display_name == "Acme Corp Renamed"

        with pytest.raises(PolicyValidationError, match="blank"):
            update_subsidiary(platform_super, new_sub.id, "   ", session)

        dept = create_department(platform_super, new_sub.id, "ops", "Operations", session)

        # Cannot delete a subsidiary that still has departments
        with pytest.raises(ConflictError, match="departments"):
            delete_subsidiary(platform_super, new_sub.id, session)

        delete_department(platform_super, dept.id, session)
        delete_subsidiary(platform_super, new_sub.id, session)
        assert session.get(db.Subsidiary, new_sub.id) is None


def test_department_rename_delete_and_role_unlink(policy_db):
    with Session(policy_db) as session:
        platform_super = _make_admin(session, "p_super", db.AdminRole.super_admin)
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))

        dept = create_department(platform_super, sub.id, "hr", "Human Resources", session)
        role = create_network_role(platform_super, sub.id, "hrstaff", "HR Staff", None, False, session)
        link_department_role(platform_super, dept.id, role.id, session)

        renamed = update_department(platform_super, dept.id, "HR Department", session)
        assert renamed.display_name == "HR Department"

        unlink_department_role(platform_super, dept.id, role.id, session)
        assert session.scalar(
            select(db.DepartmentRole).where(
                db.DepartmentRole.department_id == dept.id, db.DepartmentRole.network_role_id == role.id
            )
        ) is None

        delete_department(platform_super, dept.id, session)
        assert session.get(db.Department, dept.id) is None


def test_network_role_rename_and_delete_blocked_by_binding(policy_db):
    with Session(policy_db) as session:
        platform_super = _make_admin(session, "p_super", db.AdminRole.super_admin)
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        site = db.Site(name="Branch3", radius_cn="radius-branch3.internal", auth_token_hash="hash")
        session.add(site)
        session.flush()

        role = create_network_role(platform_super, sub.id, "guard", "Security Guard", None, False, session)
        renamed = update_network_role(platform_super, role.id, "Security Guards", "updated desc", session)
        assert renamed.display_name == "Security Guards"
        assert renamed.description == "updated desc"

        configure_site_role_binding(platform_super, site.id, sub.id, role.id, vlan_id=30, fallback_vlan_id=99, session=session)

        with pytest.raises(ConflictError, match="site VLAN bindings"):
            delete_network_role(platform_super, role.id, session)
