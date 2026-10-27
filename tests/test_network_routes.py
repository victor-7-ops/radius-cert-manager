"""Tests for network policy, tenant roles, site bindings, and switches REST API.

Implements test verification for B04 and B08 specifications:
- Tenant-scoped registry reads
- Creation of departments and network roles
- Switch toggles: tenant role state, site tenant state, platform ceiling state
- Permission boundaries (platform superadmin vs subsidiary superadmin vs ordinary admin)
- Draft binding management and status inspection
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import auth, crl_push, db, network_migrations, pki
from app.main import create_app
from tests.conftest import login_as


@pytest.fixture
def test_setup(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    # Get seeded tenants
    sub_a = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "lezzgo_boracay"))
    sub_b = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "lezzgo_cebu"))
    assert sub_a and sub_b

    # Site
    site = db.Site(
        id="boracay-station1",
        name="Boracay Station 1",
        radius_cn="boracay-st1.example.local",
        auth_token_hash="fakehash",
    )
    session.add(site)
    session.commit()

    # Admins
    admin_plat = db.Admin(
        username="plat_admin",
        password_hash=auth.hash_password("pw123"),
        role=db.AdminRole.super_admin,
    )
    admin_sub_a = db.Admin(
        username="sub_a_admin",
        password_hash=auth.hash_password("pw123"),
        role=db.AdminRole.subsidiary_super_admin,
        subsidiary_scope=sub_a.id,
    )
    admin_sub_b = db.Admin(
        username="sub_b_admin",
        password_hash=auth.hash_password("pw123"),
        role=db.AdminRole.subsidiary_super_admin,
        subsidiary_scope=sub_b.id,
    )
    admin_ord_a = db.Admin(
        username="ord_a_admin",
        password_hash=auth.hash_password("pw123"),
        role=db.AdminRole.admin,
        subsidiary_scope=sub_a.id,
    )
    session.add_all([admin_plat, admin_sub_a, admin_sub_b, admin_ord_a])
    session.commit()
    session.refresh(admin_plat)
    session.refresh(admin_sub_a)
    session.refresh(admin_sub_b)
    session.refresh(admin_ord_a)

    app = create_app(app_settings)
    client = TestClient(app)

    return {
        "client": client,
        "app_settings": app_settings,
        "session": session,
        "sub_a": sub_a,
        "sub_b": sub_b,
        "site": site,
        "admin_plat": admin_plat,
        "admin_sub_a": admin_sub_a,
        "admin_sub_b": admin_sub_b,
        "admin_ord_a": admin_ord_a,
    }


def test_subsidiaries_listing_and_creation(test_setup):
    s = test_setup
    client = s["client"]

    # Platform superadmin can see all subsidiaries
    login_as(client, s["app_settings"], s["admin_plat"])
    resp = client.get("/api/network/subsidiaries")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["subsidiaries"]) >= 7

    # Subsidiary superadmin sees only own subsidiary
    login_as(client, s["app_settings"], s["admin_sub_a"])
    resp = client.get("/api/network/subsidiaries")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["subsidiaries"]) == 1
    assert data["subsidiaries"][0]["id"] == s["sub_a"].id

    # Subsidiary superadmin cannot create a subsidiary (403)
    resp = client.post(
        "/api/network/subsidiaries",
        json={"code": "new_corp", "display_name": "New Corp"},
    )
    assert resp.status_code == 403

    # Platform superadmin can create a subsidiary
    login_as(client, s["app_settings"], s["admin_plat"])
    resp = client.post(
        "/api/network/subsidiaries",
        json={"code": "new_corp", "display_name": "New Corp"},
    )
    assert resp.status_code == 201
    assert resp.json()["code"] == "new_corp"


def test_department_and_role_management_with_scoping(test_setup):
    s = test_setup
    client = s["client"]

    # sub_a admin creates department in sub_a
    login_as(client, s["app_settings"], s["admin_sub_a"])
    resp = client.post(
        f"/api/network/subsidiaries/{s['sub_a'].id}/departments",
        json={"code": "finance", "display_name": "Finance & Accounting"},
    )
    assert resp.status_code == 201
    dept_id = resp.json()["id"]

    # sub_a admin creates network role in sub_a
    resp = client.post(
        f"/api/network/subsidiaries/{s['sub_a'].id}/roles",
        json={"code": "finance_workstation", "display_name": "Finance Workstation"},
    )
    assert resp.status_code == 201
    role_id = resp.json()["id"]

    # Link department and role
    resp = client.put(f"/api/network/departments/{dept_id}/roles/{role_id}")
    assert resp.status_code == 200

    # sub_b admin cannot view or create departments in sub_a
    login_as(client, s["app_settings"], s["admin_sub_b"])
    resp = client.get(f"/api/network/subsidiaries/{s['sub_a'].id}/departments")
    assert resp.status_code == 404

    resp = client.post(
        f"/api/network/subsidiaries/{s['sub_a'].id}/departments",
        json={"code": "hacked", "display_name": "Hacked"},
    )
    assert resp.status_code in (403, 404)


def test_network_role_switch_and_site_binding_switches(test_setup):
    s = test_setup
    client = s["client"]

    # Setup department, role, and binding
    login_as(client, s["app_settings"], s["admin_plat"])
    resp_role = client.post(
        f"/api/network/subsidiaries/{s['sub_a'].id}/roles",
        json={"code": "pos_terminal", "display_name": "POS Terminal"},
    )
    role_id = resp_role.json()["id"]

    # Platform superadmin configures draft binding on site with fallback VLAN
    resp_draft = client.put(
        f"/api/network/sites/{s['site'].id}/draft",
        json={
            "expected_revision": 0,
            "bindings": [
                {
                    "subsidiary_id": s["sub_a"].id,
                    "network_role_id": role_id,
                    "vlan_id": 140,
                    "fallback_vlan_id": 149,
                    "platform_enabled": True,
                    "tenant_enabled": True,
                }
            ],
            "reason": "Initial POS binding",
        },
    )
    assert resp_draft.status_code == 200

    # sub_a admin can toggle tenant switch OFF
    login_as(client, s["app_settings"], s["admin_sub_a"])
    resp_switch = client.patch(
        f"/api/network/sites/{s['site'].id}/roles/{role_id}/tenant-state",
        json={"enabled": False, "reason": "Maintenance window"},
    )
    assert resp_switch.status_code == 200
    assert resp_switch.json()["tenant_enabled"] is False

    # sub_a admin CANNOT toggle platform ceiling (403)
    resp_plat_block = client.patch(
        f"/api/network/sites/{s['site'].id}/roles/{role_id}/platform-state",
        json={"enabled": False, "reason": "Unauthorized platform ceiling modification"},
    )
    assert resp_plat_block.status_code == 403

    # sub_b admin CANNOT toggle sub_a's switches (403 or 404)
    login_as(client, s["app_settings"], s["admin_sub_b"])
    resp_cross = client.patch(
        f"/api/network/sites/{s['site'].id}/roles/{role_id}/tenant-state",
        json={"enabled": True, "reason": "Cross-tenant intrusion attempt"},
    )
    assert resp_cross.status_code in (403, 404)


def test_admin_role_grants(test_setup):
    s = test_setup
    client = s["client"]

    # Create role
    login_as(client, s["app_settings"], s["admin_sub_a"])
    resp_role = client.post(
        f"/api/network/subsidiaries/{s['sub_a'].id}/roles",
        json={"code": "scanner", "display_name": "Barcode Scanner"},
    )
    role_id = resp_role.json()["id"]

    # Grant issuance role to ordinary admin in sub_a
    resp_grant = client.put(f"/api/network/admins/{s['admin_ord_a'].id}/role-grants/{role_id}")
    assert resp_grant.status_code == 200
    assert resp_grant.json()["admin_id"] == s["admin_ord_a"].id

    # Revoke grant
    resp_revoke = client.delete(f"/api/network/admins/{s['admin_ord_a'].id}/role-grants/{role_id}")
    assert resp_revoke.status_code == 200
    assert resp_revoke.json()["revoked"] is True
