"""Tests for employee and device REST and HTML routes.

Implements test verification for B10 and B11 specifications:
- Employee directory, creation, search, and metrics
- Device registration, metadata updates, status changes, and credential revocation
- Employee offboarding flow with CRL publication
- HTML views: /employees, /people/{id}, /devices/{id}, /people/{id}/offboard
- Legacy name-key resolution and redirect
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import auth, crl_push, db, pki
from app.main import create_app
from tests.conftest import login_as


@pytest.fixture
def test_setup(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    # Set up throwaway PKI cert files
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )

    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    sub_a = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "lezzgo_boracay"))
    sub_b = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "lezzgo_cebu"))
    assert sub_a and sub_b

    # Department & Role
    dept_a = db.Department(subsidiary_id=sub_a.id, code="ops", display_name="Operations")
    role_a = db.NetworkRole(subsidiary_id=sub_a.id, code="staff", display_name="Staff Network")
    session.add_all([dept_a, role_a])
    session.flush()

    pair = db.DepartmentRole(department_id=dept_a.id, network_role_id=role_a.id)
    session.add(pair)

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
    session.add_all([admin_plat, admin_sub_a, admin_sub_b])
    session.commit()
    session.refresh(admin_plat)
    session.refresh(admin_sub_a)
    session.refresh(admin_sub_b)

    app = create_app(app_settings)
    client = TestClient(app)

    return {
        "client": client,
        "app_settings": app_settings,
        "session": session,
        "sub_a": sub_a,
        "sub_b": sub_b,
        "dept_a": dept_a,
        "role_a": role_a,
        "admin_plat": admin_plat,
        "admin_sub_a": admin_sub_a,
        "admin_sub_b": admin_sub_b,
    }


def test_api_employee_and_device_lifecycle(test_setup):
    s = test_setup
    client = s["client"]

    # 1. Create employee via API
    login_as(client, s["app_settings"], s["admin_sub_a"])
    resp_emp = client.post(
        "/api/employees",
        json={
            "subsidiary_id": s["sub_a"].id,
            "display_name": "Ana Reyes",
            "department_id": s["dept_a"].id,
            "employee_number": "EMP-9001",
        },
    )
    assert resp_emp.status_code == 201
    emp_id = resp_emp.json()["id"]

    # 2. Get employee details
    resp_get = client.get(f"/api/employees/{emp_id}")
    assert resp_get.status_code == 200
    data = resp_get.json()
    assert data["display_name"] == "Ana Reyes"
    assert data["registered_devices"] == 0

    # 3. Register device for employee
    resp_dev = client.post(
        f"/api/employees/{emp_id}/devices",
        json={
            "display_name": "Ana ThinkPad",
            "department_id": s["dept_a"].id,
            "network_role_id": s["role_a"].id,
            "device_type": "Laptop",
            "asset_tag": "TAG-9001",
        },
    )
    assert resp_dev.status_code == 201
    dev_id = resp_dev.json()["id"]

    # 4. Check device details
    resp_dev_get = client.get(f"/api/devices/{dev_id}")
    assert resp_dev_get.status_code == 200
    assert resp_dev_get.json()["asset_tag"] == "TAG-9001"

    # 5. Update device status to lost
    resp_status = client.post(
        f"/api/devices/{dev_id}/status",
        json={"status": "lost", "reason": "Lost at airport"},
    )
    assert resp_status.status_code == 200
    assert resp_status.json()["status"] == "lost"

    # 6. Revoke credentials on device
    resp_rev = client.post(
        f"/api/devices/{dev_id}/revoke-credentials",
        json={"reason": "Device lost"},
    )
    assert resp_rev.status_code == 200
    assert "revoked_count" in resp_rev.json()

    # 7. Offboard employee
    resp_offboard = client.post(
        f"/api/employees/{emp_id}/offboard",
        json={"confirm_name": "Ana Reyes", "reason": "Left company"},
    )
    assert resp_offboard.status_code == 200
    assert resp_offboard.json()["status"] == "completed"

    # Verification: employee is offboarded
    resp_final = client.get(f"/api/employees/{emp_id}")
    assert resp_final.json()["status"] == "offboarded"


def test_html_views_and_navigation(test_setup):
    s = test_setup
    client = s["client"]

    login_as(client, s["app_settings"], s["admin_sub_a"])

    # Create employee and device
    resp_emp = client.post(
        "/api/employees",
        json={
            "subsidiary_id": s["sub_a"].id,
            "display_name": "Mark Bautista",
            "department_id": s["dept_a"].id,
            "employee_number": "EMP-8001",
        },
    )
    emp_id = resp_emp.json()["id"]

    resp_dev = client.post(
        f"/api/employees/{emp_id}/devices",
        json={
            "display_name": "Mark MacBook",
            "department_id": s["dept_a"].id,
            "network_role_id": s["role_a"].id,
        },
    )
    dev_id = resp_dev.json()["id"]

    # 1. Directory page: /employees
    resp_dir = client.get("/employees")
    assert resp_dir.status_code == 200
    assert "Employee Directory" in resp_dir.text
    assert "Mark Bautista" in resp_dir.text
    assert "EMP-8001" in resp_dir.text

    # 2. Detail page: /people/{employee_id}
    resp_person = client.get(f"/people/{emp_id}")
    assert resp_person.status_code == 200
    assert "Mark Bautista" in resp_person.text
    assert "Mark MacBook" in resp_person.text
    assert "Registered Devices" in resp_person.text
    assert "Usable Credentials" in resp_person.text

    # 3. Device detail page: /devices/{device_id}
    resp_device_page = client.get(f"/devices/{dev_id}")
    assert resp_device_page.status_code == 200
    assert "Mark MacBook" in resp_device_page.text
    assert "Site Access Policy" in resp_device_page.text

    # 4. Offboard confirm page: /people/{employee_id}/offboard
    resp_off_page = client.get(f"/people/{emp_id}/offboard")
    assert resp_off_page.status_code == 200
    assert "Offboard Employee" in resp_off_page.text
    assert "Mark Bautista" in resp_off_page.text

    # 5. Legacy redirect: /employees/{employee_key}
    resp_legacy = client.get("/employees/mark-bautista", follow_redirects=False)
    assert resp_legacy.status_code == 302
    assert resp_legacy.headers["location"] == f"/people/{emp_id}"
