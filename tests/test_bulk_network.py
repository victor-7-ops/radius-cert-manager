"""Bulk onboarding through the real Employee/Device/Certificate chain
(app/bulk_network_service.py, app/routes/bulk_network.py)."""

from sqlalchemy import select

from app import auth, crl_push, db, network_policy, pki
from app.main import create_app
from tests.conftest import login_as
from fastapi.testclient import TestClient


def _write_throwaway_pki(app_settings, throwaway_pki):
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )


def _seed_admin(app_settings, username, role):
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    admin = db.Admin(username=username, password_hash=auth.hash_password("correcthorse123"), role=role)
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def _client(app_settings, throwaway_pki, monkeypatch, role=db.AdminRole.super_admin, username="root-admin"):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, username, role)
    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)
    return client


def _seed_department_and_role(app_settings):
    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
    platform_super = session.scalar(select(db.Admin).where(db.Admin.username == "root-admin"))
    dept = network_policy.create_department(platform_super, sub.id, "ops", "Operations", session)
    role = network_policy.create_network_role(platform_super, sub.id, "staff", "Staff", None, False, session)
    network_policy.link_department_role(platform_super, dept.id, role.id, session)
    session.commit()
    return sub, dept, role


def test_bulk_employees_preview_and_confirm(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)
    _seed_department_and_role(app_settings)

    csv_text = "subsidiary_code,department_code,display_name,employee_number\ntopline,ops,Juan Dela Cruz,EMP-001\n"
    resp = client.post(
        "/bulk/employees/preview",
        files={"csv_file": ("employees.csv", csv_text, "text/csv")},
    )
    assert resp.status_code == 200
    assert "Valid" in resp.text
    assert "Juan Dela Cruz" in resp.text

    import re
    token = re.search(r'name="batch_token" value="([^"]+)"', resp.text).group(1)

    resp = client.post("/bulk/employees/confirm", data={"batch_token": token})
    assert resp.status_code == 200
    assert "1 succeeded" in resp.text

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    emp = session.scalar(select(db.Employee).where(db.Employee.employee_number == "EMP-001"))
    assert emp is not None
    assert emp.display_name == "Juan Dela Cruz"


def test_bulk_employees_rejects_unknown_department(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)

    csv_text = "subsidiary_code,department_code,display_name,employee_number\ntopline,nosuchdept,Someone,EMP-999\n"
    resp = client.post(
        "/bulk/employees/preview",
        files={"csv_file": ("employees.csv", csv_text, "text/csv")},
    )
    assert resp.status_code == 200
    assert "Malformed" in resp.text
    assert "unknown department_code" in resp.text


def test_bulk_devices_full_flow_issues_real_cert(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)
    sub, dept, role = _seed_department_and_role(app_settings)

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    platform_super = session.scalar(select(db.Admin).where(db.Admin.username == "root-admin"))
    emp = network_policy.create_department  # noop reference to keep import used
    from app import employee_service
    emp = employee_service.create_employee(platform_super, sub.id, "Maria Santos", dept.id, "EMP-002", session)
    session.commit()

    csv_text = (
        "subsidiary_code,employee_number,role_code,device_type,device_model,mac_address,serial_number\n"
        "topline,EMP-002,staff,Laptop,HP EliteBook 840,aa:bb:cc:dd:ee:ff,C02XG2JMQ6L9\n"
    )
    resp = client.post(
        "/bulk/devices/preview",
        files={"csv_file": ("devices.csv", csv_text, "text/csv")},
    )
    assert resp.status_code == 200
    assert "Valid" in resp.text
    assert "Maria Santos" in resp.text

    import re
    token = re.search(r'name="batch_token" value="([^"]+)"', resp.text).group(1)

    resp = client.post(
        "/bulk/devices/confirm",
        data={"batch_token": token, "export_password": "correct-horse-battery-staple"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    batch_id = resp.headers["location"].rsplit("/", 1)[-1]

    resp = client.get(resp.headers["location"])
    assert resp.status_code == 200
    assert "1 succeeded" in resp.text

    device = session.scalar(select(db.Device).where(db.Device.employee_id == emp.id))
    assert device is not None
    assert device.network_role_id == role.id

    cert = session.scalar(select(db.Certificate).where(db.Certificate.device_id == device.id))
    assert cert is not None
    assert cert.subsidiary_id == sub.id
    assert cert.network_role_id == role.id
    assert cert.employee_id == emp.id

    resp = client.get(f"/bulk/devices/{batch_id}/bundle")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"


def test_bulk_devices_rejects_role_not_linked_to_department(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)
    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
    platform_super = session.scalar(select(db.Admin).where(db.Admin.username == "root-admin"))
    dept = network_policy.create_department(platform_super, sub.id, "sales", "Sales", session)
    role = network_policy.create_network_role(platform_super, sub.id, "guest", "Guest", None, False, session)
    # Deliberately NOT linked via link_department_role
    session.commit()

    from app import employee_service
    emp = employee_service.create_employee(platform_super, sub.id, "Unlinked Guy", dept.id, "EMP-777", session)
    session.commit()

    csv_text = "subsidiary_code,employee_number,role_code,device_type\ntopline,EMP-777,guest,Phone\n"
    resp = client.post(
        "/bulk/devices/preview",
        files={"csv_file": ("devices.csv", csv_text, "text/csv")},
    )
    assert resp.status_code == 200
    assert "Malformed" in resp.text
    assert "not linked" in resp.text


def test_viewer_can_see_forms_but_cannot_submit(app_settings, throwaway_pki, monkeypatch):
    # Same permission shape as the existing /certs/bulk: require_admin
    # (viewer included) can view the form, require_write (viewer excluded)
    # guards every actual mutation.
    client = _client(app_settings, throwaway_pki, monkeypatch, role=db.AdminRole.viewer, username="viewer-1")
    assert client.get("/bulk/employees").status_code == 200
    assert client.get("/bulk/devices").status_code == 200
    assert client.post(
        "/bulk/employees/preview", files={"csv_file": ("x.csv", "a,b,c,d\n", "text/csv")}
    ).status_code == 403
    assert client.post(
        "/bulk/devices/preview", files={"csv_file": ("x.csv", "a,b,c\n", "text/csv")}
    ).status_code == 403
