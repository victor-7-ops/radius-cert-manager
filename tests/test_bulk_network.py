"""Bulk onboarding through the real Employee/Device/Certificate chain
(app/bulk_network_service.py, app/routes/bulk_network.py)."""

from sqlalchemy import func, select

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


def test_bulk_employees_import_with_legal_entity(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)
    _seed_department_and_role(app_settings)

    csv_text = (
        "subsidiary_code,department_code,display_name,employee_number,legal_entity\n"
        "topline,ops,Juan Dela Cruz,EMP-001,Topline Business\n"
    )
    resp = client.post(
        "/bulk/employees/preview",
        files={"csv_file": ("employees.csv", csv_text, "text/csv")},
    )
    assert resp.status_code == 200
    assert "Valid" in resp.text

    import re
    token = re.search(r'name="batch_token" value="([^"]+)"', resp.text).group(1)
    resp = client.post("/bulk/employees/confirm", data={"batch_token": token})
    assert resp.status_code == 200
    assert "1 succeeded" in resp.text

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    emp = session.scalar(select(db.Employee).where(db.Employee.employee_number == "EMP-001"))
    assert emp.legal_entity == "Topline Business"


def test_bulk_employees_import_without_legal_entity_leaves_it_null(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)
    _seed_department_and_role(app_settings)

    csv_text = "subsidiary_code,department_code,display_name,employee_number\ntopline,ops,Maria Santos,EMP-002\n"
    resp = client.post(
        "/bulk/employees/preview",
        files={"csv_file": ("employees.csv", csv_text, "text/csv")},
    )
    import re
    token = re.search(r'name="batch_token" value="([^"]+)"', resp.text).group(1)
    client.post("/bulk/employees/confirm", data={"batch_token": token})

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    emp = session.scalar(select(db.Employee).where(db.Employee.employee_number == "EMP-002"))
    assert emp.legal_entity is None


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


def test_bulk_devices_reupload_after_partial_failure_does_not_double_issue(app_settings, throwaway_pki, monkeypatch):
    """Verifies Q3's resume claim for real: re-uploading the whole file after
    a partial failure must not double-issue a cert for the row that already
    succeeded. It also surfaces the real gap -- a row whose Device got
    created but whose cert issuance then failed is "active" in the DB, so
    the duplicate guard blocks its own retry on re-upload (the device has
    no cert, and nothing short of deleting/retiring it unblocks that row)."""
    client = _client(app_settings, throwaway_pki, monkeypatch)
    sub, dept, role = _seed_department_and_role(app_settings)

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    platform_super = session.scalar(select(db.Admin).where(db.Admin.username == "root-admin"))
    from app import employee_service
    employee_service.create_employee(platform_super, sub.id, "Employee One", dept.id, "EMP-101", session)
    employee_service.create_employee(platform_super, sub.id, "Employee Two", dept.id, "EMP-102", session)
    session.commit()

    from app import cert_service
    original_issue = cert_service._issue_one_locked
    calls = {"n": 0}

    def flaky_issue(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("simulated cert issuance failure")
        return original_issue(*a, **kw)

    monkeypatch.setattr(cert_service, "_issue_one_locked", flaky_issue)

    csv_text = (
        "subsidiary_code,employee_number,role_code,device_type,mac_address\n"
        "topline,EMP-101,staff,Laptop,aa:bb:cc:dd:ee:01\n"
        "topline,EMP-102,staff,Laptop,aa:bb:cc:dd:ee:02\n"
    )

    def run_batch():
        resp = client.post("/bulk/devices/preview", files={"csv_file": ("devices.csv", csv_text, "text/csv")})
        import re
        token_match = re.search(r'name="batch_token" value="([^"]+)"', resp.text)
        if token_match is None:
            return resp, None
        token = token_match.group(1)
        confirm_resp = client.post(
            "/bulk/devices/confirm",
            data={"batch_token": token, "export_password": "correct-horse-battery-staple"},
            follow_redirects=False,
        )
        return resp, confirm_resp

    preview1, confirm1 = run_batch()
    assert preview1.status_code == 200
    assert "Valid" in preview1.text
    assert confirm1.status_code == 303
    result_resp = client.get(confirm1.headers["location"])
    assert "1 succeeded" in result_resp.text

    # First call is flaky_issue's real run (EMP-101, succeeds). Second
    # (EMP-102) raised -- register_device had already committed before the
    # raise, so EMP-102 has an orphaned Device with no cert.
    assert session.scalar(select(func.count()).select_from(db.Certificate)) == 1
    assert session.scalar(select(func.count()).select_from(db.Device)) == 2

    # Re-upload the identical file. The claim: this is the resume procedure.
    preview2, confirm2 = run_batch()
    assert preview2.status_code == 200
    # Both rows are now rejected -- EMP-101 correctly (already has a real
    # cert, re-running would double-issue), but EMP-102 ALSO rejects, even
    # though it has no cert, because its orphaned Device is "active" and
    # carries the same MAC. This is the gap: simple re-upload cannot
    # recover a row that failed after device registration but before cert
    # issuance -- the stuck device must be deleted or retired by hand first.
    assert "Malformed" in preview2.text
    assert preview2.text.count("already registered to an active device") == 2

    # Whatever happened, no duplicate cert or device was created.
    assert confirm2 is None or confirm2.status_code != 303 or "0 succeeded" in client.get(confirm2.headers["location"]).text
    assert session.scalar(select(func.count()).select_from(db.Certificate)) == 1
    assert session.scalar(select(func.count()).select_from(db.Device)) == 2


def test_bulk_devices_rejects_duplicate_mac_within_same_csv(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)
    sub, dept, role = _seed_department_and_role(app_settings)

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    platform_super = session.scalar(select(db.Admin).where(db.Admin.username == "root-admin"))
    from app import employee_service
    employee_service.create_employee(platform_super, sub.id, "Maria Santos", dept.id, "EMP-002", session)
    employee_service.create_employee(platform_super, sub.id, "Juan Dela Cruz", dept.id, "EMP-003", session)
    session.commit()

    csv_text = (
        "subsidiary_code,employee_number,role_code,device_type,mac_address\n"
        "topline,EMP-002,staff,Laptop,aa:bb:cc:dd:ee:ff\n"
        "topline,EMP-003,staff,Laptop,AA:BB:CC:DD:EE:FF\n"
    )
    resp = client.post(
        "/bulk/devices/preview",
        files={"csv_file": ("devices.csv", csv_text, "text/csv")},
    )
    assert resp.status_code == 200
    assert "Malformed" in resp.text
    assert "appears more than once" in resp.text


def test_bulk_devices_rejects_mac_already_registered_to_active_device(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)
    sub, dept, role = _seed_department_and_role(app_settings)

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    platform_super = session.scalar(select(db.Admin).where(db.Admin.username == "root-admin"))
    from app import employee_service
    emp1 = employee_service.create_employee(platform_super, sub.id, "Maria Santos", dept.id, "EMP-002", session)
    employee_service.create_employee(platform_super, sub.id, "Juan Dela Cruz", dept.id, "EMP-003", session)
    session.commit()

    from app import device_service
    device_service.register_device(
        platform_super, emp1.id, "Maria-Laptop", dept.id, role.id, session,
        device_type="Laptop", mac_address="aa:bb:cc:dd:ee:ff",
    )
    session.commit()

    csv_text = (
        "subsidiary_code,employee_number,role_code,device_type,mac_address\n"
        "topline,EMP-003,staff,Laptop,AA:BB:CC:DD:EE:FF\n"
    )
    resp = client.post(
        "/bulk/devices/preview",
        files={"csv_file": ("devices.csv", csv_text, "text/csv")},
    )
    assert resp.status_code == 200
    assert "Malformed" in resp.text
    assert "already registered to an active device" in resp.text


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
