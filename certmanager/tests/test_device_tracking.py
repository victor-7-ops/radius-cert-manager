"""Device/employee tracking fields — cert_service level and end-to-end
through the real issue form + the employee drill-down filter."""

import datetime
import re
import uuid

from fastapi.testclient import TestClient

from app import auth, cert_service, crl_push, db, pki
from app.main import create_app


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


def _login(client, app_settings, admin):
    cookie = auth._serializer(app_settings.secret_key).dumps(
        {"sub": admin.id, "tv": admin.token_version, "session_start": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    )
    client.cookies.set(auth.SESSION_COOKIE, cookie)


def test_issue_certificate_stores_device_info(tmp_path, throwaway_pki):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    result = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="tracked-device", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
        device=cert_service.DeviceInfo(
            employee_name="Jordan Ellis",
            device_type="Laptop",
            device_mac="aa:bb:cc:dd:ee:ff",
            device_serial="C02XG2JMQ6L9",
        ),
    )
    assert result.certificate.employee_name == "Jordan Ellis"
    assert result.certificate.device_type == "Laptop"
    assert result.certificate.device_mac == "aa:bb:cc:dd:ee:ff"
    assert result.certificate.device_serial == "C02XG2JMQ6L9"

    reloaded = session.query(db.Certificate).filter_by(cn="tracked-device").one()
    assert reloaded.employee_name == "Jordan Ellis"


def test_issue_certificate_without_device_info_leaves_fields_null(tmp_path, throwaway_pki):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    result = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="untracked-device", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    )
    assert result.certificate.employee_name is None
    assert result.certificate.device_mac is None


def test_existing_db_without_device_columns_is_migrated_on_init(tmp_path):
    """A DB created before this feature (no employee_name/device_* columns)
    must not break — init_db() adds the missing columns in place."""
    engine = db.make_engine(str(tmp_path / "old.db"))
    with engine.begin() as conn:
        from sqlalchemy import text

        conn.execute(
            text(
                "CREATE TABLE certificates ("
                "id VARCHAR PRIMARY KEY, cn VARCHAR, serial VARCHAR UNIQUE, "
                "issued_at DATETIME, expires_at DATETIME, status VARCHAR, "
                "reason VARCHAR, status_changed_at DATETIME, issued_by VARCHAR, "
                "status_changed_by VARCHAR, supersedes_id VARCHAR, "
                "request_id VARCHAR UNIQUE, note VARCHAR, batch_id VARCHAR)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO certificates (id, cn, serial, issued_at, expires_at, status, "
                "issued_by, request_id) VALUES ('id1', 'pre-existing', '12345', "
                "'2026-01-01 00:00:00', '2027-01-01 00:00:00', 'active', 'alice', 'req-1')"
            )
        )

    db.init_db(engine)  # must not raise, and must add the new columns

    session = db.make_session_factory(engine)()
    row = session.query(db.Certificate).filter_by(cn="pre-existing").one()
    assert row.employee_name is None
    assert row.device_type is None
    assert row.device_mac is None
    assert row.device_serial is None
    assert row.subsidiary is None


def test_issue_form_and_employee_drilldown_e2e(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "device-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    # Issue two devices for the same employee.
    for cn in ["jordan-laptop", "jordan-phone"]:
        resp = client.post(
            "/certs/issue",
            data={
                "cn": cn,
                "request_id": str(uuid.uuid4()),
                "employee_name": "Jordan Ellis",
                "device_type": "Laptop" if "laptop" in cn else "Phone",
                "device_mac": "AA:BB:CC:DD:EE:FF" if "laptop" in cn else "",
                "device_serial": "",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200

    # Detail page shows the device info and links to the employee filter.
    cert_row = db.make_session_factory(db.make_engine(str(app_settings.db_path)))().query(
        db.Certificate
    ).filter_by(cn="jordan-laptop").one()
    detail_resp = client.get(f"/certs/{cert_row.serial}")
    assert detail_resp.status_code == 200
    assert "Jordan Ellis" in detail_resp.text
    assert "aa:bb:cc:dd:ee:ff" in detail_resp.text
    assert "+1 more device" in detail_resp.text

    # Employee drill-down shows both devices, nothing else.
    filtered_resp = client.get("/certs", params={"employee": "Jordan Ellis"})
    assert filtered_resp.status_code == 200
    assert "jordan-laptop" in filtered_resp.text
    assert "jordan-phone" in filtered_resp.text


def test_issue_rejects_invalid_mac(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "mac-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    resp = client.post(
        "/certs/issue",
        data={"cn": "bad-mac-device", "request_id": str(uuid.uuid4()), "device_mac": "not-a-mac"},
    )
    assert resp.status_code == 400
    assert "Invalid MAC" in resp.text

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    assert session.query(db.Certificate).filter_by(cn="bad-mac-device").count() == 0


def test_issue_certificate_stores_subsidiary(tmp_path, throwaway_pki):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    result = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="subsidiary-device", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
        device=cert_service.DeviceInfo(subsidiary="Lezzgo Boracay"),
    )
    assert result.certificate.subsidiary == "Lezzgo Boracay"

    reloaded = session.query(db.Certificate).filter_by(cn="subsidiary-device").one()
    assert reloaded.subsidiary == "Lezzgo Boracay"


def test_issue_form_and_subsidiary_filter_e2e(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "subsidiary-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    for cn, subsidiary in [("bay-mall-pos-01", "Bay Mall"), ("bmead-laptop-01", "BMEAD")]:
        resp = client.post(
            "/certs/issue",
            data={"cn": cn, "request_id": str(uuid.uuid4()), "subsidiary": subsidiary},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    detail_session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    bay_mall_cert = detail_session.query(db.Certificate).filter_by(cn="bay-mall-pos-01").one()
    assert bay_mall_cert.subsidiary == "Bay Mall"

    detail_resp = client.get(f"/certs/{bay_mall_cert.serial}")
    assert "Bay Mall" in detail_resp.text

    filtered_resp = client.get("/certs", params={"subsidiary": "Bay Mall"})
    assert filtered_resp.status_code == 200
    assert "bay-mall-pos-01" in filtered_resp.text
    assert "bmead-laptop-01" not in filtered_resp.text


def test_issue_form_offers_subsidiary_choices(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "form-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    resp = client.get("/certs/issue")
    assert resp.status_code == 200
    for name in db.SUBSIDIARIES:
        assert name in resp.text
