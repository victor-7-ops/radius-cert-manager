"""Reissue, CSV export, bulk CSV template, flash messages, session ping —
the "go all" enhancement batch. Route-level tests use the real HTTP
layer (TestClient) since these are thin route wrappers; cert_service
tests exercise the reissue business logic directly."""

import datetime
import uuid

import pytest
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


# --- cert_service.reissue_certificate ---


def test_reissue_creates_new_cert_linked_to_old_which_stays_active(tmp_path, throwaway_pki):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    original = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="reissue-device", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
        device=cert_service.DeviceInfo(employee_name="Sam Lee", device_type="Laptop"),
    ).certificate

    result = cert_service.reissue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        old_serial=original.serial, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    )

    assert result.certificate.cn == "reissue-device"
    assert result.certificate.serial != original.serial
    assert result.certificate.supersedes_id == original.id
    assert result.certificate.employee_name == "Sam Lee"  # carried over from old cert
    assert result.certificate.device_type == "Laptop"
    assert result.bundle is not None

    reloaded_original = session.query(db.Certificate).filter_by(id=original.id).one()
    assert reloaded_original.status == db.CertStatus.active  # untouched by reissue

    # Both cert files coexist on disk under the same CN — the serial in
    # the filename is what makes that possible (handoff-adjacent fix).
    crt_files = list((tmp_path / "issued").glob("reissue-device.*.crt"))
    assert len(crt_files) == 2


def test_reissue_rejects_revoked_certificate(tmp_path, throwaway_pki):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    original = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="revoked-then-reissue", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    ).certificate
    cert_service.revoke(session, tmp_path, original.serial, "lost device", "root-admin")

    with pytest.raises(cert_service.ReissueTargetError):
        cert_service.reissue_certificate(
            session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
            old_serial=original.serial, request_id=str(uuid.uuid4()), export_password=None,
            issued_by="alice", days=365,
        )


def test_reissue_rejects_unknown_serial(tmp_path, throwaway_pki):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    with pytest.raises(cert_service.ReissueTargetError):
        cert_service.reissue_certificate(
            session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
            old_serial="does-not-exist", request_id=str(uuid.uuid4()), export_password=None,
            issued_by="alice", days=365,
        )


# --- Route-level e2e ---


def test_reissue_route_e2e(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "reissue-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    issue_resp = client.post("/certs/issue", data={"cn": "web-reissue-device", "request_id": str(uuid.uuid4())})
    assert issue_resp.status_code == 200  # delivery page after redirect-follow

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    original = session.query(db.Certificate).filter_by(cn="web-reissue-device").one()

    reissue_resp = client.post(f"/certs/{original.serial}/reissue", follow_redirects=False)
    assert reissue_resp.status_code == 303
    assert "/delivery" in reissue_resp.headers["location"]

    delivery_resp = client.get(reissue_resp.headers["location"])
    assert delivery_resp.status_code == 200
    assert "web-reissue-device" in delivery_resp.text

    rows = session.query(db.Certificate).filter_by(cn="web-reissue-device").all()
    assert len(rows) == 2
    new_row = [r for r in rows if r.serial != original.serial][0]
    assert new_row.supersedes_id == original.id


def test_csv_export_respects_status_filter(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "export-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    client.post("/certs/issue", data={"cn": "export-active-device", "request_id": str(uuid.uuid4())})
    resp2 = client.post("/certs/issue", data={"cn": "export-revoked-device", "request_id": str(uuid.uuid4())})

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    revoked_cert = session.query(db.Certificate).filter_by(cn="export-revoked-device").one()
    client.post(f"/certs/{revoked_cert.serial}/revoke", data={"reason": "test"})

    export_resp = client.get("/certs/export.csv", params={"status": "active"})
    assert export_resp.status_code == 200
    assert "text/csv" in export_resp.headers["content-type"]
    assert "export-active-device" in export_resp.text
    assert "export-revoked-device" not in export_resp.text
    assert export_resp.text.startswith("cn,serial,status")


def test_bulk_template_csv_download(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "template-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    resp = client.get("/certs/bulk/template.csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert resp.text.startswith("cn,employee_name,device_type,device_mac,device_serial,subsidiary")
    assert db.SUBSIDIARIES[0] in resp.text


def test_auth_ping_returns_204_when_authenticated(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "ping-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    resp = client.get("/auth/ping")
    assert resp.status_code == 204


def test_auth_ping_requires_login(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)

    app = create_app(app_settings)
    client = TestClient(app)

    # /auth/ping is a web route, not /api — the shared 401 handler
    # redirects those to /login rather than returning raw JSON (matches
    # every other authenticated page).
    resp = client.get("/auth/ping", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_suspend_redirect_carries_flash_message(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "flash-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    client.post("/certs/issue", data={"cn": "flash-device", "request_id": str(uuid.uuid4())})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="flash-device").one()

    resp = client.post(f"/certs/{cert.serial}/suspend", data={"reason": "test"}, follow_redirects=False)
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert "flash=" in location
    assert "flash_kind=warn" in location


def test_activity_log_action_and_date_filters(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "activity-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    client.post("/certs/issue", data={"cn": "activity-device", "request_id": str(uuid.uuid4())})
    client.post("/admins", data={"username": "throwaway-admin", "role": "admin"})

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()

    # action filter is an exact match against the dropdown, not a substring —
    # "issue" must not also pick up "create_admin".
    resp = client.get("/activity", params={"action": "issue"})
    assert resp.status_code == 200
    assert "activity-device" in resp.text
    assert "throwaway-admin" not in resp.text

    resp = client.get("/activity", params={"action": "create_admin"})
    assert "throwaway-admin" in resp.text
    assert "activity-device" not in resp.text

    # both known actions surface as options for the dropdown
    resp = client.get("/activity")
    assert "issue" in resp.text
    assert "create_admin" in resp.text

    tomorrow = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)).date().isoformat()
    yesterday = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).date().isoformat()

    resp = client.get("/activity", params={"date_from": tomorrow})
    assert "activity-device" not in resp.text

    resp = client.get("/activity", params={"date_from": yesterday})
    assert "activity-device" in resp.text

    resp = client.get("/activity", params={"date_to": yesterday})
    assert "activity-device" not in resp.text

    # malformed date input is ignored rather than 500ing
    resp = client.get("/activity", params={"date_from": "not-a-date"})
    assert resp.status_code == 200
    assert "activity-device" in resp.text
