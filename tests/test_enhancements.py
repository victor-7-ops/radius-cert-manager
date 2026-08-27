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
from tests.conftest import login_as


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
    login_as(client, app_settings, admin)


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


def test_bulk_suspend(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "bulk-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    client.post("/certs/issue", data={"cn": "bulk-a", "request_id": str(uuid.uuid4())})
    client.post("/certs/issue", data={"cn": "bulk-b", "request_id": str(uuid.uuid4())})
    client.post("/certs/issue", data={"cn": "bulk-c", "request_id": str(uuid.uuid4())})

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    a = session.query(db.Certificate).filter_by(cn="bulk-a").one()
    b = session.query(db.Certificate).filter_by(cn="bulk-b").one()

    resp = client.post(
        "/certs/bulk-action",
        data={"action": "suspend", "reason": "quarterly sweep", "serials": [a.serial, b.serial, "does-not-exist"]},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert "flash=" in location
    assert "flash_kind=warn" in location

    session.expire_all()
    assert session.query(db.Certificate).filter_by(cn="bulk-a").one().status == db.CertStatus.suspended
    assert session.query(db.Certificate).filter_by(cn="bulk-b").one().status == db.CertStatus.suspended
    assert session.query(db.Certificate).filter_by(cn="bulk-c").one().status == db.CertStatus.active


def test_bulk_revoke_requires_super_admin(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    plain_admin = _seed_admin(app_settings, "not-super", db.AdminRole.admin)
    super_admin = _seed_admin(app_settings, "is-super", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)

    _login(client, app_settings, plain_admin)
    client.post("/certs/issue", data={"cn": "bulk-revoke-target", "request_id": str(uuid.uuid4())})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="bulk-revoke-target").one()

    resp = client.post("/certs/bulk-action", data={"action": "revoke", "serials": [cert.serial]})
    assert resp.status_code == 403
    session.expire_all()
    assert session.query(db.Certificate).filter_by(cn="bulk-revoke-target").one().status == db.CertStatus.active

    _login(client, app_settings, super_admin)
    resp = client.post("/certs/bulk-action", data={"action": "revoke", "serials": [cert.serial]}, follow_redirects=False)
    assert resp.status_code == 303
    assert "flash_kind=danger" in resp.headers["location"]
    session.expire_all()
    assert session.query(db.Certificate).filter_by(cn="bulk-revoke-target").one().status == db.CertStatus.revoked


def test_bulk_action_rejects_invalid_action_name(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "bulk-invalid-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    resp = client.post("/certs/bulk-action", data={"action": "delete-everything", "serials": ["whatever"]})
    assert resp.status_code == 400


def test_cert_search_matches_mac_and_serial(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "search-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    client.post("/certs/issue", data={
        "cn": "search-target-device", "request_id": str(uuid.uuid4()),
        "device_mac": "AA:BB:CC:11:22:33", "device_serial": "ASSET-7788",
    })
    client.post("/certs/issue", data={"cn": "search-other-device", "request_id": str(uuid.uuid4())})

    # MAC search is format-insensitive — normalized the same way at issue
    # time and at query time, so dashes/no-separator still find a
    # colon-stored MAC.
    resp = client.get("/certs", params={"q": "aa-bb-cc-11-22-33"})
    assert "search-target-device" in resp.text
    assert "search-other-device" not in resp.text

    resp = client.get("/certs", params={"q": "ASSET-7788"})
    assert "search-target-device" in resp.text
    assert "search-other-device" not in resp.text

    # a MAC-shaped substring that isn't a full MAC still falls back to a
    # plain substring match against the stored (normalized) value
    resp = client.get("/certs", params={"q": "cc:11"})
    assert "search-target-device" in resp.text


def test_delivery_page_qr_download_works_once_without_login(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "qr-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    issue_resp = client.post("/certs/issue", data={"cn": "qr-device", "request_id": str(uuid.uuid4())})
    assert issue_resp.status_code == 200  # delivery page after redirect-follow
    assert "Scan on the device instead" in issue_resp.text

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="qr-device").one()

    token = auth.make_bundle_qr_token(app_settings.secret_key, cert.serial)

    # a fresh, unauthenticated client — the whole point is this works on
    # a device with no admin session
    anon_client = TestClient(app)
    resp = anon_client.get(f"/certs/{cert.serial}/bundle/qr", params={"token": token})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/x-pkcs12"

    # single-use, same as the authenticated download link
    resp2 = anon_client.get(f"/certs/{cert.serial}/bundle/qr", params={"token": token})
    assert resp2.status_code == 410


def test_delivery_page_qr_download_rejects_bad_token(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "qr-bad-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    client.post("/certs/issue", data={"cn": "qr-bad-device", "request_id": str(uuid.uuid4())})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="qr-bad-device").one()

    anon_client = TestClient(app)
    resp = anon_client.get(f"/certs/{cert.serial}/bundle/qr", params={"token": "garbage"})
    assert resp.status_code == 403

    # a token minted for a different serial must not unlock this one
    other_token = auth.make_bundle_qr_token(app_settings.secret_key, "some-other-serial")
    resp2 = anon_client.get(f"/certs/{cert.serial}/bundle/qr", params={"token": other_token})
    assert resp2.status_code == 403


def test_issue_warns_on_duplicate_mac_and_can_be_overridden(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "dup-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    client.post("/certs/issue", data={
        "cn": "dup-mac-first", "request_id": str(uuid.uuid4()), "device_mac": "aa:bb:cc:11:22:33",
    })

    # a second device with the same MAC (typed in a different format) is
    # flagged rather than silently issued
    resp = client.post("/certs/issue", data={
        "cn": "dup-mac-second", "request_id": str(uuid.uuid4()), "device_mac": "AA-BB-CC-11-22-33",
    })
    assert resp.status_code == 200
    assert "already on an active certificate" in resp.text
    assert "dup-mac-first" in resp.text

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    assert session.query(db.Certificate).filter_by(cn="dup-mac-second").first() is None

    # re-submitting with confirm_duplicate=1 (what the "Issue anyway"
    # button sends) goes through
    resp2 = client.post("/certs/issue", data={
        "cn": "dup-mac-second", "request_id": str(uuid.uuid4()),
        "device_mac": "AA-BB-CC-11-22-33", "confirm_duplicate": "1",
    })
    assert resp2.status_code == 200
    session.expire_all()
    assert session.query(db.Certificate).filter_by(cn="dup-mac-second").one().device_mac == "aa:bb:cc:11:22:33"


def test_issue_warns_on_duplicate_serial_but_not_against_revoked_certs(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "dup-serial-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    client.post("/certs/issue", data={
        "cn": "dup-serial-first", "request_id": str(uuid.uuid4()), "device_serial": "ASSET-9999",
    })

    resp = client.post("/certs/issue", data={
        "cn": "dup-serial-second", "request_id": str(uuid.uuid4()), "device_serial": "ASSET-9999",
    })
    assert "already on an active certificate" in resp.text

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    first = session.query(db.Certificate).filter_by(cn="dup-serial-first").one()
    client.post(f"/certs/{first.serial}/revoke", data={"reason": "decommissioned"})

    # once the original is revoked, reusing its serial/asset tag no
    # longer needs an override — this is the normal hardware-reuse case
    resp2 = client.post("/certs/issue", data={
        "cn": "dup-serial-third", "request_id": str(uuid.uuid4()), "device_serial": "ASSET-9999",
    })
    assert "already on an active certificate" not in resp2.text
    session.expire_all()
    assert session.query(db.Certificate).filter_by(cn="dup-serial-third").one().device_serial == "ASSET-9999"
