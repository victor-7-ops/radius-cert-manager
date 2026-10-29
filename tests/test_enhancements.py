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


def test_bulk_network_template_csv_downloads(app_settings, throwaway_pki, monkeypatch):
    # app/routes/bulk.py's own template route (free-text, no subsidiary_id/
    # network_role_id) was removed -- real bulk onboarding is
    # /bulk/employees + /bulk/devices now (app/routes/bulk_network.py).
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "template-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    resp = client.get("/bulk/employees/template.csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert resp.text.startswith("subsidiary_code,department_code,display_name,employee_number")

    resp = client.get("/bulk/devices/template.csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert resp.text.startswith("subsidiary_code,employee_number,role_code")


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
    assert "One link" in issue_resp.text

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


def test_delivery_page_is_reloadable_until_bundle_actually_downloaded(app_settings, throwaway_pki, monkeypatch):
    """A QR/link token (10min) can outlive the admin's own page view --
    reloading /delivery must keep working (fresh token, same password)
    as long as nobody has actually downloaded the credential yet."""
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "reload-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    client.post("/certs/issue", data={"cn": "reload-device", "request_id": str(uuid.uuid4())})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="reload-device").one()

    first = client.get(f"/certs/{cert.serial}/delivery")
    assert first.status_code == 200
    second = client.get(f"/certs/{cert.serial}/delivery")
    assert second.status_code == 200  # same password shown, not a 404

    # Once the bundle is actually downloaded, the page is gone for good.
    client.get(f"/certs/{cert.serial}/bundle")
    third = client.get(f"/certs/{cert.serial}/delivery")
    assert third.status_code == 404


def test_onboard_bundle_pins_root_ca_and_ships_full_chain(app_settings, throwaway_pki, monkeypatch):
    """Regression for the live bug (29 Oct 2026): the Windows Wi-Fi
    profile's TrustedRootCA must point at the actual Root CA, not the
    intermediate -- Windows rejected with "the root certificate used
    for this network is invalid" when it was pinned to the
    intermediate, even though the intermediate cert itself was
    correctly installed. The zip must also carry both CA certs and
    import both on Windows (certutil -addstore CA / Root)."""
    import hashlib
    import io
    import zipfile

    from cryptography.hazmat.primitives import serialization

    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    # Two-tier PKI: write ca-chain.pem so app.main picks up deps.root_cert
    # (see app/main.py: ca_chain_path = settings.pki_path / "ca-chain.pem").
    (app_settings.pki_path / "ca-chain.pem").write_bytes(
        pki.cert_to_pem(throwaway_pki["root_cert"])
    )
    admin = _seed_admin(app_settings, "chain-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)
    client.post("/certs/issue", data={"cn": "chain-device", "request_id": str(uuid.uuid4())})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="chain-device").one()

    resp = client.get(f"/certs/{cert.serial}/windows-profile")
    assert resp.status_code == 200
    root_der = throwaway_pki["root_cert"].public_bytes(serialization.Encoding.DER)
    root_thumbprint = hashlib.sha1(root_der).hexdigest().lower()
    inter_der = throwaway_pki["inter_cert"].public_bytes(serialization.Encoding.DER)
    inter_thumbprint = hashlib.sha1(inter_der).hexdigest().lower()
    xml_hex = resp.text.replace(" ", "").lower()
    assert root_thumbprint in xml_hex
    assert inter_thumbprint not in xml_hex  # must pin the root, not the intermediate

    resp2 = client.get(f"/certs/{cert.serial}/onboard-bundle")
    assert resp2.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(resp2.content))
    names = zf.namelist()
    assert any(n.endswith("ca-root.pem") for n in names)
    assert any(n.endswith("ca-intermediate.pem") for n in names)
    assert any(n.endswith("ca-chain.pem") for n in names)
    install_cmd = next(n for n in names if n.endswith("Install.cmd"))
    install_cmd_text = zf.read(install_cmd).decode()
    assert "-addstore CA " in install_cmd_text
    assert "-addstore Root " in install_cmd_text


def test_root_crt_preferred_over_mislabeled_ca_chain_pem(app_settings, throwaway_pki, monkeypatch):
    """Regression for the exact live bug (29 Oct 2026, kc-laptop4): the
    hub's ca-chain.pem actually held the intermediate cert under a
    misleading name, while the real root sat at root.crt the whole
    time. load_cert_pem only reads the first cert in a file, so the
    mislabeled ca-chain.pem silently produced the intermediate's own
    thumbprint for TrustedRootCA -- the identical "root certificate
    invalid" failure the 29 Oct fix was supposed to have already
    closed. app/main.py must prefer root.crt when both exist."""
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    # Deliberately mislabel: ca-chain.pem actually holds the intermediate.
    (app_settings.pki_path / "ca-chain.pem").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    # The real root sits at root.crt, same as the live hub layout.
    (app_settings.pki_path / "root.crt").write_bytes(pki.cert_to_pem(throwaway_pki["root_cert"]))
    admin = _seed_admin(app_settings, "rootcrt-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)
    client.post("/certs/issue", data={"cn": "rootcrt-device", "request_id": str(uuid.uuid4())})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="rootcrt-device").one()

    resp = client.get(f"/certs/{cert.serial}/windows-profile")
    assert resp.status_code == 200
    import hashlib
    from cryptography.hazmat.primitives import serialization

    root_thumbprint = hashlib.sha1(
        throwaway_pki["root_cert"].public_bytes(serialization.Encoding.DER)
    ).hexdigest().lower()
    inter_thumbprint = hashlib.sha1(
        throwaway_pki["inter_cert"].public_bytes(serialization.Encoding.DER)
    ).hexdigest().lower()
    xml_hex = resp.text.replace(" ", "").lower()
    assert root_thumbprint in xml_hex
    assert inter_thumbprint not in xml_hex


def test_onboard_bundle_covers_every_authorized_site_ssid(app_settings, throwaway_pki, monkeypatch):
    """"Automatically install to any AP available" (production, multiple
    sites each with their own SSID): the zip/installers must cover every
    site the device's subsidiary is authorized at, not just one global
    SSID -- one Wi-Fi profile per site, each auto-connect, so whichever
    site the device is physically near just works."""
    import io
    import zipfile

    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "multisite-admin", db.AdminRole.admin)

    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    sub = db.Subsidiary(code="multisite-co", display_name="Multisite Co")
    session.add(sub)
    session.flush()
    site_a = db.Site(
        name="Site A", radius_cn="site-a.example.local",
        auth_token_hash=auth.hash_password("token-a"), wifi_ssid="SiteA-WiFi",
    )
    site_b = db.Site(
        name="Site B", radius_cn="site-b.example.local",
        auth_token_hash=auth.hash_password("token-b"), wifi_ssid="SiteB-WiFi",
    )
    session.add_all([site_a, site_b])
    session.flush()
    session.add_all([
        db.SiteSubsidiary(site_id=site_a.id, subsidiary_id=sub.id, is_active=True),
        db.SiteSubsidiary(site_id=site_b.id, subsidiary_id=sub.id, is_active=True),
    ])
    session.commit()

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)
    client.post("/certs/issue", data={"cn": "multisite-device", "request_id": str(uuid.uuid4())})

    session2 = db.make_session_factory(engine)()
    cert = session2.query(db.Certificate).filter_by(cn="multisite-device").one()
    cert.subsidiary_id = sub.id
    session2.commit()

    resp = client.get(f"/certs/{cert.serial}/onboard-bundle")
    assert resp.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = zf.namelist()
    assert any(n.endswith("SiteA-WiFi.xml") for n in names)
    assert any(n.endswith("SiteB-WiFi.xml") for n in names)
    install_cmd = zf.read(next(n for n in names if n.endswith("Install.cmd"))).decode()
    assert "SiteA-WiFi.xml" in install_cmd
    assert "SiteB-WiFi.xml" in install_cmd
    install_sh = zf.read(next(n for n in names if n.endswith("install.sh"))).decode()
    assert "SiteA-WiFi" in install_sh
    assert "SiteB-WiFi" in install_sh


def test_delete_employee_route_requires_platform_super_admin(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    plat_admin = _seed_admin(app_settings, "del-plat-admin", db.AdminRole.admin)
    # 'admin' role (not super_admin) must be refused -- route requires
    # deps.require_super_admin strictly, same as the legacy offboard route.

    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, plat_admin)
    r = client.get(f"/people/00000000-0000-0000-0000-000000000000/delete")
    assert r.status_code == 403  # 'admin' role, not platform super_admin


def test_department_options_route_returns_departments_for_subsidiary(app_settings, throwaway_pki, monkeypatch):
    """Regression: the Add Employee modal's subsidiary picker used to
    window.location.href on change, closing the whole modal. It now
    hx-gets this route instead -- just <option> tags, no page nav."""
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "deptopt-admin", db.AdminRole.admin)

    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    sub = session.query(db.Subsidiary).filter_by(code="topline").one()
    dept = db.Department(subsidiary_id=sub.id, code="deptopt", display_name="Dept <Options> Test")
    session.add(dept)
    session.commit()

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    resp = client.get("/departments/options", params={"subsidiary_id": sub.id})
    assert resp.status_code == 200
    assert "Dept &lt;Options&gt; Test" in resp.text
    assert dept.id in resp.text

    empty_resp = client.get("/departments/options", params={"subsidiary_id": "nonexistent"})
    assert empty_resp.status_code == 200
    assert "Select department" in empty_resp.text
    assert dept.id not in empty_resp.text


def test_delete_employee_route_deletes_clean_record(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    super_admin = _seed_admin(app_settings, "del-super-admin", db.AdminRole.super_admin)

    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    sub = session.query(db.Subsidiary).filter_by(code="topline").one()
    dept = db.Department(subsidiary_id=sub.id, code="del-test2", display_name="Delete Test Dept 2")
    session.add(dept)
    session.commit()

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, super_admin)
    client.post(
        "/people/new",
        data={"display_name": "Clean Record", "subsidiary_id": sub.id, "department_id": dept.id},
    )
    emp = session.query(db.Employee).filter_by(display_name="Clean Record").one()

    confirm_resp = client.get(f"/people/{emp.id}/delete")
    assert confirm_resp.status_code == 200

    resp = client.post(f"/people/{emp.id}/delete", data={"confirm_name": "Clean Record"})
    assert resp.status_code == 200
    assert resp.url.path == "/employees"

    session2 = db.make_session_factory(engine)()
    assert session2.get(db.Employee, emp.id) is None


def test_smart_install_serves_mobileconfig_on_apple_user_agent(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "install-mac-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)
    client.post("/certs/issue", data={"cn": "install-mac-device", "request_id": str(uuid.uuid4())})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="install-mac-device").one()
    token = auth.make_bundle_qr_token(app_settings.secret_key, cert.serial)

    anon_client = TestClient(app)
    resp = anon_client.get(
        f"/certs/{cert.serial}/install",
        params={"token": token},
        headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/x-apple-as-config"

    # single-use, same as the other QR flows
    resp2 = anon_client.get(
        f"/certs/{cert.serial}/install",
        params={"token": token},
        headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"},
    )
    assert resp2.status_code == 410


def test_smart_install_serves_zip_on_windows_user_agent(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "install-win-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)
    client.post("/certs/issue", data={"cn": "install-win-device", "request_id": str(uuid.uuid4())})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="install-win-device").one()
    token = auth.make_bundle_qr_token(app_settings.secret_key, cert.serial)

    anon_client = TestClient(app)
    resp = anon_client.get(
        f"/certs/{cert.serial}/install",
        params={"token": token},
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"

    import zipfile
    import io

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = zf.namelist()
    assert any(n.endswith("Install.cmd") for n in names)
    assert any(n.endswith("install.sh") for n in names)
    assert any(n.endswith(".mobileconfig") for n in names)
    assert any(n.endswith(".p12") for n in names)


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
