"""System health page — combines CRL status, cert counts, DB/PKI disk
usage, active sessions, and CA-expiry/orphan warnings into one
ops-focused view. Super Admin only."""

import uuid

from fastapi.testclient import TestClient

from app import auth, crl_push, db, pki
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


def test_health_page_requires_super_admin(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    plain_admin = _seed_admin(app_settings, "plain-health-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, plain_admin)

    assert client.get("/health").status_code == 403


def test_health_page_shows_cert_counts_and_storage(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    super_admin = _seed_admin(app_settings, "health-super", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, super_admin)

    client.post("/certs/issue", data={"cn": "health-device-a", "request_id": str(uuid.uuid4())})
    client.post("/certs/issue", data={"cn": "health-device-b", "request_id": str(uuid.uuid4())})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="health-device-b").one()
    client.post(f"/certs/{cert.serial}/suspend", data={"reason": "test"})

    resp = client.get("/health")
    assert resp.status_code == 200
    assert "System health" in resp.text
    assert "Database file" in resp.text
    assert "PKI directory" in resp.text
    # 2 issued, one now suspended
    assert "Active sessions" in resp.text


def test_health_page_flags_ca_expiry_and_orphans(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    super_admin = _seed_admin(app_settings, "health-super2", db.AdminRole.super_admin)

    app = create_app(app_settings)  # startup import runs now, against an empty issued/ dir

    # drop a real, validly-signed .crt file into issued/ *after* startup
    # import already ran, with no matching DB row — that's what makes it
    # an orphan for reconcile_issued_dir to flag on the next request.
    key = pki.generate_private_key()
    csr = pki.build_csr(key, "orphan-health-device")
    serial = pki.generate_serial()
    cert = pki.sign_client_cert(csr, throwaway_pki["inter_cert"], throwaway_pki["inter_key"], serial, days=365)
    (app_settings.pki_path / "issued" / "orphan-health-device.crt").write_bytes(pki.cert_to_pem(cert))

    client = TestClient(app)
    login_as(client, app_settings, super_admin)

    resp = client.get("/health")
    assert resp.status_code == 200
    assert "Attention needed" in resp.text
    assert "no matching database row" in resp.text


def test_health_page_shows_on_standby_when_no_webhook_configured(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    super_admin = _seed_admin(app_settings, "health-super3", db.AdminRole.super_admin)
    assert app_settings.alert_webhook_url is None

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, super_admin)

    resp = client.get("/health")
    assert resp.status_code == 200
    assert "On standby" in resp.text
    assert "7 days" in resp.text  # default expiry_alert_days


def test_health_page_load_triggers_expiry_alert_and_posts_slack_json(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    super_admin = _seed_admin(app_settings, "health-super4", db.AdminRole.super_admin)
    app_settings.alert_webhook_url = "https://hooks.example.test/T000/B000/xxx"

    captured = {}

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["body"] = req.data
        return _FakeResponse()

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, super_admin)

    client.post("/certs/issue", data={
        "cn": "expiring-soon-device", "request_id": str(uuid.uuid4()),
    })
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="expiring-soon-device").one()
    import datetime
    cert.expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2)
    session.commit()

    resp = client.get("/health")
    assert resp.status_code == 200
    assert "expiring-soon-device" in resp.text
    assert "Just alerted" in resp.text

    assert captured, "no webhook request was sent"
    assert captured["headers"].get("Content-type") == "application/json"
    import json
    payload = json.loads(captured["body"])
    assert "text" in payload  # Slack incoming-webhook shape
    assert "expiring-soon-device" in payload["text"]

    # reloading the page again must not re-alert on the same cert
    captured.clear()
    resp2 = client.get("/health")
    assert "Just alerted" not in resp2.text
    assert not captured
