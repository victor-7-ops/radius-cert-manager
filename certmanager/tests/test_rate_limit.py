"""Rate limiting on CSV export and .p12/QR bundle downloads — scraping/
enumeration protection. In-process sliding window (app/rate_limit.py),
reset between tests by clearing its module-level bucket dict directly."""

import uuid

import pytest
from fastapi.testclient import TestClient

from app import auth, crl_push, db, pki, rate_limit
from app.main import create_app
from tests.conftest import login_as


@pytest.fixture(autouse=True)
def _reset_rate_limit_buckets():
    rate_limit._buckets.clear()
    yield
    rate_limit._buckets.clear()


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


def test_rate_limiter_unit_behavior():
    key = "unit-test-key"
    for _ in range(5):
        assert rate_limit.is_rate_limited(key, max_requests=5, window_seconds=60) is False
    assert rate_limit.is_rate_limited(key, max_requests=5, window_seconds=60) is True


def test_csv_export_is_rate_limited_per_admin(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "export-limit-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    for _ in range(10):
        resp = client.get("/certs/export.csv")
        assert resp.status_code == 200

    resp = client.get("/certs/export.csv")
    assert resp.status_code == 429


def test_csv_export_rate_limit_is_per_admin_not_global(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin_a = _seed_admin(app_settings, "export-limit-a", db.AdminRole.super_admin)
    admin_b = _seed_admin(app_settings, "export-limit-b", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client_a = TestClient(app)
    login_as(client_a, app_settings, admin_a)
    for _ in range(10):
        assert client_a.get("/certs/export.csv").status_code == 200
    assert client_a.get("/certs/export.csv").status_code == 429

    client_b = TestClient(app)
    login_as(client_b, app_settings, admin_b)
    assert client_b.get("/certs/export.csv").status_code == 200


def test_bundle_download_is_rate_limited(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "bundle-limit-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    # 30 attempts against nonexistent/consumed bundles still count against
    # the limiter — it guards the endpoint itself, not just successes
    for _ in range(30):
        resp = client.get("/certs/no-such-serial/bundle")
        assert resp.status_code == 410

    resp = client.get("/certs/no-such-serial/bundle")
    assert resp.status_code == 429


def test_bundle_qr_download_is_rate_limited_by_ip(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)

    app = create_app(app_settings)
    client = TestClient(app)  # unauthenticated — this route needs no login

    for _ in range(20):
        resp = client.get("/certs/no-such-serial/bundle/qr", params={"token": "garbage"})
        assert resp.status_code == 403  # invalid token, but not rate limited yet

    resp = client.get("/certs/no-such-serial/bundle/qr", params={"token": "garbage"})
    assert resp.status_code == 429


def test_real_bundle_download_still_works_within_limit(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "bundle-ok-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    issue_resp = client.post("/certs/issue", data={"cn": "rate-limit-device", "request_id": str(uuid.uuid4())})
    assert issue_resp.status_code == 200

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="rate-limit-device").one()

    resp = client.get(f"/certs/{cert.serial}/bundle")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/x-pkcs12"
