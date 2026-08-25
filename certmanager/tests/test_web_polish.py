"""Phase I coverage: acceptance-criteria items not exercised by earlier
phases — last-Super-Admin protection through the real route, the
"expired" filter (computed, not a stored status), and HTML error pages
for web routes instead of raw JSON."""

import datetime
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
    return admin, session


def _login(client, app_settings, admin):
    cookie = auth._serializer(app_settings.secret_key).dumps(
        {"sub": admin.id, "tv": admin.token_version, "session_start": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    )
    client.cookies.set(auth.SESSION_COOKIE, cookie)


def test_last_active_super_admin_cannot_be_deactivated(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin, _ = _seed_admin(app_settings, "only-super-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    resp = client.post(f"/admins/{admin.id}/deactivate")
    assert resp.status_code == 409

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    reloaded = session.get(db.Admin, admin.id)
    assert reloaded.is_active is True


def test_second_super_admin_can_be_deactivated_when_two_exist(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin, session = _seed_admin(app_settings, "first-super", db.AdminRole.super_admin)
    second = db.Admin(username="second-super", password_hash=auth.hash_password("x"), role=db.AdminRole.super_admin)
    session.add(second)
    session.commit()
    session.refresh(second)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    resp = client.post(f"/admins/{second.id}/deactivate", follow_redirects=False)
    assert resp.status_code == 303

    reloaded_session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    reloaded = reloaded_session.get(db.Admin, second.id)
    assert reloaded.is_active is False


def test_expired_filter_matches_active_certs_past_expiry(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin, session = _seed_admin(app_settings, "expiry-admin", db.AdminRole.super_admin)

    # Issue with a 1-day lifetime then backdate expires_at into the past
    # to simulate an aged-out cert without waiting a year.
    result = cert_service.issue_certificate(
        session, app_settings.pki_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="aged-out-device", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=1,
    )
    result.certificate.expires_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    session.commit()

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    resp = client.get("/certs?status=expired")
    assert resp.status_code == 200
    assert "aged-out-device" in resp.text

    resp_active = client.get("/certs?status=active")
    assert "aged-out-device" not in resp_active.text


def test_web_route_404_renders_html_error_page_not_json(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin, _ = _seed_admin(app_settings, "error-page-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    resp = client.get("/certs/does-not-exist-serial")
    assert resp.status_code == 404
    assert "text/html" in resp.headers["content-type"]
    assert "Not found" in resp.text


def test_api_route_404_still_returns_json(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin, _ = _seed_admin(app_settings, "api-error-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    resp = client.get("/api/certs/does-not-exist-serial")
    assert resp.status_code == 404
    assert resp.json()["error"]["message"] == "not found"
