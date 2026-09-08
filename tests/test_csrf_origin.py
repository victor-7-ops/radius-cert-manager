"""Coverage for the Origin-check CSRF middleware (app/main.py). Defense
in depth on top of the SameSite=Strict session cookie: a state-changing
request carrying the admin session cookie must have a matching Origin
(or Referer) when one is present."""

from fastapi.testclient import TestClient

from app import auth, db, pki
from app.main import create_app
from tests.conftest import login_as


def _write_throwaway_pki(app_settings, throwaway_pki):
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )


def _seed_admin(app_settings):
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    admin = db.Admin(
        username="csrf-admin", password_hash=auth.hash_password("correcthorse123"), role=db.AdminRole.super_admin
    )
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def test_mismatched_origin_rejected(app_settings, throwaway_pki):
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings)
    app = create_app(app_settings)
    client = TestClient(app, base_url="https://testserver")
    login_as(client, app_settings, admin)

    resp = client.post(
        f"/admins/{admin.id}/force-logout",
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status_code == 403


def test_matching_origin_allowed(app_settings, throwaway_pki):
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings)
    app = create_app(app_settings)
    client = TestClient(app, base_url="https://testserver")
    login_as(client, app_settings, admin)

    resp = client.post(
        f"/admins/{admin.id}/force-logout",
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert resp.status_code != 403


def test_no_origin_header_allowed(app_settings, throwaway_pki):
    # Non-browser / API-style callers that send neither Origin nor
    # Referer aren't the threat this middleware guards against — a
    # forged cross-origin *browser* request always carries Origin.
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings)
    app = create_app(app_settings)
    client = TestClient(app, base_url="https://testserver")
    login_as(client, app_settings, admin)

    resp = client.post(f"/admins/{admin.id}/force-logout", follow_redirects=False)
    assert resp.status_code != 403


def test_unauthenticated_request_not_subject_to_check(app_settings, throwaway_pki):
    # No session cookie in play (e.g. the login route itself) — the
    # middleware must not interfere with it regardless of Origin.
    _write_throwaway_pki(app_settings, throwaway_pki)
    app = create_app(app_settings)
    client = TestClient(app, base_url="https://testserver")

    resp = client.post(
        "/auth/login",
        data={"username": "nobody", "password": "wrong"},
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status_code != 403
