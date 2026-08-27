"""must_change_password enforcement + self-service password change.

The flag was already set by admin creation and password reset — it
just never did anything. require_admin now redirects anywhere else to
/account/change-password until it's cleared."""

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


def _seed_admin(app_settings, username, role, password="correcthorse123", must_change_password=False):
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    admin = db.Admin(
        username=username, password_hash=auth.hash_password(password), role=role,
        must_change_password=must_change_password,
    )
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def test_forced_admin_is_redirected_away_from_other_pages(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "forced-admin", db.AdminRole.admin, must_change_password=True)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/account/change-password"

    resp2 = client.get("/certs", follow_redirects=False)
    assert resp2.status_code == 303
    assert resp2.headers["location"] == "/account/change-password"


def test_forced_admin_can_reach_the_change_password_page_itself(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "forced-admin2", db.AdminRole.admin, must_change_password=True)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    resp = client.get("/account/change-password")
    assert resp.status_code == 200
    assert "temporary password" in resp.text

    # logout and the keepalive ping must not bounce either — no
    # redirect loop for the very mechanisms that would break the page
    assert client.post("/auth/logout", follow_redirects=False).status_code == 303


def test_change_password_clears_the_flag_and_new_password_works(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(
        app_settings, "forced-admin3", db.AdminRole.admin,
        password="temp-password-123", must_change_password=True,
    )

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    resp = client.post("/account/change-password", data={
        "current_password": "temp-password-123",
        "new_password": "brand-new-password-456",
        "confirm_password": "brand-new-password-456",
    }, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/dashboard")

    # the flag is cleared — now free to reach anywhere else
    resp2 = client.get("/dashboard")
    assert resp2.status_code == 200

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    reloaded = session.query(db.Admin).filter_by(username="forced-admin3").one()
    assert reloaded.must_change_password is False
    assert auth.verify_password("brand-new-password-456", reloaded.password_hash)
    assert not auth.verify_password("temp-password-123", reloaded.password_hash)


def test_change_password_rejects_wrong_current_password(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "wrong-current-admin", db.AdminRole.admin, must_change_password=True)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    resp = client.post("/account/change-password", data={
        "current_password": "totally-wrong",
        "new_password": "brand-new-password-456",
        "confirm_password": "brand-new-password-456",
    })
    assert resp.status_code == 400
    assert "incorrect" in resp.text

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    assert session.query(db.Admin).filter_by(username="wrong-current-admin").one().must_change_password is True


def test_change_password_rejects_mismatched_confirmation(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "mismatch-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    resp = client.post("/account/change-password", data={
        "current_password": "correcthorse123",
        "new_password": "brand-new-password-456",
        "confirm_password": "does-not-match",
    })
    assert resp.status_code == 400
    assert "match" in resp.text


def test_change_password_rejects_too_short_new_password(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "short-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    resp = client.post("/account/change-password", data={
        "current_password": "correcthorse123",
        "new_password": "short",
        "confirm_password": "short",
    })
    assert resp.status_code == 400
    assert str(auth.MIN_PASSWORD_LENGTH) in resp.text


def test_change_password_rejects_reusing_current_password(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "reuse-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    resp = client.post("/account/change-password", data={
        "current_password": "correcthorse123",
        "new_password": "correcthorse123",
        "confirm_password": "correcthorse123",
    })
    assert resp.status_code == 400
    assert "different" in resp.text


def test_unforced_admin_can_still_visit_the_page_voluntarily(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "voluntary-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    resp = client.get("/account/change-password")
    assert resp.status_code == 200
    assert "temporary password" not in resp.text
    assert "Back to your sessions" in resp.text


def test_admin_created_via_admin_form_is_forced_to_change_password(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    super_admin = _seed_admin(app_settings, "creator-super", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, super_admin)

    client.post("/admins", data={"username": "brand-new-admin", "role": "admin"})

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    new_admin = session.query(db.Admin).filter_by(username="brand-new-admin").one()
    assert new_admin.must_change_password is True
