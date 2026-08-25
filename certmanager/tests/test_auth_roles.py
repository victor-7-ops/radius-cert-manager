import datetime

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from app import auth, db


@pytest.fixture
def session_factory(tmp_path):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    return db.make_session_factory(engine)


@pytest.fixture
def secret_key():
    return "s" * 40


@pytest.fixture
def app_client(session_factory, secret_key):
    require_admin, require_super_admin = auth.get_current_admin_factory(
        get_db_session=lambda: session_factory(),
        get_secret_key=lambda: secret_key,
    )

    app = FastAPI()

    @app.get("/api/certs")
    def list_certs(admin: db.Admin = Depends(require_admin)):
        return {"ok": True}

    @app.post("/api/certs/x/revoke")
    def revoke(admin: db.Admin = Depends(require_super_admin)):
        return {"ok": True}

    @app.post("/api/admins")
    def create_admin(admin: db.Admin = Depends(require_super_admin)):
        return {"ok": True}

    client = TestClient(app)
    return client


def make_admin(session_factory, username, role, password="correct horse battery staple"):
    session = session_factory()
    admin = db.Admin(
        username=username, password_hash=auth.hash_password(password), role=role
    )
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def cookie_for(secret_key, admin):
    return auth._serializer(secret_key).dumps(
        {
            "sub": admin.id,
            "tv": admin.token_version,
            "session_start": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
    )


@pytest.mark.parametrize(
    "path,method",
    [("/api/certs/x/revoke", "post"), ("/api/admins", "post")],
)
def test_admin_gets_403_on_super_admin_routes(
    app_client, session_factory, secret_key, path, method
):
    admin = make_admin(session_factory, "regular-admin", db.AdminRole.admin)
    app_client.cookies.set(auth.SESSION_COOKIE, cookie_for(secret_key, admin))
    resp = getattr(app_client, method)(path)
    assert resp.status_code == 403


def test_super_admin_can_access_super_admin_route(app_client, session_factory, secret_key):
    admin = make_admin(session_factory, "root-admin", db.AdminRole.super_admin)
    app_client.cookies.set(auth.SESSION_COOKIE, cookie_for(secret_key, admin))
    resp = app_client.post("/api/certs/x/revoke")
    assert resp.status_code == 200


def test_no_cookie_is_401(app_client):
    resp = app_client.get("/api/certs")
    assert resp.status_code == 401


def test_deactivating_admin_invalidates_live_session(app_client, session_factory, secret_key):
    admin = make_admin(session_factory, "will-deactivate", db.AdminRole.admin)
    cookie = cookie_for(secret_key, admin)
    app_client.cookies.set(auth.SESSION_COOKIE, cookie)
    assert app_client.get("/api/certs").status_code == 200

    session = session_factory()
    live = session.get(db.Admin, admin.id)
    auth.bump_token_version(session, live)

    resp = app_client.get("/api/certs")
    assert resp.status_code == 401


def test_lockout_after_five_failed_attempts(session_factory):
    session = session_factory()
    make_admin(session_factory, "lockout-target", db.AdminRole.admin, password="realpassword123")

    for _ in range(auth.LOCKOUT_MAX_ATTEMPTS):
        result = auth.attempt_login(session, "lockout-target", "wrong")
        assert result.ok is False

    result = auth.attempt_login(session, "lockout-target", "realpassword123")
    assert result.ok is False
    assert result.locked is True


def test_generic_failure_no_user_enumeration(session_factory):
    session = session_factory()
    make_admin(session_factory, "real-user", db.AdminRole.admin, password="realpassword123")

    unknown = auth.attempt_login(session, "does-not-exist", "whatever")
    wrong_pw = auth.attempt_login(session, "real-user", "wrong")

    assert unknown.ok is False and unknown.admin is None
    assert wrong_pw.ok is False and wrong_pw.admin is None


def test_password_hash_is_argon2id():
    h = auth.hash_password("hunter2hunter2")
    assert h.startswith("$argon2id$")
    assert auth.verify_password("hunter2hunter2", h)
    assert not auth.verify_password("wrong", h)
