"""Per-session tracking: an admin can see and end their own active
sessions individually, rather than the previous all-or-nothing
token_version bump. Route-level tests use the real HTTP layer."""

from fastapi.testclient import TestClient

from app import auth, crl_push, db, pki
from app.main import create_app
from tests.conftest import login_as


def _client(app):
    # https base_url, not http://testserver's default — the session
    # cookie is Secure, and httpx's real cookie jar (used whenever the
    # server sets it via a real login, as opposed to hand-installing one
    # with .cookies.set()) won't send a Secure cookie back over http.
    return TestClient(app, base_url="https://testserver")


def _write_throwaway_pki(app_settings, throwaway_pki):
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )


def _seed_admin(app_settings, username, role=db.AdminRole.admin):
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    admin = db.Admin(username=username, password_hash=auth.hash_password("correcthorse123"), role=role)
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def test_login_creates_a_session_row_visible_in_the_list(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "sessions-admin")

    app = create_app(app_settings)
    client = _client(app)
    resp = client.post("/auth/login", data={"username": "sessions-admin", "password": "correcthorse123"})
    assert resp.status_code == 200  # dashboard, after redirect-follow

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    rows = session.query(db.AdminSession).filter_by(admin_id=admin.id).all()
    assert len(rows) == 1
    assert rows[0].revoked_at is None

    resp = client.get("/account/sessions")
    assert resp.status_code == 200
    assert "This device" in resp.text


def test_second_login_creates_a_second_independent_session(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "two-device-admin")

    app = create_app(app_settings)
    laptop = _client(app)
    phone = _client(app)
    laptop.post("/auth/login", data={"username": "two-device-admin", "password": "correcthorse123"})
    phone.post("/auth/login", data={"username": "two-device-admin", "password": "correcthorse123"})

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    rows = session.query(db.AdminSession).filter_by(admin_id=admin.id).all()
    assert len(rows) == 2

    # each client only sees "This device" on its own row, not the other's
    laptop_list = laptop.get("/account/sessions").text
    assert laptop_list.count("This device") == 1


def test_revoking_another_session_logs_it_out_but_not_the_current_one(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "revoke-admin")

    app = create_app(app_settings)
    laptop = _client(app)
    phone = _client(app)
    laptop.post("/auth/login", data={"username": "revoke-admin", "password": "correcthorse123"})
    phone.post("/auth/login", data={"username": "revoke-admin", "password": "correcthorse123"})

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    phone_record = session.query(db.AdminSession).filter_by(admin_id=admin.id).order_by(db.AdminSession.created_at).all()[1]

    assert phone.get("/dashboard").status_code == 200

    revoke_resp = laptop.post(f"/account/sessions/{phone_record.id}/revoke", follow_redirects=False)
    assert revoke_resp.status_code == 303

    # phone's session is now dead...
    assert phone.get("/dashboard", follow_redirects=False).status_code in (303, 401)
    # ...but laptop's own session is untouched
    assert laptop.get("/dashboard").status_code == 200


def test_cannot_revoke_someone_elses_session(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    _seed_admin(app_settings, "victim-admin")
    attacker = _seed_admin(app_settings, "attacker-admin")

    app = create_app(app_settings)
    victim_client = _client(app)
    victim_client.post("/auth/login", data={"username": "victim-admin", "password": "correcthorse123"})

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    victim_record = session.query(db.AdminSession).filter_by(admin_id=session.query(db.Admin).filter_by(username="victim-admin").one().id).one()

    attacker_client = _client(app)
    login_as(attacker_client, app_settings, attacker)

    resp = attacker_client.post(f"/account/sessions/{victim_record.id}/revoke")
    assert resp.status_code == 404

    session.expire_all()
    assert session.get(db.AdminSession, victim_record.id).revoked_at is None


def test_cannot_revoke_current_session_via_this_route(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    _seed_admin(app_settings, "self-revoke-admin")

    app = create_app(app_settings)
    client = _client(app)
    client.post("/auth/login", data={"username": "self-revoke-admin", "password": "correcthorse123"})

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    admin = session.query(db.Admin).filter_by(username="self-revoke-admin").one()
    record = session.query(db.AdminSession).filter_by(admin_id=admin.id).one()

    resp = client.post(f"/account/sessions/{record.id}/revoke")
    assert resp.status_code == 400


def test_logout_revokes_the_session_row(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    _seed_admin(app_settings, "logout-admin")

    app = create_app(app_settings)
    client = _client(app)
    client.post("/auth/login", data={"username": "logout-admin", "password": "correcthorse123"})
    client.post("/auth/logout")

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    admin = session.query(db.Admin).filter_by(username="logout-admin").one()
    record = session.query(db.AdminSession).filter_by(admin_id=admin.id).one()
    assert record.revoked_at is not None


def test_deactivating_admin_revokes_all_their_sessions(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    super_admin = _seed_admin(app_settings, "deactivate-super", db.AdminRole.super_admin)
    target = _seed_admin(app_settings, "gets-deactivated")

    app = create_app(app_settings)
    target_client = _client(app)
    target_client.post("/auth/login", data={"username": "gets-deactivated", "password": "correcthorse123"})
    assert target_client.get("/dashboard").status_code == 200

    super_client = _client(app)
    login_as(super_client, app_settings, super_admin)
    super_client.post(f"/admins/{target.id}/deactivate")

    assert target_client.get("/dashboard", follow_redirects=False).status_code in (303, 401)

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    rows = session.query(db.AdminSession).filter_by(admin_id=target.id).all()
    assert all(r.revoked_at is not None for r in rows)


def test_cookie_from_before_session_tracking_is_rejected(app_settings, throwaway_pki, monkeypatch):
    # Regression guard for the sid-less cookie format that existed before
    # this feature — must not be silently treated as still valid.
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "old-cookie-admin")

    import datetime
    old_style_cookie = auth._serializer(app_settings.secret_key).dumps({
        "sub": admin.id, "tv": admin.token_version,
        "session_start": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })

    app = create_app(app_settings)
    client = _client(app)
    client.cookies.set(auth.SESSION_COOKIE, old_style_cookie)
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code in (303, 401)
