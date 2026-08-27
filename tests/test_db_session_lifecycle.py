"""Regression test for a real connection leak: every route called
deps.get_db_session() straight into session_factory() with nothing
ever closing the result, so each request left a checked-out connection
behind — under any sustained traffic the pool (size 5 + overflow 10)
exhausted and every request started raising sqlalchemy.exc.TimeoutError,
which is exactly what happened repeatedly against the live demo server
during manual verification of unrelated features this session.

Fixed by scoping one session per request via scoped_session, closed by
a middleware after the response — verified here by checking the
underlying connection pool has nothing checked out after each request,
across enough sequential requests that the old code would have
exhausted the pool (default size 5 + overflow 10 = 15) well before this
test's request count."""

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


def test_db_connections_are_returned_to_the_pool_after_each_request(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "pool-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    # 40 requests is well past the default pool_size=5 + max_overflow=10
    # ceiling — the pre-fix code would raise sqlalchemy.exc.TimeoutError
    # partway through this loop.
    for i in range(40):
        resp = client.get("/dashboard")
        assert resp.status_code == 200, f"request {i} failed: {resp.status_code} {resp.text[:200]}"

    # every request that used deps.regenerate_and_push_crl also went
    # through a mutation route — exercise those too, since that function
    # used to open its own separate, also-never-closed session.
    for i in range(10):
        client.post("/certs/issue", data={"cn": f"pool-check-device-{i}-{uuid.uuid4()}", "request_id": str(uuid.uuid4())})

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    assert session.query(db.Certificate).count() == 10
