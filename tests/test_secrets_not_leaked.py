"""§10 acceptance criterion: no CA key, client key, .p12 byte, or export
password appears in any error response or traceback sent to the client
— verified by deliberately triggering a signing failure. A catch-all
handler must return a generic message plus a correlation ID regardless
of what the underlying exception says (handoff §5.6)."""

import datetime

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


def _login(client, app_settings, admin):
    login_as(client, app_settings, admin)


def test_signing_failure_leaks_no_key_material_in_response(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "secrets-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app, raise_server_exceptions=False)
    _login(client, app_settings, admin)

    inter_key_pem = pki.private_key_to_pem(throwaway_pki["inter_key"])

    def boom(*a, **k):
        raise RuntimeError(f"signing exploded, key was {inter_key_pem!r}")

    monkeypatch.setattr(pki, "sign_client_cert", boom)

    resp = client.post("/api/certs", json={"cn": "leak-test-device", "request_id": "leak-1"})

    assert resp.status_code == 500
    body = resp.text
    assert inter_key_pem.decode() not in body
    assert "PRIVATE KEY" not in body
    assert "signing exploded" not in body  # no raw exception text either
    assert "correlation_id" in body
