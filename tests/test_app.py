"""End-to-end smoke test of main.create_app wiring, against a throwaway PKI."""

import uuid

from fastapi.testclient import TestClient

from app import auth, crl_push, db, pki
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
    return admin


def test_issue_list_suspend_revoke_flow(app_settings, throwaway_pki, monkeypatch):
    # main.regenerate_and_push_crl calls crl_push.push_crl for real —
    # stub it so this test never spawns scp/ssh (handoff §12).
    monkeypatch.setattr(
        crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed")
    )
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "flow-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)

    from tests.conftest import login_as

    login_as(client, app_settings, admin)

    resp = client.post(
        "/api/certs",
        json={"cn": "e2e-device", "request_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 201, resp.text
    serial = resp.json()["serial"]

    bundle_resp = client.get(f"/api/certs/{serial}/bundle")
    assert bundle_resp.status_code == 200
    second_bundle_resp = client.get(f"/api/certs/{serial}/bundle")
    assert second_bundle_resp.status_code == 410

    list_resp = client.get("/api/certs")
    assert list_resp.status_code == 200
    assert any(c["serial"] == serial for c in list_resp.json()["items"])

    revoke_resp = client.post(f"/api/certs/{serial}/revoke", json={"reason": "lost laptop"})
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["status"] == "revoked"
