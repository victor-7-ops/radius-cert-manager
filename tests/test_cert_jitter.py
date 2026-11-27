"""T3: jittered first-issuance validity, and reissue inheriting the
original's days instead of re-rolling."""

import uuid

from fastapi.testclient import TestClient

from app import cert_service, crl_push, db, pki
from app.main import create_app
from tests.conftest import create_test_device, login_as


def test_jittered_days_stays_within_range():
    seen = {cert_service.jittered_days(365, 35) for _ in range(200)}
    assert seen  # sanity: loop actually ran
    assert min(seen) >= 330
    assert max(seen) <= 400


def test_jittered_days_disabled_returns_base_unchanged():
    assert cert_service.jittered_days(365, 0) == 365
    assert cert_service.jittered_days(90, -5) == 90


def _write_throwaway_pki(app_settings, throwaway_pki):
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )


def test_reissue_inherits_original_days_not_rejittered(app_settings, throwaway_pki, monkeypatch):
    """A reissued cert keeps the same validity period as the one it
    replaces, so a device stays on a stable renewal anniversary."""
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    admin = db.Admin(username="reissue-admin", password_hash="x", role=db.AdminRole.super_admin)
    session.add(admin)
    session.commit()
    session.refresh(admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    device_id = create_test_device(app_settings)
    issue_resp = client.post(
        "/certs/issue",
        data={"cn": "renew-me", "request_id": str(uuid.uuid4()), "device_id": device_id},
        follow_redirects=False,
    )
    assert issue_resp.status_code == 303

    session2 = db.make_session_factory(engine)()
    original = session2.query(db.Certificate).filter_by(cn="renew-me").one()
    original_days = (original.expires_at - original.issued_at).days

    reissue_resp = client.post(f"/certs/{original.serial}/reissue", follow_redirects=False)
    assert reissue_resp.status_code == 303

    session3 = db.make_session_factory(engine)()
    new_cert = (
        session3.query(db.Certificate)
        .filter_by(cn="renew-me")
        .order_by(db.Certificate.issued_at.desc())
        .first()
    )
    new_days = (new_cert.expires_at - new_cert.issued_at).days
    assert new_days == original_days
