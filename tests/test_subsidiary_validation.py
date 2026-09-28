"""Subsidiary is a controlled list (HANDOFF-COMPLIANCE.md §2) — every
write path must reject a value outside db.SUBSIDIARIES."""

import uuid

from fastapi.testclient import TestClient

from app import auth, bulk_service, crl_push, db, pki
from app.main import create_app
from tests.conftest import login_as


def test_bulk_classify_rejects_unknown_subsidiary(app_settings):
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    rows = [
        bulk_service.BatchInputRow(identifier="device-1.example", subsidiary="Not A Real Company"),
        bulk_service.BatchInputRow(identifier="device-2.example", subsidiary=db.SUBSIDIARIES[0]),
    ]
    classified = bulk_service.classify(session, rows)
    assert classified[0].classification == "malformed"
    assert classified[0].reason == "unknown subsidiary"
    assert classified[1].classification == "valid"


def _write_throwaway_pki(app_settings, throwaway_pki):
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )


def _seed_super_admin(app_settings, username="root-admin"):
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    admin = db.Admin(
        username=username, password_hash=auth.hash_password("correcthorse123"),
        role=db.AdminRole.super_admin,
    )
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def test_issue_form_rejects_unknown_subsidiary(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_super_admin(app_settings)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    resp = client.post(
        "/certs/issue",
        data={
            "cn": "device-1.example",
            "request_id": str(uuid.uuid4()),
            "subsidiary": "Not A Real Company",
        },
    )
    assert resp.status_code == 400
    assert "Invalid subsidiary" in resp.text

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    from sqlalchemy import select

    assert session.scalar(select(db.Certificate)) is None


def test_issue_form_accepts_known_subsidiary(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_super_admin(app_settings)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    resp = client.post(
        "/certs/issue",
        data={
            "cn": "device-2.example",
            "request_id": str(uuid.uuid4()),
            "subsidiary": db.SUBSIDIARIES[0],
        },
        follow_redirects=False,
    )
    assert resp.status_code in (200, 303)
