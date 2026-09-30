"""Renewal campaign UI/routes (HANDOFF-LIFECYCLE.md §2)."""

import datetime
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import auth, cert_service, crl_push, db, pki
from app.main import create_app
from tests.conftest import login_as


def _write_throwaway_pki(app_settings, throwaway_pki):
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )


def _seed_admin(app_settings, username="admin-1", role=db.AdminRole.super_admin, subsidiary_scope=None):
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    admin = db.Admin(
        username=username, password_hash=auth.hash_password("correcthorse123"),
        role=role, subsidiary_scope=subsidiary_scope,
    )
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def _client(app_settings, throwaway_pki, monkeypatch, **admin_kwargs):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, **admin_kwargs)
    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)
    return client, app_settings


def _issue_with_expiry(app_settings, throwaway_pki, cn, days_until_expiry, employee_name=None, subsidiary=None):
    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    result = cert_service.issue_certificate(
        session, app_settings.pki_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn=cn, note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
        device=cert_service.DeviceInfo(employee_name=employee_name, subsidiary=subsidiary),
    )
    cert = session.get(db.Certificate, result.certificate.id)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert.expires_at = now + datetime.timedelta(days=days_until_expiry)
    session.commit()
    return cert


def test_cohort_counts_match_direct_query(app_settings, throwaway_pki, monkeypatch):
    client, app_settings = _client(app_settings, throwaway_pki, monkeypatch)
    _issue_with_expiry(app_settings, throwaway_pki, "in-window-1", 10)
    _issue_with_expiry(app_settings, throwaway_pki, "in-window-2", 25)
    _issue_with_expiry(app_settings, throwaway_pki, "out-of-window", 60)

    resp = client.get("/renewals?window=30")
    assert resp.status_code == 200
    assert "in-window-1" in resp.text
    assert "in-window-2" in resp.text
    assert "out-of-window" not in resp.text


def test_export_matches_onscreen_list(app_settings, throwaway_pki, monkeypatch):
    client, app_settings = _client(app_settings, throwaway_pki, monkeypatch)
    _issue_with_expiry(app_settings, throwaway_pki, "export-me", 10, employee_name="Jane Doe")

    page = client.get("/renewals?window=30")
    csv_resp = client.get("/renewals/export.csv?window=30")
    assert csv_resp.status_code == 200
    assert "export-me" in page.text
    assert "export-me" in csv_resp.text
    assert "Jane Doe" in csv_resp.text


def test_reissued_certificate_moves_from_outstanding_to_done(app_settings, throwaway_pki, monkeypatch):
    client, app_settings = _client(app_settings, throwaway_pki, monkeypatch)
    cert = _issue_with_expiry(app_settings, throwaway_pki, "renew-me", 10)

    resp = client.get("/renewals?window=30")
    assert "Outstanding" in resp.text

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    cert_service.reissue_certificate(
        session, app_settings.pki_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        old_serial=cert.serial, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    )

    resp = client.get("/renewals?window=30")
    assert "Done" in resp.text


def test_retire_removes_cert_from_cohort_and_records_reason(app_settings, throwaway_pki, monkeypatch):
    client, app_settings = _client(app_settings, throwaway_pki, monkeypatch)
    cert = _issue_with_expiry(app_settings, throwaway_pki, "retiring-device", 10)

    resp = client.post(f"/certs/{cert.serial}/retire", data={"reason": "device decommissioned"}, follow_redirects=False)
    assert resp.status_code == 303

    resp = client.get("/renewals?window=30")
    assert "retiring-device" not in resp.text

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    row = session.scalar(select(db.Certificate).where(db.Certificate.cn == "retiring-device"))
    assert row.retired_at is not None

    audit_row = session.scalar(select(db.AuditLog).where(db.AuditLog.action == "cert_retire"))
    assert audit_row is not None
    assert "device decommissioned" in audit_row.detail


def test_subsidiary_scoping_applies(app_settings, throwaway_pki, monkeypatch):
    client, app_settings = _client(
        app_settings, throwaway_pki, monkeypatch,
        username="scoped-admin", role=db.AdminRole.admin, subsidiary_scope="Bay Mall",
    )
    _issue_with_expiry(app_settings, throwaway_pki, "in-scope", 10, subsidiary="Bay Mall")
    _issue_with_expiry(app_settings, throwaway_pki, "out-of-scope", 10, subsidiary="BMEAD")
    resp = client.get("/renewals?window=30")
    assert "in-scope" in resp.text
    assert "out-of-scope" not in resp.text


def test_viewer_cannot_export_or_retire(app_settings, throwaway_pki, monkeypatch):
    client, app_settings = _client(app_settings, throwaway_pki, monkeypatch, username="viewer-1", role=db.AdminRole.viewer)
    cert = _issue_with_expiry(app_settings, throwaway_pki, "device-1", 10)
    assert client.get("/renewals/export.csv?window=30").status_code == 403
    assert client.post(f"/certs/{cert.serial}/retire", data={"reason": "x"}).status_code == 403
    assert client.get("/renewals?window=30").status_code == 200
