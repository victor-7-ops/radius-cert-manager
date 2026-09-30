"""Employee offboarding (HANDOFF-LIFECYCLE.md §1.2)."""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import auth, cert_service, crl_push, db, pki
from app.main import create_app
from app.validation import normalize_employee_key
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


def _issue(app_settings, throwaway_pki, cn, employee_name, subsidiary=None, request_id=None):
    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    return cert_service.issue_certificate(
        session, app_settings.pki_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn=cn, note=None, request_id=request_id or str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
        device=cert_service.DeviceInfo(employee_name=employee_name, subsidiary=subsidiary),
    )


def test_offboard_revokes_all_active_and_suspended_only(app_settings, throwaway_pki, monkeypatch):
    client, app_settings = _client(app_settings, throwaway_pki, monkeypatch)
    _issue(app_settings, throwaway_pki, "laptop-1", "Jordan Ellis")
    _issue(app_settings, throwaway_pki, "phone-1", "Jordan Ellis")
    already_revoked = _issue(app_settings, throwaway_pki, "tablet-1", "Jordan Ellis")

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    cert_service.revoke(session, app_settings.pki_path, already_revoked.certificate.serial, "prior", "alice")

    key = normalize_employee_key("Jordan Ellis")
    resp = client.post(
        f"/employees/{key}/offboard",
        data={"confirm_name": "Jordan Ellis", "reason": "left the company"},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    certs = session.scalars(select(db.Certificate).where(db.Certificate.employee_key == key)).all()
    assert {c.cn: c.status for c in certs} == {
        "laptop-1": db.CertStatus.revoked,
        "phone-1": db.CertStatus.revoked,
        "tablet-1": db.CertStatus.revoked,
    }
    for c in certs:
        if c.cn != "tablet-1":
            assert c.reason == "left the company"
    # the already-revoked one was skipped, not re-revoked with the new reason
    tablet = next(c for c in certs if c.cn == "tablet-1")
    assert tablet.reason == "prior"


def test_offboard_writes_one_summary_audit_row(app_settings, throwaway_pki, monkeypatch):
    client, app_settings = _client(app_settings, throwaway_pki, monkeypatch)
    _issue(app_settings, throwaway_pki, "laptop-2", "Sam Reyes")
    _issue(app_settings, throwaway_pki, "phone-2", "Sam Reyes")

    key = normalize_employee_key("Sam Reyes")
    client.post(f"/employees/{key}/offboard", data={"confirm_name": "Sam Reyes"})

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    summary_rows = session.scalars(
        select(db.AuditLog).where(db.AuditLog.action == "employee_offboard")
    ).all()
    assert len(summary_rows) == 1
    assert summary_rows[0].target == "Sam Reyes"


def test_offboard_regenerates_crl_containing_every_revoked_serial(app_settings, throwaway_pki, monkeypatch):
    client, app_settings = _client(app_settings, throwaway_pki, monkeypatch)
    a = _issue(app_settings, throwaway_pki, "laptop-3", "Alex Kim")
    b = _issue(app_settings, throwaway_pki, "phone-3", "Alex Kim")

    key = normalize_employee_key("Alex Kim")
    resp = client.post(f"/employees/{key}/offboard", data={"confirm_name": "Alex Kim"}, follow_redirects=False)
    assert resp.status_code == 303

    from cryptography import x509

    crl_path = app_settings.pki_path / "crl.pem"
    assert crl_path.exists()
    crl = x509.load_pem_x509_crl(crl_path.read_bytes())
    revoked_serials = {str(r.serial_number) for r in crl}
    assert a.certificate.serial in revoked_serials
    assert b.certificate.serial in revoked_serials


def test_offboard_confirm_name_mismatch_does_not_revoke(app_settings, throwaway_pki, monkeypatch):
    client, app_settings = _client(app_settings, throwaway_pki, monkeypatch)
    _issue(app_settings, throwaway_pki, "laptop-4", "Taylor Cruz")

    key = normalize_employee_key("Taylor Cruz")
    resp = client.post(f"/employees/{key}/offboard", data={"confirm_name": "wrong name"})
    assert resp.status_code == 400
    assert "Typed name" in resp.text

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    cert = session.scalar(select(db.Certificate).where(db.Certificate.cn == "laptop-4"))
    assert cert.status == db.CertStatus.active


def test_scoped_admin_cannot_see_or_act_on_out_of_scope_employee(app_settings, throwaway_pki, monkeypatch):
    client, app_settings = _client(
        app_settings, throwaway_pki, monkeypatch,
        username="scoped-admin", role=db.AdminRole.admin, subsidiary_scope="Lezzgo Boracay",
    )
    _issue(app_settings, throwaway_pki, "laptop-5", "Casey Dela Cruz", subsidiary="Bay Mall")
    key = normalize_employee_key("Casey Dela Cruz")

    resp = client.get(f"/employees/{key}")
    assert resp.status_code == 404

    resp = client.post(f"/employees/{key}/offboard", data={"confirm_name": "Casey Dela Cruz"})
    assert resp.status_code in (403, 404)  # super-admin gate fires first for a regular admin

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    cert = session.scalar(select(db.Certificate).where(db.Certificate.cn == "laptop-5"))
    assert cert.status == db.CertStatus.active


def test_employee_not_found_is_404(app_settings, throwaway_pki, monkeypatch):
    client, app_settings = _client(app_settings, throwaway_pki, monkeypatch)
    resp = client.get("/employees/nobody-here")
    assert resp.status_code == 404
