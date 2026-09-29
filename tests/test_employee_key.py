"""employee_key normalisation (HANDOFF-LIFECYCLE.md §1.1) — derived on
write, backfilled for pre-existing rows, and warned-but-not-blocked at
issue/bulk-issue time when a name normalises to an existing key under a
different spelling."""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import auth, bulk_service, cert_service, crl_push, db, pki
from app.main import create_app
from app.validation import normalize_employee_key
from tests.conftest import login_as


def _write_throwaway_pki(app_settings, throwaway_pki):
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )


def _seed_admin(app_settings, username="admin-1", role=db.AdminRole.super_admin):
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    admin = db.Admin(username=username, password_hash=auth.hash_password("correcthorse123"), role=role)
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
    return client


def test_issue_certificate_sets_employee_key(tmp_path, throwaway_pki):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    result = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="laptop-1", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
        device=cert_service.DeviceInfo(employee_name="Juan  Dela   Cruz"),
    )
    assert result.certificate.employee_key == normalize_employee_key("Juan Dela Cruz")
    assert result.certificate.employee_name == "Juan  Dela   Cruz"  # display value untouched


def test_reissue_recomputes_employee_key_from_carried_over_name(tmp_path, throwaway_pki):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    original = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="laptop-2", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
        device=cert_service.DeviceInfo(employee_name="Jane Doe"),
    )
    reissued = cert_service.reissue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        old_serial=original.certificate.serial, request_id=str(uuid.uuid4()),
        export_password=None, issued_by="alice", days=365,
    )
    assert reissued.certificate.employee_key == normalize_employee_key("Jane Doe")


def test_no_employee_name_means_no_employee_key(tmp_path, throwaway_pki):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    result = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="laptop-3", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    )
    assert result.certificate.employee_key is None


def test_backfill_employee_key_derives_from_existing_rows(tmp_path):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    session.add(db.Certificate(
        id=str(uuid.uuid4()), cn="legacy-device", serial="555", issued_at=now,
        expires_at=now + datetime.timedelta(days=365), status=db.CertStatus.active,
        issued_by="alice", request_id=str(uuid.uuid4()), employee_name="Pat Reyes",
    ))
    session.commit()

    updated = db.backfill_employee_key(engine)
    assert updated == 1
    row = session.scalar(select(db.Certificate).where(db.Certificate.cn == "legacy-device"))
    assert row.employee_key == normalize_employee_key("Pat Reyes")


def test_backfill_employee_key_is_idempotent(tmp_path):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    session.add(db.Certificate(
        id=str(uuid.uuid4()), cn="legacy-device-2", serial="556", issued_at=now,
        expires_at=now + datetime.timedelta(days=365), status=db.CertStatus.active,
        issued_by="alice", request_id=str(uuid.uuid4()), employee_name="Sam Cruz",
    ))
    session.commit()

    first = db.backfill_employee_key(engine)
    second = db.backfill_employee_key(engine)
    assert first == 1
    assert second == 0


def test_init_db_runs_employee_key_backfill_once(tmp_path, monkeypatch):
    engine = db.make_engine(str(tmp_path / "test.db"))
    calls = []
    monkeypatch.setattr(db, "backfill_employee_key", lambda eng: calls.append(1))
    db.init_db(engine)
    assert len(calls) == 1
    db.init_db(engine)  # second boot — must not run again
    assert len(calls) == 1


def test_issue_form_warns_but_does_not_block_on_spelling_mismatch(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)

    resp = client.post(
        "/certs/issue",
        data={"cn": "device-1.example", "request_id": str(uuid.uuid4()), "employee_name": "Juan Dela Cruz"},
        follow_redirects=False,
    )
    assert resp.status_code in (200, 303)

    resp = client.post(
        "/certs/issue",
        data={"cn": "device-2.example", "request_id": str(uuid.uuid4()), "employee_name": "juan dela cruz"},
    )
    assert resp.status_code == 200
    assert "different spelling" in resp.text
    assert "Juan Dela Cruz" in resp.text

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    assert session.scalar(select(db.Certificate).where(db.Certificate.cn == "device-2.example")) is None


def test_issue_form_confirm_duplicate_bypasses_spelling_warning(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)
    client.post(
        "/certs/issue",
        data={"cn": "device-1.example", "request_id": str(uuid.uuid4()), "employee_name": "Juan Dela Cruz"},
    )
    resp = client.post(
        "/certs/issue",
        data={
            "cn": "device-2.example", "request_id": str(uuid.uuid4()),
            "employee_name": "juan dela cruz", "confirm_duplicate": "1",
        },
        follow_redirects=False,
    )
    assert resp.status_code in (200, 303)
    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    assert session.scalar(select(db.Certificate).where(db.Certificate.cn == "device-2.example")) is not None


def test_bulk_classify_flags_spelling_mismatch_but_stays_valid(app_settings, throwaway_pki, monkeypatch):
    _write_throwaway_pki(app_settings, throwaway_pki)
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    cert_service.issue_certificate(
        session, app_settings.pki_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="existing-device", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365, device=cert_service.DeviceInfo(employee_name="Juan Dela Cruz"),
    )

    rows = bulk_service.classify(session, [
        bulk_service.BatchInputRow(identifier="new-device", employee_name="juan dela cruz"),
    ])
    assert rows[0].classification == "valid"
    assert rows[0].employee_spelling_matches == ["Juan Dela Cruz"]
