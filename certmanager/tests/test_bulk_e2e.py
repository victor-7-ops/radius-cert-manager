"""End-to-end bulk-issue flow through the real HTML routes (handoff §6.5)."""

import io
import re
import zipfile

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


def test_bulk_preview_confirm_download_flow(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(
        crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed")
    )
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "bulk-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    preview_resp = client.post(
        "/certs/bulk/preview",
        data={"identifiers_text": "bulk-a\nbulk-b\nbad cn!\nbulk-a"},
    )
    assert preview_resp.status_code == 200, preview_resp.text
    assert "Valid" in preview_resp.text
    assert "Malformed" in preview_resp.text
    assert "Duplicate" in preview_resp.text

    token_match = re.search(r'name="batch_token" value="([^"]+)"', preview_resp.text)
    assert token_match, preview_resp.text
    batch_token = token_match.group(1)

    confirm_resp = client.post(
        "/certs/bulk/confirm",
        data={"batch_token": batch_token, "export_password": "SharedBatchPassword123"},
        follow_redirects=False,
    )
    assert confirm_resp.status_code == 303, confirm_resp.text
    result_url = confirm_resp.headers["location"]
    batch_id = result_url.rsplit("/", 1)[-1]

    result_resp = client.get(result_url)
    assert result_resp.status_code == 200
    assert "bulk-a" in result_resp.text
    assert "bulk-b" in result_resp.text
    assert "SharedBatchPassword123" not in result_resp.text  # never re-shown

    status_resp = client.get(f"/api/batches/{batch_id}")
    assert status_resp.status_code == 200
    body = status_resp.json()
    assert len(body["succeeded"]) == 2
    assert body["failed"] == []

    zip_resp = client.get(f"/api/batches/{batch_id}/bundle")
    assert zip_resp.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(zip_resp.content))
    names = zf.namelist()
    assert "bulk-a.p12" in names
    assert "bulk-b.p12" in names
    assert "manifest.csv" in names
    manifest = zf.read("manifest.csv").decode()
    assert "SharedBatchPassword123" not in manifest

    # One-time ZIP: second download returns 410.
    second_zip_resp = client.get(f"/api/batches/{batch_id}/bundle")
    assert second_zip_resp.status_code == 410

    # Preview token is single-use: resubmitting confirm 410s.
    replay_resp = client.post(
        "/certs/bulk/confirm",
        data={"batch_token": batch_token, "export_password": "AnotherPassword123"},
    )
    assert replay_resp.status_code == 410

    # DB rows exist and share a batch_id.
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    rows = session.query(db.Certificate).filter_by(batch_id=batch_id).all()
    assert len(rows) == 2


def test_fix_row_corrects_a_malformed_identifier_without_restarting(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "fix-row-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    preview_resp = client.post("/certs/bulk/preview", data={"identifiers_text": "good-device\nbad cn!"})
    assert "1 of 2" in preview_resp.text
    token = re.search(r'name="batch_token" value="([^"]+)"', preview_resp.text).group(1)

    fix_resp = client.post(f"/certs/bulk/{token}/fix-row", data={
        "row_index": "1", "identifier": "fixed-device",
    })
    assert fix_resp.status_code == 200
    assert "fixed-device" in fix_resp.text
    assert "bulk-valid-badge" in fix_resp.text  # server marks it valid; the
    # count itself is now recomputed client-side from these badges (see
    # bulk_preview.html) rather than server-rendered in this response

    # confirm now issues BOTH — the fixed row wasn't dropped
    confirm_resp = client.post(
        "/certs/bulk/confirm",
        data={"batch_token": token, "export_password": "SharedBatchPassword123"},
        follow_redirects=False,
    )
    result_resp = client.get(confirm_resp.headers["location"])
    assert "good-device" in result_resp.text
    assert "fixed-device" in result_resp.text

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    assert session.query(db.Certificate).filter_by(cn="fixed-device").count() == 1


def test_fix_row_can_reintroduce_a_new_problem(app_settings, throwaway_pki, monkeypatch):
    # fixing a malformed row with a value that's now a duplicate of
    # another row in the same batch must show as duplicate, not valid
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "fix-row-admin2", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    preview_resp = client.post("/certs/bulk/preview", data={"identifiers_text": "existing-device\nbad cn!"})
    token = re.search(r'name="batch_token" value="([^"]+)"', preview_resp.text).group(1)

    fix_resp = client.post(f"/certs/bulk/{token}/fix-row", data={
        "row_index": "1", "identifier": "existing-device",
    })
    assert "Duplicate" in fix_resp.text
    assert "bulk-valid-badge" not in fix_resp.text  # not marked valid


def test_fix_row_rejects_unknown_batch_token(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "fix-row-admin3", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    resp = client.post("/certs/bulk/does-not-exist/fix-row", data={"row_index": "0", "identifier": "device"})
    assert resp.status_code == 410


def test_fix_row_rejects_out_of_range_index(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "fix-row-admin4", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    preview_resp = client.post("/certs/bulk/preview", data={"identifiers_text": "one-device"})
    token = re.search(r'name="batch_token" value="([^"]+)"', preview_resp.text).group(1)

    resp = client.post(f"/certs/bulk/{token}/fix-row", data={"row_index": "5", "identifier": "device"})
    assert resp.status_code == 400


def test_bulk_regular_admin_can_issue(app_settings, throwaway_pki, monkeypatch):
    """Bulk issue uses require_admin (not super_admin) — matches single issue's role."""
    monkeypatch.setattr(
        crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed")
    )
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "regular-bulk-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    preview_resp = client.post("/certs/bulk/preview", data={"identifiers_text": "reg-device"})
    assert preview_resp.status_code == 200
    token_match = re.search(r'name="batch_token" value="([^"]+)"', preview_resp.text)
    batch_token = token_match.group(1)

    confirm_resp = client.post(
        "/certs/bulk/confirm",
        data={"batch_token": batch_token, "export_password": "SomePassword123"},
        follow_redirects=False,
    )
    assert confirm_resp.status_code == 303
