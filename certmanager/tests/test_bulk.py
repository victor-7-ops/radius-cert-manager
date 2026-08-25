import io
import uuid
import zipfile

import pytest

from app import bulk_service, cert_service, db


@pytest.fixture
def session(tmp_path):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    return db.make_session_factory(engine)()


def test_parse_identifiers_strips_blank_lines():
    raw = "device-a\n\n  device-b  \ndevice-c\n"
    assert bulk_service.parse_identifiers(raw) == ["device-a", "device-b", "device-c"]


def test_parse_csv_single_column():
    data = b"cn\ndevice-a\ndevice-b\n"
    assert bulk_service.parse_csv(data) == ["cn", "device-a", "device-b"]


def test_classify_flags_malformed_duplicate_and_valid(session, tmp_path, throwaway_pki):
    cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="existing-device", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    )

    rows = bulk_service.classify(
        session, ["new-device", "existing-device", "bad cn!", "new-device"]
    )
    by_id = {r.identifier: r for r in rows}
    assert rows[0].classification == "valid"
    assert by_id["existing-device"].classification == "duplicate"
    assert by_id["bad cn!"].classification == "malformed"
    # second occurrence of "new-device" is a within-batch duplicate
    assert rows[3].classification == "duplicate"


def test_classify_rejects_batch_over_cap(session):
    identifiers = [f"device-{i}" for i in range(bulk_service.MAX_BATCH_SIZE + 1)]
    with pytest.raises(bulk_service.BatchTooLargeError):
        bulk_service.classify(session, identifiers)


def test_issue_batch_all_succeed_zip_has_p12_and_manifest_without_password(
    session, tmp_path, throwaway_pki
):
    identifiers = ["batch-a", "batch-b", "batch-c"]
    result, zip_bytes = bulk_service.issue_batch(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        identifiers, batch_id="batch-1", export_password="sharedpassword123",
        issued_by="alice", days=365,
    )

    assert len(result.succeeded) == 3
    assert len(result.failed) == 0

    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    names = zf.namelist()
    assert "batch-a.p12" in names
    assert "batch-b.p12" in names
    assert "manifest.csv" in names

    manifest = zf.read("manifest.csv").decode()
    assert "sharedpassword123" not in manifest
    assert "batch-a" in manifest

    rows = session.query(db.Certificate).filter_by(batch_id="batch-1").all()
    assert len(rows) == 3
    assert all(r.batch_id == "batch-1" for r in rows)


def test_issue_batch_partial_failure_keeps_successful_rows(session, tmp_path, throwaway_pki):
    cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="already-active", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    )

    identifiers = ["ok-device", "already-active", "another-ok-device"]
    result, zip_bytes = bulk_service.issue_batch(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        identifiers, batch_id="batch-2", export_password="sharedpassword123",
        issued_by="alice", days=365,
    )

    assert len(result.succeeded) == 2
    assert len(result.failed) == 1
    assert result.failed[0].cn == "already-active"
    assert result.failed[0].error is not None

    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    assert "ok-device.p12" in zf.namelist()
    assert "already-active.p12" not in zf.namelist()


def test_retried_batch_submission_does_not_double_issue(session, tmp_path, throwaway_pki):
    identifiers = ["retry-device"]
    result1, _ = bulk_service.issue_batch(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        identifiers, batch_id="batch-retry", export_password="pw", issued_by="alice", days=365,
    )
    result2, _ = bulk_service.issue_batch(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        identifiers, batch_id="batch-retry", export_password="pw", issued_by="alice", days=365,
    )
    assert result1.succeeded[0].serial == result2.succeeded[0].serial
    count = session.query(db.Certificate).filter_by(cn="retry-device").count()
    assert count == 1
