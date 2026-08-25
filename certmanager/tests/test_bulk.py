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


def _ids(rows):
    return [r.identifier for r in rows]


def test_parse_identifiers_strips_blank_lines():
    raw = "device-a\n\n  device-b  \ndevice-c\n"
    rows = bulk_service.parse_identifiers(raw)
    assert _ids(rows) == ["device-a", "device-b", "device-c"]
    assert all(r.employee_name is None for r in rows)


def test_parse_csv_single_column_no_header():
    data = b"device-a\ndevice-b\n"
    rows = bulk_service.parse_csv(data)
    assert _ids(rows) == ["device-a", "device-b"]


def test_parse_csv_skips_recognized_header_row():
    data = b"cn,employee_name\ndevice-a,Jordan Ellis\n"
    rows = bulk_service.parse_csv(data)
    assert len(rows) == 1
    assert rows[0].identifier == "device-a"
    assert rows[0].employee_name == "Jordan Ellis"


def test_parse_csv_reads_optional_device_columns_and_normalizes_mac():
    data = b"device-a,Jordan Ellis,Laptop,AA-BB-CC-DD-EE-FF,C02XG2JMQ6L9\n"
    rows = bulk_service.parse_csv(data)
    assert rows[0].employee_name == "Jordan Ellis"
    assert rows[0].device_type == "Laptop"
    assert rows[0].device_mac == "aa:bb:cc:dd:ee:ff"
    assert rows[0].device_serial == "C02XG2JMQ6L9"


def test_classify_flags_malformed_duplicate_and_valid(session, tmp_path, throwaway_pki):
    cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="existing-device", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    )

    input_rows = bulk_service.parse_identifiers(
        "new-device\nexisting-device\nbad cn!\nnew-device"
    )
    rows = bulk_service.classify(session, input_rows)
    by_id = {r.identifier: r for r in rows}
    assert rows[0].classification == "valid"
    assert by_id["existing-device"].classification == "duplicate"
    assert by_id["bad cn!"].classification == "malformed"
    # second occurrence of "new-device" is a within-batch duplicate
    assert rows[3].classification == "duplicate"


def test_classify_carries_device_info_through_to_preview_row(session):
    input_rows = [
        bulk_service.BatchInputRow(identifier="dev-x", employee_name="Sam Lee", device_type="Phone")
    ]
    rows = bulk_service.classify(session, input_rows)
    assert rows[0].employee_name == "Sam Lee"
    assert rows[0].device_type == "Phone"


def test_classify_rejects_batch_over_cap(session):
    input_rows = bulk_service.parse_identifiers(
        "\n".join(f"device-{i}" for i in range(bulk_service.MAX_BATCH_SIZE + 1))
    )
    with pytest.raises(bulk_service.BatchTooLargeError):
        bulk_service.classify(session, input_rows)


def test_issue_batch_all_succeed_zip_has_p12_and_manifest_without_password(
    session, tmp_path, throwaway_pki
):
    input_rows = [
        bulk_service.BatchInputRow(identifier="batch-a", employee_name="Jordan Ellis", device_type="Laptop"),
        bulk_service.BatchInputRow(identifier="batch-b"),
        bulk_service.BatchInputRow(identifier="batch-c"),
    ]
    result, zip_bytes = bulk_service.issue_batch(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        input_rows, batch_id="batch-1", export_password="sharedpassword123",
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
    assert "Jordan Ellis" in manifest
    assert "Laptop" in manifest

    rows = session.query(db.Certificate).filter_by(batch_id="batch-1").all()
    assert len(rows) == 3
    assert all(r.batch_id == "batch-1" for r in rows)
    by_cn = {r.cn: r for r in rows}
    assert by_cn["batch-a"].employee_name == "Jordan Ellis"
    assert by_cn["batch-a"].device_type == "Laptop"
    assert by_cn["batch-b"].employee_name is None


def test_issue_batch_partial_failure_keeps_successful_rows(session, tmp_path, throwaway_pki):
    cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="already-active", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    )

    input_rows = bulk_service.parse_identifiers("ok-device\nalready-active\nanother-ok-device")
    result, zip_bytes = bulk_service.issue_batch(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        input_rows, batch_id="batch-2", export_password="sharedpassword123",
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
    input_rows = bulk_service.parse_identifiers("retry-device")
    result1, _ = bulk_service.issue_batch(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        input_rows, batch_id="batch-retry", export_password="pw", issued_by="alice", days=365,
    )
    result2, _ = bulk_service.issue_batch(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        input_rows, batch_id="batch-retry", export_password="pw", issued_by="alice", days=365,
    )
    assert result1.succeeded[0].serial == result2.succeeded[0].serial
    count = session.query(db.Certificate).filter_by(cn="retry-device").count()
    assert count == 1
