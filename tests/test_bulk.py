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


def test_parse_csv_reads_subsidiary_as_sixth_column():
    data = b"device-a,Jordan Ellis,Laptop,AA:BB:CC:DD:EE:FF,C02XG2JMQ6L9,Bay Mall\n"
    rows = bulk_service.parse_csv(data)
    assert rows[0].subsidiary == "Bay Mall"


def test_parse_csv_by_name_header_any_column_order():
    # Same fields as the app's own template, but shuffled and with an
    # identifier/cn/hostname column present — should map by name, not
    # position, and ignore nothing since every header is recognized.
    data = (
        b"Device Serial,Employee Name,Identifier,Device MAC,Subsidiary,Device Type\n"
        b"C02XG2JMQ6L9,Jordan Ellis,device-a,AA:BB:CC:DD:EE:FF,Bay Mall,Laptop\n"
    )
    rows = bulk_service.parse_csv(data)
    assert len(rows) == 1
    r = rows[0]
    assert r.identifier == "device-a"
    assert r.employee_name == "Jordan Ellis"
    assert r.device_type == "Laptop"
    assert r.device_mac == "aa:bb:cc:dd:ee:ff"
    assert r.device_serial == "C02XG2JMQ6L9"
    assert r.subsidiary == "Bay Mall"


def test_parse_csv_by_name_header_ignores_unrecognized_columns():
    data = (
        b"Name,Device Type,MAC Address,Serial Number,Model,Is it a Company issued device?\n"
        b"John Jake Quino,Laptop,A8-E2-91-95-BD-66,5CD5Q94X37,VICTUS,Yes\n"
    )
    rows = bulk_service.parse_csv(data)
    assert len(rows) == 1
    r = rows[0]
    # no identifier/cn/hostname column exists, so the CN is generated
    # from the fields that do — never left blank or set to "Model"/"Yes"
    assert r.identifier != ""
    assert bulk_service.CN_RE.match(r.identifier)
    assert "quino" in r.identifier.lower()
    assert r.employee_name == "John Jake Quino"
    assert r.device_type == "Laptop"
    assert r.device_serial == "5CD5Q94X37"
    assert r.device_mac == "a8:e2:91:95:bd:66"


def test_parse_csv_by_name_header_generated_cns_are_distinct_per_row():
    data = (
        b"Name,Device Type,Serial Number\n"
        b"John Jake Quino,Laptop,5CD5Q94X37\n"
        b"Crizaldi Reyes,Laptop,5CD5094XMK\n"
        b"Rodjohn Tuingco,Laptop,5CD4033N1C\n"
    )
    rows = bulk_service.parse_csv(data)
    identifiers = [r.identifier for r in rows]
    assert len(identifiers) == len(set(identifiers)) == 3
    for i in identifiers:
        assert bulk_service.CN_RE.match(i)


def test_parse_csv_by_name_header_with_no_device_columns_still_generates_cn():
    data = b"Name\nJordan Ellis\n"
    rows = bulk_service.parse_csv(data)
    assert len(rows) == 1
    assert bulk_service.CN_RE.match(rows[0].identifier)
    assert "jordan" in rows[0].identifier.lower()


def test_parse_csv_by_name_header_skips_fully_blank_row():
    # a trailing CSV line where every recognized column is empty (only
    # an unmapped column, like a stray checkbox answer, has a value)
    # must not turn into a fabricated "device" placeholder row
    data = (
        b"Name,Device Type,Is it a Company issued device?\n"
        b"Jordan Ellis,Laptop,Yes\n"
        b",,Yes\n"
    )
    rows = bulk_service.parse_csv(data)
    assert len(rows) == 1
    assert "jordan" in rows[0].identifier.lower()


def test_issue_batch_stores_subsidiary_and_includes_it_in_manifest(session, tmp_path, throwaway_pki):
    input_rows = [
        bulk_service.BatchInputRow(identifier="bmead-device", subsidiary="BMEAD"),
    ]
    result, zip_bytes = bulk_service.issue_batch(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        input_rows, batch_id="batch-subsidiary", export_password="sharedpassword123",
        issued_by="alice", days=365,
    )
    assert len(result.succeeded) == 1

    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    manifest = zf.read("manifest.csv").decode()
    assert "BMEAD" in manifest

    row = session.query(db.Certificate).filter_by(cn="bmead-device").one()
    assert row.subsidiary == "BMEAD"


def test_parse_csv_reads_device_model_as_seventh_positional_column():
    data = b"device-a,Jordan Ellis,Laptop,AA:BB:CC:DD:EE:FF,C02XG2JMQ6L9,Bay Mall,VICTUS 15\n"
    rows = bulk_service.parse_csv(data)
    assert rows[0].device_model == "VICTUS 15"


def test_parse_csv_positional_without_model_column_still_works():
    # a CSV built against the pre-device_model 6-column order must not break
    data = b"device-a,Jordan Ellis,Laptop,AA:BB:CC:DD:EE:FF,C02XG2JMQ6L9,Bay Mall\n"
    rows = bulk_service.parse_csv(data)
    assert rows[0].device_model is None
    assert rows[0].subsidiary == "Bay Mall"


def test_parse_csv_by_name_header_recognizes_model_and_brand_aliases():
    data = (
        b"Name,Device Type,Model\n"
        b"Jordan Ellis,Laptop,VICTUS 15\n"
    )
    rows = bulk_service.parse_csv(data)
    assert rows[0].device_model == "VICTUS 15"

    data2 = b"Name,Brand\nJordan Ellis,Acer\n"
    rows2 = bulk_service.parse_csv(data2)
    assert rows2[0].device_model == "Acer"


def test_issue_batch_stores_device_model_and_includes_it_in_manifest(session, tmp_path, throwaway_pki):
    input_rows = [
        bulk_service.BatchInputRow(identifier="model-device", device_model="HP EliteBook 840"),
    ]
    result, zip_bytes = bulk_service.issue_batch(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        input_rows, batch_id="batch-model", export_password="sharedpassword123",
        issued_by="alice", days=365,
    )
    assert len(result.succeeded) == 1

    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    manifest = zf.read("manifest.csv").decode()
    assert "HP EliteBook 840" in manifest

    row = session.query(db.Certificate).filter_by(cn="model-device").one()
    assert row.device_model == "HP EliteBook 840"
