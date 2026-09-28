"""init_db() runs the audit_log subsidiary backfill exactly once, guarded
by a MigrationFlag row, instead of re-scanning audit_log on every boot
forever (HANDOFF-COMPLIANCE.md §6)."""

import datetime
import uuid

from sqlalchemy import select

from app import db


def test_init_db_runs_backfill_once_and_flags_it(tmp_path, monkeypatch):
    engine = db.make_engine(str(tmp_path / "test.db"))

    calls = []
    real_backfill = db.backfill_audit_log_subsidiary

    def _counting_backfill(eng):
        calls.append(1)
        return real_backfill(eng)

    monkeypatch.setattr(db, "backfill_audit_log_subsidiary", _counting_backfill)

    db.init_db(engine)
    assert len(calls) == 1

    flag = db.Session(engine).get(db.MigrationFlag, "audit_log_subsidiary_backfill")
    assert flag is not None


def test_init_db_does_not_rerun_backfill_on_second_boot(tmp_path, monkeypatch):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)

    calls = []
    monkeypatch.setattr(db, "backfill_audit_log_subsidiary", lambda eng: calls.append(1))

    db.init_db(engine)  # simulates a second boot against the same DB
    assert calls == []


def test_run_once_runs_exactly_once(tmp_path):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)

    calls = []
    ran_first = db.run_once(engine, "some_step", lambda: calls.append(1))
    ran_second = db.run_once(engine, "some_step", lambda: calls.append(1))

    assert ran_first is True
    assert ran_second is False
    assert calls == [1]


def test_deleting_flag_row_lets_it_rerun(tmp_path):
    """The documented way to deliberately re-run a one-shot step."""
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)

    session = db.make_session_factory(engine)()
    now = datetime.datetime.now(datetime.timezone.utc)
    session.add(db.Certificate(
        id=str(uuid.uuid4()), cn="legacy-device", serial="777", issued_at=now,
        expires_at=now + datetime.timedelta(days=365), status=db.CertStatus.active,
        issued_by="alice", request_id=str(uuid.uuid4()), subsidiary="BMEAD",
    ))
    session.add(db.AuditLog(actor="alice", action="issue", target="legacy-device", subsidiary=None))
    session.commit()

    db.init_db(engine)  # already flagged done — won't touch the row above
    row = session.scalar(select(db.AuditLog).where(db.AuditLog.target == "legacy-device"))
    assert row.subsidiary is None

    flag_session = db.Session(engine)
    flag = flag_session.get(db.MigrationFlag, "audit_log_subsidiary_backfill")
    flag_session.delete(flag)
    flag_session.commit()

    db.init_db(engine)  # flag gone — backfill runs again
    session.refresh(row)
    assert row.subsidiary == "BMEAD"
