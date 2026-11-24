import datetime

from app import crl_health, crl_push, db


def make_session(tmp_path):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    return db.make_session_factory(engine)()


def test_health_reports_generated_and_pushed_state(tmp_path):
    session = make_session(tmp_path)
    next_update = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
    crl_health.record_generation(session, next_update)
    crl_health.record_push_result(session, ok=True)

    health = crl_health.get_health(session)
    assert health.last_push_ok is True
    assert health.is_stale is False
    assert 160 < health.hours_remaining < 170


def test_health_flags_critical_under_48h_remaining(tmp_path):
    session = make_session(tmp_path)
    next_update = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=10)
    crl_health.record_generation(session, next_update)
    crl_health.record_push_result(session, ok=True)

    health = crl_health.get_health(session)
    assert health.is_critical is True


def test_health_flags_stale_when_next_update_passed(tmp_path):
    session = make_session(tmp_path)
    next_update = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    crl_health.record_generation(session, next_update)

    health = crl_health.get_health(session)
    assert health.is_stale is True
    assert health.is_critical is True


def test_no_state_yet_reports_no_crash(tmp_path):
    session = make_session(tmp_path)
    health = crl_health.get_health(session)
    assert health.next_update is None
    assert health.hours_remaining is None


def test_no_crl_ever_generated_is_critical(tmp_path):
    session = make_session(tmp_path)
    health = crl_health.get_health(session)
    assert health.is_critical is True
    assert health.is_stale is True


def _site(session, **overrides):
    import uuid
    defaults = dict(
        id=str(uuid.uuid4()), name="Boracay", radius_cn="radius-boracay.internal",
        auth_token_hash="x", crl_validity_days=30, checkin_interval_seconds=3600,
        is_active=True,
    )
    defaults.update(overrides)
    site = db.Site(**defaults)
    session.add(site)
    session.commit()
    return site


def test_per_host_freshness_current_when_hash_matches(tmp_path):
    session = make_session(tmp_path)
    next_update = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
    crl_health.record_generation(session, next_update, sha256="abc123")
    site = _site(session, last_reported_crl_sha256="abc123")

    results = crl_health.per_host_crl_freshness(session, [site])
    assert len(results) == 1
    assert results[0].is_current is True
    assert results[0].is_critical is False


def test_per_host_freshness_stale_when_hash_does_not_match(tmp_path):
    session = make_session(tmp_path)
    next_update = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
    crl_health.record_generation(session, next_update, sha256="new-hash")
    site = _site(session, last_reported_crl_sha256="old-hash")

    results = crl_health.per_host_crl_freshness(session, [site])
    assert results[0].is_current is False
    assert results[0].is_critical is True
    assert results[0].hours_remaining is None


def test_per_host_freshness_critical_when_site_never_reported(tmp_path):
    session = make_session(tmp_path)
    next_update = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
    crl_health.record_generation(session, next_update, sha256="abc123")
    site = _site(session, last_reported_crl_sha256=None)

    results = crl_health.per_host_crl_freshness(session, [site])
    assert results[0].is_current is False
    assert results[0].is_critical is True


def test_push_retries_with_backoff_and_succeeds_on_second_attempt(tmp_path):
    session = make_session(tmp_path)
    attempts = []

    def push_fn():
        attempts.append(1)
        if len(attempts) < 2:
            return crl_push.PushResult(ok=False, detail="transient failure")
        return crl_push.PushResult(ok=True, detail="ok")

    sleeps = []
    result = crl_health.push_with_retry(
        session, push_fn, alert_fn=None, sleep_fn=sleeps.append, delays=[0, 5, 10]
    )
    assert result.ok is True
    assert len(attempts) == 2
    assert sleeps == [5]  # first delay is 0 (skipped), second triggers a real sleep call


def test_push_exhausts_retries_writes_audit_and_fires_alert(tmp_path):
    session = make_session(tmp_path)

    def push_fn():
        return crl_push.PushResult(ok=False, detail="permanent failure")

    alerts = []
    result = crl_health.push_with_retry(
        session, push_fn, alert_fn=alerts.append, sleep_fn=lambda s: None, delays=[0, 1, 1]
    )
    assert result.ok is False
    assert len(alerts) == 1
    assert "permanent failure" in alerts[0]

    audit_row = session.query(db.AuditLog).filter_by(action="crl_push_failed").one()
    assert audit_row.target == "crl.pem"


def test_push_failure_alert_names_the_failing_host(tmp_path):
    session = make_session(tmp_path)

    def push_fn():
        return crl_push.PushResult(ok=False, detail="permanent failure")

    alerts = []
    crl_health.push_with_retry(
        session, push_fn, alert_fn=alerts.append, sleep_fn=lambda s: None, delays=[0], host="192.168.13.102"
    )
    assert "192.168.13.102" in alerts[0]
    audit_row = session.query(db.AuditLog).filter_by(action="crl_push_failed").one()
    assert "192.168.13.102" in audit_row.detail
