"""Fleet status derivation (HANDOFF-FLEET.md §5) and the edge-triggered
alert dedup in app/fleet_watch.py (§5.1 TRAP: exactly one alert per
transition, not one per scheduler run)."""

import datetime
import uuid

from app import crl_health, db, fleet_health, fleet_watch


def _fresh(site_id="s", hours_remaining=1000.0, is_current=True, is_critical=False):
    return crl_health.HostCrlFreshness(
        site_id=site_id, name="Boracay", radius_cn="radius-boracay.internal",
        reported_sha256="abc", is_current=is_current,
        hours_remaining=hours_remaining, is_critical=is_critical,
    )


def _site(**overrides):
    defaults = dict(
        id=str(uuid.uuid4()), name="Boracay", radius_cn="radius-boracay.internal",
        subsidiary="Lezzgo Boracay", auth_token_hash="x", crl_validity_days=30,
        checkin_interval_seconds=3600, is_active=True,
    )
    defaults.update(overrides)
    return db.Site(**defaults)


def _cert(days_remaining, **overrides):
    now = datetime.datetime.now(datetime.timezone.utc)
    defaults = dict(
        id=str(uuid.uuid4()), cn="radius-boracay.internal", serial="1",
        issued_at=now - datetime.timedelta(days=1),
        expires_at=now + datetime.timedelta(days=days_remaining),
        status=db.CertStatus.active, issued_by="alice", request_id=str(uuid.uuid4()),
        cert_type="server",
    )
    defaults.update(overrides)
    return db.Certificate(**defaults)


def test_ok_when_everything_fresh():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=now - datetime.timedelta(minutes=5))
    cert = _cert(days_remaining=300)
    health = fleet_health.evaluate_site(site, cert, _fresh(), now=now)
    assert health.status == fleet_health.SiteStatus.ok


def test_silent_when_missed_more_than_three_intervals():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(
        last_seen_at=now - datetime.timedelta(hours=4),  # 4 intervals at 1h each
        checkin_interval_seconds=3600,
    )
    health = fleet_health.evaluate_site(site, None, _fresh(), now=now)
    assert health.status == fleet_health.SiteStatus.silent


def test_silent_when_never_checked_in():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=None)
    health = fleet_health.evaluate_site(site, None, _fresh(), now=now)
    assert health.status == fleet_health.SiteStatus.silent


def test_critical_when_freeradius_down():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=now, last_reported_freeradius_ok=False)
    health = fleet_health.evaluate_site(site, None, _fresh(), now=now)
    assert health.status == fleet_health.SiteStatus.critical


def test_critical_when_cert_expiring_within_14_days():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=now)
    cert = _cert(days_remaining=10)
    health = fleet_health.evaluate_site(site, cert, _fresh(), now=now)
    assert health.status == fleet_health.SiteStatus.critical


def test_critical_when_crl_expiring_within_48_hours():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=now, crl_validity_days=30)
    health = fleet_health.evaluate_site(
        site, None, _fresh(hours_remaining=23.0, is_critical=True), now=now,
    )
    assert health.status == fleet_health.SiteStatus.critical


def test_critical_when_site_not_running_latest_crl():
    """Task N item 2: a site running a stale CRL must show critical on
    its own, even though the hub's own current CRL is perfectly fresh —
    this is exactly the "averaged into a fleet-wide green banner" gap."""
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=now)
    stale = crl_health.HostCrlFreshness(
        site_id=site.id, name=site.name, radius_cn=site.radius_cn,
        reported_sha256="old-hash", is_current=False,
        hours_remaining=None, is_critical=True,
    )
    health = fleet_health.evaluate_site(site, None, stale, now=now)
    assert health.status == fleet_health.SiteStatus.critical
    assert health.crl_is_current is False


def test_critical_when_canary_probe_fails():
    """Task O2: the core gap this closes -- a site can have a fresh CRL,
    a healthy service, and an OK check-in, and still reject every real
    authentication. That must not read as OK."""
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=now, last_canary_ok=False)
    health = fleet_health.evaluate_site(site, None, _fresh(), now=now)
    assert health.status == fleet_health.SiteStatus.critical
    assert health.canary_ok is False


def test_ok_when_canary_never_probed():
    """A site with no canary configured yet (task O2 setup is opt-in per
    site) must not show critical just because nobody's issued it a
    canary cert -- that's "not configured", not "failing"."""
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=now, last_canary_ok=None)
    health = fleet_health.evaluate_site(site, None, _fresh(), now=now)
    assert health.status == fleet_health.SiteStatus.ok
    assert health.canary_ok is None


def test_warn_when_cert_inside_renewal_window_but_not_critical():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=now)
    # 90-day cert, 25 days remaining: under the 1/3-remaining renewal_due
    # threshold (30 days), but comfortably clear of the 14-day CRITICAL cutoff.
    cert = _cert(
        days_remaining=25,
        issued_at=now - datetime.timedelta(days=65),
    )
    health = fleet_health.evaluate_site(site, cert, _fresh(), now=now)
    assert health.status == fleet_health.SiteStatus.warn


def test_warn_on_one_missed_checkin():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(
        last_seen_at=now - datetime.timedelta(hours=1, minutes=30),
        checkin_interval_seconds=3600,
    )
    health = fleet_health.evaluate_site(site, None, _fresh(), now=now)
    assert health.status == fleet_health.SiteStatus.warn


def test_fleet_watch_fires_once_on_transition_then_stays_quiet(tmp_path):
    engine = db.make_engine(str(tmp_path / "t.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=None)  # SILENT from the start
    session.add(site)
    session.commit()

    alerts = []
    fleet_watch.check_and_alert(session, alerts.append, now=now)
    assert len(alerts) == 1

    # Second run, nothing changed — must NOT alert again.
    fleet_watch.check_and_alert(session, alerts.append, now=now)
    assert len(alerts) == 1


def test_fleet_watch_alerts_again_on_recovery(tmp_path):
    engine = db.make_engine(str(tmp_path / "t.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=None)
    session.add(site)
    session.commit()

    alerts = []
    fleet_watch.check_and_alert(session, alerts.append, now=now)
    assert len(alerts) == 1

    site.last_seen_at = now
    site.last_reported_freeradius_ok = True
    session.commit()
    fleet_watch.check_and_alert(session, alerts.append, now=now)
    assert len(alerts) == 2  # recovery to OK is its own transition
