# Sustained-observation validation plan (closes STAGING-READINESS blocker #4)

Closes: "Confirm policy refresh, expiry withdrawal, acknowledgement
recording, and non-zero timer failure status over a longer observation
window (today's test was one forced pull, not a sustained run)."

Run this over a real ~24-48h window, not a forced single pull. Don't
touch the system except to make the deliberate edits below and record
timestamps/output at each checkpoint.

## 0. Baseline (T+0)

On the hub (`192.168.13.73`):
```bash
curl -sk https://localhost:8443/api/health/crl
sqlite3 /srv/data/certmanager/certmanager.db \
  "select site_id, revision, success, installed_at from site_policy_acks order by installed_at desc limit 5;"
```
On the site (`topline-freeradius1`, CM4):
```bash
systemctl list-timers | grep certmanager
journalctl -u certmanager-policy-refresh.service --since "-24h" | tail -40
cat /opt/certmanager-agent/policy.json | jq .revision,.expires_at
```
Record revision number, expires_at, and last successful refresh timestamp.

## 1. Normal refresh cycle (T+4h, T+8h, T+12h...)

Timer is `OnCalendar` every 4h with up to 10min jitter. No CM4 shell access
exists (only the scoped crlpush forced-command key) — everything here is
observed from the hub side only:
- `docker logs --timestamps certmanager --since <window> | grep network-policy` — each natural tick shows up here as a `GET /api/site/network-policy` line, `304 Not Modified` if the policy hasn't changed, `200` if it has.
- **A `304` tick writes no `site_policy_acks` row** (`fetch_and_install_policy` in `deploy/agent/site_agent.py` only calls `_send_policy_ack` on a 200/installed or an error path — confirmed by reading the code, not assumed). Don't treat "no new ack row" as "no tick happened" — check the access log line instead.
- `db.Site.last_seen_at` moving forward is a general liveness signal (any hub call updates it), not proof of this specific timer firing — corroborate with the access log.
- Only a real policy change (200, new revision) or an error produces a `site_policy_acks` row — that's the real "ack recording round-trips" signal, tested properly in step 2 below.

No manual trigger. Just let the timer fire naturally across this window.

**Known limitation hit in practice (28 Oct 2026):** `docker logs` only covers
the *current* container instance — every `docker compose up -d --build`
during active development that day silently truncated tick history. On a
day with ongoing deploys, treat each redeploy as resetting the access-log
observation window; `db.Site.last_seen_at` survives across redeploys (it's
DB-persisted) but is a weak liveness signal only — any authenticated agent
call updates it, not specifically a policy-refresh tick. Real gap-free
observation needs a day with no redeploys in between.

## 2. Deliberate policy change mid-window (any tick after T+4h)

From the hub admin UI, change one `SiteRoleBinding` VLAN id (reversible — note old value first). Then:
- Wait for the next natural timer tick (don't force it).
- Confirm the new VLAN id shows up in the agent's installed `policy.json` after that tick, with a bumped `revision`.
- Confirm `site_policy_acks` recorded the new revision.
- Revert the VLAN id change afterward.

This proves the 4h cycle actually propagates real changes, not just re-confirms a cached lease.

## 3. Expiry withdrawal (requires a controlled outage)

The whole point of the 24h lease / 4h refresh margin is: if the hub goes dark, the site's cached policy must self-invalidate once `expires_at` passes, rather than authorize forever on stale policy.

- Stop the `certmanager` container on the hub (`docker stop certmanager`) for longer than the lease's remaining validity — easiest: do this test starting from a *stale* checkpoint when `expires_at` is <4h out (check timestamp from step 0/1 first), stop the container, and wait past `expires_at`.
- Confirm `_validate_cached_policy` rejects the expired lease: `journalctl -u certmanager-policy-refresh.service` shows `cached policy lease has expired`, and `authorize_policy.py` falls back to reject/deny (check `freeradius -X` or the real auth log for a denied auth attempt during the outage window) rather than silently authorizing on the stale cache.
- Restart `certmanager` on the hub, confirm the next tick recovers normally (new lease installed, acks resume).

## 4. Non-zero timer failure status

- While the hub container is stopped (step 3), confirm `systemctl status certmanager-policy-refresh.service` on the site shows a failed/non-zero exit for that tick, and `systemctl list-timers` still shows the timer armed for the next tick (i.e., one failed run doesn't kill the timer).
- Confirm this failure is visible somewhere an admin would actually see it — check `/health` or the dashboard's fleet/site health view for a stale/SILENT flag on this site once refresh has failed for longer than the alert threshold (see `fleet_watch.timer` / HANDOFF-FLEET.md §5.1).

## Pass criteria

- [ ] At least 4 natural (non-forced) refresh ticks observed, all producing an ack row on the hub.
- [ ] A real policy change propagated through a natural tick, not a forced pull.
- [ ] Expired-lease rejection confirmed: auth denied during outage, not silently allowed.
- [ ] Failed tick shows non-zero systemd status, timer stays armed, and surfaces in fleet/site health.
- [ ] System recovers cleanly once the hub comes back (no manual intervention needed beyond restarting the container).

## Record results back in STAGING-READINESS.md

Once all boxes are checked, replace blocker #4 with a "CLOSED on <date>"
entry summarizing what was observed, same format as the existing closed
items.
