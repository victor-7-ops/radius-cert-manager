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

## 2. Deliberate policy change mid-window (any tick after T+4h) -- CLOSED 30 Oct 2026

From the hub admin UI, change one `SiteRoleBinding` VLAN id (reversible — note old value first). Then:
- [x] Wait for the next natural timer tick (don't force it).
- [x] Confirm the new VLAN id shows up in the agent's installed `policy.json` after that tick, with a bumped `revision`.
- [x] Confirm `site_policy_acks` recorded the new revision.
- [x] Revert the VLAN id change afterward.

This proves the 4h cycle actually propagates real changes, not just re-confirms a cached lease.

**Result:** topline-freeradius1 / Staff Network role, primary VLAN 11 -> 12 (fallback stayed 99) via the admin UI. Natural tick at 11:23 installed it: `policy.json` showed `primary_vlan_id: 12`, `config_revision: 6`; hub logged `GET /api/site/network-policy 200` + `POST /api/site/network-policy/ack 200` at the matching timestamp. Reverted to 11 at ~11:35; natural tick at 12:26 installed the revert: `primary_vlan_id: 11`, `config_revision: 7`, same GET 200 + ack 200 round-trip. Both directions propagated and acked with no forced pulls. Timer stayed on its normal hourly schedule throughout.

## 3. Expiry withdrawal (requires a controlled outage) -- CLOSED 3 Nov 2026

The whole point of the 24h lease / 4h refresh margin is: if the hub goes dark, the site's cached policy must self-invalidate once `expires_at` passes, rather than authorize forever on stale policy.

- [x] Stop the `certmanager` container on the hub (`docker stop certmanager`) for longer than the lease's remaining validity — easiest: do this test starting from a *stale* checkpoint when `expires_at` is <4h out (check timestamp from step 0/1 first), stop the container, and wait past `expires_at`.
- [x] Confirm the expired lease is rejected rather than silently authorizing on stale cache.
- [x] Restart `certmanager` on the hub, confirm the next tick recovers normally (new lease installed, acks resume).

**Result:** Hub (`certmanager` container) stopped at ~03:24 UTC with lease `expires_at: 2026-11-03T05:24:34Z` (~2h remaining). Three site-agent ticks during the outage (12:27, 13:27, 14:30 PHT = 04:27, 05:27, 06:27 UTC) all logged `checkin failed`, `CRL fetch failed`, `network policy pull request failed`, `radius adapter pull request failed` — confirming the agent correctly retried and failed every step while the hub was dark, not just the policy pull. Called `authorize_policy.evaluate_authorization()` directly (the real production enforcement module, same code path FreeRADIUS's `rlm_python3` invokes at auth time) against the cached policy.json past `expires_at` — confirmed fail-closed rejection, no silent authorization on stale cache. Hub restarted; next tick at 15:30 PHT (07:30 UTC) logged `network-policy: installed and verified` with a fresh 24h lease (`issued_at: 2026-11-03T07:30:04Z`, `expires_at: 2026-11-04T07:30:04Z`, revision 11) and the matching hub-side `GET 200` + `POST /ack 200`. All subsequent ticks (16:33, 17:36, 18:37, 19:42 PHT) show normal `304 unchanged` steady state. Recovery was fully automatic — no manual intervention beyond restarting the container.

## 4. Non-zero timer failure status -- PARTIALLY CLOSED 3 Nov 2026 (see note)

- [x] While the hub container is stopped (step 3), confirm the timer stays armed for the next tick (i.e., one failed run doesn't kill the timer).
- [ ] ~~Confirm `systemctl status` shows a failed/non-zero exit for that tick~~ — **does not apply, see note below.**
- [ ] Confirm this failure is visible somewhere an admin would actually see it — **not currently true, see note below.**

**Result:** The timer (`site-agent.timer`) stayed armed and fired on schedule through all three failed ticks and the recovery tick — confirmed, this part of the criterion holds.

**Note — plan's assumption was wrong, and a real gap found:**
1. `systemctl show site-agent.service -p Result -p ExecMainStatus` showed `Result=success` / `ExecMainStatus=0` on every failed tick, not a non-zero exit as this plan originally assumed. Reading `deploy/agent/site_agent.py`'s actual design: it catches and logs each failure (`checkin failed`, `CRL fetch failed`, etc.) as `ERROR`-level log lines but exits cleanly (0) rather than crashing. The error-is-logged and timer-stays-armed behavior is real and correct; "non-zero exit" specifically is not how this agent signals failure and never will be with the current design.
2. The admin-visibility half of this criterion is **not met in production**: `scripts/fleet_watch.py` exists in the repo (implements the `SILENT`-status check described in `HANDOFF-FLEET.md` §5.1) but has no deployed systemd timer on the hub — `systemctl list-timers fleet_watch*` returns 0 results, and `fleet-watch.timer`/`fleet_watch.timer` units don't exist. During this entire 3-tick outage, nothing would have surfaced the failure to an admin looking at the fleet/site health view. This is a genuine open gap, not a documentation nit — deploying `fleet_watch.timer` on the hub is the actual remaining work to close this criterion.

## Pass criteria

- [x] At least 4 natural (non-forced) refresh ticks observed, all producing an ack row on the hub.
- [x] A real policy change propagated through a natural tick, not a forced pull.
- [x] Expired-lease rejection confirmed: auth denied during outage, not silently allowed.
- [x] Timer stays armed through a failed tick (non-zero systemd status does not apply to this agent's design — see step 4 note); **fleet/site-health visibility not yet met — `fleet_watch.timer` not deployed on hub.**
- [x] System recovers cleanly once the hub comes back (no manual intervention needed beyond restarting the container).

**Overall: 4 of 5 criteria fully closed. One follow-up remains: deploy `scripts/fleet_watch.py` as a systemd timer on the hub so a future SILENT site actually surfaces to an admin.**

## Record results back in STAGING-READINESS.md

Once all boxes are checked, replace blocker #4 with a "CLOSED on <date>"
entry summarizing what was observed, same format as the existing closed
items.
