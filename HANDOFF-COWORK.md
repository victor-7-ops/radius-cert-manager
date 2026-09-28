# Handoff: Fleet phase complete — for the next session (Claude Cowork)

**Audience:** an AI coding agent with no other context, picking this repo up fresh.
**As of:** commit `67e26e1` on `master`, pushed to `origin/master`, CI green.
**Read `HANDOFF-FLEET.md` first** — this doc reports what happened against that plan.
It supersedes nothing in that file; treat it as the "here's what actually landed" companion.

---

## 1. What this session did

Everything in `HANDOFF-FLEET.md` §3–§8 has been implemented, tested, committed, and
pushed. 223 tests pass locally and on GitHub Actions. In commit order:

| Commit | What |
|---|---|
| `d160c3b` | **Feature A** — RADIUS server-certificate lifecycle |
| `d447b0b` | **Feature B** — site registry + check-in/pull API |
| `aca57fa` | **Feature B §4.4** — the actual site agent script |
| `a33d9ec` | **Feature C** — fleet view |
| `20969d6` | §8.1 — CI (GitHub Actions, `pytest tests/ -q`) |
| `56eeb54` | §8.2 — hub self-monitoring (liveness route + heartbeat) |
| `6c865c7` | §8.3 — audit_log subsidiary/site_id |
| `073d76c` | §8.4 — backup + restore-drill scripts |
| `eaf19d1` | CI action version bump (Node 20 deprecation) |
| `67e26e1` | pytest config (silences an unrelated deprecation warning) |

Every commit landed with tests in the same commit and the suite green before moving
to the next item, per the handoff's working method (§2). Nothing was squashed or
amended — full history is real.

---

## 2. Feature A — server-certificate lifecycle

- `Certificate.cert_type` (`"client"`/`"server"`, default `"client"`) and
  `Certificate.site_id` (nullable FK, no DB-level constraint — SQLite + this
  project's hand-rolled migrations don't enforce FKs anywhere).
- `cert_service.issue_server_cert()` — takes a CSR (never a private key) from the
  caller, validates the CSR's CN against the requesting site's registered CN,
  signs with `pki.sign_server_cert()` (already existed, was previously dead code).
- `cert_service.renewal_due()` — true when less than 1/3 of lifetime remains.
- `cert_service.renewal_offset()` — deterministic per-site stagger,
  `sha256(site_id) % window_days`.
- 8 existing queries across `web.py`, `certs.py`, `expiry_alerts.py`,
  `bulk_service.py` were audited and filtered to `cert_type == "client"` so server
  certs never leak into device lists/counts/bulk ops. The CRL-regeneration query
  was **deliberately left unfiltered** — a revoked server cert must still appear
  on the CRL.
- Tests: `tests/test_server_cert.py`.

## 3. Feature B — site registry + check-in/pull API + agent

- New `Site` table (`app/db.py`): id, name, subsidiary, radius_cn, address,
  auth_token_hash, crl_validity_days, checkin_interval_seconds, last_seen_at,
  last_reported_crl_sha256, last_reported_freeradius_ok, server_cert_id,
  agent_version, is_active, created_at, notes, last_alerted_status (added later
  for §8's fleet-watch dedup).
- `app/site_auth.py` — bearer-token dependency (`require_site`), Argon2-hashed
  (reuses `app.auth`'s hasher), **no cookie path exists in this dependency at
  all** — it only ever reads the `Authorization` header, so an admin session
  cookie can never authenticate an agent route by accident.
- `app/site_service.py` — create/rotate-token/deactivate, all audited.
- `app/routes/site.py` (`/api/site/*`, token-authed, rate-limited per site):
  - `POST /checkin` — agent reports version/FreeRADIUS-ok/CRL-hash/cert-serial;
    hub responds with `newer_crl_available` / `renewal_due` / next interval.
  - `GET /crl` — ETag/304 pull.
  - `POST /server-cert/renew` — CSR in, signed cert + chain out. 403 (no detail
    leaked) on CN mismatch.
- `app/routes/sites_admin.py` (`/api/admin/sites`, Super Admin only) — JSON CRUD
  to create a site and see its token **once**. No template UI was built for this
  — deliberate scope call, the fleet view is the intended UI surface for sites,
  not a site-management screen. If Victor wants a proper "create site" page in
  the admin UI, that's still open.
- `deploy/agent/site_agent.py` — stdlib + `requests` only, runs from a systemd
  timer (`deploy/agent/site-agent.timer`), one idempotent pass per invocation.
  Key/CSR generation shells out to `openssl` (never a Python serialization path —
  the private key never leaves the box, never gets password-protected).
  `_install_with_safety()` is the single choke point for both the CRL and the
  server cert/key: stage → `freeradius -XC` → install → reload → verify active →
  roll back and reload again on **any** failure.
- Startup seeds one `Site` row from the existing `RADIUS_HOST` env var so the old
  push-based rig (`crl_push.py`) keeps working untouched — it was never removed,
  per the handoff's explicit "don't delete it" instruction (§6).
- Tests: `tests/test_site_registry.py`, `tests/test_site_agent.py`.

**Not done / not verifiable from here:** the agent has never run against real
hardware — deploy/agent/README.md has the install steps, but executing them
against an actual FreeRADIUS box (verifying `_install_with_safety`'s rollback
against a real `freeradius -XC` failure, not a mocked one) is still ahead, same
caveat the original Phase A runbook already carried.

## 4. Feature C — fleet view

- `app/fleet_health.py` — pure `evaluate_site()`/`evaluate_fleet()`, no I/O side
  effects, unit-testable like `crl_health.py`. Derives OK/WARN/CRITICAL/SILENT
  per the handoff's exact rules (§5).
- `app/fleet_watch.py` — the alerting side. Edge-triggered via
  `Site.last_alerted_status`: fires once on a transition into a worse status, and
  again on recovery back to OK. **Does not** fire once per scheduler tick for a
  site stuck at CRITICAL — that was the explicit §5.1 trap.
- `scripts/fleet_watch.py` — systemd-timer entrypoint, same shape as the
  pre-existing `regenerate_crl_cron.py`. Also pings the §8.2 heartbeat after a
  successful run.
- `GET /api/health/fleet` + a fleet table on `/health`, both Super Admin only.
- Tests: `tests/test_fleet_health.py` + 4 tests appended to `tests/test_health_page.py`.

## 5. §8 adjacent work

- **§8.1 CI** — `.github/workflows/tests.yml`, `pytest tests/ -q` on push/PR,
  Python 3.14, pinned `requirements.txt`. Verified green on GitHub itself (not
  just locally) via `gh run view`, multiple times, including after the
  `actions/checkout`/`setup-python` v4→v7 bump that cleared a Node-20-deprecation
  warning.
- **§8.2 hub monitoring** — `GET /api/live/{liveness_token}` (unauthenticated,
  404s identically whether disabled or wrong-token, so its existence doesn't
  leak). `scripts/fleet_watch.py` pings `HEARTBEAT_URL` after a successful run,
  deliberately independent of the app's own `alert_webhook_url`.
  **`deploy/HUB_MONITORING.md` documents the CloudWatch side as copy-pasteable
  `aws cloudwatch` commands — these were NOT run.** I have no AWS credentials
  or console access from this environment. Someone with access to the real AWS
  account needs to actually create: the EC2 instance-status alarm, and the
  heartbeat-absence alarm (or wire `HEARTBEAT_URL` to a healthchecks.io-style
  service instead, which needs no AWS access at all — see that doc for both
  options).
- **§8.3 audit_log subsidiary** — `AuditLog.subsidiary`/`site_id` columns,
  populated on write at every call site that has the info, plus a one-time
  idempotent backfill (`db.backfill_audit_log_subsidiary()`, runs every boot,
  joins historical rows' `target` CN back to `certificates.subsidiary`).
- **§8.4 backup/restore** — `app/backup.py` (shared core: in-memory tar → Fernet
  encryption with a PBKDF2-derived key, nothing plaintext ever touches disk),
  `scripts/backup.py`, `scripts/restore_check.py` (exits non-zero on any
  failure — wrong passphrase, zero certs, mismatched key/cert). **This was
  smoke-tested end-to-end against a real generated PKI+DB, not just under mocks**
  — see the session transcript around "check §8 acceptance criteria one more
  time" for the actual CLI run and output.

---

## 6. Local dev environment

A throwaway dev setup now exists on this machine (not in git — all gitignored):

- `pki/` — throwaway root + intermediate CA.
- `.env` — dev settings pointing at that PKI and a local SQLite DB.
- Dev admin: username `admin`, password `devpassword123`.
- `.claude/launch.json` was fixed — it previously pointed at a nonexistent
  `demo_launch:app` module (unrelated stale leftover, not something this
  session's work created). It now correctly launches `app.main:create_app`.

Run it with:

```bash
.venv\Scripts\python.exe -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8443
```

None of this (`pki/`, `.env`, `.claude/`) is tracked by git — a fresh clone
needs this redone. `deploy/agent/site-agent.env.example` and the bootstrap
pattern in `scripts/bootstrap_superadmin.py` are the reference for doing it
properly (interactive password prompt) rather than the shortcut used here.

---

## 7. What's still open

Everything below is **explicitly out of scope** per `HANDOFF-FLEET.md` §6, or
was flagged as a deliberate scope cut during this session — none of it is a
bug, all of it is a known gap:

1. **AWS provisioning itself** — CloudWatch alarms (§8.2), the actual EC2 hub
   deployment, moving the hub there. This repo is ready for it; none of it has
   been run against real AWS. Still open — needs real AWS credentials/console
   access, not available to a coding agent.
2. **Site-agent hardware verification** — `deploy/agent/site_agent.py` has never
   executed against a real FreeRADIUS box. Install-safety logic is unit-tested
   with every subprocess mocked, which proves the control flow but not the real
   `freeradius -XC` behavior on real hardware. Still open — needs real hardware.
3. ~~**No admin UI for site management**~~ — **done** (2026-09-28, part of the
   HANDOFF-COMPLIANCE.md work, commit `38a5f55`): `/sites` page, Super-Admin-only
   — list with fleet-view status, create, rotate token (shown once), deactivate,
   reactivate.
4. Everything `HANDOFF-FLEET.md` §6 already ruled out: AWS-hosted FreeRADIUS,
   non-expiring certs, silent auto-renewal of client certs, Alembic/task queue.

**Also closed since this doc was written** (HANDOFF-COMPLIANCE.md phase,
2026-09-28, commits `aa149d9`..`bd3189a`): data retention/minimisation,
subsidiary as a controlled list, a read-only viewer admin role, the site
agent's missing CA bundle (security defect — it now fails closed), and the
one-shot audit backfill (§8.3 above ran every boot until then). A follow-up
audit against `HANDOFF-FLEET.md` also found and fixed three smaller gaps:
`renewal_offset()` was dead code (the per-site renewal stagger from §3.3 was
never actually applied), `scripts/fleet_watch.py` had no systemd timer (so
SILENT detection never ran on a schedule), and the CN-availability check
didn't exclude server certs like every other cert query in the app.

---

## 8. Verification commands for whoever picks this up

```bash
# Full suite
.venv\Scripts\python.exe -m pytest tests/ -q

# CI status on GitHub
gh run list --workflow=tests.yml --limit 5

# Confirm the fleet-phase commits are all present
git log --oneline d160c3b..67e26e1
```

Expect: 223 passed, CI green, 15 commits from `d160c3b` through `67e26e1`.
