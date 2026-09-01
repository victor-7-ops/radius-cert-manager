# Handoff: Fleet Phase — server-cert lifecycle, site check-in, fleet view

**Audience:** an AI coding agent (Claude Code) working in this repo with no other context.
**Supersedes nothing.** This is additive to what exists. Read `SESSION-SUMMARY.md` for what the
app already does; read this before writing any code for the three features below.

Sections marked **DECISION** are settled — implement as written, do not re-litigate.
Sections marked **TRAP** describe failure modes already paid for in this project.

---

## 0. Why this phase exists

The app manages *client* certificates for one office. The deployment target has changed:

- **DECISION (2026-09-01):** the cert manager is hosted on **AWS EC2**, in a private subnet inside
  the VPC the company's AWS VPN terminates into. Admins reach it in a browser over the VPN from any
  subsidiary. There is no desktop client.
- **DECISION:** FreeRADIUS stays **on each site's LAN**, never in AWS. A dropped VPN must not stop
  people joining WiFi at that office.
- **DECISION:** CRL delivery flips from **hub-push to site-pull**. Pushing over a WAN fails whenever
  a site is briefly offline; a pull recovers by itself on the next cycle.
- Planned scale is **8 subsidiaries, potentially 20–30 sites.** Everything below must be written for
  N sites, not for one.

Three features follow from that: RADIUS **server-certificate lifecycle**, a **site check-in/pull
API**, and a **fleet view**. They are described in §3, §4 and §5.

---

## 1. Where the code actually is (verified by reading it, not from docs)

| Area | State |
|---|---|
| `app/pki.py` | X.509 primitives. **`sign_server_cert()` already exists** (serverAuth EKU, line ~206) but is only called by `scripts/restructure_pki.py` and one test. Keys are **EC P-256** (`ec.SECP256R1`). |
| `app/cert_service.py` | issue / reissue / suspend / revoke / regenerate_crl, file-locked around PKI mutations. Client certs only. |
| `app/crl_push.py` | `push_crl()` — scp + forced-command ssh + read-back hash verify. **Push only. No pull path exists.** |
| `app/crl_health.py` | `crl_state` single-row table, `push_with_retry()`, staleness banner. **Single CRL, single target.** |
| `app/config.py` | `radius_host`, `radius_ssh_user`, `radius_ssh_key` are **scalars**. There is no concept of a site anywhere in the codebase. |
| `app/db.py` | `certificates`, `admins`, `admin_sessions`, `audit_log`. `certificates` has **no `cert_type`** (client vs server) and **no site column**. |
| `app/routes/health.py` | `/api/health/crl` — the hub's own CRL state only. |
| `scripts/regenerate_crl_cron.py` | The scheduling mechanism is an external cron/systemd timer calling into the app. There is no in-process scheduler. |
| Tests | 27 files. `conftest.py` builds a throwaway CA per test. SSH is always mocked and must stay mocked. |

### 1.1 Corrections to the existing planning docs

Two things in `PhaseA-CertManager-Nano-Handoff.md` are wrong against this code. Do not propagate them.

1. **"Bulk issue is CPU-bound on RSA key generation — reduce the bulk cap to 25–50."** The code
   generates **EC P-256** keys, which are effectively instant. There is no RSA keygen anywhere in the
   issuance path. Leave the bulk cap alone.
2. **§2 hardware (USB SSD, eMMC wear, 12V PSU, UPS) and §8 CRL push** describe the CM4-Nano-hosted
   plan, superseded by the EC2 decision above. They still apply to the *RADIUS* Nanos at sites.

### 1.2 Repo hygiene — do this before starting

`git status` shows uncommitted modifications to `app/main.py` and six test files, plus an untracked
`PHASE_A_SESSION_LOG.md`. Commit or discard deliberately before beginning; do not build on top of an
unexplained dirty tree.

---

## 2. Required working method

- **Read before writing.** This codebase has consistent internal patterns (dependency injection via
  `RouteDeps`, request-scoped DB sessions, injectable `run`/`sleep_fn` for testability). Match them.
- **Tests are not optional.** 147 pass today. Every change lands with tests, and the suite must be
  green before you move to the next item. `pytest tests/ -q`.
- **Never make a real network call in a test.** SSH, HTTP to sites, everything is injected and mocked.
- **Migrations are hand-rolled `ALTER TABLE` against SQLite** (`app/db.py`). Follow the existing
  in-place migration story; do not introduce Alembic in this phase.
- **The `Secure` session cookie means tests need `base_url="https://testserver"`.** Known quirk.
- Work in the order §3 → §4 → §5. Each is independently shippable.

---

## 3. Feature A — RADIUS server-certificate lifecycle

**The problem:** every site's FreeRADIUS has its own server certificate. When it expires, that site's
WiFi stops. Nothing in the app tracks these today, and at 30 sites that is 30 silent time bombs.
**This is the most likely cause of a future outage in the whole system.**

### 3.1 Schema

Add to `certificates`:

- `cert_type` — `"client" | "server"`, default `"client"`, indexed. Backfill existing rows to `client`.
- `site_id` — nullable FK to the new `sites` table (§4.1); set for server certs.

**Server certs must be excluded from the normal cert list, dashboard counts and bulk operations by
default** — they are infrastructure, not devices. Add an explicit filter rather than letting them
leak into every existing query. Audit every existing `select(Certificate)` for this.

### 3.2 Issuance

Reuse `pki.sign_server_cert()`. **DECISION: the site agent generates its own key and sends a CSR.**
The RADIUS server's private key never travels over the network and never exists on the hub. The hub
signs and returns cert + `ca-chain.pem` only.

Validate the CSR before signing: the CN must match the requesting site's registered CN. A site must
never be able to obtain a certificate for another site.

**TRAP — `bad decrypt`.** Any private key written for FreeRADIUS must be serialized with explicit
`NoEncryption()`. `pki.private_key_to_pem()` already does this and carries the comment explaining why.
The agent-side key writing must do the same. This has cost this project debugging time twice.

### 3.3 Renewal policy

- Renew when **less than one third of the certificate's lifetime remains** — not at the last minute.
- **Stagger across the fleet.** Derive a deterministic per-site offset (e.g. `hash(site_id) % window`)
  so 30 sites never renew on the same night. An automated renewal that goes wrong must break one site,
  not all of them simultaneously at 3am with nobody on site.
- Renewal is initiated by the site during check-in (§4), never pushed by the hub.

### 3.4 Agent-side install safety — non-negotiable

The agent must, in this order: write the new cert and key to a staging path → run `freeradius -XC`
→ only on success move them into place and reload → verify FreeRADIUS came back → **on any failure,
restore the previous cert and key, reload again, and report the failure in the next check-in.**

A renewal that cannot be verified is rolled back, not left in place hoping.

---

## 4. Feature B — site registry and check-in/pull API

### 4.1 `sites` table

`id`, `name`, `subsidiary`, `radius_cn`, `address` (informational), `auth_token_hash`,
`crl_validity_days` (per-site override — **30 for remote sites, 7 for the local one**),
`checkin_interval_seconds`, `last_seen_at`, `last_reported_crl_sha256`, `last_reported_freeradius_ok`,
`server_cert_id`, `agent_version`, `is_active`, `created_at`, `notes`.

Seed one row from the existing `RADIUS_HOST` env value so the working test rig keeps functioning.
**Do not break the existing push path in this phase** — the current rig is the safety net; leave
`crl_push.py` in place and working until pull is proven.

### 4.2 Authentication for agents

**DECISION: per-site bearer token**, generated at site creation, shown once, stored Argon2-hashed
(reuse the existing password hashing), rotatable from the UI, revocable by deactivating the site.

Rationale and the trade-off, stated honestly: mutual TLS using a cert from your own intermediate
would be more elegant and would dogfood the PKI, but it needs client-cert termination in front of
uvicorn and creates a chicken-and-egg problem when a site's cert is the very thing that has expired.
A token has no such failure mode. **Design the endpoints so mTLS can be added later** — keep auth in
one dependency, not scattered through the routes.

Agent routes are token-authenticated and must **not** accept the admin session cookie, and must not
be reachable by an admin session either. Rate-limit them per site (reuse `app/rate_limit.py`).

### 4.3 Endpoints — new `app/routes/site.py`, prefix `/api/site`

- `POST /checkin` — agent reports: agent version, FreeRADIUS running yes/no, current CRL sha256,
  current server cert serial and `notAfter`. Hub records `last_seen_at` and the reported values, and
  responds with: whether a newer CRL exists, whether a renewal is due, and the next check-in interval.
- `GET /crl` — returns `crl.pem` with an `ETag` of its sha256; returns `304` when unchanged. This is
  the pull that replaces the push.
- `POST /server-cert/renew` — agent posts a CSR, hub validates CN against the site and returns the
  signed cert plus `ca-chain.pem`.

Every one of these writes an `audit_log` row with the site as actor.

### 4.4 Agent

Ship a small script under `deploy/agent/` — plain Python standard library plus `requests` at most, so
it runs on a CM4 with no build chain. Systemd timer, not a daemon. Idempotent: safe to run twice.

**TRAP — installing a CRL.** The agent must refuse to install a CRL whose `nextUpdate` is already in
the past, and must validate with `freeradius -XC` before reloading. `deploy/crlpush_forced_command.sh`
already does this on the push side; port that logic, don't reinvent it.

---

## 5. Feature C — fleet view

**DECISION: no UI on the site boxes.** A machine that is down cannot serve a status page saying it is
down. Thirty status pages are thirty things to patch and thirty attack surfaces, none of which are
reachable exactly when you need them. The fleet view lives on the hub, and **absence of a check-in is
the signal.**

Extend `/health` (Super Admin only) with a fleet table, and add `GET /api/health/fleet`. Per site:
last seen, CRL age against that site's own window, server-cert days remaining, FreeRADIUS status,
agent version. Derive one status per site:

- `OK` — checked in recently, CRL fresh, cert comfortably in date
- `WARN` — CRL past half its window, or cert inside its renewal window, or one missed check-in
- `CRITICAL` — CRL expired or expiring within 48h, cert expiring within 14 days, or FreeRADIUS down
- `SILENT` — no check-in for more than three intervals

`SILENT` is the one that matters and the one a page-load-driven check cannot produce.

### 5.1 This forces the scheduler

Staleness alerts cannot keep running opportunistically on `/health` page loads — "nobody opened the
dashboard, so nobody noticed Boracay died" is precisely the failure this feature exists to prevent.

**DECISION:** add `scripts/fleet_watch.py` on a systemd timer, following the existing
`regenerate_crl_cron.py` pattern. No new runtime dependency, no in-process scheduler, consistent with
the app's single-process design. It evaluates every site, and alerts through the same webhook path
`crl_health` already uses.

**TRAP — the webhook.** `expiry_alerts` once POSTed `text/plain`, which Slack accepts with a 200 and
silently never posts. Send the `{"text": ...}` JSON shape. Batch alerts per run; do not send one
message per site.

---

## 6. Explicitly out of scope for this phase

- Any UI, web server or dashboard running on the site machines (§5).
- Moving FreeRADIUS into AWS.
- "Lifetime" or non-expiring certificates. Certificate lifetime is the security envelope, and no
  leaf can outlive the 5-year intermediate that signs it anyway. Client certs stay at 365 days.
- Silent auto-renewal of *client* certificates. Device certs stay a deliberate admin action.
- Replacing SQLite, adding Alembic, or introducing a task queue.
- Deleting `crl_push.py`. It stays until pull is proven against a real site.

---

## 7. Acceptance

- A site row can be created, its token shown once, and an agent using that token can check in.
- A revocation on the hub reaches a site **by pull**: revoke → CRL regenerates → agent's next pull
  fetches it (ETag changes) → `eapol_test` with the revoked cert **fails**. Issuance-only testing
  verifies half a system.
- A server certificate inside its renewal window is renewed end to end: agent generates a key, posts
  a CSR, installs the response, `freeradius -XC` passes, FreeRADIUS reloads, `eapol_test` still
  succeeds — and the site's row shows the new expiry.
- **A deliberately corrupted renewal is rolled back** and the failure appears in the fleet view.
- A site whose agent is stopped shows `SILENT` within three intervals and fires exactly one alert.
- Two sites cannot read each other's CRL endpoint or obtain each other's certificate.
- No token, key, or CSR material appears in any log or error response.
- The existing 147 tests still pass, and server certs do not appear in client cert lists or counts.

---

## 8. Adjacent work — small, separate, do NOT fold into Features A–C

Each of these is its own commit and its own session. They are listed here so they are not forgotten,
not so they can be bundled into the fleet work. **Do not start any of them unless asked.**

### 8.1 CI — do this first, it is the cheapest

A GitHub Actions workflow running `pytest tests/ -q` on push and pull request. Python 3.14, install
from the pinned `requirements.txt`. Nothing currently runs the 147 tests automatically; the first
quiet regression a refactor introduces will otherwise reach a live PKI.

### 8.2 Monitoring the hub itself

The fleet view (§5) reports on sites. **Nothing reports on the hub.** When the hub is down the fleet
view is down with it, so the failure surfaces days later as a CRL-expiry outage at every site
simultaneously — the exact fail-closed scenario this system is meant to avoid.

- Expose a minimal unauthenticated-but-unguessable liveness endpoint, or emit a heartbeat from
  `fleet_watch.py` on each successful run.
- On EC2: a CloudWatch alarm on instance status plus an alarm on heartbeat absence.
- The alarm must not route only through the same Slack webhook the app uses — if the app is down,
  it cannot tell you it is down.

### 8.3 Audit log: add a subsidiary column

`audit_log` has no subsidiary dimension, which blocks a subsidiary-scoped activity view for scoped
admins. It has been flagged as a structural gap twice. It only gets more expensive to backfill as the
table grows, and this phase is already touching the schema. Add `subsidiary` and `site_id`, populate
on write, backfill what can be derived from the target certificate.

### 8.4 Backup and restore as scripts

Phase A acceptance requires a restore drill, and an improvised drill is a skipped drill. Add:

- `scripts/backup.py` — DB, `pki/issued/`, and the encrypted intermediate key, to an encrypted
  archive with a timestamped name. Never writes plaintext key material.
- `scripts/restore_check.py` — restores an archive into a scratch directory, opens the DB, verifies
  the cert count and that `openssl verify` passes against the restored chain. Exits non-zero on any
  failure so a timer can run it.

An untested backup is a belief, not a backup.
