# RADIUS Certificate Manager

Internal admin tool for issuing/suspending/revoking client certificates
used in EAP-TLS WiFi authentication. See the handoff document for full
design rationale and Phase A/F–I work not yet built.

## Beyond the handoff (added after v1)

- **Device/owner tracking**: employee name, device type (with icon),
  MAC (validated/normalized), device serial, and company/subsidiary
  (fixed colorway) on every cert. Employee and subsidiary both drill
  down into a filtered cert list from anywhere they appear.
- **Dashboard**: fleet-status donut (colored by company), by-company
  breakdown card, 6-month issuance trend bar chart, all with count-up
  numbers and staggered entrance animation.
- **Reissue**: same-CN new cert linked via `supersedes_id`, old cert
  untouched (handoff §8.1's overlap window) — `cert_service.reissue_certificate`.
- **CSV export** of the cert list (respects whatever filter is active)
  and a **bulk-issue CSV template** download.
- **Toast notifications** on suspend/unsuspend/revoke/admin actions,
  carried via a one-shot `?flash=` query param on the redirect, stripped
  from the URL client-side after showing.
- **Session-expiry warning**: a "stay signed in" toast ~60s before the
  15-minute inactivity timeout, backed by a `GET /auth/ping` no-op that
  rides the existing silent-cookie-refresh in `require_admin`.
- **Keyboard shortcuts**: `/` focuses search, `g` then `d`/`c`/`b`/`a`
  jumps to dashboard/certs/bulk/activity.
- Topline branding (logo, favicon), boosted nav transitions, colored
  avatars, and a general visual pass (see git log for the blow-by-blow).

- **Dark mode** (explicit request, overriding the handoff's §6.1 "no
  dark mode in v1" decision): toggle button in the nav, persisted to
  `localStorage`, defaults to OS preference on first visit. FOUC-safe
  (theme class applied before the stylesheet loads). Component classes
  carry `dark:` variants directly; raw Tailwind utility classes already
  in use across templates (`text-slate-900`, `bg-white`, ...) are
  overridden via targeted `.dark .{class}` rules in `input.css` rather
  than touching every template.

Not done: anything requiring the live hosts (Phase A — see below).

## Status

Built: Phase B (pki.py), Phase C (db.py + first-run import), Phase D
(auth.py — session cookie, roles, lockout), Phase E (cert routes —
issue/list/detail/suspend/revoke, CRL regen), Phase F (CRL health
endpoint + push retry/backoff/alert), Phase G (Jinja2+HTMX+Tailwind web
UI — login, dashboard, cert list/detail/issue, one-time `.p12` delivery
screen, admin management, activity log), Phase H (bulk issue — paste/CSV,
preview/classify before signing, shared batch password, ZIP + manifest.csv
delivery, partial-failure handling, request_id idempotency per row).
45/45 tests pass against a throwaway PKI; the UI was walked through
manually in a browser (login, issue, delivery, list, detail), and the
bulk flow is covered end-to-end through the real HTML routes in
tests/test_bulk_e2e.py (browser-click automation against the live bulk
form was unreliable in this environment, so that flow's correctness
rests on the e2e test rather than a manual click-through).

Built (Phase I — polish): HTML error pages for web routes (404/403/409/
410/500) instead of raw JSON, a stale-CRL banner on every authenticated
page (was missing from the bulk-issue screens), a fixed "Expired" cert
filter (it's a computed status, not a stored one — the filter and the
"Active" filter now agree with the badge shown on each row), and a
regression test proving the 500 handler never leaks key material or a
raw traceback to the client.

Phase I also surfaced and fixed a real bug: `certs.py`, `health.py`, and
`web_auth.py` built their `APIRouter` at module import time and mutated
it inside `get_router()`. A second `create_app()` call in the same
process (e.g. two tests back to back) appended duplicate routes to that
shared router, and the *first* app's stale handlers — bound to its own
DB session and secret key — won route matching for the second app,
producing spurious 401s. All routers are now built fresh inside their
`get_router()` call. This wouldn't have surfaced in a single long-running
production process, but the tests that caught it are worth keeping.

Beyond the phase list: device/owner tracking. Each certificate can carry
an employee name, device type, MAC address, and device serial/asset tag
— captured at issue time (single or bulk CSV, columns
`cn, employee_name, device_type, device_mac, device_serial`), shown on
the cert list and detail pages, and searchable. Clicking an employee's
name filters the cert list down to every device issued to them
(`/certs?employee=...`), since one person often has more than one
device on the network. MAC addresses are validated and normalized to
`aa:bb:cc:dd:ee:ff` regardless of how they're typed in (colon, dash,
Cisco dotted, or bare hex). None of this touches the certificate
itself — it's tracking metadata in SQLite only. Existing databases are
migrated in place on startup (`db.py`'s `_migrate_certificate_columns`
adds the new columns via `ALTER TABLE` if they're missing — there's no
Alembic in this project, so this is the whole migration story; it only
ever adds columns, never drops or renames).

Phase A (static IPs, live PKI restructuring, host hardening) is a manual
procedure on the real CA/RADIUS hosts that can't be run from this
environment — no network path to `192.168.200.18`/`.19`. What's built
instead: `scripts/restructure_pki.py` (builds the offline root + online
intermediate + reissues `radius-server`, tested against a throwaway
output tree), `deploy/certmanager.service` (systemd hardening per §4),
`deploy/crlpush_forced_command.sh` + `authorized_keys.crlpush.example`
(the §8.4 forced-command credential), and `deploy/RUNBOOK.md`, which
walks through every remaining step in order with checkpoints — including
the exact-order test-device transition from §3 step 5 and the
`eapol_test` gates from §10 that only your real CM4 can verify.

55/55 automated tests pass against throwaway PKIs; nothing here has
touched or can touch the live PKI or the live CM4.

## Setup

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt
cp .env.example .env   # fill in real values

npm install                # tailwindcss + htmx.org (dev-time only)
npx tailwindcss -i ./app/static/input.css -o ./app/static/tailwind.css --minify
cp node_modules/htmx.org/dist/htmx.min.js app/static/htmx.min.js
```

`app/static/tailwind.css` and `htmx.min.js` are committed build artifacts — rerun
the two commands above after editing templates or `tailwind.config.js`.

## Run the app locally

`demo_launch.py` seeds env vars for a quick local run against whatever PKI/DB
`PKI_PATH`/`DB_PATH` point at — see the file. In production, `.env` (loaded by
`app/config.py`) is the real config path.

```bash
.venv/Scripts/python -m uvicorn demo_launch:app --host 127.0.0.1 --port 8443
```

## Run tests

```bash
.venv/Scripts/python -m pytest tests/ -q
```

Tests never touch a live PKI or live RADIUS host — `conftest.py` builds
a throwaway CA under `tmp_path` for every test.

## Bootstrap the first Super Admin

```bash
.venv/Scripts/python -m scripts.bootstrap_superadmin --username <you>
```

Refuses to run if an admin already exists.
