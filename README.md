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
- **Bulk "renew"** from the cert list's bulk action bar (alongside
  suspend/revoke): select certs (e.g. everything expiring soon),
  reissue all of them under one shared export password, download one
  ZIP of the new `.p12`s + manifest.csv. Same coexistence rule as a
  single reissue — old certs are never touched, only linked via
  `supersedes_id`; suspending/revoking them once the new ones are
  installed is still a separate, deliberate action. A per-row failure
  (e.g. a selected cert is already revoked) doesn't block the rest of
  the batch. `bulk_service.renew_batch()` reuses the exact
  `(BatchResult, zip_bytes)` shape `issue_batch()` already produces, so
  the existing bulk-issue results page renders either one unmodified.
- **Rate limiting on CSV export and .p12/QR bundle downloads**
  (`app/rate_limit.py`, in-process sliding window): CSV export capped
  at 10 per 5 minutes per admin, `.p12` bundle download at 30/minute
  per admin, the unauthenticated QR bundle link at 20/minute per IP.
  Guards against scraping the cert list and against enumerating serials
  to catch someone else's pending one-time bundle before they download
  it themselves.
- **Fix a malformed/duplicate row inline in the bulk-issue preview**
  instead of restarting the whole paste/CSV upload — an inline form on
  each non-valid row re-classifies just that row via
  `POST /certs/bulk/{token}/fix-row` and swaps it in place. Found and
  fixed a real htmx bug while building this: htmx 1.9's response
  handling throws (`e.querySelectorAll is not a function`) if a
  response mixes a bare `<tr>` with non-table oob elements — so the
  valid-count/confirm-button sync happens client-side off a
  `.bulk-valid-badge` count instead of server-rendered OOB swaps.
- **must_change_password is now actually enforced.** The flag was set
  by admin creation and password reset but nothing ever checked it — a
  temp password stayed valid forever. `require_admin` now redirects
  anywhere else to `/account/change-password` until it's cleared
  (logout and the session-keepalive ping are exempt, so it can't
  deadlock). Also added self-service password change for any admin at
  any time — there was no way to change your own password at all
  before this, only a Super Admin resetting it to a new temp one.
- **Certificate expiry alerts** (`app/expiry_alerts.py`, on standby):
  active certs within `EXPIRY_ALERT_DAYS` (default 7) of expiring — or
  already past expiry but not yet acted on — get bundled into one alert
  (not one ping per cert) sent to `ALERT_WEBHOOK_URL`, the same webhook
  CRL-push-failure alerts already used. Each cert is only ever alerted
  once (`Certificate.expiry_alert_sent_at`), so re-checking doesn't
  re-spam. There's no scheduler in this app, so the check runs
  opportunistically on every `/health` page load rather than on a
  timer — genuinely "on standby" until something with a clock (a cron
  hitting `/health`, or a real scheduled task) triggers it periodically.
  Also fixed the webhook payload itself while wiring this up: it was
  POSTing `text/plain`, which Slack's incoming-webhook endpoint accepts
  with a 200 but never actually posts anywhere — now sends the
  `{"text": ...}` JSON shape Slack expects, so pointing
  `ALERT_WEBHOOK_URL` at a Slack incoming webhook works today.
- **Bulk-issue CSV accepts any column order** — headers are matched by
  name (`Name`/`Employee`/`Owner` → employee_name, `MAC Address` →
  device_mac, etc, case-insensitive, unrecognized columns like a
  vendor's `Model` field are just ignored) instead of requiring the
  app's exact `cn, employee_name, device_type, device_mac,
  device_serial, subsidiary` order. If the sheet has no
  identifier/cn/hostname column at all — a real device-inventory export
  usually doesn't — a CN is generated from employee name + device type
  + serial (slugified to fit the CN format) instead of failing every
  row. A fully-blank row is dropped rather than turning into a bogus
  placeholder cert. Falls back to the old strict positional format
  when the header row doesn't match anything recognized, so the app's
  own template and a plain identifier-per-line paste are unaffected.
- **Fixed a real connection-pool leak**: every route called
  `deps.get_db_session()` straight into `session_factory()` with
  nothing ever closing the result — each request quietly leaked a
  connection, and under sustained traffic (or `regenerate_and_push_crl`
  holding its own separate never-closed session open through a CRL-push
  retry/backoff) the pool exhausted and every request started raising
  `sqlalchemy.exc.TimeoutError`. This actually happened repeatedly
  against the live demo server during manual verification earlier in
  development. Fixed with a `scoped_session` keyed by a `ContextVar` set
  once per request by a middleware — one session per request, closed
  automatically after the response, no route signatures changed.
- **System health page** (`/health`, Super Admin only): CRL status,
  cert counts by status, DB file size, PKI directory size, disk
  free/used, active admin/session counts, and the same CA-expiry and
  orphaned-file warnings the dashboard surfaces — one ops-focused view
  instead of piecing it together from the dashboard and server access.
- **Per-session tracking**: login now creates a real `AdminSession` row
  (device/IP/last-active), and the session cookie carries its id — not
  just the coarse `token_version` that used to make every session for
  an admin an all-or-nothing unit. "Your sessions" (click your name in
  the nav) lists every device you're signed in on and lets you end any
  but the current one; deactivate/reset-password/force-logout still
  work exactly as before, now revoking every session row too so the
  list can't show a stale "active" device. A cookie from before this
  feature (no session id) is treated as expired, not silently trusted.
- **Per-subsidiary admin scoping**: an admin created with a "Restrict to
  subsidiary" set can only see/manage certs for that one company —
  enforced at the route layer (cert list/detail/export/dashboard, not
  just hidden UI). Issuing forces the subsidiary to their own regardless
  of what the form sends. Bulk issue and the activity log are unscoped-
  admin-only (bulk issue lets a subsidiary override per row; the audit
  log has no subsidiary column to filter by, so a scoped admin gets 403
  rather than seeing everyone's activity).
- **Duplicate MAC/serial warning at issue time**: reusing a MAC or
  serial that's already on another *active* certificate shows a
  warning with a link to the existing cert, rather than silently
  issuing a second one — catches typos and forgotten-decommission
  mistakes. Doesn't fire against suspended/revoked certs, since
  reusing a serial after decommissioning the old cert is normal. One
  click ("Issue anyway") overrides it.
- **Certificate search** now also matches device MAC (any input format,
  normalized the same way as at issue time) and device serial/asset
  tag, not just CN/employee.
- **QR code on the delivery screen**: scans straight to a .p12
  download on the device being provisioned, which usually isn't
  logged into this app. Backed by a short-lived (10 min) signed token
  independent of the admin session — the bundle stays single-use, so
  the QR and the "Download .p12" button race for the same one-time
  download, same as before.
- **Bulk suspend/revoke**: checkbox per row (desktop table) + a floating
  action bar once anything's selected. Suspend is any admin; revoke is
  gated to super admin same as the single-cert route (`/certs/bulk-action`).
  De-dupes serials and reports a not-found count without failing the
  whole batch.
- **Activity log filters**: action is now an exact-match dropdown driven
  by the distinct actions actually in the DB (was a substring match that
  could cross-match, e.g. "issue" inside "reissue"-adjacent text), plus
  an inclusive date-from/date-to range. Truncation at the 200-row cap
  is now surfaced instead of silent.
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
migrated in place on startup (`db.py`'s `_migrate_columns` adds the
new columns via `ALTER TABLE` if they're missing — there's no
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
