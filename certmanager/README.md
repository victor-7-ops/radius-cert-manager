# RADIUS Certificate Manager

Internal admin tool for issuing/suspending/revoking client certificates
used in EAP-TLS WiFi authentication. See the handoff document for full
design rationale and Phase A/F–I work not yet built.

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

Not yet built: Phase I (polish/a11y pass, dark mode explicitly out of
scope). Phase A (static IPs, live PKI
restructuring, host hardening) is a manual procedure on the real
CA/RADIUS hosts — see handoff §3–§4 — and the `eapol_test` gates in §10
can only be run against your real CM4/CA machine, not from here.

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
