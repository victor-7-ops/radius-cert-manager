# Session Summary — RADIUS Certificate Manager

Covers everything done in this working session, in order.

## 1. Password policy + self-service change
- `app/auth.py`: `require_admin` now enforces `must_change_password` via a custom 428 status, exempting `/account/change-password` itself.
- `app/main.py`: exception handler redirects 428 → `/account/change-password` (303).
- New routes `GET`/`POST /account/change-password` in `app/routes/web.py`.
- New template `change_password.html` (forced vs voluntary variants); link added to `account_sessions.html`.
- Tests: `tests/test_password_change.py` (9 tests).

## 2. Bulk-issue preview: fix malformed/duplicate rows inline
- Found and fixed a real bug: the fix-row form only submitted `identifier`/`employee_name`/`device_mac`, silently wiping `device_type`/`device_serial`/`subsidiary` on save. Fixed with hidden inputs carrying the other fields through.
- Found and worked around an htmx 1.9.12 bug (`e.querySelectorAll is not a function`) caused by mixing a bare `<tr>` swap with non-table `hx-swap-oob` elements — moved valid-count/confirm-button sync to client-side JS.
- Templates: `_bulk_preview_row.html`, `bulk_preview_row_response.html`, `bulk_preview.html`.

## 3. Rate-limit CSV export and bundle downloads
- New module `app/rate_limit.py` — in-process sliding-window limiter keyed by admin id or IP.
- Applied to `cert_export`, `download_bundle`, `download_bundle_via_qr` in `app/routes/web.py`.
- Note: `cert_export` had to use literal `429` instead of `status.HTTP_429_TOO_MANY_REQUESTS` because its own `status` query param shadows the `fastapi.status` import in that function's scope.
- Tests: `tests/test_rate_limit.py` (6 tests).

## 4. Bulk "renew" action for expiring certs
- `app/bulk_service.py`: new `renew_batch()`, same `(BatchResult, zip_bytes)` shape as `issue_batch()`.
- "Renew" button added to `cert_list.html` bulk action bar with its own export-password prompt flow.
- Tests: `tests/test_bulk_renew.py` (5 tests).

## 5. DB connection-pool leak (found proactively)
- `deps.get_db_session()` called `session_factory()` directly, nothing ever closed the session.
- Fixed with `scoped_session(session_factory, scopefunc=ContextVar.get)` + a `@app.middleware("http")` that sets the ContextVar per request and calls `.remove()` after.
- Regression test proves the bug against pre-fix code via `git stash`: `tests/test_db_session_lifecycle.py`.

## 6. Smarter CSV bulk-import (real user bug)
- User's real file had different column names/order than the app expected (`Name, Device Type, MAC Address, Serial Number, Model, Is it a company issued device?`), and got rejected as "malformed" on every row.
- Fixed with `_HEADER_ALIASES` + `_match_header_field()` — any-order/any-subset header-name matching — plus `_slugify_cn()` to auto-generate a CN when no identifier column exists, plus a blank-row skip fix.
- Verified against the user's actual file, both via unit test and live browser (13/13 valid).

## 7. Cert-expiry alerts (Slack-ready, standby)
- New module `app/expiry_alerts.py`: `check_and_alert()` batches newly-due certs into one alert, dedup via `Certificate.expiry_alert_sent_at`.
- `app/config.py` gained `expiry_alert_days: int = 7`.
- Found and fixed a real Slack-compatibility bug: `_alert()` posted `Content-Type: text/plain` — Slack silently 200s but never posts. Fixed to send JSON `{"text": message}`.
- No scheduler exists yet in the app — this is built and tested but not wired to fire automatically (by design, per request — "make it on standby").
- Tests: `tests/test_expiry_alerts.py` (6 tests).

## 8. Device brand/model tracking
- `app/db.py`: `Certificate.device_model` column (nullable, indexed) + migration entry.
- `app/cert_service.py`, `app/bulk_service.py`: `DeviceInfo`/`BatchInputRow`/`PreviewRow` carry `device_model` through issue, reissue, and bulk CSV (7th optional positional column, or by-name via aliases `device_model`/`model`/`brand`/etc — older 6-column CSVs still parse unchanged).
- `app/routes/web.py`, `app/routes/bulk.py`: single-issue form, search, export, cert list/detail, and bulk fix-row all updated.
- Templates: `issue.html`, `cert_list.html`, `cert_detail.html`, `bulk.html`, `_bulk_preview_row.html`.
- Tests: extended `tests/test_device_tracking.py`, `tests/test_bulk.py`, `tests/test_bulk_e2e.py`. 155/155 passing.

## 9. Repo restructuring
- Flattened nested `certmanager/` folder to repo root via `git mv` (preserves rename history) — `app/`, `tests/`, `deploy/`, `scripts/`, etc now live directly at repo root.
- Removed `.claude/` from tracking (`git rm -r --cached`), rewrote `.gitignore` to drop the `certmanager/` prefix.
- Created GitHub repo `victor-7-ops/radius-cert-manager` (private), pushed.

## 10. Removed Claude traces from GitHub history
- `git filter-branch --index-filter` stripped `.claude/` from all history; `--msg-filter` stripped `Co-Authored-By: Claude` lines from every commit message.
- Local safety branch `backup-before-rewrite` created first (never pushed).
- Force-pushed rewritten history to `origin/master`. Verified: no Co-Authored-By lines, no `.claude` files in history.

## 11. CM4 (Raspberry Pi) deployment-readiness pass
Answered: "is the repo ready to put on the CM4 for full Phase A testing, is anything lacking?"

Found and fixed two real gaps:
- **Python 3.10+ crash bug**: `app/config.py` and `app/validation.py` used `str | None` syntax without `from __future__ import annotations` — breaks on import under Python <3.10 (e.g. Raspberry Pi OS Bullseye's 3.9; Bookworm's 3.11 is fine).
- **Stale deploy docs**: `deploy/RUNBOOK.md` and `README.md` still referenced the pre-flatten nested `certmanager/` checkout path and Windows-only `.venv/Scripts/` paths — updated to the Linux `.venv/bin/` layout the CM4 actually needs.
- Checked `deploy/certmanager.service`, `scripts/bootstrap_superadmin.py`, `scripts/restructure_pki.py` — no other OS-specific assumptions found.
- 155/155 tests re-confirmed passing after the fix.
- Committed and pushed (`ff34867`).

**Flagged as not fixable in-session — the real remaining gap:** Phase A itself (static IPs, live PKI restructure, FreeRADIUS trust-chain swap, `eapol_test` verification, CRL push cron) has never been executed against real hardware. It only exists as scripts + a manual runbook (`deploy/RUNBOOK.md`), tested solely against throwaway PKI in dev. Executing it against the real `192.168.200.18`/`.19` hosts is entirely still ahead.

## Status
- Test suite: 155/155 passing.
- Repo: `https://github.com/victor-7-ops/radius-cert-manager` (private), flattened, Claude-trace-free history, up to date at commit `ff34867`.
- App code: ready for CM4 deployment. Phase A hardware execution: not started, not verifiable from this environment (no network path to the real hosts).
