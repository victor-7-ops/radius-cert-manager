# RADIUS Certificate Manager

Internal admin tool for issuing/suspending/revoking client certificates
used in EAP-TLS WiFi authentication. See the handoff document for full
design rationale and Phase A/F–I work not yet built.

## Status

Built: Phase B (pki.py), Phase C (db.py + first-run import), Phase D
(auth.py — session cookie, roles, lockout), Phase E (cert routes —
issue/list/detail/suspend/revoke, CRL regen). 29/29 tests pass against a
throwaway PKI.

Not yet built: Phase F (CRL push automation scheduling + health
endpoint), Phase G (web UI), Phase H (bulk issue), Phase I (polish).
Phase A (static IPs, live PKI restructuring, host hardening) is a
manual procedure on the real CA/RADIUS hosts — see handoff §3–§4.

## Setup

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt
cp .env.example .env   # fill in real values
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
