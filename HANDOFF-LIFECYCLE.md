# Handoff: lifecycle phase — offboarding and the renewal campaign

**Status: DONE (2026-09-30).** All of §0, §1.1, §1.2 and §2 are implemented, tested, committed and
pushed to `origin/master`:

| Commit | What |
|---|---|
| `7303bfa` | §0 — retention eligibility keyed on expiry, not revoked status; ORDER BY fix; audit "anonymised" → "detail redaction" |
| `ad03669` | §1.1 — `employee_key` normalisation, backfill, mismatch-report script, non-blocking spelling warnings |
| `ffe503f` | §1.2 — employee offboarding: detail view + revoke-all with typed confirmation |
| `af29f64` | §2 — renewal campaign cohort view, done/outstanding via `supersedes_id`, retire marker, CSV export, bulk-renew wiring |

Full suite (308 tests as of `af29f64`) green throughout, each commit landing with its own tests per
the required working method.

**One caveat, not closeable from a coding session:** `scripts/report_employee_key_mismatches.py` has
only been run against this machine's local dev DB (1 certificate, 0 findings) — that proves the
script works, not that production data is clean. Run it against the real production DB before relying
on the "no collisions" result:
```bash
sudo -u certmgr /opt/certmanager/.venv/bin/python scripts/report_employee_key_mismatches.py
```

**Audience:** an AI coding agent (Claude Code) working in this repo with no other context.
**Read first:** `SESSION-SUMMARY.md`, then `HANDOFF-FLEET.md` §1–2 for codebase conventions and the
required working method (tests land with each change; the suite stays green; no real network calls in
tests; hand-rolled SQLite migrations, no Alembic).

**Prerequisite — do this before anything else.** There is an open defect in `app/retention.py`
described in §0. Fix it first, as its own commit. It is small and it is currently letting the
retention feature miss the majority of records.

---

## 0. Defect — expired certificates are never minimised — DONE (commit `7303bfa`)

`retention._cert_cutoff_reached()` returns `False` unless `cert.status == revoked`, and
`find_eligible_certs()` filters on revoked as well. But `CertStatus` has only `active`, `suspended`
and `revoked` — expiry is derived from `expires_at`, never written as a status. So a certificate that
simply lapses stays `active` forever and keeps `employee_name`, `device_mac` and `device_serial`
indefinitely.

Most certificates will expire rather than be revoked, so the feature currently misses the common case.

The CRL argument in that module's docstring justifies excluding **revoked-but-unexpired**
certificates only. Once a certificate is past `expires_at` it fails validity checking regardless of
the CRL, so its identifiers do not need keeping.

**Fix:** key eligibility on expiry, not on revocation.

```python
if not cert.is_expired(now):
    return False
anchor = max(_aware(cert.expires_at), _aware(cert.status_changed_at or cert.expires_at))
return now >= anchor + datetime.timedelta(days=retention_days)
```

Drop the `status == revoked` condition from both the helper and the query. Keep the
`cert_type == "client"` and `minimised_at is None` filters.

**Two smaller items in the same commit:**

- `find_eligible_certs()` prefilters with `.limit(BATCH_SIZE * 4)` and **no `ORDER BY`**. Above
  2,000 unminimised rows an arbitrary slice comes back and eligible records may never surface —
  progress stalls silently. Add `.order_by(db.Certificate.expires_at)`.
- Audit "anonymisation" clears `detail` only; `actor` (an admin username) survives indefinitely.
  That may be correct for an audit trail, but the module and the dry-run output call it
  *anonymised*, which overstates it and a DPO will read it literally. Rename the concept to
  **detail redaction** in the docstrings, the action names and the CLI output. Do not change what is
  cleared — whether `actor` should also go is a DPO decision, not a code decision.

**Tests:** an expired-never-revoked certificate becomes eligible; a revoked-but-unexpired one does
not; an active unexpired one does not; ordering means a large table makes progress across runs.

---

## 1. Feature A — employee offboarding — DONE (commits `ad03669`, `ffe503f`)

**Why.** Revocation is per-certificate. When an employee leaves, someone must find every certificate
they hold — laptop, phone, tablet — and revoke each one individually. Miss one and a departed
employee keeps network access. This is the scenario that actually recurs; stolen laptops are rare,
leavers are monthly. It is item 10 of the security review, unaddressed.

### 1.1 The data problem, which must be solved first

`employee_name` is **free text**, set independently on the issue form and on each bulk-import row.
"Juan Dela Cruz", "juan dela cruz" and "J. Dela Cruz" are three different employees to the current
code, and an offboarding action built on exact matching will silently miss devices.

Do **not** fix this by fuzzy matching at revoke time — a revoke-all that guesses is worse than one
that misses, because it can disable someone still employed.

Instead:
- Add a normalised, indexed `employee_key` column derived on write (casefold, collapse internal
  whitespace, trim). Keep `employee_name` as the display value.
- Backfill existing rows, and **report** — do not auto-merge — groups of distinct `employee_name`
  values that share an `employee_key`, and near-miss keys. Merging identities is a human decision.
- Validate at issue and bulk-issue time: if the entered name normalises to an existing key with a
  different display spelling, warn in the UI and show the existing spelling, the same way the
  duplicate MAC/serial warning already behaves. Warn, do not block.

### 1.2 The offboarding action

- An **employee detail view** (the cert list already filters by `employee`): every certificate for
  that `employee_key` with status, device, subsidiary and expiry.
- A **revoke-all** action on that view. Super Admin only, matching the existing revoke permission.
  Subsidiary-scoped admins never see or act on employees outside their scope — enforce at the route
  layer, as the existing scoping does.
- One confirmation step showing exactly which certificates will be revoked, by device, with a typed
  confirmation of the employee name. This action disables a person's network access across every
  device; a single click is too cheap.
- Regenerate the CRL **once** after the batch, not once per certificate. Reuse the existing bulk
  suspend/revoke path rather than looping `cert_service.revoke()`.
- Write **one** audit row naming the employee and listing the serials, plus the per-certificate rows
  the existing status change already writes. An auditor asking "what happened when X left" should
  find one entry, not fifteen.
- A reason field, defaulting to something like "employee offboarding", stored on each certificate.

### 1.3 Acceptance

Revoke-all covers every active and suspended certificate for that employee and no others; already
revoked ones are skipped, not re-revoked; the CRL contains every serial afterwards and is
regenerated once; a scoped admin cannot reach an employee outside their subsidiary; the confirmation
cannot be bypassed by posting directly to the endpoint.

---

## 2. Feature B — the renewal campaign — DONE (commit `af29f64`)

**Why.** Client certificates are 365 days and Topline has **no endpoint management platform**, so
there is no automated re-enrolment. Every year the whole fleet must be re-enrolled by hand. The app
currently reports what is expiring; it does not help anyone *run* that campaign. This is the feature
that decides whether the system is still working in year two.

Think of it as a work queue, not a report.

### 2.1 Cohort view

A page answering "what has to be re-enrolled, and what is left to do":

- Filter by window — expiring within 30 / 60 / 90 days, and already expired.
- Group by subsidiary, with counts; drill into the list.
- Columns: employee, device type and model, expiry date, days remaining, current status.
- Export the cohort to CSV, reusing the existing export path and its rate limit. This is what gets
  handed to whoever is physically doing the enrolment.

### 2.2 Campaign progress

Reissuing a certificate already creates a new record linked by `supersedes_id`. Use that as the
progress signal rather than adding a parallel workflow state:

- A certificate in the cohort is **done** when a successor exists that is active and not itself
  within the renewal window.
- The cohort view shows done versus outstanding per subsidiary, so someone can see the campaign
  burn down.
- A per-certificate "not renewing — device retired" marker, so decommissioned devices leave the
  queue without pretending they were re-enrolled. Store the reason; it belongs in the audit trail.

### 2.3 Bulk renew already exists — connect it

`bulk_service` has bulk renew with a shared export password and a single ZIP. The cohort view should
feed a selection straight into it rather than reimplementing. The missing piece is the selection and
the tracking around it, not the issuing.

### 2.4 Acceptance

Cohort counts match a direct database query for the same window; export matches the on-screen list;
a reissued certificate moves from outstanding to done without any manual marking; a retired device
leaves the queue and says why; subsidiary scoping applies throughout.

---

## 3. Out of scope — do not start any of these

- **SCEP or EST enrolment.** Blocked on an endpoint-management decision Topline has not taken.
  Building an unattended certificate-issuing endpoint ahead of that decision is the wrong order.
- **Employee self-service portal.** Without device management this moves the manual problem somewhere
  less controlled, not away.
- **OCSP**, Postgres, Alembic, a task queue, replacing the CA.
- **Admin two-factor** and **secondary RADIUS per site** are both worth doing and both belong to a
  later phase. Not here.

---

## 4. Order and stopping point

1. §0 defect fix — own commit.
2. §1.1 `employee_key` normalisation and the mismatch report — own commit. **Stop and report the
   mismatch findings before building the action on top of them**; if the existing data is messier
   than expected, that changes what §1.2 should do.
3. §1.2 offboarding action.
4. §2 renewal campaign.

The full suite passes and CI is green on GitHub, not only locally, at every step.
