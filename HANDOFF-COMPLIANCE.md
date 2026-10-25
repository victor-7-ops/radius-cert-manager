# Handoff: compliance phase — the gaps that code can actually close

**Audience:** Engineering and operations teams working in this repo.
**Read first:** `SESSION-SUMMARY.md`, then `HANDOFF-FLEET.md` §1–2 for the codebase conventions and
the required working method. This document is additive.

---

## 0. Where this comes from, and what it is not

Two reviews landed on this project:

1. Topline's Security Officer returned a 10-item gap register against the architecture.
2. A BRD intake analysis (`02 Business Requirements/[New Build] Certificate-Based WiFi
   Authentication/Intake analysis - findings and open items.md`) raised 15 open items, including a
   data-protection finding the security review did not cover.

**Most of those items are decisions, not code** — who owns rollback, whether Topline deploys endpoint
management, who the Project Owner is, what the retention period should be. Nothing in this repo can
close them and no amount of building will.

**This document covers only the subset that code can close.** Six items. Do not expand the scope.

**Explicitly out of scope, and do not start any of them:**
- SCEP or EST enrolment endpoints. They depend on an endpoint-management decision that has not been
  taken, and building an unattended certificate-issuing endpoint ahead of that decision is the worst
  possible order.
- Replacing the certificate authority, or any work that presumes the custom-CA-versus-platform
  question has been settled. It has not.
- Anything in `HANDOFF-FLEET.md` §6's out-of-scope list.
- Deciding any value this document says a human must supply. Make it configurable and leave it unset.

---

## 1. Feature A — retention and data minimisation

**This is the largest item and the one with a legal driver.** Currently there is **no deletion or
minimisation logic anywhere in the codebase**. Certificates, audit rows, admin sessions and site
records accumulate permanently. Revoking a certificate flips its status and leaves the employee
name, MAC address and serial in place indefinitely.

### 1.1 The constraint that shapes the design

**You cannot simply delete certificate rows.** A revoked certificate's serial must remain on the CRL
until its own expiry date, or a revoked device silently becomes valid again. Deleting the record
would be a security regression dressed as a privacy improvement.

**So the mechanism is anonymisation, not deletion**, for certificates:

- After the retention period elapses, clear the personal fields — `employee_name`, `device_mac`,
  `device_serial`, `device_model` — and set a marker column (e.g. `minimised_at`).
- **Keep** `serial`, `cn`, `issued_at`, `expires_at`, `status`, `subsidiary`. These are what the CRL
  and the audit trail need, and they are not personal data once the identifiers are gone.
- Never minimise a certificate that is still active, or whose serial must still appear on a CRL.

For `admin_sessions` (which hold `ip_address` and `user_agent`), straightforward deletion of rows
past the period is correct — nothing downstream depends on them.

For `audit_log`, minimise rather than delete, and take the period from a **separate** setting: audit
retention and enrolment retention answer to different obligations and will not be the same number.

### 1.2 Configuration

Add to `config.py`, all **optional and unset by default**:

- `cert_retention_days` — days after a certificate expires or is revoked before its personal fields
  are cleared.
- `audit_retention_days`
- `session_retention_days`

**Unset means "do nothing".** A deployment that has not been told a period must not start deleting
things on upgrade. This matters: the period is OI-13 and only the DPO can set it.

### 1.3 Safety requirements — non-negotiable

- A **dry-run mode** that reports exactly what would be minimised or deleted and changes nothing.
  This is what gets shown to the DPO.
- Every minimisation and deletion writes an `audit_log` row recording what was affected and under
  which policy. **The audit row recording a deletion is never itself deleted by the same run.**
- Run it from `scripts/retention.py` on a systemd timer, following the existing
  `scripts/fleet_watch.py` pattern. No in-process scheduler.
- Batch and bound the work so a first run against a large table cannot hang the box.
- Surface counts on `/health`: how many records are eligible, when the job last ran.

### 1.4 Tests

Nothing active is minimised. A revoked-but-unexpired certificate keeps its serial and stays on the
CRL. Dry-run changes nothing. Unset config is a no-op. The deletion audit row survives. Re-running is
idempotent.

---

## 2. Feature B — subsidiary as a controlled list

`subsidiary` is free text on `certificates`, `admins.subsidiary_scope`, `sites` and `audit_log`. The
same company can be entered two ways and silently split every grouping, count and scope check —
including the per-subsidiary access control, which is a security consequence, not just a reporting one.

- Constrain to the known list (Lezzgo Boracay, Lezzgo Cebu, Topline Business Development Corporation,
  Light Fuels Corporation, Commercial Fuel Trade, Bay Mall, BMEAD, Others), validated on every write
  path — issue, bulk issue, reissue, site creation, admin creation.
- Add a migration that reports, but does **not** auto-correct, existing values that do not match.
  Near-miss values are a human decision; guessing risks re-scoping somebody's access.
- The list must be editable in one place, since subsidiaries change.

---

## 3. Feature C — a read-only role

Only `admin` and `super_admin` exist. An auditor, a DPO, or a subsidiary manager who should see
without touching currently has to be given an account that can issue certificates.

Add a third role that can view the certificate list, detail pages, activity log and fleet view, and
**cannot** issue, reissue, suspend, revoke, bulk-operate, download a bundle, manage admins or sites,
or export. Enforce at the route layer — the pattern is already established for subsidiary scoping.
Subsidiary scope applies to this role exactly as to `admin`.

Test that every mutating route and every bundle or export route rejects it with 403, by enumerating
the routes rather than by hand-listing them.

---

## 4. Feature D — site management in the UI

Site creation and token rotation are JSON-only (`/api/admin/sites`). Onboarding a site currently
means hand-crafting an API call, which does not survive being handed to anyone else.

A Super-Admin-only page to list sites, create one, rotate its token (**shown once**), deactivate and
reactivate. Reuse the existing templates and the fleet-view status derivation; no new status logic.

---

## 5. Feature E — fix the agent's missing CA bundle *(security defect)*

`deploy/agent/site_agent.py` builds a bare `requests.Session()` with no CA bundle, and
`site-agent.env.example` has no setting for one. The hub's TLS certificate is issued by the Arekushi
intermediate, which is not in the system trust store, so verification against a real hub fails — and
the obvious workaround under time pressure is `verify=False`, which exposes the CRL feed and the CSR
exchange to anyone on the network path.

Add `HUB_CA_BUNDLE`, point it at `ca-chain.pem`, pass it explicitly to the session, and document it
in `deploy/agent/README.md`. **Fail closed** if it is unset or the file is missing — do not fall back
to system trust and do not fall back to no verification. Test both.

---

## 6. Feature F — make the audit backfill one-shot

`db.backfill_audit_log_subsidiary()` runs on every boot. It is idempotent, but it scans the audit
table each start and that cost grows forever. Guard it behind a stored flag so it runs once, with a
documented way to re-run it deliberately.

---

## 7. Acceptance

- Retention: dry-run output is legible enough to hand to a DPO; nothing active or CRL-relevant is
  touched; unset config is a no-op; deletion audit rows survive; `/health` reports eligibility counts.
- Subsidiary: every write path rejects an unknown value; the migration reports mismatches without
  changing them.
- Read-only role: enumerated mutating routes all return 403; subsidiary scope still applies.
- Sites: a site can be created, its token rotated and shown once, and deactivated from the UI.
- Agent: fails closed with no CA bundle; succeeds with one.
- The full suite passes, and CI is green on GitHub, not only locally.

Each feature is its own commit with its tests. Stop and report after Feature A — it is the one with
the legal driver and the one most likely to need a conversation before the rest proceed.
