# Working in this repo

FreeRADIUS + a hub-based certificate and policy manager for Topline's
corporate Wi-Fi (WPA2/WPA3-Enterprise, EAP-TLS).

## Rules — these are not negotiable

1. **Every `.md` file in this repo is local-only.** Never `git add`,
   commit or push one, tracked or untracked, even one you just edited.
   This file is the single exception and only because it contains no
   addresses, secrets or topology — keep it that way.
2. **No AI attribution on any commit or PR, ever.** No
   `Co-Authored-By: Claude`, no `Generated with`. Code commits included.
3. **No direct SSH or shell to the live boxes.** Hand over exact commands
   and wait for the output to be pasted back.
4. **Never enter a password** to authenticate into a live service.
5. **Tests pass before anything is committed.**
6. **Never `reload` FreeRADIUS where a `restart` is required** — CRL,
   X509 store, or `clients.conf`. A SIGHUP does not rebuild them. This has
   caused two silent production incidents.

## How work is handed over

Claude Desktop does review, analysis and planning. Claude Code does the
building. Work moves between them through files in this repo.

| File pattern | What it is |
|---|---|
| `PROMPTS-<date>-ROUND<n>.md` | Task prompts, each self-contained — a cold session can run one without reading the others |
| `HANDOFF-SESSION-<date>.md` | What a session actually did |
| `deploy/*.md` | Durable reference — plans, audits, runbooks |

Consolidated cross-surface notes live in the Obsidian vault under
`Projects/Topline Network & RADIUS`.

## Orientation

Read in this order when picking the project up cold:

1. `deploy/TENANT-AND-VLAN-PLAN.md` — the tenant, department and VLAN model
2. The newest `HANDOFF-SESSION-*.md` — current state
3. The newest `PROMPTS-*.md` — what is queued
4. `deploy/STAGING-READINESS.md` — the long-running blocker list

Hosts, addresses and infrastructure detail are in `deploy/` — deliberately
not here.

## What this project keeps getting wrong

Two patterns account for most of the incidents. Expect both.

**An assumption that looks right.** Each of these held for weeks because
the code read correctly:

- `reload` rebuilds FreeRADIUS's X509/CRL store — it does not
- `freeradius -XC` proves a config works — four separate bugs passed it
- `crl_health` alerts on a stale CRL — it was silent on a fresh install
- Prometheus rules imply monitoring — nothing was listening for months
- `check_crl=yes` means revocation is enforced — a revoked canary still
  authenticated, because the CRL never contained it

**Built + tested + documented ≠ deployed.** A per-site setup step was
documented and never performed. The site-agent on both boxes predated a
feature by weeks. The boxes are not git-managed; code arrives by hand copy.

The lesson both times: **verify behaviour on a live box, not config or
code.** If something is reported as done in an older handoff, ask whether
it was ever actually run, not whether it was written.

**The first-time path.** A real bug: `/checkin` handled the renewal case
and fell straight past the from-scratch case. Any code with a "first"
— first CRL, first policy, first device at a new site — deserves that
second look.

## Things that are easy to get wrong here

- A site can be **"Authorized" and still reject everything** if it has no
  `SiteRoleBinding` rows.
- `freeradius -X` **bypasses the systemd drop-in** that injects
  `CERTMANAGER_SITE_ID` and `CERTMANAGER_POLICY_FILE`, producing false
  "configuration incomplete" rejections while debugging.
- A box left with **`freeradius` stopped is worse than one powered off** —
  the site-agent keeps running and silently rolls back every install.
- `cert_service.revoke()` **does not regenerate or push the CRL.** Only the
  web routes do. Anything else calling it must push explicitly.
- The two RADIUS appliances are a failover pair and **keep diverging**.
  A fix verified on one is not verified on the other.
