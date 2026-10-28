# Spec: Super Admin UI for subsidiaries, departments, and per-subsidiary site bindings

## Why

The network-policy data model (subsidiaries → departments → roles → VLAN
bindings per site) already exists and is fully functional
(`app/network_policy.py`, `app/db.py`), but it has no admin web UI. Every
subsidiary, department, role, and site-role binding in production today
(`topline` / `ops` / `staff`) was created by hand-written one-off Python
scripts run directly against the hub's database, because the only way to
reach `app/network_policy.py`'s functions is its JSON API
(`app/routes/network_policy.py`) — no HTML page exists for a Super Admin to
do this through the browser. That's the gap this spec closes.

## Existing backend to build on (do not duplicate this logic — call it)

- `app/db.py` — real tables: `Subsidiary`, `Department`, `NetworkRole`,
  `DepartmentRole` (join), `SiteRoleBinding` (site + subsidiary + role →
  `vlan_id`/`fallback_vlan_id`), `Site`.
- `app/network_policy.py` — service layer, already enforces authorization
  (`actor: db.Admin` param on every mutating call) and validation:
  - `create_subsidiary(actor, code, display_name, session)`
  - `create_department(actor, subsidiary_id, code, display_name, session)`
  - `create_network_role(actor, subsidiary_id, code, display_name, session)`
  - `link_department_role(actor, department_id, role_id, session)`
  - `configure_site_role_binding(actor, site_id, subsidiary_id, role_id, vlan_id, fallback_vlan_id, session, ...)`
    — **Super Admin only** (`ForbiddenError` otherwise); `vlan_id` must be
    1–4094 and `fallback_vlan_id` must differ from `vlan_id`.
  - `set_network_role_tenant_state`, `set_site_binding_tenant_state`,
    `set_site_binding_platform_state` — enable/disable toggles.
- `app/routes/network_policy.py` — the existing JSON API wrapping all of the
  above, mounted under (check `main.py`'s `include_router` call for the
  actual prefix). Reuse these endpoints from the new pages via `hx-*`
  attributes (the rest of the app is htmx + server-rendered Jinja2, not a
  JS SPA — follow that pattern, see `app/templates/cert_detail.html` for
  the house style) rather than writing new JSON routes, unless a page needs
  data these don't already return.

## Real inconsistency to resolve first

`app/db.py` also has this, unrelated to the real `Subsidiary` table above:

```python
SUBSIDIARIES = ["Lezzgo Boracay", "Lezzgo Cebu", "Topline Business Development Corporation", ...]
```

A hardcoded free-text list used only by the legacy standalone cert-issue
form (`app/templates/issue.html`, `Certificate.subsidiary` as a plain
string column) and CSV bulk-issue. It has no relationship to the real
`Subsidiary` table — issuing a cert through that old form doesn't create or
reference a real `Subsidiary` row at all.

**Decide and implement one of:**
- (a) Replace `SUBSIDIARIES`'s free-text picker with a live dropdown
  sourced from the real `Subsidiary` table, so every issued cert
  eventually points at a real row — bigger change, touches
  `app/routes/web_certs.py`'s `issue_submit`/`cert_bulk_action` and
  `bulk.py`.
- (b) Leave the legacy free-text path alone for now and only build the new
  pages against the real tables — smaller, but the inconsistency persists
  and a cert issued the old way still won't show up under its
  "subsidiary" in the new UI.

Pick (b) first if you want this shippable fast; flag (a) as a known
follow-up either way.

## Open design question — answer before building

**Does a Site belong to exactly one Subsidiary, or can one physical site
serve several Subsidiaries?**

Today's schema is many-to-many by construction: `SiteRoleBinding` links a
`site_id` + `subsidiary_id` + `role_id` independently, so nothing stops the
same `Site` row from having bindings under two different subsidiaries (a
single CM4 box serving two co-located companies, each with its own VLAN).
That's a deliberate, real scenario — a branch office shared by, say,
`topline` and a related subsidiary, same RADIUS server, isolated by VLAN.

If the product decision is "one site = one subsidiary, period," that needs
either (1) a new unique constraint plus UI that hides/forbids a second
subsidiary's binding on an already-bound site, or (2) stays a soft
UI-level rule only. Pick before building the Sites page below, since it
changes whether "Sites" lives under a Subsidiary's own page or stays a
flat top-level list with a subsidiary filter.

## Pages to build

All under the existing **Super Admin** nav section (`app/templates/base.html`
already has `Admins`, `Health`, `Sites`, `Activity` there — add these
alongside). Require `admin.role == db.AdminRole.super_admin` the same way
`sites_admin.py` and `configure_site_role_binding` already do —
**mirror that check in the route, don't rely on the nav link being hidden.**

### 1. Subsidiaries list + create (`/admin/subsidiaries`)

- Table: code, display name, department count, active/inactive, created
  date.
- "New subsidiary" form (code + display name) → `create_subsidiary`.
- Row click → subsidiary detail page.

### 2. Subsidiary detail (`/admin/subsidiaries/{id}`)

- Departments list (code, display name, linked roles) + "Add department"
  form → `create_department`.
- Network roles list (code, display name, enabled/disabled) + "Add role"
  form → `create_network_role`.
- Per-department: link/unlink roles → `link_department_role`.
- Site bindings for this subsidiary: which sites, which role, primary/
  fallback VLAN, platform/tenant enabled state — table + "Add site
  binding" form → `configure_site_role_binding`. This is the piece that
  answers "sites of each subsidiary" from the request.
- Toggle switches wired to `set_network_role_tenant_state` /
  `set_site_binding_tenant_state` / `set_site_binding_platform_state`.

### 3. Sites page changes (`app/templates/sites_list.html`, already exists)

- Add a column or expandable row showing which subsidiaries/roles/VLANs
  are bound to each site (currently `sites_list.html` only shows agent
  check-in health, not policy bindings — confirm by reading the current
  template before changing it).
- If the design decision above is "one site, one subsidiary," enforce it
  here: creating a second binding for an already-bound site should warn
  or block, matching whatever was decided.

## Non-negotiables (carry over from the rest of this codebase)

- Every mutating action takes the real `admin: db.Admin` from
  `deps.require_admin`/`deps.require_super_admin` and passes it through as
  `actor` — never bypass `network_policy.py`'s own authorization checks
  with a raw ORM write.
- `db.audit(...)` — confirm `network_policy.py`'s functions already audit
  internally (check before adding a second redundant audit call in the
  route).
- Follow the existing htmx + Jinja2 + Tailwind house style, not a new JS
  framework — see `app/templates/cert_detail.html` and
  `app/templates/sites_list.html` for the patterns (status badges,
  `hx-post`/`hx-confirm` buttons, `_status_badge.html` macro import).
- **Use the `HX-Redirect` middleware already fixed in `app/main.py`** (the
  `_htmx_redirect` middleware added 28 Oct 2026) — any `RedirectResponse`
  from these new routes gets translated correctly for htmx automatically,
  no per-route special-casing needed.
- Add tests under `tests/` for every new route (see existing
  `tests/test_network_policy*.py` for the service-layer test patterns to
  extend) — the project has zero tolerance for untested admin mutation
  routes based on the rest of the codebase's test coverage.
- Run the real full suite (`.venv/Scripts/python.exe -m pytest tests/ -q`)
  before calling this done — 395 tests passing as of 28 Oct 2026, this
  should stay the baseline, not regress it.

## Addendum: per-site VLAN segmentation on/off toggle

Real-world driver (28 Oct 2026): `topline-freeradius1`'s RAP72 is plugged
directly into a consumer ISP router with no 802.1Q support. VLAN 10
couldn't reach a DHCP scope, so as a stopgap `SiteRoleBinding.vlan_id` was
manually set to `1` (a hand-done hack to fake "no real segmentation") just
to restore internet access. Not every site will have a managed/L3 switch —
some will only ever be router + FreeRADIUS + AP, authenticating devices
without VLAN segmentation. This needs to be a real, first-class setting,
not a hack repeated by hand at every such site.

**Add a site-level flag**, not a binding-level one — segmentation capability
is a property of the site's physical network, independent of which
subsidiary/role/VLAN numbers are configured for it:

- `app/db.py`: add `Site.vlan_segmentation_enabled: Mapped[bool] = mapped_column(default=True)`
  (default True — don't silently disable segmentation on existing sites
  that do have a switch; only `topline-freeradius1` should actually be
  flipped off, explicitly, after this ships). Needs a migration
  (`app/network_migrations.py` has the existing pattern — one-shot flag
  row per migration name, see its own docstring).
- `app/site_policy.py`'s `compile_site_policy`: include this flag in the
  signed `policy.json` payload so the adapter can read it locally
  (fail-closed design — the adapter must never phone home mid-auth, same
  reasoning as everything else it already reads from the local policy
  file).
- `deploy/radius/authorize_policy.py`: when the site's
  `vlan_segmentation_enabled` is `false`, build every `accept` decision
  with `vlan_id=None` regardless of what the matched binding's
  `vlan_id`/`fallback_vlan_id` say — this already produces a VLAN-free
  `Access-Accept` (see the existing `if decision.outcome == "accept" and
  decision.vlan_id is not None:` branch around line 315 that only emits
  `Tunnel-*` attributes when `vlan_id` is set). Bump
  `deploy/radius/README.md`'s docs to describe this, and update
  `deploy/STAGING-READINESS.md` once `topline-freeradius1` is switched
  over from the manual `vlan_id=1` hack to the real flag.
- **UI**: a toggle on the Site create/edit form (wherever `sites_admin.py`
  /`sites_list.html` currently live) — "This site has VLAN-capable
  infrastructure (managed/L3 switch)" on by default, off for
  authenticate-only sites. When off, the Sites page and the Subsidiary
  detail page's site-binding table (section 2 above) should visibly mark
  VLAN columns as "n/a — authentication only" rather than showing numbers
  that don't actually apply.
- Test coverage: a fail-closed negative (segmentation disabled + a
  binding with a real `vlan_id` → decision still carries no `Tunnel-*`
  attributes) belongs in whatever test file already exercises
  `authorize_policy.py`'s decision matrix.

## Out of scope for this spec

- VLAN/switch trunk hardware setup (separate, physical — see
  `deploy/STAGING-READINESS.md` blocker 5b).
- Employee/Device UI — already exists (`app/routes/web_employees.py`),
  untouched by this work except that its forms should eventually source
  subsidiary/department/role from these new real tables instead of (or in
  addition to) however they currently populate those dropdowns — worth a
  quick check during implementation, not a rebuild.
