# Ubuntu ML350 staging deployment guide

Status: BLOCKED pending [staging readiness findings](STAGING-READINESS.md). Do not enable a live corporate pilot with the current adapter/agent trust-boundary findings unresolved.

## Hardware actually reported

HPE ProLiant ML350 Gen10, Intel Xeon 4110, total RAM 32 GB; user intends Ubuntu. Exact Ubuntu release/install status, CPU count, DIMM layout, controller, disks/RAID, NICs and UPS remain unverified. Previous resource/throughput figures were not measurements and must not be used for capacity guarantees.

## Service contract

Use the existing `deploy/certmanager.service`, whose ExecStart runs `scripts/serve.py`. That wrapper calls Uvicorn without a worker override; verify effective service environment has no multi-worker override. Keep exactly one worker because enrollment state is process-local. This is not a general claim that SQLite cannot support multiple processes. Bind to loopback behind approved HTTPS proxy; validate secure-cookie and proxy behavior before enrollment.

The existing unit uses `/opt/certmanager`, service user/group `certmgr`, and `/opt/certmanager/.env`. Verify all configured paths/permissions and install dependencies into a fresh Linux virtual environment. Do not copy a Windows virtual environment or format storage through this runbook. Validate Python/package compatibility on the selected Ubuntu release first.

## Policy signing key

The existing helper is `site_policy.get_or_create_policy_signing_key(settings.pki_path)`. Under the service identity, with protected configuration loaded and the approved PKI directory selected, the matching Python expression is:

```python
from app import config, site_policy
settings = config.load_settings()
site_policy.get_or_create_policy_signing_key(settings.pki_path)
```

This writes `private/policy_signing.key` and `policy_signing.pub` under that PKI path if needed. Never print the returned objects or private material. Verify permissions, backup and public-key pin provisioning. Missing production key must not silently rotate trust; review bootstrap/rotation behavior before live use. No key was generated during the readiness review.

## Scheduler and agent

`certmanager-policy-refresh.timer` currently schedules every 4 hours with up to 10 minutes jitter; its service renews policies expiring within 6 hours with a 24-hour lease. This differs from the earlier 6-hour scheduler claim. Verify lease margin, job completion and installed acknowledgements before enabling timers. Inspect actual unit paths and remove no schedule without identifying its owner.

The current agent is environment-driven, not a JSON CLI. Required settings include HUB_URL, SITE_TOKEN, SITE_CN, HUB_CA_BUNDLE and POLICY_PUBLIC_KEY_FILE; provision exact SITE_ID, POLICY_DIR and STATE_DIR explicitly. Optional RADIUS_ADAPTER_PATH overrides where the agent installs `authorize_policy.py` (default `/opt/certmanager/deploy/radius/authorize_policy.py`) — the agent now also pulls and verifies that file itself, signed with the same pinned key as the network policy, and installs it via the same stage/validate/restart/rollback path (see deploy/agent/README.md). Use a protected service environment, never paste credentials into logs or source. The agent now refuses to start without a readable policy public-key pin, validates cached lease/site/revision on HTTP 304, and returns a failing process status when policy synchronization fails.

## Availability and release gates

An independent RADIUS host can continue with valid local materials during a hub outage until the earliest relevant certificate/CRL/policy expiry. A powered-off RADIUS host cannot authenticate; a VM on this chassis shares its outage. Never claim indefinite cached operation. Verify encrypted off-server backup/restore, UPS, storage health, clocks, ACLs and one authoritative issuer.

Resolve STAGING-READINESS.md, record a clean Linux test/integration result and perform the exact RAP72/trunk/DHCP pilot before enabling broad enrollment. Revocation takes effect on new full authentication after updated CRL installation; active sessions need tested termination/reauthentication.
