# Staging readiness review

26 October 2026. Status: BLOCKED for live pilot. Earlier completion claims are historical reports, not verified production readiness.

## Confirmed blockers

### Locally remediated on 26 October 2026

Source and regression tests now close findings 1, 2, 3, 4, 5, 8, and 9: certificate identity is TLS-subject-only with strict cardinality and conservative DN parsing; site/path are pinned locally; policy verification requires a readable key pin; 304 responses validate the installed lease; same-revision/different-hash responses fail; the agent propagates synchronization failure; empty site membership compiles an empty policy; and the runbooks describe the persistent signing helper plus the real environment-driven CLI. These are local test results, not proof of FreeRADIUS, Ubuntu, RAP72, switching, or DHCP behavior.

### Closed on 27 October 2026

1. ~~Confirm the exact certificate-subject attribute and callback cardinality delivered by the installed FreeRADIUS version after a successful EAP-TLS handshake.~~ **CLOSED.** FreeRADIUS 3.2.5 (Ubuntu 24.04 `noble`, arm64) installed and live on a Raspberry Pi CM4 site appliance (`topline-freeradius1`, 192.168.13.54). The `python3_policy` module/post-auth hook was deployed per the (now-corrected, see `deploy/radius/README.md`) config and ran a real end-to-end EAP-TLS handshake using `eapol_test` (built from upstream `w1.fi/hostap` source) against a client certificate issued through this repo's own `app/pki.py` (subject `CN=eap-test-device1, O=<subsidiary-uuid>, OU=<network-role-uuid>`).

   Observed delivered attribute, verbatim from the FreeRADIUS debug log:
   ```
   TLS-Client-Cert-Subject := "/CN=eap-test-device1/O=11111111-1111-1111-1111-111111111111/OU=22222222-2222-2222-2222-222222222222"
   ```
   Single `TLS-Client-Cert-Subject` pair, OpenSSL-oneline format (`/CN=.../O=.../OU=...`) — matches `authorize_policy.py`'s `parse_certificate_identity` exactly. The adapter correctly returned `RLM_MODULE_OK` with `Tunnel-Type`/`Tunnel-Medium-Type`/`Tunnel-Private-Group-Id` reply attrs for a known binding, and the full chain reached `Access-Accept` (confirmed via `eapol_test`'s `SUPP_BE: SUCCESS` state). Test-only CA/cert/policy.json and build tooling (`hostap`, `eapol_test`) were removed from the CM4 afterward; the real `python3_policy` module wiring was left in place since it is the production config, not test scaffolding.

   Also found and fixed a real bug during this: `deploy/radius/README.md`'s config snippet had `mod_post_auth`/`func_post_auth` swapped, which fails module instantiation on FreeRADIUS 3.2.x. Corrected in the README.

### Remaining live-integration blockers

2. Verify the local service environment securely pins `CERTMANAGER_SITE_ID`, `CERTMANAGER_POLICY_FILE`, `SITE_ID`, `POLICY_PUBLIC_KEY_FILE`, and `HUB_CA_BUNDLE`, with ownership and permissions appropriate to the service identities. (`CERTMANAGER_SITE_ID`/`CERTMANAGER_POLICY_FILE` are pinned via a systemd drop-in on the CM4 above; the hub-side vars are not yet applicable since the hub app isn't deployed anywhere yet.)
3. Confirm policy refresh, expiry withdrawal, acknowledgement recording, and non-zero timer failure status on the Linux staging host.
4. The hardware inventory and real Ruijie Reyee RAP72/mixed-switch integration remain unverified. Validate module paths, outer/inner hook placement, VLAN trunks, DHCP, reauthentication, CRL behavior, and fail-closed cases on the installed versions.
5. `policy.json` on the CM4 is not yet a real, hub-signed file — no production `policy.json` is present (test fixture removed in cleanup). Needs `site_agent.py` actually syncing from a deployed hub with Ed25519 signature verification exercised live, not just in unit tests.
6. Server-side TLS cert for FreeRADIUS is still the distro's default self-signed snakeoil cert — unaddressed, separate from client-cert verification.

## Next required checks

Reproduce full-suite results and add the missing security negatives; passing current tests cannot close these findings. Audit issuance/role grants, subsidiary-superadmin UI/API completeness, offboarding retry and issuance races against B01–B12 before reasserting all tasks complete. Source inspection shows multiple commits during offboarding, so do not call the whole operation atomic without transaction/crash evidence. Verify policy freshness/withdrawal and installed acknowledgements in a real local RADIUS test.

No private keys, production database contents or environment secrets were read by this review. The callback proof used random identities, an in-memory fictional policy and a temporary directory. No application source, remote host or production network was changed in this review.

## Deployment inputs

Need installed Ubuntu version, host SSH address/username (no passwords), verified storage/UPS/NIC inventory, approved DNS/static IPs, site identity and primary/fallback network mappings. Hardware pilot must prove primary VLAN, fallback VLAN, wrong-server rejection and revoked credential rejection after CRL installation/full authentication. Already-established sessions require separately tested reauthentication/disconnect behavior; no immediate termination guarantee.

## Verification results from resumed session

- Full regression command: `.venv\Scripts\python.exe -m pytest -q`.
- Observed result: **377 passed in 330.43s** on the local Windows checkout. This does not cover the source-confirmed negatives above or Ubuntu/AP behavior.
- Isolated adapter negative: no TLS certificate subject, forged User-Name identity and temporary fictional policy returned module OK (2); expected REJECT (0). No live RADIUS claim is inferred.
- SSH attempted in batch mode with strict host-key checking to `topline-server@192.168.13.73`; failed with `Permission denied (publickey,password)`. No remote inventory or changes occurred. Do not send passwords/private keys in chat; establish approved SSH authentication before retrying.
- Documentation updated: both root handoffs, hardware deployment guide, RADIUS guide warning and this report. Existing application/source changes were preserved; no new application source fix was made in this review.
- Next work: remediate and add regression tests for certificate-only identity, locally pinned site/path, mandatory policy signature verification, cached-policy expiry, agent exit status and empty allowlist withdrawal; then rerun checks before staging. Establish authenticated SSH for a read-only host inventory.
