# FreeRADIUS EAP-TLS Tenant Network Policy Adapter

> SOURCE HARDENING COMPLETE; LIVE INTEGRATION UNVERIFIED: read [STAGING-READINESS.md](../STAGING-READINESS.md). Validate the exact FreeRADIUS attribute names and hook behavior on the selected Ubuntu/FreeRADIUS package before a pilot.

## Overview

This adapter implements the authoritative 802.1X EAP-TLS decision tree for FreeRADIUS on site appliances (Ubuntu HPE ML350 Gen10 / Raspberry Pi CM4):
- Validates the X.509 client certificate identity schema: `CN=<device_id>, O=<subsidiary_uuid>, OU=<network_role_uuid>`
- Looks up the locally staged, Ed25519-signed `policy.json` (synchronized by `site_agent.py`)
- Emits RFC 3580 802.1Q VLAN attributes in the final `Access-Accept`:
  * `Tunnel-Type = VLAN` (13)
  * `Tunnel-Medium-Type = IEEE-802` (6)
  * `Tunnel-Private-Group-Id = "<vlan_id>"` (81)
- Never makes online HTTP calls during authentication; fail-closed on expired lease or missing binding.

## Authoritative Decision Matrix

| Role Switch (Tenant) | Site Switch (Tenant) | Platform State | Result | VLAN Assigned |
| :--- | :--- | :--- | :--- | :--- |
| **ON** | **ON** | **Enabled** | **Access-Accept** | **Primary VLAN** |
| **OFF** | **ON** | **Enabled** | **Access-Accept** | **Configured Fallback VLAN** |
| **ON** | **OFF** | **Enabled** | **Access-Accept** | **Configured Fallback VLAN** |
| **OFF** | **OFF** | **Enabled** | **Access-Accept** | **Configured Fallback VLAN** |
| Any | Any | **Blocked** | **Access-Reject** | None (Platform block never falls back) |
| Nonexistent | Any | Any | **Access-Reject** | None (Untrusted role/tenant) |
| Invalid / Expired Cert | Any | Any | **Access-Reject** | None (TLS handshake rejects before policy) |
| Policy Lease Expired | Any | Any | **Access-Reject** | None (Fail closed until agent updates lease) |

## FreeRADIUS Configuration Integration

The adapter requires trusted local configuration in the FreeRADIUS service environment:

```ini
CERTMANAGER_SITE_ID=site-boracay-station1
CERTMANAGER_POLICY_FILE=/etc/freeradius/3.0/policy.json
```

Do not populate `Site-Id` or `Policy-File` from RADIUS request pairs. The adapter ignores those pairs and fails closed when either local value is absent. It authorizes only when exactly one `TLS-Client-Cert-Subject` pair is present; `User-Name` is never treated as certificate identity.

### 1. Enable rlm_python3

In `/etc/freeradius/3.0/mods-available/python3_policy`:

```unlang
python3 python3_policy {
    module = "deploy.radius.authorize_policy"
    python_path = "/opt/certmanager:/etc/freeradius/3.0"

    mod_post_auth = ${.module}
    func_post_auth = "post_auth"
}
```

`mod_post_auth` is the module reference, `func_post_auth` is the function name string — swapping them fails module instantiation (`you should set 'func_post_auth = ...' too`) on FreeRADIUS 3.2.x.

Enable module:
```bash
ln -s /etc/freeradius/3.0/mods-available/python3_policy /etc/freeradius/3.0/mods-enabled/python3_policy
```

### 2. Configure Post-Auth Hook in Virtual Server

In `/etc/freeradius/3.0/sites-available/default` (or `inner-tunnel`):

```unlang
post-auth {
    # Call the Python policy adapter after successful EAP-TLS verification
    python3_policy

    # Ensure tunnel attributes are copied to the outer Access-Accept reply
    update outer.reply {
        &Tunnel-Type := &reply:Tunnel-Type
        &Tunnel-Medium-Type := &reply:Tunnel-Medium-Type
        &Tunnel-Private-Group-Id := &reply:Tunnel-Private-Group-Id
    }
}
```

### 3. AP and Switch Trunk Configuration (Ruijie Reyee RAP72 / planned mixed-vendor access switches)

1. **AP Trunking**: Configure switch port connecting to the AP as 802.1Q trunk carrying native management VLAN and tagged user VLANs.
2. **SSID Configuration**:
   - Security: WPA2/WPA3-Enterprise (802.1X).
   - Dynamic VLAN Assignment: Enabled (respects RADIUS `Tunnel-Private-Group-Id`).
3. **Session Reauthentication**: Set AP reauthentication interval (e.g. 14400s / 4 hours) or configure RADIUS `Session-Timeout` as a proposed value requiring real AP validation; it does not guarantee session termination or revocation latency.
