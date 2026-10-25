"""Apple .mobileconfig profile generator for EAP-TLS Wi-Fi onboarding.

Generates an Apple Configuration Profile XML plist that packages:
1. Root / Intermediate CA trust anchor (com.apple.security.pkcs1) so
   Apple devices trust the FreeRADIUS authentication server without warnings.
2. Client identity certificate and private key (com.apple.security.pkcs12).
3. Enterprise Wi-Fi settings (com.apple.wifi.managed) preconfigured for
   WPA2-Enterprise with EAP-TLS (EAP Type 13) linked to the identity cert.
"""

from __future__ import annotations

import plistlib
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def generate_mobileconfig(
    cn: str,
    serial: str | int,
    pkcs12_data: bytes,
    ca_cert: x509.Certificate,
    wifi_ssid: str = "Corporate-WiFi",
    export_password: str | None = None,
    organization: str | None = None,
    auto_join: bool = True,
    hidden_network: bool = False,
    tls_trusted_server_names: list[str] | None = None,
) -> bytes:
    """Build a .mobileconfig XML plist for Apple iOS/iPadOS/macOS devices.

    Parameters:
    - cn: Common Name of the client certificate.
    - serial: Serial number of the certificate.
    - pkcs12_data: Raw bytes of the PKCS#12 bundle (.p12).
    - ca_cert: Issuing / Root CA certificate used as the trust anchor.
    - wifi_ssid: SSID of the 802.1X corporate Wi-Fi network.
    - export_password: Password protecting the PKCS#12 bundle. If provided,
      embedded into the profile so Apple devices install without password prompt.
    - organization: Organization / Subsidiary name displayed in profile summary.
    - auto_join: Whether the device automatically joins this network.
    - hidden_network: Whether the SSID is broadcasted or hidden.
    - tls_trusted_server_names: Optional list of RADIUS server names to trust.
    """
    profile_uuid = str(uuid.uuid4())
    ca_uuid = str(uuid.uuid4())
    identity_uuid = str(uuid.uuid4())
    wifi_uuid = str(uuid.uuid4())

    ca_der = ca_cert.public_bytes(serialization.Encoding.DER)
    org_name = organization or "Enterprise Network"
    serial_str = str(serial)

    # 1. CA Root/Intermediate Trust Anchor payload
    ca_payload = {
        "PayloadType": "com.apple.security.pkcs1",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"org.radius.profile.{serial_str}.ca",
        "PayloadUUID": ca_uuid,
        "PayloadDisplayName": "RADIUS Trust Anchor CA",
        "PayloadDescription": "Configures the trusted Certificate Authority for 802.1X RADIUS authentication.",
        "PayloadContent": ca_der,
    }

    # 2. Client Identity PKCS#12 payload
    identity_payload: dict = {
        "PayloadType": "com.apple.security.pkcs12",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"org.radius.profile.{serial_str}.identity",
        "PayloadUUID": identity_uuid,
        "PayloadDisplayName": f"Identity Certificate ({cn})",
        "PayloadDescription": "Client certificate and private key for EAP-TLS network authentication.",
        "PayloadContent": pkcs12_data,
    }
    if export_password is not None:
        identity_payload["Password"] = export_password

    # 3. Wi-Fi EAP-TLS managed payload
    eap_client_config: dict = {
        "AcceptEAPTypes": [13],  # EAP-TLS (RFC 5216)
        "PayloadCertificateAnchorUUID": [ca_uuid],
        "UserIdentities": [cn],
    }
    if tls_trusted_server_names:
        eap_client_config["TLSTrustedServerNames"] = tls_trusted_server_names

    wifi_payload = {
        "PayloadType": "com.apple.wifi.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"org.radius.profile.{serial_str}.wifi",
        "PayloadUUID": wifi_uuid,
        "PayloadDisplayName": f"{wifi_ssid} Wi-Fi",
        "PayloadDescription": f"Wi-Fi settings for {wifi_ssid}",
        "SSID_STR": wifi_ssid,
        "HIDDEN_NETWORK": hidden_network,
        "AutoJoin": auto_join,
        "EncryptionType": "WPA2",
        "PayloadCertificateUUID": identity_uuid,
        "EAPClientConfiguration": eap_client_config,
    }

    # Top-level Configuration Profile
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"org.radius.profile.{serial_str}",
        "PayloadUUID": profile_uuid,
        "PayloadDisplayName": f"{wifi_ssid} ({cn})",
        "PayloadDescription": f"Configures {wifi_ssid} Wi-Fi with EAP-TLS certificate authentication for {cn}.",
        "PayloadOrganization": org_name,
        "PayloadScope": "User",
        "PayloadContent": [
            ca_payload,
            identity_payload,
            wifi_payload,
        ],
    }

    return plistlib.dumps(profile, fmt=plistlib.FMT_XML)
