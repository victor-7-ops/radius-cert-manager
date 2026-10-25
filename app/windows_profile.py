"""Windows 802.1X XML Wi-Fi profile generator for EAP-TLS onboarding.

Generates a Microsoft WLANProfile XML document configured for WPA2-Enterprise
with EAP-TLS (EAP Type 13) and pinned to the trusted CA certificate thumbprint.
Can be applied on Windows 10/11 with:
    netsh wlan add profile filename="<profile>.xml" user=current
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from cryptography import x509
from cryptography.hazmat.primitives import hashes


def generate_windows_wifi_xml(
    ssid: str,
    ca_cert: x509.Certificate,
    non_broadcast: bool = False,
    server_names: str = "",
) -> str:
    """Generate a Windows WLANProfile XML for 802.1X EAP-TLS Wi-Fi connection.

    Parameters:
    - ssid: Wi-Fi network name (SSID).
    - ca_cert: Issuing / Root CA certificate to calculate SHA-1 thumbprint for ServerValidation.
    - non_broadcast: True if the network is hidden, False otherwise.
    - server_names: Semicolon-separated list of RADIUS server names to validate (optional).
    """
    # Microsoft WLANProfile XML expects the SHA-1 thumbprint of the trusted Root/Intermediate CA.
    ca_fp = ca_cert.fingerprint(hashes.SHA1()).hex().lower()
    # Format as space-separated two-hex pairs (e.g. "0b aa fd ...") as used in Windows EAP properties
    ca_thumbprint = " ".join(ca_fp[i : i + 2] for i in range(0, len(ca_fp), 2))

    xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
        <nonBroadcast>{'true' if non_broadcast else 'false'}</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <autoSwitch>false</autoSwitch>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2</authentication>
                <encryption>AES</encryption>
                <useOneX>true</useOneX>
            </authEncryption>
            <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
                <authMode>user</authMode>
                <EAPConfig>
                    <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                        <EapMethod>
                            <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13</Type>
                            <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
                            <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
                            <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
                        </EapMethod>
                        <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                            <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                                <Type>13</Type>
                                <EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">
                                    <CredentialsSource>
                                        <CertificateStore>
                                            <SimpleCertSelection>true</SimpleCertSelection>
                                        </CertificateStore>
                                    </CredentialsSource>
                                    <ServerValidation>
                                        <DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>
                                        <ServerNames>{server_names}</ServerNames>
                                        <TrustedRootCA>{ca_thumbprint}</TrustedRootCA>
                                    </ServerValidation>
                                    <DifferentUsername>false</DifferentUsername>
                                </EapType>
                            </Eap>
                        </Config>
                    </EapHostConfig>
                </EAPConfig>
            </OneX>
        </security>
    </MSM>
</WLANProfile>
"""
    # Verify XML validity before returning
    ET.fromstring(xml)
    return xml
