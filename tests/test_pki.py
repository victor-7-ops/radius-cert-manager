import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app import pki


def test_private_key_serializes_unencrypted_pkcs8_and_reloads():
    # This is the §5.1 OpenSSL 3 trap — test it explicitly.
    key = pki.generate_private_key()
    pem = pki.private_key_to_pem(key)
    assert b"ENCRYPTED" not in pem
    reloaded = serialization.load_pem_private_key(pem, password=None)
    assert reloaded.private_numbers().private_value == key.private_numbers().private_value


def test_encrypted_pem_requires_password_and_rejects_wrong_one():
    key = pki.generate_private_key()
    pem = pki.private_key_to_encrypted_pem(key, b"correct-horse-battery")
    assert b"ENCRYPTED" in pem

    import pytest

    with pytest.raises(TypeError):
        serialization.load_pem_private_key(pem, password=None)

    reloaded = serialization.load_pem_private_key(pem, password=b"correct-horse-battery")
    assert reloaded.private_numbers().private_value == key.private_numbers().private_value


def test_sign_server_cert_has_server_auth_eku_not_client_auth(throwaway_pki):
    key = pki.generate_private_key()
    csr = pki.build_csr(key, "radius-server")
    serial = pki.generate_serial()
    cert = pki.sign_server_cert(
        csr, throwaway_pki["inter_cert"], throwaway_pki["inter_key"], serial, days=365
    )
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    assert ExtendedKeyUsageOID.CLIENT_AUTH not in eku


def test_signed_cert_has_correct_validity_window_eku_and_chains(throwaway_pki):
    key = pki.generate_private_key()
    csr = pki.build_csr(key, "device-01")
    serial = pki.generate_serial()
    cert = pki.sign_client_cert(
        csr, throwaway_pki["inter_cert"], throwaway_pki["inter_key"], serial, days=365
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    assert cert.not_valid_after_utc - now < datetime.timedelta(days=366)
    assert cert.not_valid_after_utc - now > datetime.timedelta(days=364)

    eku = cert.extensions.get_extension_for_class(
        __import__("cryptography.x509", fromlist=["ExtendedKeyUsage"]).ExtendedKeyUsage
    ).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku

    assert cert.issuer == throwaway_pki["inter_cert"].subject
    # verifies signature chains to intermediate's public key
    throwaway_pki["inter_cert"].public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        __import__("cryptography.hazmat.primitives.asymmetric.ec", fromlist=["ECDSA"]).ECDSA(
            cert.signature_hash_algorithm
        ),
    )


def test_pkcs12_round_trips(throwaway_pki):
    key = pki.generate_private_key()
    csr = pki.build_csr(key, "device-02")
    serial = pki.generate_serial()
    cert = pki.sign_client_cert(
        csr, throwaway_pki["inter_cert"], throwaway_pki["inter_key"], serial, days=365
    )
    bundle = pki.build_pkcs12(
        "device-02", key, cert, [throwaway_pki["inter_cert"], throwaway_pki["root_cert"]]
    )
    loaded_key, loaded_cert, loaded_cas = pki.load_pkcs12(bundle.data, bundle.password)
    assert loaded_cert.serial_number == serial
    assert loaded_key is not None
    assert len(loaded_cas) == 2


def test_serials_are_random_64bit_and_never_collide_1000_generations():
    serials = {pki.generate_serial() for _ in range(1000)}
    assert len(serials) == 1000
    for s in serials:
        assert s.bit_length() >= 63


def test_crl_contains_revoked_and_omits_active(throwaway_pki):
    key1 = pki.generate_private_key()
    csr1 = pki.build_csr(key1, "revoked-device")
    serial1 = pki.generate_serial()
    pki.sign_client_cert(
        csr1, throwaway_pki["inter_cert"], throwaway_pki["inter_key"], serial1, days=365
    )

    serial2 = pki.generate_serial()

    crl = pki.build_crl(
        throwaway_pki["inter_cert"],
        throwaway_pki["inter_key"],
        [(serial1, datetime.datetime.now(datetime.timezone.utc))],
        validity_days=7,
    )

    assert crl.get_revoked_certificate_by_serial_number(serial1) is not None
    assert crl.get_revoked_certificate_by_serial_number(serial2) is None
    assert crl.next_update_utc - crl.last_update_utc == datetime.timedelta(days=7)


def test_cert_validity_clamped_to_issuing_ca(throwaway_pki):
    short_ca_cert, short_ca_key = pki.build_intermediate_ca(
        "Short CA", 30, throwaway_pki["root_cert"], throwaway_pki["root_key"]
    )
    key = pki.generate_private_key()
    csr = pki.build_csr(key, "short-lived-client")
    serial = pki.generate_serial()

    # Request 365 days under a CA that only has 30 days left
    cert = pki.sign_client_cert(csr, short_ca_cert, short_ca_key, serial, days=365)
    assert cert.not_valid_after_utc == short_ca_cert.not_valid_after_utc


def test_expired_ca_raises_value_error(throwaway_pki):
    import pytest

    # Construct an expired CA (valid from 10 days ago to 1 day ago)
    key = pki.generate_private_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    expired_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Expired CA")]))
        .issuer_name(throwaway_pki["root_cert"].subject)
        .public_key(key.public_key())
        .serial_number(pki.generate_serial())
        .not_valid_before(now - datetime.timedelta(days=10))
        .not_valid_after(now - datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(throwaway_pki["root_key"], hashes.SHA256())
    )
    client_key = pki.generate_private_key()
    csr = pki.build_csr(client_key, "client")
    serial = pki.generate_serial()

    with pytest.raises(ValueError, match="already expired"):
        pki.sign_client_cert(csr, expired_ca_cert, key, serial, days=30)


def test_crl_contains_reason_codes_for_suspended_and_revoked(throwaway_pki):
    serial_hold = pki.generate_serial()
    serial_comp = pki.generate_serial()
    now = datetime.datetime.now(datetime.timezone.utc)

    crl = pki.build_crl(
        throwaway_pki["inter_cert"],
        throwaway_pki["inter_key"],
        [
            (serial_hold, now, x509.ReasonFlags.certificate_hold),
            (serial_comp, now, x509.ReasonFlags.key_compromise),
        ],
        validity_days=7,
    )

    hold_rev = crl.get_revoked_certificate_by_serial_number(serial_hold)
    assert hold_rev is not None
    hold_reason_ext = hold_rev.extensions.get_extension_for_class(x509.CRLReason)
    assert hold_reason_ext.value.reason == x509.ReasonFlags.certificate_hold

    comp_rev = crl.get_revoked_certificate_by_serial_number(serial_comp)
    assert comp_rev is not None
    comp_reason_ext = comp_rev.extensions.get_extension_for_class(x509.CRLReason)
    assert comp_reason_ext.value.reason == x509.ReasonFlags.key_compromise


def test_sign_client_cert_with_crl_dp_url(throwaway_pki):
    key = pki.generate_private_key()
    csr = pki.build_csr(key, "cdp-device")
    serial = pki.generate_serial()

    cert = pki.sign_client_cert(
        csr,
        throwaway_pki["inter_cert"],
        throwaway_pki["inter_key"],
        serial,
        days=365,
        crl_dp_url="http://radius.internal/crl.pem",
    )

    cdp_ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    assert cdp_ext is not None
    assert cdp_ext.value[0].full_name[0].value == "http://radius.internal/crl.pem"
