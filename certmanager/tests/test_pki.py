import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from app import pki


def test_private_key_serializes_unencrypted_pkcs8_and_reloads():
    # This is the §5.1 OpenSSL 3 trap — test it explicitly.
    key = pki.generate_private_key()
    pem = pki.private_key_to_pem(key)
    assert b"ENCRYPTED" not in pem
    reloaded = serialization.load_pem_private_key(pem, password=None)
    assert reloaded.private_numbers().private_value == key.private_numbers().private_value


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
