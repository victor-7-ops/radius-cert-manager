"""Certificate operations: keygen, CSR, signing, PKCS12, CRL.

No web or database imports here — this module is tested in isolation
because a subtle bug here produces certificates that look fine and fail
in the field (handoff §11).
"""

from __future__ import annotations

import datetime
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SERIAL_BITS = 64


class SerialCollisionError(Exception):
    """Raised by caller-supplied uniqueness check; pki.py itself just generates."""


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def private_key_to_pem(key: CertificateIssuerPrivateKeyTypes) -> bytes:
    # TRAP (handoff §5.1): OpenSSL 3.x wraps "no password" keys in an
    # empty-password encrypted PKCS8 container unless NoEncryption() is
    # passed explicitly. FreeRADIUS's TLS stack rejects that with
    # "bad decrypt". Do not rely on the serialization default.
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def generate_serial() -> int:
    # Random, >=64 bits, never sequential (handoff §5.8): sequential
    # serials leak issuance volume and invite collisions with any
    # parallel tooling. Caller must check DB uniqueness before use.
    return secrets.randbits(SERIAL_BITS) | (1 << (SERIAL_BITS - 1))


def build_csr(
    private_key: CertificateIssuerPrivateKeyTypes, cn: str
) -> x509.CertificateSigningRequest:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(private_key, hashes.SHA256())
    )


def _cert_builder(
    subject_cn: str,
    issuer_cert: x509.Certificate,
    public_key,
    serial: int,
    days: int,
) -> x509.CertificateBuilder:
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
    )


def sign_client_cert(
    csr: x509.CertificateSigningRequest,
    issuer_cert: x509.Certificate,
    issuer_key: CertificateIssuerPrivateKeyTypes,
    serial: int,
    days: int,
) -> x509.Certificate:
    builder = _cert_builder(
        csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        issuer_cert,
        csr.public_key(),
        serial,
        days,
    )
    builder = (
        builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    )
    return builder.sign(issuer_key, hashes.SHA256())


@dataclass
class Pkcs12Bundle:
    data: bytes
    password: str


def build_pkcs12(
    cn: str,
    private_key: CertificateIssuerPrivateKeyTypes,
    cert: x509.Certificate,
    chain: list[x509.Certificate],
    password: str | None = None,
) -> Pkcs12Bundle:
    if password is None:
        password = secrets.token_urlsafe(18)
    # cryptography's modern PKCS12 default (AES) may be rejected by older
    # Android/Windows supplicants (handoff §5.1). Use the legacy
    # RC2/3DES-compatible profile when available; fall back to the modern
    # default otherwise, and flag it so device-compat testing catches it.
    try:
        encryption = (
            serialization.PrivateFormat.PKCS12.encryption_builder()
            .kdf_rounds(50000)
            .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
            .hmac_hash(hashes.SHA1())
            .build(password.encode())
        )
    except Exception:
        encryption = serialization.BestAvailableEncryption(password.encode())
    data = pkcs12.serialize_key_and_certificates(
        name=cn.encode(),
        key=private_key,
        cert=cert,
        cas=chain,
        encryption_algorithm=encryption,
    )
    return Pkcs12Bundle(data=data, password=password)


def load_pkcs12(data: bytes, password: str):
    return pkcs12.load_key_and_certificates(data, password.encode())


def build_crl(
    issuer_cert: x509.Certificate,
    issuer_key: CertificateIssuerPrivateKeyTypes,
    revoked_serials: list[tuple[int, datetime.datetime]],
    validity_days: int,
) -> x509.CertificateRevocationList:
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=validity_days))
    )
    for serial, revoked_at in revoked_serials:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(revoked_at)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def build_self_signed_ca(cn: str, days: int) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes]:
    key = generate_private_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(generate_serial())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
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
        .sign(key, hashes.SHA256())
    )
    return cert, key


def build_intermediate_ca(
    cn: str,
    days: int,
    root_cert: x509.Certificate,
    root_key: CertificateIssuerPrivateKeyTypes,
) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes]:
    key = generate_private_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(generate_serial())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
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
        .sign(root_key, hashes.SHA256())
    )
    return cert, key


def load_cert_pem(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def load_key_pem(path: Path, password: bytes | None = None):
    return serialization.load_pem_private_key(path.read_bytes(), password=password)


def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def crl_to_pem(crl: x509.CertificateRevocationList) -> bytes:
    return crl.public_bytes(serialization.Encoding.PEM)
