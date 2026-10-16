from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.config import get_settings


def _write_private(path: Path, key) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def public_key_pin(public_key) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")


def ensure_local_pki(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    ca_key_path = directory / "ca.key"
    ca_cert_path = directory / "ca.crt"
    server_key_path = directory / "server.key"
    server_cert_path = directory / "server.crt"
    server_pin_path = directory / "server.pin"
    paths = (ca_key_path, ca_cert_path, server_key_path, server_cert_path, server_pin_path)
    if all(path.exists() for path in paths):
        return
    if any(path.exists() for path in paths):
        raise RuntimeError("PKI directory is incomplete; refusing to overwrite existing key material")

    ca_common_name = os.environ.get("PKI_CA_COMMON_NAME", "Local Service CA").strip()
    server_dns_name = os.environ.get("PKI_SERVER_NAME", "agent-gateway").strip().lower()
    if not 1 <= len(ca_common_name) <= 64:
        raise ValueError("PKI CA common name must contain 1..64 characters")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?", server_dns_name):
        raise ValueError("PKI server name must be a valid lowercase DNS name")

    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP384R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_common_name)])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA384())
    )

    server_key = ec.generate_private_key(ec.SECP256R1())
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_dns_name)])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(server_dns_name), x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA384())
    )

    _write_private(ca_key_path, ca_key)
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_private(server_key_path, server_key)
    server_cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    server_pin_path.write_text(public_key_pin(server_key.public_key()) + "\n", encoding="ascii")


def sign_agent_csr(csr_pem: str, identity_id, host_id) -> tuple[str, str, str, datetime]:
    settings = get_settings()
    csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")
    public_key = csr.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Only EC agent keys are accepted")

    ca_cert = x509.load_pem_x509_certificate(Path(settings.ca_cert_path).read_bytes())
    ca_key = serialization.load_pem_private_key(Path(settings.ca_key_path).read_bytes(), password=None)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=settings.agent_certificate_days)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"runtime:{identity_id}")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=2))
        .not_valid_after(expires_at)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(f"urn:runtime:identity:{identity_id}"), x509.UniformResourceIdentifier(f"urn:runtime:node:{host_id}")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA384())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    serial = format(cert.serial_number, "x")
    return pem, fingerprint, public_key_pin(public_key), expires_at
