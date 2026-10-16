from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def ensure_key_and_csr(key_path: Path, csr_path: Path) -> str:
    if not key_path.exists():
        key = ec.generate_private_key(ec.SECP256R1())
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
    else:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Runtime Enrollment")]))
        .sign(key, hashes.SHA256())
    )
    pem = csr.public_bytes(serialization.Encoding.PEM)
    csr_path.write_bytes(pem)
    return pem.decode("ascii")


def server_spki_pin(certificate_der: bytes) -> str:
    cert = x509.load_der_x509_certificate(certificate_der)
    public_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(hashlib.sha256(public_der).digest()).decode("ascii")
