from __future__ import annotations

import socket
import ssl
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from agent.config import AgentSettings


def heartbeat_probe_request(server_name: str, transport_prefix: str) -> bytes:
    if transport_prefix not in {"/agent", "/assets/runtime"}:
        raise ValueError("Unsupported transport prefix")
    path = f"{transport_prefix}/v1/heartbeat"
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {server_name}\r\n"
        "Content-Length: 0\r\nConnection: close\r\n\r\n"
    ).encode("ascii")


def verify_untrusted_client_is_rejected(
    host: str,
    port: int,
    server_name: str,
    ca_cert: str,
    transport_prefix: str = "/assets/runtime",
) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "untrusted-test-client")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    with tempfile.TemporaryDirectory() as directory:
        cert_path = Path(directory) / "client.crt"
        key_path = Path(directory) / "client.key"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        context = ssl.create_default_context(cafile=ca_cert)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        try:
            with socket.create_connection((host, port), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname=server_name) as secured:
                    secured.sendall(heartbeat_probe_request(server_name, transport_prefix))
                    response = secured.recv(256)
        except ssl.SSLError:
            print("untrusted_client=rejected")
            return
    if b" 200 " in response:
        raise SystemExit("untrusted client certificate was accepted")
    print("untrusted_client=rejected")


if __name__ == "__main__":
    settings = AgentSettings()
    parsed = urlparse(settings.base_url)
    verify_untrusted_client_is_rejected(
        parsed.hostname or settings.server_name,
        parsed.port or 443,
        settings.server_name,
        settings.ca_cert,
        settings.transport_prefix,
    )
