from __future__ import annotations

import os
import ssl
import tempfile
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from agent.config import AgentSettings
from agent.transport import PinnedHTTPTransport, read_expected_pin


class AgentClient:
    def __init__(self, settings: AgentSettings, client_factory=None):
        self.settings = settings
        self.identity_paths = settings.identity_paths()
        self.key_path = self.identity_paths.key
        self.cert_path = self.identity_paths.certificate
        self._client_factory = client_factory
        self._enrollment_client: httpx.Client | None = None
        self._authenticated_client: httpx.Client | None = None

    def _new_client(self, authenticated: bool) -> httpx.Client:
        if self._client_factory is not None:
            return self._client_factory(authenticated)
        tls_context = ssl.create_default_context(cafile=self.settings.ca_cert)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        if authenticated:
            tls_context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
        limits = httpx.Limits(
            max_connections=2,
            max_keepalive_connections=1,
            keepalive_expiry=self.settings.keepalive_seconds,
        )
        transport = PinnedHTTPTransport(
            ssl_context=tls_context,
            expected_pin=read_expected_pin(self.settings.server_pin_file),
            limits=limits,
        )
        return httpx.Client(
            base_url=self.settings.base_url,
            transport=transport,
            timeout=10,
            trust_env=False,
            follow_redirects=False,
        )

    def _client(self, authenticated: bool = True) -> httpx.Client:
        attribute = "_authenticated_client" if authenticated else "_enrollment_client"
        client = getattr(self, attribute)
        if client is None:
            client = self._new_client(authenticated)
            setattr(self, attribute, client)
        return client

    def _path(self, suffix: str) -> str:
        return f"{self.settings.transport_prefix}/v1/{suffix.lstrip('/')}"

    def _drop_client(self, authenticated: bool) -> None:
        attribute = "_authenticated_client" if authenticated else "_enrollment_client"
        client = getattr(self, attribute)
        if client is not None:
            client.close()
            setattr(self, attribute, None)

    def _request(
        self,
        method: str,
        suffix: str,
        *,
        authenticated: bool = True,
        json: dict[str, Any] | None = None,
    ) -> httpx.Response:
        try:
            response = self._client(authenticated).request(method, self._path(suffix), json=json)
        except (httpx.TransportError, ssl.SSLError):
            self._drop_client(authenticated)
            raise
        response.raise_for_status()
        return response

    def enroll(self, token: str, csr_pem: str) -> dict:
        return self._request(
            "POST",
            "enroll",
            authenticated=False,
            json={"token": token, "csr_pem": csr_pem, "agent_version": self.settings.agent_version},
        ).json()

    def heartbeat(self, queue_depth: int) -> None:
        self._request(
            "POST",
            "heartbeat",
            json={"agent_version": self.settings.agent_version, "queue_depth": queue_depth},
        )

    def configuration(self) -> dict:
        return self._request("GET", "config").json()

    def send_events(self, events: list[dict]) -> dict:
        return self._request("POST", "events", json={"events": events}).json()

    def jobs(self) -> list[dict]:
        return self._request("GET", "jobs").json()

    def acknowledge_job(self, job_id: str, state: str, result: dict) -> None:
        self._request("POST", f"jobs/{job_id}/ack", json={"state": state, "result": result})

    def report_status(self, statuses: list[dict]) -> None:
        self._request("POST", "status", json={"statuses": statuses})

    def rotate_certificate(self, csr_pem: str) -> dict:
        result = self._request("POST", "certificate/rotate", json={"csr_pem": csr_pem}).json()
        self._install_rotated_certificate(result["certificate_pem"])
        return result

    def _install_rotated_certificate(self, certificate_pem: str) -> None:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        private_key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
        certificate_public_key = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_public_key = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if certificate_public_key != private_public_key:
            raise ValueError("Rotated certificate does not match the client private key")

        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=self.cert_path.parent,
                prefix=f".{self.cert_path.name}.",
                delete=False,
            ) as handle:
                temporary_path = Path(handle.name)
                handle.write(certificate_pem.encode("ascii"))
                handle.flush()
                os.fsync(handle.fileno())
            temporary_path.chmod(0o600)
            os.replace(temporary_path, self.cert_path)
        except BaseException:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            raise
        self.activate_identity()

    def activate_identity(self) -> None:
        self._drop_client(authenticated=False)
        self._drop_client(authenticated=True)

    def close(self) -> None:
        self._drop_client(authenticated=False)
        self._drop_client(authenticated=True)

    def __enter__(self) -> "AgentClient":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
