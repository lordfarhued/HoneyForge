from __future__ import annotations

import base64
import secrets
import ssl
from pathlib import Path
from typing import Iterable

import httpcore
import httpx

from agent.pki import server_spki_pin


class PinnedNetworkStream(httpcore.NetworkStream):
    def __init__(self, stream: httpcore.NetworkStream, expected_pin: str, backend: "PinnedNetworkBackend"):
        self._stream = stream
        self._expected_pin = expected_pin
        self._backend = backend

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._stream.read(max_bytes, timeout)

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._stream.write(buffer, timeout)

    def close(self) -> None:
        self._stream.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        secured = self._stream.start_tls(ssl_context, server_hostname, timeout)
        try:
            ssl_object = secured.get_extra_info("ssl_object")
            certificate_der = ssl_object.getpeercert(True) if ssl_object else None
            if not certificate_der:
                raise ssl.SSLError("TLS peer certificate is unavailable")
            actual_pin = server_spki_pin(certificate_der)
            if not secrets.compare_digest(actual_pin, self._expected_pin):
                raise ssl.SSLError("Server SPKI pin mismatch")
        except BaseException:
            secured.close()
            raise
        self._backend.verified_connections += 1
        return PinnedNetworkStream(secured, self._expected_pin, self._backend)

    def get_extra_info(self, info: str):
        return self._stream.get_extra_info(info)


class PinnedNetworkBackend(httpcore.NetworkBackend):
    def __init__(self, expected_pin: str):
        self._backend = httpcore.SyncBackend()
        self._expected_pin = expected_pin
        self.verified_connections = 0

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        stream = self._backend.connect_tcp(host, port, timeout, local_address, socket_options)
        return PinnedNetworkStream(stream, self._expected_pin, self)

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        stream = self._backend.connect_unix_socket(path, timeout, socket_options)
        return PinnedNetworkStream(stream, self._expected_pin, self)

    def sleep(self, seconds: float) -> None:
        self._backend.sleep(seconds)


def read_expected_pin(path: str) -> str:
    pin = Path(path).read_text(encoding="ascii").strip()
    try:
        decoded = base64.b64decode(pin, validate=True)
    except ValueError as exc:
        raise ValueError("Invalid SPKI pin encoding") from exc
    if len(decoded) != 32:
        raise ValueError("Invalid SPKI pin length")
    return pin


class PinnedHTTPTransport(httpx.HTTPTransport):
    """HTTPX transport that pins every actual TLS connection before HTTP is sent.

    httpx 0.28.1 builds its sync transport on httpcore 1.0.9 ConnectionPool.
    The pinned project versions expose the pool network backend, which lets us
    validate the peer in NetworkStream.start_tls while retaining HTTP pooling.
    """

    def __init__(self, ssl_context: ssl.SSLContext, expected_pin: str, limits: httpx.Limits):
        super().__init__(verify=ssl_context, trust_env=False, limits=limits, retries=0)
        pool = getattr(self, "_pool", None)
        if not isinstance(pool, httpcore.ConnectionPool) or not hasattr(pool, "_network_backend"):
            super().close()
            raise RuntimeError("Unsupported httpx/httpcore transport internals")
        self.pinning_backend = PinnedNetworkBackend(expected_pin)
        pool._network_backend = self.pinning_backend
