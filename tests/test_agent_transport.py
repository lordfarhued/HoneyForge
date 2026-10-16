from __future__ import annotations

import base64
import json
import socket
import ssl
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from agent.client import AgentClient
from agent.config import AgentSettings
from agent.diagnostics import heartbeat_probe_request
from agent.main import flush_events, heartbeat_delay
from agent.pki import server_spki_pin
from agent.queue import DurableQueue


def issue_test_tls_files(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test transport CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.crt"
    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    pin_path = tmp_path / "server.pin"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pin_path.write_text(
        server_spki_pin(server_cert.public_bytes(serialization.Encoding.DER)), encoding="ascii"
    )
    return ca_path, cert_path, key_path, pin_path


class TransportTestServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.connection_count = 0
        self.paths: list[str] = []
        self.headers_seen: list[dict[str, str]] = []
        self.fail_next_config = False
        self.redirect_config = False

    def get_request(self):
        request, address = super().get_request()
        self.connection_count += 1
        return request, address


class TransportHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return

    def _body(self) -> dict:
        length = int(self.headers.get("content-length", "0"))
        return json.loads(self.rfile.read(length)) if length else {}

    def _send(self, status: int, payload: dict | list, headers: dict[str, str] | None = None):
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.paths.append(self.path)
        self.server.headers_seen.append(dict(self.headers.items()))
        if self.path.endswith("/config") and self.server.fail_next_config:
            self.server.fail_next_config = False
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        if self.path.endswith("/config") and self.server.redirect_config:
            self._send(302, {}, {"Location": "http://127.0.0.1:9/not-followed"})
        elif self.path.endswith("/config"):
            self._send(200, {"configurations": []})
        elif self.path.endswith("/jobs"):
            self._send(200, [])
        else:
            self._send(404, {})

    def do_POST(self):
        self.server.paths.append(self.path)
        self.server.headers_seen.append(dict(self.headers.items()))
        payload = self._body()
        if self.path.endswith("/enroll"):
            self._send(200, {"identity_id": "id", "host_id": "host", "certificate_pem": "cert", "certificate_expires_at": "later"})
        elif self.path.endswith("/events"):
            ids = [item["external_id"] for item in payload["events"]]
            self._send(200, {"accepted_ids": ids, "duplicate_ids": []})
        elif self.path.endswith("/certificate/rotate"):
            self._send(200, {"certificate_pem": self.server.rotated_certificate_pem, "certificate_expires_at": "later"})
        else:
            self._send(200, {"status": "ok"})


@contextmanager
def tls_server(tmp_path: Path):
    ca_path, cert_path, key_path, pin_path = issue_test_tls_files(tmp_path)
    server = TransportTestServer(("127.0.0.1", 0), TransportHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.rotated_certificate_pem = cert_path.read_text(encoding="ascii")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, ca_path, cert_path, key_path, pin_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def client_settings(tmp_path: Path, server, ca_path, cert_path, key_path, pin_path, prefix: str):
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    (state / "agent.crt").write_bytes(cert_path.read_bytes())
    (state / "agent.key").write_bytes(key_path.read_bytes())
    return AgentSettings(
        base_url=f"https://localhost:{server.server_port}",
        server_name="localhost",
        ca_cert=str(ca_path),
        server_pin_file=str(pin_path),
        transport_prefix=prefix,
        state_dir=str(state),
        keepalive_seconds=60,
    )


@pytest.mark.parametrize("prefix", ["/agent", "/assets/runtime"])
def test_both_prefixes_all_operations_and_connection_pooling(tmp_path, prefix):
    with tls_server(tmp_path) as resources:
        server, ca_path, cert_path, key_path, pin_path = resources
        settings = client_settings(tmp_path, *resources, prefix)
        client = AgentClient(settings)
        client.heartbeat(0)
        assert client.configuration() == {"configurations": []}
        assert client.jobs() == []
        client.report_status([])
        event_id = "00000000-0000-4000-8000-000000000001"
        assert client.send_events([{"external_id": event_id}])["accepted_ids"] == [event_id]
        client.acknowledge_job("00000000-0000-4000-8000-000000000002", "succeeded", {})
        assert "BEGIN CERTIFICATE" in client.rotate_certificate("csr")["certificate_pem"]
        assert server.connection_count == 1
        expected = {
            f"{prefix}/v1/heartbeat",
            f"{prefix}/v1/config",
            f"{prefix}/v1/jobs",
            f"{prefix}/v1/status",
            f"{prefix}/v1/events",
            f"{prefix}/v1/jobs/00000000-0000-4000-8000-000000000002/ack",
            f"{prefix}/v1/certificate/rotate",
        }
        assert expected.issubset(set(server.paths))
        exposed_headers = "\n".join(
            f"{name}: {value}"
            for headers in server.headers_seen
            for name, value in headers.items()
        ).lower()
        assert "honeyforge" not in exposed_headers
        assert "honeypot" not in exposed_headers
        client.heartbeat(0)
        assert server.connection_count == 2
        client.close()


@pytest.mark.parametrize("prefix", ["/agent", "/assets/runtime"])
def test_enrollment_uses_selected_prefix_and_closes_cleanly(tmp_path, prefix):
    with tls_server(tmp_path) as resources:
        server, *_ = resources
        settings = client_settings(tmp_path, *resources, prefix)
        client = AgentClient(settings)
        assert client.enroll("one-time", "csr")["identity_id"] == "id"
        assert server.paths == [f"{prefix}/v1/enroll"]
        client.close()


def test_neutral_transport_is_the_client_default_and_legacy_is_explicitly_supported():
    neutral = AgentSettings(
        base_url="https://localhost",
        server_name="localhost",
        keepalive_seconds=60,
    )
    legacy = AgentSettings(
        base_url="https://localhost",
        server_name="localhost",
        transport_prefix="/agent",
        keepalive_seconds=60,
    )
    assert neutral.transport_prefix == "/assets/runtime"
    assert legacy.transport_prefix == "/agent"
    assert heartbeat_probe_request("localhost", neutral.transport_prefix).startswith(
        b"POST /assets/runtime/v1/heartbeat HTTP/1.1\r\n"
    )
    assert heartbeat_probe_request("localhost", legacy.transport_prefix).startswith(
        b"POST /agent/v1/heartbeat HTTP/1.1\r\n"
    )


def test_wrong_pin_is_rejected_before_any_http_request_and_on_reconnect(tmp_path):
    with tls_server(tmp_path) as resources:
        server, *_, pin_path = resources
        pin_path.write_text(base64.b64encode(b"\x00" * 32).decode("ascii"), encoding="ascii")
        settings = client_settings(tmp_path, *resources, "/agent")
        client = AgentClient(settings)
        for _ in range(2):
            with pytest.raises((ssl.SSLError, httpx.TransportError)):
                client.configuration()
            assert client._authenticated_client is None
        deadline = time.monotonic() + 1
        while server.connection_count < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.connection_count == 2
        assert server.paths == []
        client.close()


def test_connection_loss_recreates_pool_and_rechecks_tls(tmp_path):
    with tls_server(tmp_path) as resources:
        server, *_ = resources
        settings = client_settings(tmp_path, *resources, "/agent")
        client = AgentClient(settings)
        server.fail_next_config = True
        with pytest.raises(httpx.TransportError):
            client.configuration()
        assert client.configuration() == {"configurations": []}
        assert server.connection_count == 2
        client.close()


def test_redirect_is_not_followed(tmp_path):
    with tls_server(tmp_path) as resources:
        server, *_ = resources
        settings = client_settings(tmp_path, *resources, "/agent")
        client = AgentClient(settings)
        server.redirect_config = True
        with pytest.raises(httpx.HTTPStatusError):
            client.configuration()
        assert server.paths == ["/agent/v1/config"]
        client.close()


def test_heartbeat_jitter_is_configurable_and_bounded():
    settings = AgentSettings(
        base_url="https://localhost",
        server_name="localhost",
        heartbeat_seconds=15,
        heartbeat_jitter_ratio=0.15,
        keepalive_seconds=60,
    )
    assert heartbeat_delay(settings, lambda low, high: low) == pytest.approx(12.75)
    assert heartbeat_delay(settings, lambda low, high: high) == pytest.approx(17.25)
    with pytest.raises(ValueError, match="jitter"):
        AgentSettings(
            base_url="https://localhost",
            server_name="localhost",
            heartbeat_jitter_ratio=0.5,
            keepalive_seconds=60,
        )


def test_event_ack_preserves_queue_order_and_deletes_only_acknowledged(tmp_path):
    queue = DurableQueue(str(tmp_path / "queue.sqlite3"))
    first = {"external_id": "00000000-0000-4000-8000-000000000001", "value": 1}
    second = {"external_id": "00000000-0000-4000-8000-000000000002", "value": 2}
    queue.enqueue(first)
    queue.enqueue(second)
    assert queue.pending(2) == [first, second]

    class AckClient:
        def send_events(self, events):
            assert events == [first, second]
            return {"accepted_ids": [first["external_id"]], "duplicate_ids": [second["external_id"]]}

    flush_events(AckClient(), queue, 50)
    assert queue.depth() == 0


def test_events_survive_failed_delivery_and_retry(tmp_path):
    queue = DurableQueue(str(tmp_path / "retry-queue.sqlite3"))
    first = {"external_id": "00000000-0000-4000-8000-000000000011", "value": 1}
    second = {"external_id": "00000000-0000-4000-8000-000000000012", "value": 2}

    queue.enqueue(first)
    queue.enqueue(second)

    class FlakyClient:
        def __init__(self):
            self.attempts = 0

        def send_events(self, events):
            self.attempts += 1
            assert events == [first, second]
            if self.attempts == 1:
                raise httpx.ConnectError("Simulated connection failure")
            return {
                "accepted_ids": [first["external_id"], second["external_id"]],
                "duplicate_ids": [],
            }

    client = FlakyClient()

    with pytest.raises(httpx.ConnectError):
        flush_events(client, queue, 50)

    assert queue.depth() == 2

    queue.connection.close()
    queue = DurableQueue(str(tmp_path / "retry-queue.sqlite3"))
    assert queue.pending(10) == [first, second]

    flush_events(client, queue, 50)

    assert client.attempts == 2
    assert queue.depth() == 0
    queue.connection.close()
