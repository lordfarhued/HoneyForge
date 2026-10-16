import base64
import json
import os
import socket
import time
import uuid
from pathlib import Path

os.environ.setdefault("DATABASE_URL", os.environ.get("TEST_DATABASE_URL", "sqlite://"))
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-that-is-longer-than-32-characters")
os.environ.setdefault("ENVIRONMENT", "test")

import paramiko
import pytest

from agent.config import AgentSettings
from agent.engines import EngineController
from agent.main import sync_configuration
from agent.queue import DurableQueue
from honeypots import common as common_module
from honeypots import medium as medium_module
from honeypots import relay as relay_module
from honeypots.common import EventWriter, RuntimeSupervisor, start_server
from honeypots.low import service_factory as low_service_factory
from honeypots.medium import fake_command_response, load_or_create_host_key, make_service_factory
from honeypots.relay import TCPRelayServer, UDPRelayServer


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def wait_for_events(directory: Path, count: int) -> list[dict]:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        paths = list(directory.glob("*.event.json"))
        if len(paths) >= count:
            return [json.loads(path.read_text(encoding="utf-8")) for path in paths]
        time.sleep(0.05)
    raise AssertionError(f"expected {count} engine event files")


def engine_payload(
    level: str,
    instance_id: str,
    services: list[dict],
    *,
    bait_credentials: list[dict] | None = None,
    logging: dict | None = None,
    masking: dict | None = None,
    config_version: int = 3,
) -> dict:
    return {
        "schema_version": 1,
        "interaction_level": level,
        "instances": [
            {
                "instance_id": instance_id,
                "instance_name": f"{level}-test",
                "config_version": config_version,
                "enabled": True,
                "services": services,
                "bait_credentials": bait_credentials or [],
                "logging": logging or {},
                "masking": masking or {},
            }
        ],
    }


def clear_events(directory: Path) -> None:
    for path in directory.glob("*.event.json"):
        path.unlink()


def http_request(port: int, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.sendall(request)
        return connection.recv(4096)


def udp_request(port: int, payload: bytes) -> tuple[bytes, int]:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(3)
        connection.bind(("127.0.0.1", 0))
        source_port = int(connection.getsockname()[1])
        connection.sendto(payload, ("127.0.0.1", port))
        response, _ = connection.recvfrom(4096)
        return response, source_port


def test_low_http_engine_captures_real_connection(tmp_path):
    instance_id = str(uuid.uuid4())
    port = free_port()
    events = tmp_path / "events"
    supervisor = RuntimeSupervisor("low", str(tmp_path / "config.json"), str(events), low_service_factory)
    payload = engine_payload(
        "low",
        instance_id,
        [{"name": "http", "protocol": "tcp", "port": port, "banner": "nginx"}],
    )
    supervisor.apply(json.dumps(payload).encode(), payload)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
            connection.sendall(
                b"GET /admin HTTP/1.1\r\nHost: localhost\r\nX-HoneyForge-Verification: stage3\r\n\r\n"
            )
            response = connection.recv(4096)
        assert b"HTTP/1.1 200 OK" in response
        assert b"Server: nginx" in response
        event = wait_for_events(events, 1)[0]
        assert event["event_type"] == "low.http_request"
        assert event["is_test"] is False
        assert event["data"]["request_line"] == "GET /admin HTTP/1.1"
        assert event["data"]["destination_port"] == port
        assert event["data"]["controlled_test"] is True
    finally:
        supervisor.stop_services()


def test_low_ssh_banner_captures_real_tcp_session(tmp_path):
    instance_id = str(uuid.uuid4())
    port = free_port()
    events = tmp_path / "events"
    supervisor = RuntimeSupervisor("low", str(tmp_path / "config.json"), str(events), low_service_factory)
    payload = engine_payload(
        "low",
        instance_id,
        [{"name": "ssh", "protocol": "tcp", "port": port, "banner": "SSH-2.0-OpenSSH_8.9p1"}],
    )
    supervisor.apply(json.dumps(payload).encode(), payload)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
            banner = connection.recv(4096)
            connection.sendall(b"SSH-2.0-controlled-client\r\n")
            response = connection.recv(4096)

        assert banner == b"SSH-2.0-OpenSSH_8.9p1\r\n"
        assert response == b"OK\r\n"
        event = wait_for_events(events, 1)[0]
        assert event["event_type"] == "low.tcp_session"
        assert event["instance_id"] == instance_id
        assert event["source_ip"] == "127.0.0.1"
        assert event["data"]["service"] == "ssh"
        assert event["data"]["protocol"] == "tcp"
        assert event["data"]["request_line"] == "SSH-2.0-controlled-client"
        assert event["data"]["destination_port"] == port
    finally:
        supervisor.stop_services()


def test_low_udp_engine_captures_real_datagrams_and_releases_port(tmp_path):
    instance_id = str(uuid.uuid4())
    port = free_udp_port()
    events = tmp_path / "events"
    supervisor = RuntimeSupervisor("low", str(tmp_path / "config.json"), str(events), low_service_factory)
    payload = engine_payload(
        "low",
        instance_id,
        [{"name": "discovery", "protocol": "udp", "port": port, "banner": "ready"}],
        logging={
            "capture_connections": True,
            "capture_credentials": False,
            "capture_commands": True,
            "capture_payloads": True,
        },
    )
    supervisor.apply(json.dumps(payload).encode(), payload)
    try:
        response, source_port = udp_request(port, b"STATUS\x00\xff")
        assert response == b"ready"
        event = wait_for_events(events, 1)[0]
        assert event["event_type"] == "low.udp_datagram"
        assert event["instance_id"] == instance_id
        assert event["source_ip"] == "127.0.0.1"
        assert event["is_test"] is False
        assert event["occurred_at"].endswith("+00:00")
        assert event["data"]["protocol"] == "udp"
        assert event["data"]["source_port"] == source_port
        assert event["data"]["destination_port"] == port
        assert event["data"]["destination_address"] == "0.0.0.0"
        assert event["data"]["bytes_received"] == 8
        assert event["data"]["request_line"].startswith("STATUS")
        assert base64.b64decode(event["data"]["payload_base64"]) == b"STATUS\x00\xff"
        assert event["data"]["payload_truncated"] is False

        status = json.loads((events / "status.json").read_text(encoding="utf-8"))
        assert status["instances"][instance_id]["endpoints"] == [{"protocol": "udp", "port": port}]

        clear_events(events)
        udp_request(port, b"x" * 9000)
        oversized = wait_for_events(events, 1)[0]
        assert oversized["data"]["bytes_received"] == 9000
        assert oversized["data"]["payload_truncated"] is True
        assert len(base64.b64decode(oversized["data"]["payload_base64"])) == 8192

        disabled = json.loads(json.dumps(payload))
        disabled["instances"][0]["enabled"] = False
        supervisor.apply(json.dumps(disabled).encode(), disabled)
        stopped = json.loads((events / "status.json").read_text(encoding="utf-8"))
        assert stopped["instances"][instance_id]["state"] == "offline"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("0.0.0.0", port))
    finally:
        supervisor.stop_services()


def test_low_udp_respects_logging_and_masking(tmp_path, monkeypatch):
    instance_id = str(uuid.uuid4())
    port = free_udp_port()
    events = tmp_path / "events"
    observed_delays: list[int] = []
    monkeypatch.setattr("honeypots.low.apply_response_delay", lambda instance: observed_delays.append(instance["masking"]["response_delay_ms"]))
    supervisor = RuntimeSupervisor("low", str(tmp_path / "config.json"), str(events), low_service_factory)
    service = {"name": "discovery", "protocol": "udp", "port": port, "banner": "ready"}
    try:
        metadata_only = engine_payload(
            "low",
            instance_id,
            [service],
            logging={
                "capture_connections": True,
                "capture_credentials": False,
                "capture_commands": False,
                "capture_payloads": False,
            },
            masking={"response_delay_ms": 75},
            config_version=1,
        )
        supervisor.apply(json.dumps(metadata_only).encode(), metadata_only)
        udp_request(port, b"secret-payload")
        metadata = wait_for_events(events, 1)[0]["data"]
        assert "source_port" in metadata
        assert "payload_base64" not in metadata
        assert "request_line" not in metadata

        clear_events(events)
        payload_only = engine_payload(
            "low",
            instance_id,
            [service],
            logging={
                "capture_connections": False,
                "capture_credentials": False,
                "capture_commands": False,
                "capture_payloads": True,
            },
            masking={"response_delay_ms": 75},
            config_version=2,
        )
        supervisor.apply(json.dumps(payload_only).encode(), payload_only)
        udp_request(port, b"visible-payload")
        captured = wait_for_events(events, 1)[0]["data"]
        assert base64.b64decode(captured["payload_base64"]) == b"visible-payload"
        assert "source_port" not in captured
        assert observed_delays == [75, 75]
    finally:
        supervisor.stop_services()


def test_udp_ingress_relay_preserves_source_metadata(tmp_path, monkeypatch):
    monkeypatch.setenv("HF_PROXY_PROTOCOL", "1")
    instance_id = str(uuid.uuid4())
    engine_port = free_udp_port()
    ingress_port = free_udp_port()
    events = tmp_path / "events"
    supervisor = RuntimeSupervisor("low", str(tmp_path / "config.json"), str(events), low_service_factory)
    payload = engine_payload(
        "low",
        instance_id,
        [{"name": "discovery", "protocol": "udp", "port": engine_port, "banner": "relay-ready"}],
        logging={"capture_connections": True, "capture_commands": False, "capture_payloads": True},
    )
    supervisor.apply(json.dumps(payload).encode(), payload)
    relay = UDPRelayServer(("127.0.0.1", ingress_port), "127.0.0.1", engine_port)
    relay_handle = common_module.start_server(relay, "test-udp-relay")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as malformed:
            malformed.settimeout(0.2)
            malformed.sendto(b"missing-proxy-header", ("127.0.0.1", engine_port))
            with pytest.raises(socket.timeout):
                malformed.recvfrom(1024)
        assert list(events.glob("*.event.json")) == []

        response, source_port = udp_request(ingress_port, b"through-relay")
        assert response == b"relay-ready"
        event = wait_for_events(events, 1)[0]
        assert event["source_ip"] == "127.0.0.1"
        assert event["data"]["source_port"] == source_port
        assert event["data"]["destination_address"] == "127.0.0.1"
        assert event["data"]["destination_port"] == engine_port
        assert base64.b64decode(event["data"]["payload_base64"]) == b"through-relay"
    finally:
        relay_handle.stop()
        supervisor.stop_services()


def test_medium_http_and_ssh_capture_credentials_and_simulate_commands(tmp_path):
    instance_id = str(uuid.uuid4())
    http_port, ssh_port = free_port(), free_port()
    events = tmp_path / "events"
    factory = make_service_factory(load_or_create_host_key(tmp_path / "ssh_host.key"))
    supervisor = RuntimeSupervisor("medium", str(tmp_path / "config.json"), str(events), factory)
    payload = engine_payload(
        "medium",
        instance_id,
        [
            {"name": "http", "protocol": "tcp", "port": http_port, "banner": "nginx"},
            {"name": "ssh", "protocol": "tcp", "port": ssh_port, "banner": "SSH-2.0-OpenSSH_8.9p1"},
        ],
        bait_credentials=[
            {"username": "hfcheck-web", "password": "decoy"},
            {"username": "hfcheck-ssh", "password": "decoy"},
        ],
    )
    supervisor.apply(json.dumps(payload).encode(), payload)
    marker = tmp_path / "must-not-exist"
    try:
        body = b"username=hfcheck-web&password=decoy"
        request = (
            b"POST /login HTTP/1.1\r\nHost: localhost\r\nX-HoneyForge-Verification: stage3\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        with socket.create_connection(("127.0.0.1", http_port), timeout=2) as connection:
            connection.sendall(request)
            assert b"Administration" in connection.recv(4096)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            "127.0.0.1",
            port=ssh_port,
            username="hfcheck-ssh",
            password="decoy",
            allow_agent=False,
            look_for_keys=False,
            timeout=4,
        )
        _, stdout, _ = client.exec_command(f"touch {marker}")
        assert b"command not found" in stdout.read()
        client.close()
        assert not marker.exists()
        assert "command not found" in fake_command_response("shutdown -h now", "guest")

        captured = wait_for_events(events, 5)
        by_type = {event["event_type"]: event for event in captured}
        assert by_type["medium.http_auth"]["data"]["username"] == "hfcheck-web"
        assert by_type["medium.ssh_auth"]["data"]["password"] == "decoy"
        assert by_type["medium.ssh_command"]["data"]["execution"] == "simulated_only"
        assert all(event["is_test"] is False for event in captured)
    finally:
        supervisor.stop_services()


def test_medium_ssh_closes_oversized_unterminated_command(tmp_path):
    instance_id = str(uuid.uuid4())
    port = free_port()
    events = tmp_path / "events"
    factory = make_service_factory(load_or_create_host_key(tmp_path / "ssh_host.key"))
    supervisor = RuntimeSupervisor("medium", str(tmp_path / "config.json"), str(events), factory)
    payload = engine_payload(
        "medium",
        instance_id,
        [{"name": "ssh", "protocol": "tcp", "port": port, "banner": "SSH-2.0-OpenSSH_8.9p1"}],
        bait_credentials=[{"username": "hfcheck-ssh", "password": "decoy"}],
        logging={
            "capture_connections": True,
            "capture_credentials": False,
            "capture_commands": True,
            "capture_payloads": False,
        },
    )
    supervisor.apply(json.dumps(payload).encode(), payload)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    channel = None
    try:
        client.connect(
            "127.0.0.1",
            port=port,
            username="hfcheck-ssh",
            password="decoy",
            allow_agent=False,
            look_for_keys=False,
            timeout=4,
        )
        channel = client.invoke_shell()
        channel.settimeout(2)
        assert b"web-node-02" in channel.recv(4096)

        channel.sendall(b"x" * (medium_module.MAX_COMMAND + 1024))
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            transport = client.get_transport()
            if channel.closed or transport is None or not transport.is_active():
                break
            time.sleep(0.02)

        transport = client.get_transport()
        assert channel.closed or transport is None or not transport.is_active(), (
            "Medium SSH kept an oversized unterminated command buffered"
        )
    finally:
        if channel is not None:
            try:
                channel.close()
            except (OSError, EOFError):
                pass
        client.close()
        supervisor.stop_services()


def test_medium_ssh_enforces_total_session_duration_with_controlled_clock(tmp_path, monkeypatch):
    class ControlledClock:
        def __init__(self):
            self.current = 0

        def monotonic(self):
            self.current += 10_000
            return self.current

        def sleep(self, seconds):
            pass

    class EndlessChannel:
        def __init__(self):
            self.closed = False
            self.recv_calls = 0

        def settimeout(self, timeout):
            self.timeout = timeout

        def recv(self, size):
            self.recv_calls += 1
            if self.recv_calls > 8:
                raise AssertionError("Medium SSH session kept reading after its total time budget elapsed")
            return b"x"

        def send(self, payload):
            return len(payload)

    transports = []

    class ControlledTransport:
        def __init__(self, request):
            self.channel = EndlessChannel()
            self.active = True
            self.closed = False
            transports.append(self)

        def add_server_key(self, host_key):
            pass

        def start_server(self, server):
            server.username = "hfcheck-ssh"
            server.shell_requested = True

        def accept(self, timeout):
            return self.channel

        def is_active(self):
            return self.active

        def close(self):
            self.active = False
            self.closed = True
            self.channel.closed = True

    class ControlledSocket:
        def settimeout(self, timeout):
            self.timeout = timeout

    monkeypatch.delenv("HF_PROXY_PROTOCOL", raising=False)
    monkeypatch.setattr(medium_module, "time", ControlledClock())
    monkeypatch.setattr(medium_module.paramiko, "Transport", ControlledTransport)
    instance = {
        "instance_id": str(uuid.uuid4()),
        "bait_credentials": [],
        "logging": {
            "capture_connections": False,
            "capture_credentials": False,
            "capture_commands": False,
            "capture_payloads": False,
        },
        "masking": {},
    }
    service = {
        "name": "ssh",
        "protocol": "tcp",
        "port": free_port(),
        "banner": "SSH-2.0-OpenSSH_8.9p1",
    }
    handler = medium_module.build_ssh_handler(
        instance,
        service,
        EventWriter(str(tmp_path / "events")),
        object(),
    )

    handler(ControlledSocket(), ("127.0.0.1", 32000), None)

    assert transports[0].closed is True
    assert transports[0].channel.recv_calls <= 8


def test_medium_ssh_interactive_commands_and_exit(tmp_path):
    instance_id = str(uuid.uuid4())
    port = free_port()
    events = tmp_path / "events"
    factory = make_service_factory(load_or_create_host_key(tmp_path / "ssh_host.key"))
    supervisor = RuntimeSupervisor("medium", str(tmp_path / "config.json"), str(events), factory)
    payload = engine_payload(
        "medium",
        instance_id,
        [{"name": "ssh", "protocol": "tcp", "port": port, "banner": "SSH-2.0-OpenSSH_8.9p1"}],
        bait_credentials=[{"username": "hfcheck-ssh", "password": "decoy"}],
        logging={
            "capture_connections": True,
            "capture_credentials": False,
            "capture_commands": True,
            "capture_payloads": False,
        },
    )
    supervisor.apply(json.dumps(payload).encode(), payload)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    channel = None
    try:
        client.connect(
            "127.0.0.1",
            port=port,
            username="hfcheck-ssh",
            password="decoy",
            allow_agent=False,
            look_for_keys=False,
            timeout=4,
        )
        channel = client.invoke_shell()
        channel.settimeout(2)
        assert b"web-node-02" in channel.recv(4096)

        channel.sendall(b"whoami\npwd\nls\nid\n")
        output = b""
        deadline = time.monotonic() + 2
        while output.count(b"hfcheck-ssh@web-node-02:~$ ") < 4 and time.monotonic() < deadline:
            if channel.recv_ready():
                output += channel.recv(4096)
            else:
                time.sleep(0.02)
        assert b"hfcheck-ssh\n" in output
        assert b"/home/hfcheck-ssh\n" in output
        assert b"backup  logs  public_html\n" in output
        assert b"uid=1001(hfcheck-ssh)" in output

        channel.sendall(b"exit\n")
        exit_output = channel.recv(4096)
        assert b"logout" in exit_output

        captured = wait_for_events(events, 6)
        commands = [
            event["data"]["command"]
            for event in captured
            if event["event_type"] == "medium.ssh_command"
        ]
        assert sorted(commands) == ["exit", "id", "ls", "pwd", "whoami"]
    finally:
        if channel is not None:
            try:
                channel.close()
            except (OSError, EOFError):
                pass
        client.close()
        supervisor.stop_services()


def test_medium_ssh_relay_survives_password_prompt_and_records_auth_session_command(
    tmp_path,
    monkeypatch,
):
    instance_id = str(uuid.uuid4())
    engine_port = free_port()
    relay_port = free_port()
    events = tmp_path / "events"
    monkeypatch.setenv("HF_PROXY_PROTOCOL", "1")
    monkeypatch.setattr(relay_module, "TCP_CONNECT_TIMEOUT_SECONDS", 0.2)
    supervisor = RuntimeSupervisor(
        "medium",
        str(tmp_path / "config.json"),
        str(events),
        make_service_factory(load_or_create_host_key(tmp_path / "ssh_host.key")),
    )
    payload = engine_payload(
        "medium",
        instance_id,
        [{"name": "ssh", "protocol": "tcp", "port": engine_port, "banner": "SSH-2.0-OpenSSH_8.9p1"}],
        bait_credentials=[{"username": "hfcheck-ssh", "password": "test-decoy"}],
        logging={
            "capture_connections": True,
            "capture_credentials": True,
            "capture_commands": True,
            "capture_payloads": False,
        },
    )
    supervisor.apply(json.dumps(payload).encode(), payload)
    relay = start_server(
        TCPRelayServer(("127.0.0.1", relay_port), "127.0.0.1", engine_port),
        "test-medium-ssh-relay",
    )

    def transport_after_prompt_delay() -> paramiko.Transport:
        connection = socket.create_connection(("127.0.0.1", relay_port), timeout=2)
        transport = paramiko.Transport(connection)
        transport.start_client(timeout=3)
        time.sleep(0.35)
        return transport

    rejected = None
    accepted = None
    try:
        rejected = transport_after_prompt_delay()
        with pytest.raises(paramiko.AuthenticationException):
            rejected.auth_password("hfcheck-ssh", "incorrect-test-value")
        rejected.close()
        rejected = None

        accepted = transport_after_prompt_delay()
        accepted.auth_password("hfcheck-ssh", "test-decoy")
        channel = accepted.open_session(timeout=3)
        channel.exec_command("whoami")
        assert channel.makefile("rb").read() == b"hfcheck-ssh\n"
        channel.close()

        captured = wait_for_events(events, 4)
        auth_results = sorted(
            event["data"]["result"]
            for event in captured
            if event["event_type"] == "medium.ssh_auth"
        )
        assert auth_results == ["accepted_decoy", "rejected"]
        assert any(event["event_type"] == "medium.ssh_session" for event in captured)
        assert any(
            event["event_type"] == "medium.ssh_command" and event["data"]["command"] == "whoami"
            for event in captured
        )
    finally:
        if rejected is not None:
            rejected.close()
        if accepted is not None:
            accepted.close()
        relay.stop()
        supervisor.stop_services()


def test_event_spool_write_failure_does_not_raise_into_protocol_handler(tmp_path, monkeypatch):
    writer = EventWriter(str(tmp_path / "events"))

    def fail_write(path, payload):
        raise OSError("controlled spool failure")

    monkeypatch.setattr(common_module, "atomic_json", fail_write)

    assert writer.emit(str(uuid.uuid4()), "medium.ssh_auth", "192.0.2.10", {}) == ""


def test_engine_defers_event_until_instance_configuration_is_available(tmp_path):
    instance_id = str(uuid.uuid4())
    settings = AgentSettings(
        state_dir=str(tmp_path / "state"),
        low_config_file=str(tmp_path / "low-control" / "config.json"),
        medium_config_file=str(tmp_path / "medium-control" / "config.json"),
        high_config_file=str(tmp_path / "high-control" / "config.json"),
        low_event_dir=str(tmp_path / "low-events"),
        medium_event_dir=str(tmp_path / "medium-events"),
        high_event_dir=str(tmp_path / "high-events"),
    )
    queue = DurableQueue(str(tmp_path / "state" / "queue.sqlite3"))
    writer = EventWriter(settings.medium_event_dir)
    event_id = writer.emit(
        instance_id,
        "medium.ssh_auth",
        "192.0.2.20",
        {"engine": "medium", "service": "ssh", "result": "rejected"},
    )
    event_path = Path(settings.medium_event_dir) / f"{event_id}.event.json"
    controller = EngineController(settings)

    assert controller.ingest_events(queue) == 0
    assert event_path.exists()
    assert queue.depth() == 0

    queue.store_configuration(
        instance_id,
        1,
        {"instance_id": instance_id, "profile": {"interaction_level": "medium"}},
    )
    assert controller.ingest_events(queue) == 1
    assert not event_path.exists()
    assert queue.pending(1)[0]["external_id"] == event_id
    queue.connection.close()


def test_low_logging_flags_change_captured_data(tmp_path):
    instance_id = str(uuid.uuid4())
    port = free_port()
    events = tmp_path / "events"
    supervisor = RuntimeSupervisor("low", str(tmp_path / "config.json"), str(events), low_service_factory)
    service = {"name": "http", "protocol": "tcp", "port": port, "banner": "nginx"}
    request = b"GET /private?token=payload HTTP/1.1\r\nHost: localhost\r\n\r\n"
    try:
        connections_only = engine_payload(
            "low",
            instance_id,
            [service],
            logging={
                "capture_connections": True,
                "capture_credentials": False,
                "capture_commands": False,
                "capture_payloads": False,
            },
            config_version=1,
        )
        supervisor.apply(json.dumps(connections_only).encode(), connections_only)
        assert b"200 OK" in http_request(port, request)
        data = wait_for_events(events, 1)[0]["data"]
        assert "source_port" in data and "duration_ms" in data
        assert "request_line" not in data and "request" not in data

        clear_events(events)
        commands_only = engine_payload(
            "low",
            instance_id,
            [service],
            logging={
                "capture_connections": False,
                "capture_credentials": False,
                "capture_commands": True,
                "capture_payloads": False,
            },
            config_version=2,
        )
        supervisor.apply(json.dumps(commands_only).encode(), commands_only)
        http_request(port, request)
        data = wait_for_events(events, 1)[0]["data"]
        assert data["request_line"].startswith("GET /private")
        assert "source_port" not in data and "request" not in data

        clear_events(events)
        payloads_only = engine_payload(
            "low",
            instance_id,
            [service],
            logging={
                "capture_connections": False,
                "capture_credentials": False,
                "capture_commands": False,
                "capture_payloads": True,
            },
            config_version=3,
        )
        supervisor.apply(json.dumps(payloads_only).encode(), payloads_only)
        http_request(port, request)
        data = wait_for_events(events, 1)[0]["data"]
        assert "token=payload" in data["request"]
        assert "source_port" not in data and "request_line" not in data

        clear_events(events)
        disabled = engine_payload(
            "low",
            instance_id,
            [service],
            logging={
                "capture_connections": False,
                "capture_credentials": False,
                "capture_commands": False,
                "capture_payloads": False,
            },
            config_version=4,
        )
        supervisor.apply(json.dumps(disabled).encode(), disabled)
        assert b"200 OK" in http_request(port, request)
        time.sleep(0.1)
        assert list(events.glob("*.event.json")) == []
    finally:
        supervisor.stop_services()


def test_medium_bait_credentials_and_credential_logging(tmp_path):
    instance_id = str(uuid.uuid4())
    http_port, ssh_port = free_port(), free_port()
    events = tmp_path / "events"
    factory = make_service_factory(load_or_create_host_key(tmp_path / "ssh_host.key"))
    supervisor = RuntimeSupervisor("medium", str(tmp_path / "config.json"), str(events), factory)
    services = [
        {"name": "http", "protocol": "tcp", "port": http_port, "banner": "nginx"},
        {"name": "ssh", "protocol": "tcp", "port": ssh_port, "banner": "SSH-2.0-OpenSSH_8.9p1"},
    ]
    logging = {
        "capture_connections": True,
        "capture_credentials": True,
        "capture_commands": True,
        "capture_payloads": False,
    }
    credentials = [
        {"username": "web-admin", "password": "web-decoy"},
        {"username": "ssh-admin", "password": "ssh-decoy"},
    ]

    def login_request(username: str, password: str) -> bytes:
        body = f"username={username}&password={password}".encode()
        request = b"POST /login HTTP/1.1\r\nHost: localhost\r\n" + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
        return http_request(http_port, request)

    try:
        payload = engine_payload(
            "medium",
            instance_id,
            services,
            bait_credentials=credentials,
            logging=logging,
            config_version=1,
        )
        supervisor.apply(json.dumps(payload).encode(), payload)
        assert b"401 Unauthorized" in login_request("web-admin", "wrong")
        assert b"Administration" in login_request("web-admin", "web-decoy")

        rejected_client = paramiko.SSHClient()
        rejected_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        with pytest.raises(paramiko.AuthenticationException):
            rejected_client.connect(
                "127.0.0.1",
                port=ssh_port,
                username="ssh-admin",
                password="wrong",
                allow_agent=False,
                look_for_keys=False,
                timeout=4,
            )
        rejected_client.close()

        accepted_client = paramiko.SSHClient()
        accepted_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        accepted_client.connect(
            "127.0.0.1",
            port=ssh_port,
            username="ssh-admin",
            password="ssh-decoy",
            allow_agent=False,
            look_for_keys=False,
            timeout=4,
        )
        accepted_client.close()

        captured = wait_for_events(events, 6)
        auth_results = {
            (event["event_type"], event["data"]["username"], event["data"]["password"]): event["data"]["result"]
            for event in captured
            if event["event_type"] in {"medium.http_auth", "medium.ssh_auth"}
        }
        assert auth_results[("medium.http_auth", "web-admin", "wrong")] == "rejected"
        assert auth_results[("medium.http_auth", "web-admin", "web-decoy")] == "accepted_decoy"
        assert auth_results[("medium.ssh_auth", "ssh-admin", "wrong")] == "rejected"
        assert auth_results[("medium.ssh_auth", "ssh-admin", "ssh-decoy")] == "accepted_decoy"
        assert all("body" not in event["data"] for event in captured if event["event_type"] == "medium.http_request")

        clear_events(events)
        payload_logging = engine_payload(
            "medium",
            instance_id,
            services,
            bait_credentials=credentials,
            logging={
                "capture_connections": False,
                "capture_credentials": False,
                "capture_commands": False,
                "capture_payloads": True,
            },
            config_version=2,
        )
        supervisor.apply(json.dumps(payload_logging).encode(), payload_logging)
        assert b"Administration" in login_request("web-admin", "web-decoy")
        payload_event = wait_for_events(events, 1)[0]
        assert payload_event["event_type"] == "medium.http_request"
        assert payload_event["data"]["body"] == "[credentials omitted]"
        assert "duration_ms" not in payload_event["data"]

        clear_events(events)
        no_credential_logging = engine_payload(
            "medium",
            instance_id,
            services,
            bait_credentials=credentials,
            logging={
                "capture_connections": False,
                "capture_credentials": False,
                "capture_commands": False,
                "capture_payloads": False,
            },
            config_version=3,
        )
        supervisor.apply(json.dumps(no_credential_logging).encode(), no_credential_logging)
        assert b"Administration" in login_request("web-admin", "web-decoy")
        time.sleep(0.1)
        assert list(events.glob("*.event.json")) == []
    finally:
        supervisor.stop_services()


@pytest.mark.parametrize(
    ("query", "secret_values"),
    [
        ("view=status&password=unique-test-secret", ("unique-test-secret",)),
        (
            "view=status&PASSWD=uppercase-test-secret&PwD=short-test-secret",
            ("uppercase-test-secret", "short-test-secret"),
        ),
        (
            "view=status&%61%70%69%5F%6B%65%79=encoded%2Dtest%2Dsecret",
            ("encoded-test-secret", "encoded%2Dtest%2Dsecret"),
        ),
        (
            "view=status&access-token=first-test-secret&access-token=second-test-secret",
            ("first-test-secret", "second-test-secret"),
        ),
        (
            "view=status&Pass=pass-test-secret&TOKEN=token-test-secret&secret=secret-test-secret"
            "&ACCESS_TOKEN=access-test-secret&Authorization=bearer-test-secret&apiKey=api-test-secret",
            (
                "pass-test-secret",
                "token-test-secret",
                "secret-test-secret",
                "access-test-secret",
                "bearer-test-secret",
                "api-test-secret",
            ),
        ),
    ],
)
def test_medium_http_omits_query_secrets_when_credential_capture_disabled(
    tmp_path, query, secret_values
):
    instance_id = str(uuid.uuid4())
    port = free_port()
    events = tmp_path / "events"
    factory = make_service_factory(load_or_create_host_key(tmp_path / "ssh_host.key"))
    supervisor = RuntimeSupervisor("medium", str(tmp_path / "config.json"), str(events), factory)
    payload = engine_payload(
        "medium",
        instance_id,
        [{"name": "http", "protocol": "tcp", "port": port, "banner": "nginx"}],
        logging={
            "capture_connections": True,
            "capture_credentials": False,
            "capture_commands": True,
            "capture_payloads": True,
        },
    )
    supervisor.apply(json.dumps(payload).encode(), payload)
    request = (
        f"GET /reports?{query} HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "X-HoneyForge-Verification: stage3\r\n\r\n"
    ).encode()

    try:
        response = http_request(port, request)
        assert b"HTTP/1.1 200 OK" in response
        assert b"Sign in" in response

        event = wait_for_events(events, 1)[0]
        assert event["event_type"] == "medium.http_request"
        assert event["instance_id"] == instance_id
        assert event["data"]["method"] == "GET"
        assert event["data"]["path"].startswith("/reports?")
        assert "view=status" in event["data"]["path"]
        assert event["data"]["http_version"] == "HTTP/1.1"
        assert event["data"]["headers"]["host"] == "localhost"
        assert event["data"]["body"] == ""
        serialized_event = json.dumps(event, ensure_ascii=False)
        assert all(secret not in serialized_event for secret in secret_values)
    finally:
        supervisor.stop_services()


def test_engine_masking_delay_is_applied_to_low_and_medium_http(tmp_path, monkeypatch):
    delays: list[float] = []
    monkeypatch.setattr(common_module.time, "sleep", delays.append)
    masking = {"response_delay_ms": 125}
    supervisors: list[RuntimeSupervisor] = []
    try:
        for level, factory in (
            ("low", low_service_factory),
            ("medium", make_service_factory(load_or_create_host_key(tmp_path / "ssh_host.key"))),
        ):
            instance_id = str(uuid.uuid4())
            port = free_port()
            events = tmp_path / f"{level}-events"
            supervisor = RuntimeSupervisor(level, str(tmp_path / f"{level}.json"), str(events), factory)
            supervisors.append(supervisor)
            payload = engine_payload(
                level,
                instance_id,
                [{"name": "http", "protocol": "tcp", "port": port, "banner": "nginx"}],
                masking=masking,
            )
            supervisor.apply(json.dumps(payload).encode(), payload)
            assert b"200 OK" in http_request(port, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert delays == [0.125, 0.125]
    finally:
        for supervisor in supervisors:
            supervisor.stop_services()


def test_agent_renders_updated_profile_controls(tmp_path):
    instance_id = str(uuid.uuid4())
    settings = AgentSettings(
        state_dir=str(tmp_path / "state"),
        low_config_file=str(tmp_path / "low-control" / "config.json"),
        medium_config_file=str(tmp_path / "medium-control" / "config.json"),
        low_event_dir=str(tmp_path / "low-events"),
        medium_event_dir=str(tmp_path / "medium-events"),
    )
    queue = DurableQueue(str(tmp_path / "state" / "queue.sqlite3"))
    base_profile = {
        "interaction_level": "low",
        "config_version": 1,
        "services": [{"name": "http", "protocol": "tcp", "port": 8081, "banner": "nginx"}],
        "bait_credentials": [],
        "logging": {"capture_connections": True, "capture_credentials": True, "capture_commands": True, "capture_payloads": False},
        "masking": {"endpoint_path": "/assets/telemetry", "process_name": "system-metrics", "install_path": "/opt/system-metrics", "response_delay_ms": 0},
    }
    class ConfigClient:
        def __init__(self, configuration: dict):
            self.current = configuration

        def configuration(self) -> dict:
            return {"host_id": str(uuid.uuid4()), "configurations": [self.current]}

    first_configuration = {
        "instance_id": instance_id,
        "instance_name": "low-test",
        "profile": base_profile,
    }
    client = ConfigClient(first_configuration)
    sync_configuration(client, queue)
    controller = EngineController(settings)
    assert controller.render(queue)["low"] is True
    first = json.loads(Path(settings.low_config_file).read_text(encoding="utf-8"))["instances"][0]
    assert first["config_version"] == 1
    assert first["masking"]["response_delay_ms"] == 0

    updated_profile = {
        **base_profile,
        "config_version": 2,
        "bait_credentials": [{"username": "operator", "password": "decoy-only"}],
        "logging": {**base_profile["logging"], "capture_credentials": False, "capture_payloads": True},
        "masking": {**base_profile["masking"], "response_delay_ms": 175},
    }
    client.current = {
        "instance_id": instance_id,
        "instance_name": "low-test",
        "profile": updated_profile,
    }
    sync_configuration(client, queue)
    assert controller.render(queue)["low"] is True
    rendered = json.loads(Path(settings.low_config_file).read_text(encoding="utf-8"))["instances"][0]
    assert rendered["config_version"] == 2
    assert rendered["bait_credentials"] == updated_profile["bait_credentials"]
    assert rendered["logging"] == updated_profile["logging"]
    assert rendered["masking"] == updated_profile["masking"]


def test_engine_events_move_to_existing_durable_queue_and_survive_restart(tmp_path):
    instance_id = str(uuid.uuid4())
    state = tmp_path / "state"
    settings = AgentSettings(
        state_dir=str(state),
        low_config_file=str(tmp_path / "low-control" / "config.json"),
        medium_config_file=str(tmp_path / "medium-control" / "config.json"),
        low_event_dir=str(tmp_path / "low-events"),
        medium_event_dir=str(tmp_path / "medium-events"),
    )
    queue_path = state / "queue.sqlite3"
    queue = DurableQueue(str(queue_path))
    config = {
        "instance_id": instance_id,
        "instance_name": "low-test",
        "profile": {
            "interaction_level": "low",
            "config_version": 1,
            "services": [{"name": "http", "protocol": "tcp", "port": 8081, "banner": "nginx"}],
            "bait_credentials": [],
            "logging": {},
        },
    }
    queue.store_configuration(instance_id, 1, config)
    queue.set_engine_enabled(instance_id, True)
    controller = EngineController(settings)
    controller.render(queue)
    (Path(settings.low_event_dir) / "status.json").write_text(
        json.dumps(
            {
                "engine": "low",
                "instances": {
                    instance_id: {"state": "online", "config_version": 1, "ports": [8081], "error": None}
                },
            }
        ),
        encoding="utf-8",
    )
    state, result = controller.execute_job(
        queue,
        {"command": "start_trap", "instance_id": instance_id},
    )
    assert state == "succeeded"
    assert result["state"] == "online"
    event_id = EventWriter(settings.low_event_dir).emit(
        instance_id,
        "low.http_request",
        "127.0.0.1",
        {"engine": "low", "request_line": "GET / HTTP/1.1"},
    )
    assert controller.ingest_events(queue) == 1
    assert queue.pending(10)[0]["external_id"] == event_id
    queue.connection.close()

    restarted = DurableQueue(str(queue_path))
    assert restarted.depth() == 1
    restarted.enqueue({**restarted.pending(1)[0]})
    assert restarted.depth() == 1
    restarted.acknowledge([event_id])
    assert restarted.depth() == 0
