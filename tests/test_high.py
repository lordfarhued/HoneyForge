import json
import socket
import time
import uuid
from pathlib import Path

import paramiko
import pytest
from pydantic import ValidationError

from agent.config import AgentSettings
from agent.engines import EngineController
from agent.queue import DurableQueue
from app.schemas import ProfileInput
from honeypots.common import EventWriter, RuntimeSupervisor, ThreadedTCPServer, start_server
from honeypots.high import (
    MAX_COMMAND,
    HighEnvironment,
    HighShell,
    build_http_handler,
    build_ssh_handler,
    make_service_factory,
)
from honeypots.medium import load_or_create_host_key


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def high_instance(instance_id: str, http_port: int, ssh_port: int) -> dict:
    return {
        "instance_id": instance_id,
        "instance_name": "northbridge-high",
        "config_version": 3,
        "enabled": True,
        "services": [
            {"name": "http", "protocol": "tcp", "port": http_port, "banner": "nginx"},
            {"name": "ssh", "protocol": "tcp", "port": ssh_port, "banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"},
        ],
        "bait_credentials": [{"username": "deploy", "password": "Decoy-Portal-Only-2026!"}],
        "logging": {
            "capture_connections": True,
            "capture_credentials": True,
            "capture_commands": True,
            "capture_payloads": False,
        },
        "masking": {"response_delay_ms": 0},
    }


def high_payload(instance: dict) -> dict:
    return {"schema_version": 1, "interaction_level": "high", "instances": [instance]}


def wait_for_events(directory: Path, minimum: int) -> list[dict]:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        paths = list(directory.glob("*.event.json"))
        if len(paths) >= minimum:
            return [json.loads(path.read_text(encoding="utf-8")) for path in paths]
        time.sleep(0.05)
    raise AssertionError(f"expected at least {minimum} High event files")


def http_request(port: int, request: bytes) -> bytes:
    response = bytearray()
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        while True:
            chunk = connection.recv(8192)
            if not chunk:
                break
            response.extend(chunk)
    return bytes(response)


def profile_payload() -> dict:
    return {
        "name": "Northbridge High",
        "description": "Linked virtual SSH and corporate HTTP environment",
        "interaction_level": "high",
        "services": [
            {"name": "http", "protocol": "tcp", "port": 8084, "banner": "nginx"},
            {"name": "ssh", "protocol": "tcp", "port": 2223, "banner": "SSH-2.0-OpenSSH_9.6p1"},
        ],
        "bait_credentials": [{"username": "deploy", "password": "decoy-only"}],
        "logging": {},
        "masking": {},
    }


def test_high_profile_requires_linked_http_and_ssh_tcp_services():
    profile = ProfileInput.model_validate(profile_payload())
    assert profile.interaction_level.value == "high"
    assert {service.name for service in profile.services} == {"http", "ssh"}

    missing = profile_payload()
    missing["services"] = missing["services"][:1]
    with pytest.raises(ValidationError, match="ровно сервисы http и ssh"):
        ProfileInput.model_validate(missing)

    udp = profile_payload()
    udp["services"][0]["protocol"] = "udp"
    with pytest.raises(ValidationError, match="только протокол tcp"):
        ProfileInput.model_validate(udp)


def test_high_virtual_filesystem_is_consistent_bounded_and_never_uses_network(monkeypatch):
    environment = HighEnvironment(high_instance(str(uuid.uuid4()), 8084, 2223))
    shell = HighShell(environment, "deploy")

    assert shell.run("pwd")[0] == "/home/deploy\n"
    assert "company-portal" in shell.run("ls /opt")[0]
    assert shell.run("cd /opt/company-portal/config")[0] == ""
    assert shell.run("pwd")[0] == "/opt/company-portal/config\n"
    application = shell.run("cat application.env")
    assert "PORTAL_URL=http://portal.intra.example:8080" in application[0]
    assert application[1] == ["/opt/company-portal/config/application.env"]
    assert "root:x:0:0" in shell.run("cat ../../../../etc/passwd")[0]
    assert "No such file" in shell.run("cat C:/Windows/System32/config/SAM")[0]
    assert "syntax error" in shell.run("cat /etc/passwd; id")[0]
    assert len(shell.run("find /")[0].encode("utf-8")) <= 32_768

    def unexpected_connection(*args, **kwargs):
        raise AssertionError("High shell attempted a real network connection")

    monkeypatch.setattr("honeypots.high.socket.create_connection", unexpected_connection)
    assert "Could not resolve host" in shell.run("curl https://outside.invalid/tool")[0]
    assert "302 Found" in shell.run("wget http://portal.intra.example/")[0]


def test_high_shell_metacharacters_cannot_execute_host_commands(tmp_path):
    environment = HighEnvironment(high_instance(str(uuid.uuid4()), 8084, 2223))
    shell = HighShell(environment, "deploy")
    marker = tmp_path / "must-not-exist"

    output, _ = shell.run(f"id; touch {marker}")

    assert "syntax error" in output
    assert not marker.exists()
    source = (Path(__file__).resolve().parents[1] / "honeypots/high.py").read_text(encoding="utf-8")
    for forbidden in ("subprocess", "os.system", "os.popen", "shell=True", "eval(", "exec("):
        assert forbidden not in source


def test_high_http_auth_routes_and_in_memory_honeytoken_are_safe(tmp_path):
    instance = high_instance(str(uuid.uuid4()), free_port(), free_port())
    environment = HighEnvironment(instance)
    events = tmp_path / "events"
    writer = EventWriter(str(events))
    service = instance["services"][0]
    server = ThreadedTCPServer(("127.0.0.1", service["port"]), build_http_handler(instance, service, writer, environment))
    handle = start_server(server, "test-high-http")
    try:
        unauthorized = http_request(service["port"], b"GET /services HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert b"302 Found" in unauthorized and b"Location: /login" in unauthorized

        wrong_body = b"username=deploy&password=wrong"
        wrong = http_request(
            service["port"],
            b"POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Length: "
            + str(len(wrong_body)).encode()
            + b"\r\n\r\n"
            + wrong_body,
        )
        assert b"401 Unauthorized" in wrong

        body = b"username=deploy&password=Decoy-Portal-Only-2026%21"
        accepted = http_request(
            service["port"],
            b"POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\n\r\n"
            + body,
        )
        assert b"303 See Other" in accepted
        cookie = accepted.split(b"NBSESSION=", 1)[1].split(b";", 1)[0]
        services = http_request(
            service["port"],
            b"GET /services HTTP/1.1\r\nHost: localhost\r\nCookie: NBSESSION=" + cookie + b"\r\n\r\n",
        )
        assert b"200 OK" in services and "Сервисы".encode() in services

        token = environment.honeytoken
        honeytoken_response = http_request(
            service["port"],
            f"GET /api/internal/status?view=status&token={token} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode(),
        )
        assert b'"status":"ok"' in honeytoken_response
        captured = sorted(wait_for_events(events, 6), key=lambda event: event["occurred_at"])
        serialized = json.dumps(captured, ensure_ascii=False)
        assert "Decoy-Portal-Only-2026!" not in serialized
        assert token not in serialized
        assert any(event["event_type"] == "high.http_auth" and event["data"]["result"] == "accepted_decoy" for event in captured)
        triggered = next(event for event in captured if event["data"].get("_high_honeytoken_use") is True)
        assert triggered["event_type"] == "high.http_request"
        assert "view=status" in triggered["data"]["path"]
        assert "token=%5Bcredentials+omitted%5D" in triggered["data"]["path"]
    finally:
        handle.stop()


def test_high_ssh_exec_logs_virtual_commands_without_password_or_token(tmp_path):
    instance = high_instance(str(uuid.uuid4()), free_port(), free_port())
    environment = HighEnvironment(instance)
    events = tmp_path / "events"
    writer = EventWriter(str(events))
    service = instance["services"][1]
    host_key = load_or_create_host_key(tmp_path / "high-host.key")
    server = ThreadedTCPServer(
        ("127.0.0.1", service["port"]),
        build_ssh_handler(instance, service, writer, host_key, environment),
    )
    handle = start_server(server, "test-high-ssh")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            "127.0.0.1", port=service["port"], username="deploy",
            password="Decoy-Portal-Only-2026!", allow_agent=False, look_for_keys=False, timeout=4,
        )
        _, stdout, _ = client.exec_command("cat /opt/company-portal/backups/service-access.txt", timeout=4)
        output = stdout.read().decode("utf-8")
        assert environment.honeytoken in output
        captured = wait_for_events(events, 4)
        serialized = json.dumps(captured, ensure_ascii=False)
        assert environment.honeytoken not in serialized
        assert "Decoy-Portal-Only-2026!" not in serialized
        assert any(event["event_type"] == "high.ssh_command" and event["data"]["execution"] == "virtual_only" for event in captured)
        assert any(event["event_type"] == "high.ssh_sensitive_file" for event in captured)
        session_ids = {event["data"].get("session_id") for event in captured if event["event_type"].startswith("high.ssh")}
        assert len(session_ids) == 1
    finally:
        client.close()
        handle.stop()


def test_high_ssh_interactive_session_handles_sequential_commands_and_exit(tmp_path):
    instance = high_instance(str(uuid.uuid4()), free_port(), free_port())
    service = instance["services"][1]
    events = tmp_path / "events"
    server = ThreadedTCPServer(
        ("127.0.0.1", service["port"]),
        build_ssh_handler(
            instance,
            service,
            EventWriter(str(events)),
            load_or_create_host_key(tmp_path / "high-host.key"),
            HighEnvironment(instance),
        ),
    )
    handle = start_server(server, "test-high-ssh-interactive")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            "127.0.0.1", port=service["port"], username="deploy",
            password="Decoy-Portal-Only-2026!", allow_agent=False, look_for_keys=False, timeout=4,
        )
        channel = client.invoke_shell()
        channel.settimeout(2)
        transcript = bytearray(channel.recv(4096))
        channel.send(b"\x1b[Acd /opt/company-portax\x7fl\r\npwd\r\nls config\r\nexit\r\n")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                chunk = channel.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            transcript.extend(chunk)
        decoded = transcript.decode("utf-8", errors="replace")
        assert "cd /opt/company-portax\b \bl" in decoded
        assert "/opt/company-portal" in decoded
        assert "application.env" in decoded
        assert "logout" in decoded
        captured = sorted(wait_for_events(events, 6), key=lambda event: event["occurred_at"])
        commands = [event["data"]["command"] for event in captured if event["event_type"] == "high.ssh_command"]
        assert commands == ["cd /opt/company-portal", "pwd", "ls config", "exit"]
    finally:
        client.close()
        handle.stop()


def test_high_ssh_reports_rejected_and_successful_password_auth_and_session_events(tmp_path):
    instance = high_instance(str(uuid.uuid4()), free_port(), free_port())
    service = instance["services"][1]
    events = tmp_path / "events"
    server = ThreadedTCPServer(
        ("127.0.0.1", service["port"]),
        build_ssh_handler(
            instance,
            service,
            EventWriter(str(events)),
            load_or_create_host_key(tmp_path / "high-host.key"),
            HighEnvironment(instance),
        ),
    )
    handle = start_server(server, "test-high-ssh-auth-events")
    rejected = paramiko.SSHClient()
    rejected.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    accepted = paramiko.SSHClient()
    accepted.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        with pytest.raises(paramiko.AuthenticationException):
            rejected.connect(
                "127.0.0.1", port=service["port"], username="deploy",
                password="incorrect-test-value", allow_agent=False, look_for_keys=False, timeout=4,
            )
        accepted.connect(
            "127.0.0.1", port=service["port"], username="deploy",
            password="Decoy-Portal-Only-2026!", allow_agent=False, look_for_keys=False, timeout=4,
        )
        _, stdout, _ = accepted.exec_command("whoami", timeout=4)
        assert stdout.read() == b"deploy\n"

        captured = wait_for_events(events, 5)
        auth_events = [event for event in captured if event["event_type"] == "high.ssh_auth"]
        assert sorted(event["data"]["result"] for event in auth_events) == ["accepted_decoy", "rejected"]
        assert all(event["data"]["password"] == "[credentials omitted]" for event in auth_events)
        assert any(
            event["event_type"] == "high.ssh_session" and event["data"]["action"] == "opened"
            for event in captured
        )
        assert any(
            event["event_type"] == "high.ssh_command" and event["data"]["command"] == "whoami"
            for event in captured
        )
    finally:
        rejected.close()
        accepted.close()
        handle.stop()


def test_high_ssh_closes_oversized_unterminated_command(tmp_path):
    instance = high_instance(str(uuid.uuid4()), free_port(), free_port())
    environment = HighEnvironment(instance)
    service = instance["services"][1]
    server = ThreadedTCPServer(
        ("127.0.0.1", service["port"]),
        build_ssh_handler(
            instance,
            service,
            EventWriter(str(tmp_path / "events")),
            load_or_create_host_key(tmp_path / "high-host.key"),
            environment,
        ),
    )
    handle = start_server(server, "test-high-ssh-limit")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            "127.0.0.1", port=service["port"], username="deploy",
            password="Decoy-Portal-Only-2026!", allow_agent=False, look_for_keys=False, timeout=4,
        )
        channel = client.invoke_shell()
        channel.settimeout(2)
        channel.recv(4096)
        channel.send(b"x" * (MAX_COMMAND + 64))
        deadline = time.monotonic() + 3
        while not channel.closed and time.monotonic() < deadline:
            try:
                if not channel.recv(1024):
                    break
            except (socket.timeout, EOFError):
                pass
            time.sleep(0.05)
        assert channel.eof_received or channel.closed or not client.get_transport().is_active()
    finally:
        client.close()
        handle.stop()


def test_high_ssh_enforces_total_session_duration(tmp_path, monkeypatch):
    monkeypatch.setattr("honeypots.high.SSH_SESSION_TIMEOUT_SECONDS", 0.25)
    instance = high_instance(str(uuid.uuid4()), free_port(), free_port())
    service = instance["services"][1]
    server = ThreadedTCPServer(
        ("127.0.0.1", service["port"]),
        build_ssh_handler(
            instance,
            service,
            EventWriter(str(tmp_path / "events")),
            load_or_create_host_key(tmp_path / "high-host.key"),
            HighEnvironment(instance),
        ),
    )
    handle = start_server(server, "test-high-ssh-deadline")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            "127.0.0.1", port=service["port"], username="deploy",
            password="Decoy-Portal-Only-2026!", allow_agent=False, look_for_keys=False, timeout=4,
        )
        channel = client.invoke_shell()
        channel.settimeout(1)
        try:
            channel.recv(4096)
        except socket.timeout:
            pass
        deadline = time.monotonic() + 2
        while not channel.eof_received and time.monotonic() < deadline:
            try:
                channel.send(b"pwd\n")
                channel.recv(4096)
            except (OSError, EOFError, socket.timeout):
                pass
            time.sleep(0.05)
        assert channel.eof_received or channel.closed or not client.get_transport().is_active()
    finally:
        client.close()
        handle.stop()


def test_high_runtime_and_agent_support_apply_start_stop_and_durable_events(tmp_path, monkeypatch):
    instance_id = str(uuid.uuid4())
    instance = high_instance(instance_id, free_port(), free_port())
    events = tmp_path / "engine-events"
    supervisor = RuntimeSupervisor(
        "high",
        str(tmp_path / "engine-config.json"),
        str(events),
        make_service_factory(load_or_create_host_key(tmp_path / "runtime-host.key")),
    )
    payload = high_payload(instance)
    try:
        supervisor.apply(json.dumps(payload).encode(), payload)
        status = json.loads((events / "status.json").read_text(encoding="utf-8"))
        assert status["instances"][instance_id]["state"] == "online"
        assert status["instances"][instance_id]["ports"] == [instance["services"][0]["port"], instance["services"][1]["port"]]

        disabled = high_payload({**instance, "enabled": False, "config_version": 4})
        supervisor.apply(json.dumps(disabled).encode(), disabled)
        status = json.loads((events / "status.json").read_text(encoding="utf-8"))
        assert status["instances"][instance_id]["state"] == "offline"
    finally:
        supervisor.stop_services()

    settings = AgentSettings(
        state_dir=str(tmp_path / "state"),
        low_config_file=str(tmp_path / "control-low" / "config.json"),
        medium_config_file=str(tmp_path / "control-medium" / "config.json"),
        high_config_file=str(tmp_path / "control-high" / "config.json"),
        low_event_dir=str(tmp_path / "events-low"),
        medium_event_dir=str(tmp_path / "events-medium"),
        high_event_dir=str(tmp_path / "events-high"),
    )
    queue = DurableQueue(str(tmp_path / "state" / "queue.sqlite3"))
    config = {
        "instance_id": instance_id,
        "instance_name": "northbridge-high",
        "profile": {
            "interaction_level": "high", "config_version": 3,
            "services": instance["services"], "bait_credentials": instance["bait_credentials"],
            "logging": instance["logging"], "masking": instance["masking"],
        },
    }
    queue.store_configuration(instance_id, 3, config)
    controller = EngineController(settings)
    assert controller.render(queue)["high"] is True
    rendered = json.loads(Path(settings.high_config_file).read_text(encoding="utf-8"))
    assert rendered["instances"][0]["services"] == instance["services"]

    queue.set_engine_enabled(instance_id, True)
    monkeypatch.setattr(
        controller,
        "_wait_for",
        lambda _queue, _instance_id, expected, version, _not_before: {
            "state": expected, "config_version": version,
            "details": {"ports": [instance["services"][0]["port"], instance["services"][1]["port"]], "endpoints": []},
        },
    )
    state, result = controller.execute_job(queue, {"command": "start_trap", "instance_id": instance_id})
    assert state == "succeeded" and result["engine"] == "high"
    state, result = controller.execute_job(queue, {"command": "stop_trap", "instance_id": instance_id})
    assert state == "succeeded" and result["state"] == "offline"
    assert queue.engine_enabled(instance_id) is False

    event_id = EventWriter(settings.high_event_dir).emit(
        instance_id, "high.ssh_command", "198.51.100.40",
        {"engine": "high", "command": "whoami", "execution": "virtual_only"},
    )
    assert controller.ingest_events(queue) == 1
    assert queue.pending(10)[0]["external_id"] == event_id
    queue.connection.close()
    restored = DurableQueue(str(tmp_path / "state" / "queue.sqlite3"))
    assert restored.pending(10)[0]["external_id"] == event_id
    restored.connection.close()
