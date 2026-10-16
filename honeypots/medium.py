from __future__ import annotations

import hashlib
import re
import socket
import time
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit, urlunsplit

import paramiko

from honeypots.common import (
    EventWriter,
    RuntimeSupervisor,
    ServiceHandle,
    ThreadedTCPServer,
    apply_response_delay,
    evaluate_bait_credentials,
    logging_enabled,
    proxy_peer,
    start_server,
)

MAX_HTTP_REQUEST = 16_384
MAX_COMMAND = 1024
SSH_IDLE_TIMEOUT_SECONDS = 30
SSH_SESSION_TIMEOUT_SECONDS = 120
REDACTED_QUERY_VALUE = "[credentials omitted]"
HONEYTOKEN_REDACTION = "[honeytoken omitted]"
HONEYTOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9_-])hft_[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")


def redact_sensitive_query_values(path: str) -> str:
    parsed = urlsplit(path)
    if not parsed.query:
        return path

    def is_sensitive(name: str) -> bool:
        normalized = "".join(character for character in name.casefold() if character.isalnum())
        if normalized in {"pass", "pwd", "auth", "bearer"}:
            return True
        return normalized.endswith(
            ("password", "passwd", "passphrase", "token", "secret", "apikey", "authorization")
        )

    query = urlencode(
        [
            (name, REDACTED_QUERY_VALUE if is_sensitive(name) else value)
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def redact_honeytoken_candidates(value: str) -> tuple[str, set[str]]:
    matched: set[str] = set()

    def replace(match: re.Match[str]) -> str:
        digest = hashlib.sha256(match.group(0).encode("utf-8")).hexdigest()
        matched.add(digest)
        return HONEYTOKEN_REDACTION

    return HONEYTOKEN_PATTERN.sub(replace, value), matched


def safe_banner(value: str, fallback: str) -> str:
    return value.replace("\r", " ").replace("\n", " ")[:200] or fallback


def split_http_request(raw: bytes) -> tuple[str, str, str, dict[str, str], bytes]:
    header_bytes, _, body = raw.partition(b"\r\n\r\n")
    lines = header_bytes.decode("iso-8859-1", errors="replace").split("\r\n")
    parts = lines[0].split(" ", 2) if lines else []
    method, path, version = (parts + ["", "", ""])[:3]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()[:80]] = value.strip()[:500]
    return method[:16], path[:2048], version[:20], headers, body[:8192]


def build_http_handler(instance: dict, service: dict, writer: EventWriter):
    class MediumHTTPHandler:
        def __init__(self, request: socket.socket, client_address, server):
            self.request = request
            self.client_address = client_address
            self.handle()

        def handle(self) -> None:
            started = time.monotonic()
            source_ip, source_port = self.client_address[0], self.client_address[1]
            self.request.settimeout(4)
            try:
                source_ip, source_port = proxy_peer(self.request, source_ip, source_port)
            except (OSError, ValueError):
                return
            raw = b""
            try:
                raw = self.request.recv(MAX_HTTP_REQUEST)
            except (OSError, TimeoutError):
                pass
            method, path, version, headers, body = split_http_request(raw)
            controlled = headers.get("x-honeyforge-verification") == "stage3"
            capture_connections = logging_enabled(instance, "capture_connections")
            capture_credentials = logging_enabled(instance, "capture_credentials")
            capture_commands = logging_enabled(instance, "capture_commands")
            capture_payloads = logging_enabled(instance, "capture_payloads")
            telemetry_path, matched_honeytokens = redact_honeytoken_candidates(path)
            telemetry_headers: dict[str, str] = {}
            for key, value in headers.items():
                protected, header_matches = redact_honeytoken_candidates(value)
                telemetry_headers[key] = protected
                matched_honeytokens.update(header_matches)
            visible_body, body_matches = redact_honeytoken_candidates(
                body.decode("utf-8", errors="replace")[:4096]
            )
            matched_honeytokens.update(body_matches)
            is_login = method.upper() == "POST" and path.split("?", 1)[0] in ("/login", "/admin/login")
            common = {
                "engine": "medium",
                "service": "http",
                "protocol": "tcp",
                "destination_port": int(service["port"]),
                "controlled_test": controlled,
            }
            if capture_connections:
                common.update(source_port=source_port, bytes_received=len(raw))
            if capture_commands:
                if not capture_credentials:
                    telemetry_path = redact_sensitive_query_values(telemetry_path)
                common.update(method=method, path=telemetry_path, http_version=version)
            if capture_payloads:
                visible_headers = telemetry_headers
                if not capture_credentials:
                    for sensitive_header in ("authorization", "cookie", "proxy-authorization", "set-cookie"):
                        visible_headers.pop(sensitive_header, None)
                    if is_login:
                        visible_body = "[credentials omitted]"
                common.update(headers=visible_headers, body=visible_body)
            if matched_honeytokens:
                common["_honeytoken_hashes"] = sorted(matched_honeytokens)
            auth_event: dict | None = None
            status_line = b"HTTP/1.1 200 OK\r\n"
            if is_login:
                form = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
                username = (form.get("username") or form.get("user") or [""])[0][:80]
                password = (form.get("password") or form.get("pass") or [""])[0][:128]
                accepted, credentials_configured = evaluate_bait_credentials(instance, username, password)
                if capture_credentials:
                    auth_event = {
                        "engine": "medium",
                        "service": "http",
                        "source_port": source_port,
                        "destination_port": int(service["port"]),
                        "username": redact_honeytoken_candidates(username)[0],
                        "password": redact_honeytoken_candidates(password)[0],
                        "path": telemetry_path,
                        "result": (
                            "accepted_decoy"
                            if accepted and credentials_configured
                            else "accepted_fake_session"
                            if accepted
                            else "rejected"
                        ),
                        "controlled_test": controlled,
                    }
                    if matched_honeytokens:
                        auth_event["_honeytoken_hashes"] = sorted(matched_honeytokens)
                if accepted:
                    page = b"<html><body><h1>Administration</h1><p>System status: nominal</p></body></html>"
                else:
                    status_line = b"HTTP/1.1 401 Unauthorized\r\n"
                    page = b"<html><body><h1>Sign in</h1><p>Invalid credentials</p></body></html>"
            else:
                page = (
                    b"<html><body><h1>Sign in</h1><form method='post' action='/login'>"
                    b"<input name='username'><input name='password' type='password'><button>Login</button>"
                    b"</form></body></html>"
                )
            banner = safe_banner(str(service.get("banner", "")), "nginx")
            response = (
                status_line
                + f"Server: {banner}\r\n".encode("utf-8")
                + b"Content-Type: text/html; charset=utf-8\r\n"
                + f"Content-Length: {len(page)}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
                + page
            )
            try:
                apply_response_delay(instance)
                self.request.sendall(response)
            except OSError:
                pass
            if capture_connections:
                common["duration_ms"] = round((time.monotonic() - started) * 1000, 2)
            if capture_connections or capture_commands or capture_payloads or matched_honeytokens:
                writer.emit(str(instance["instance_id"]), "medium.http_request", source_ip, common)
            if auth_event is not None:
                writer.emit(str(instance["instance_id"]), "medium.http_auth", source_ip, auth_event)

    return MediumHTTPHandler


class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, instance: dict, service: dict, writer: EventWriter, source_ip: str, source_port: int):
        self.instance = instance
        self.service = service
        self.writer = writer
        self.source_ip = source_ip
        self.source_port = source_port
        self.username = "guest"
        self.controlled = False
        self.shell_requested = False
        self.exec_command: str | None = None

    def check_auth_password(self, username: str, password: str):
        self.username = username[:80]
        password = password[:128]
        self.controlled = self.username.startswith("hfcheck")
        apply_response_delay(self.instance)
        accepted, credentials_configured = evaluate_bait_credentials(self.instance, self.username, password)
        if logging_enabled(self.instance, "capture_credentials"):
            self.writer.emit(
                str(self.instance["instance_id"]),
                "medium.ssh_auth",
                self.source_ip,
                {
                    "engine": "medium",
                    "service": "ssh",
                    "source_port": self.source_port,
                    "destination_port": int(self.service["port"]),
                    "username": self.username,
                    "password": password,
                    "result": (
                        "accepted_decoy"
                        if accepted and credentials_configured
                        else "accepted_fake_session"
                        if accepted
                        else "rejected"
                    ),
                    "controlled_test": self.controlled,
                },
            )
        return paramiko.AUTH_SUCCESSFUL if accepted else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.shell_requested = True
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = command.decode("utf-8", errors="replace")[:MAX_COMMAND]
        return True


def fake_command_response(command: str, username: str) -> str:
    normalized = command.strip()
    responses = {
        "whoami": f"{username}\n",
        "pwd": f"/home/{username}\n",
        "ls": "backup  logs  public_html\n",
        "ls -la": "drwxr-xr-x 5 user user 4096 .\ndrwxr-xr-x 3 root root 4096 ..\n-rw-r--r-- 1 user user 220 .bash_logout\n",
        "id": f"uid=1001({username}) gid=1001({username}) groups=1001({username})\n",
        "uname -a": "Linux web-node-02 5.15.0-107-generic #117-Ubuntu SMP x86_64 GNU/Linux\n",
        "cat /etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n',
    }
    if normalized in responses:
        return responses[normalized]
    if not normalized:
        return ""
    return f"bash: {normalized.split()[0][:80]}: command not found\n"


def emit_ssh_command(server: FakeSSHServer, command: str) -> None:
    if not logging_enabled(server.instance, "capture_commands"):
        return
    server.writer.emit(
        str(server.instance["instance_id"]),
        "medium.ssh_command",
        server.source_ip,
        {
            "engine": "medium",
            "service": "ssh",
            "source_port": server.source_port,
            "destination_port": int(server.service["port"]),
            "username": server.username,
            "command": command[:MAX_COMMAND],
            "execution": "simulated_only",
            "controlled_test": server.controlled,
        },
    )


def build_ssh_handler(instance: dict, service: dict, writer: EventWriter, host_key: paramiko.PKey):
    class MediumSSHHandler:
        def __init__(self, request: socket.socket, client_address, tcp_server):
            self.request = request
            self.client_address = client_address
            self.handle()

        def handle(self) -> None:
            source_ip, source_port = self.client_address[0], self.client_address[1]
            self.request.settimeout(10)
            try:
                source_ip, source_port = proxy_peer(self.request, source_ip, source_port)
            except (OSError, ValueError):
                return
            transport = paramiko.Transport(self.request)
            transport.local_version = safe_banner(str(service.get("banner", "")), "SSH-2.0-OpenSSH_8.9p1")
            transport.add_server_key(host_key)
            fake = FakeSSHServer(instance, service, writer, source_ip, source_port)
            channel = None
            try:
                transport.start_server(server=fake)
                channel = transport.accept(10)
                if channel is None:
                    return
                session_deadline = time.monotonic() + SSH_SESSION_TIMEOUT_SECONDS
                deadline = time.monotonic() + 3
                while not fake.shell_requested and fake.exec_command is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                if logging_enabled(instance, "capture_connections"):
                    writer.emit(
                        str(instance["instance_id"]),
                        "medium.ssh_session",
                        source_ip,
                        {
                            "engine": "medium",
                            "service": "ssh",
                            "source_port": source_port,
                            "destination_port": int(service["port"]),
                            "username": fake.username,
                            "action": "opened",
                            "controlled_test": fake.controlled,
                        },
                    )
                if fake.exec_command is not None:
                    emit_ssh_command(fake, fake.exec_command)
                    channel.send(fake_command_response(fake.exec_command, fake.username).encode("utf-8"))
                    channel.send_exit_status(0)
                    return
                channel.send(f"Ubuntu 22.04.4 LTS\r\n{fake.username}@web-node-02:~$ ".encode("utf-8"))
                buffer = b""
                while transport.is_active():
                    remaining = session_deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    channel.settimeout(min(SSH_IDLE_TIMEOUT_SECONDS, remaining))
                    try:
                        chunk = channel.recv(1024)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    buffer += chunk
                    while True:
                        delimiters = [position for position in (buffer.find(b"\n"), buffer.find(b"\r")) if position >= 0]
                        if not delimiters:
                            break
                        delimiter = min(delimiters)
                        command_bytes = buffer[:delimiter]
                        delimiter_size = 2 if buffer[delimiter : delimiter + 2] in (b"\r\n", b"\n\r") else 1
                        buffer = buffer[delimiter + delimiter_size :]
                        if len(command_bytes) > MAX_COMMAND:
                            return
                        command = command_bytes.decode("utf-8", errors="replace")[:MAX_COMMAND].strip()
                        if command in ("exit", "logout"):
                            emit_ssh_command(fake, command)
                            channel.send(b"logout\r\n")
                            return
                        emit_ssh_command(fake, command)
                        response = fake_command_response(command, fake.username)
                        channel.send((response + f"{fake.username}@web-node-02:~$ ").encode("utf-8"))
                    if len(buffer) > MAX_COMMAND:
                        return
            except (OSError, paramiko.SSHException, EOFError):
                pass
            finally:
                if channel is not None:
                    try:
                        channel.close()
                    except Exception:
                        pass
                try:
                    transport.close()
                except Exception:
                    pass

    return MediumSSHHandler


def load_or_create_host_key(path: Path) -> paramiko.RSAKey:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return paramiko.RSAKey.from_private_key_file(str(path))
    key = paramiko.RSAKey.generate(3072)
    key.write_private_key_file(str(path))
    path.chmod(0o600)
    return key


def make_service_factory(host_key: paramiko.PKey):
    def service_factory(instance: dict, service: dict, writer: EventWriter) -> ServiceHandle:
        name = str(service.get("name", "")).lower()
        port = int(service["port"])
        if name == "http":
            handler = build_http_handler(instance, service, writer)
        elif name == "ssh":
            handler = build_ssh_handler(instance, service, writer, host_key)
        else:
            raise ValueError(f"unsupported medium service: {name}")
        server = ThreadedTCPServer(("0.0.0.0", port), handler)
        return start_server(server, f"medium-{name}-{instance['instance_id']}-{port}")

    return service_factory


if __name__ == "__main__":
    key = load_or_create_host_key(Path("/var/lib/honeyforge-medium/ssh_host.key"))
    RuntimeSupervisor(
        "medium",
        "/run/honeyforge-config/config.json",
        "/var/lib/honeyforge-events",
        make_service_factory(key),
    ).run()
