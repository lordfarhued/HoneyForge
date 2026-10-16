from __future__ import annotations

import html
import json
import posixpath
import re
import secrets
import shlex
import socket
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from http import cookies
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, urlsplit

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
from honeypots.medium import load_or_create_host_key, redact_sensitive_query_values, safe_banner

MAX_HTTP_REQUEST = 16_384
MAX_HTTP_BODY = 8_192
MAX_COMMAND = 1_024
MAX_COMMANDS_PER_SESSION = 64
MAX_OUTPUT = 32_768
SSH_IDLE_TIMEOUT_SECONDS = 30
SSH_SESSION_TIMEOUT_SECONDS = 180
HTTP_SESSION_TIMEOUT_SECONDS = 900
MAX_HTTP_SESSIONS = 256
HONEYTOKEN_REDACTION = "[honeytoken omitted]"
_HONEYTOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9_-])hft_[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")
_INLINE_SECRET_PATTERN = re.compile(
    r"(?i)\b(password|passwd|passphrase|secret|token|authorization|cookie|api[_-]?key)"
    r"(\s*(?:=|:)\s*|\s+)([^\s&]+)"
)
_SHELL_META_PATTERN = re.compile(r"[;&|`$<>]|\n|\r")


@dataclass(frozen=True)
class VirtualEntry:
    kind: str
    owner: str = "root"
    mode: str = "0644"
    content: str = ""
    modified: str = "2026-09-18 10:42:00 +0000"


class VirtualFileSystem:
    """Immutable, in-memory POSIX-like tree with no host filesystem access."""

    def __init__(self, portal_password: str, honeytoken: str):
        files = {
            "/etc/hostname": "portal-app-01\n",
            "/etc/os-release": (
                'PRETTY_NAME="Ubuntu 24.04.3 LTS"\nNAME="Ubuntu"\n'
                'VERSION_ID="24.04"\nVERSION_CODENAME=noble\n'
            ),
            "/etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "deploy:x:1001:1001:Deployment User:/home/deploy:/bin/bash\n"
                "analyst:x:1002:1002:SOC Analyst:/home/analyst:/bin/bash\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            ),
            "/etc/nginx/sites-enabled/portal.conf": (
                "server {\n  listen 8080;\n  server_name portal.intra.example;\n"
                "  location / { proxy_pass http://127.0.0.1:9000; }\n}\n"
            ),
            "/etc/ssh/sshd_config": "PasswordAuthentication yes\nPermitRootLogin no\nMaxAuthTries 4\n",
            "/home/deploy/.bash_history": (
                "cd /opt/company-portal\nls -la config\n"
                "systemctl status company-portal\ntail -n 30 /var/log/company-portal/access.log\n"
            ),
            "/home/deploy/README.txt": (
                "Portal operations are documented in /opt/company-portal/config.\n"
                "Backups are verified every Friday by the infrastructure team.\n"
            ),
            "/home/analyst/notes.txt": "Review failed sign-ins and backup access after maintenance.\n",
            "/opt/company-portal/config/application.env": (
                "APP_ENV=production\nPORTAL_URL=http://portal.intra.example:8080\n"
                f"PORTAL_USER=deploy\nPORTAL_PASSWORD={portal_password}\n"
                "BACKUP_DIR=/opt/company-portal/backups\n"
            ),
            "/opt/company-portal/config/services.yml": (
                "services:\n  - name: portal-web\n    node: portal-app-01\n    port: 8080\n"
                "  - name: document-index\n    node: portal-app-02\n    port: 9200\n"
            ),
            "/opt/company-portal/backups/README": (
                "Encrypted application archives. Access is restricted to deployment automation.\n"
            ),
            "/opt/company-portal/backups/service-access.txt": (
                "Temporary validation credential for the internal status endpoint:\n"
                f"token={honeytoken}\n"
            ),
            "/opt/company-portal/logs/deploy.log": (
                "2026-09-18T10:40:12Z release 2026.09.18 deployed by deploy\n"
                "2026-09-18T10:40:17Z health checks passed on 3 nodes\n"
            ),
            "/var/log/company-portal/access.log": (
                '10.40.8.21 - - [18/Sep/2026:10:41:03 +0000] "GET /services HTTP/1.1" 200 3812\n'
                '10.40.8.34 - - [18/Sep/2026:10:41:11 +0000] "GET /backups HTTP/1.1" 403 241\n'
            ),
            "/var/log/auth.log": (
                "Sep 18 10:39:58 portal-app-01 sshd[712]: Accepted password for deploy from 10.40.8.12 port 51844 ssh2\n"
            ),
            "/var/www/html/index.html": "<h1>Northbridge Operations Portal</h1>\n",
            "/tmp/.keep": "",
        }
        directories = {
            "/",
            "/etc",
            "/etc/nginx",
            "/etc/nginx/sites-enabled",
            "/etc/ssh",
            "/home",
            "/home/deploy",
            "/home/analyst",
            "/opt",
            "/opt/company-portal",
            "/opt/company-portal/config",
            "/opt/company-portal/backups",
            "/opt/company-portal/logs",
            "/var",
            "/var/log",
            "/var/log/company-portal",
            "/var/www",
            "/var/www/html",
            "/tmp",
        }
        self._entries = {path: VirtualEntry("dir", mode="0755") for path in directories}
        self._entries.update({path: VirtualEntry("file", content=content) for path, content in files.items()})

    @staticmethod
    def normalize(path: str, cwd: str) -> str:
        candidate = path if path.startswith("/") else posixpath.join(cwd, path)
        normalized = posixpath.normpath(candidate)
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        return normalized

    def entry(self, path: str, cwd: str) -> VirtualEntry | None:
        return self._entries.get(self.normalize(path, cwd))

    def list_dir(self, path: str, cwd: str) -> list[str]:
        normalized = self.normalize(path, cwd)
        entry = self._entries.get(normalized)
        if entry is None or entry.kind != "dir":
            raise ValueError("not_directory")
        prefix = "/" if normalized == "/" else f"{normalized}/"
        children = {
            candidate[len(prefix) :].split("/", 1)[0]
            for candidate in self._entries
            if candidate.startswith(prefix) and candidate != normalized
        }
        return sorted(child for child in children if child)

    def descendants(self, path: str, cwd: str, *, limit: int = 80) -> list[str]:
        normalized = self.normalize(path, cwd)
        if normalized not in self._entries:
            raise ValueError("missing")
        prefix = "/" if normalized == "/" else f"{normalized}/"
        matches = [candidate for candidate in sorted(self._entries) if candidate == normalized or candidate.startswith(prefix)]
        return matches[:limit]

    def read(self, path: str, cwd: str) -> tuple[str, str]:
        normalized = self.normalize(path, cwd)
        entry = self._entries.get(normalized)
        if entry is None:
            raise ValueError("missing")
        if entry.kind != "file":
            raise ValueError("directory")
        return normalized, entry.content


class HighEnvironment:
    def __init__(self, instance: dict):
        credentials = instance.get("bait_credentials") or []
        first = credentials[0] if credentials and isinstance(credentials[0], dict) else {}
        self.portal_username = str(first.get("username") or "deploy")[:80]
        self.portal_password = str(first.get("password") or "Northbridge-Archive-2026!")[:128]
        self.honeytoken = "hft_" + secrets.token_urlsafe(32)
        self.filesystem = VirtualFileSystem(self.portal_password, self.honeytoken)
        self._sessions: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._lock = threading.Lock()

    def create_web_session(self, source_ip: str) -> str:
        now = time.monotonic()
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._expire_sessions(now)
            while len(self._sessions) >= MAX_HTTP_SESSIONS:
                self._sessions.popitem(last=False)
            self._sessions[token] = (source_ip, now + HTTP_SESSION_TIMEOUT_SECONDS)
        return token

    def valid_web_session(self, token: str | None, source_ip: str) -> bool:
        if not token:
            return False
        now = time.monotonic()
        with self._lock:
            self._expire_sessions(now)
            stored = self._sessions.get(token)
            if stored is None or stored[0] != source_ip:
                return False
            self._sessions.move_to_end(token)
            self._sessions[token] = (stored[0], now + HTTP_SESSION_TIMEOUT_SECONDS)
            return True

    def _expire_sessions(self, now: float) -> None:
        for token, (_, expires_at) in list(self._sessions.items()):
            if expires_at <= now:
                self._sessions.pop(token, None)


class HighShell:
    def __init__(self, environment: HighEnvironment, username: str):
        self.environment = environment
        self.username = username or "deploy"
        self.cwd = f"/home/{self.username}" if environment.filesystem.entry(f"/home/{self.username}", "/") else "/home/deploy"
        self.history: list[str] = []

    def run(self, command: str) -> tuple[str, list[str]]:
        command = command.strip()
        if not command:
            return "", []
        self.history.append(command[:MAX_COMMAND])
        if _SHELL_META_PATTERN.search(command):
            return "bash: syntax error near unexpected token\n", []
        try:
            args = shlex.split(command, posix=True)
        except ValueError:
            return "bash: unmatched quote\n", []
        if not args:
            return "", []
        name = args[0]
        handlers = {
            "pwd": self._pwd,
            "ls": self._ls,
            "cd": self._cd,
            "find": self._find,
            "tree": self._tree,
            "cat": self._cat,
            "head": self._head,
            "tail": self._tail,
            "grep": self._grep,
            "stat": self._stat,
            "whoami": self._whoami,
            "id": self._id,
            "hostname": self._hostname,
            "uname": self._uname,
            "uptime": self._uptime,
            "date": self._date,
            "ps": self._ps,
            "ss": self._ss,
            "netstat": self._ss,
            "ip": self._ip,
            "sudo": self._sudo,
            "curl": self._curl,
            "wget": self._wget,
            "systemctl": self._systemctl,
            "history": self._history,
        }
        handler = handlers.get(name)
        if handler is None:
            return f"bash: {name[:80]}: command not found\n", []
        output, sensitive_paths = handler(args[1:])
        return output[:MAX_OUTPUT], sensitive_paths

    def _pwd(self, args):
        return f"{self.cwd}\n", []

    def _ls(self, args):
        long = any(arg.startswith("-") and "l" in arg for arg in args)
        paths = [arg for arg in args if not arg.startswith("-")]
        path = paths[-1] if paths else "."
        normalized = self.environment.filesystem.normalize(path, self.cwd)
        entry = self.environment.filesystem.entry(path, self.cwd)
        if entry is None:
            return f"ls: cannot access '{path}': No such file or directory\n", []
        if entry.kind == "file":
            names = [PurePosixPath(normalized).name]
        else:
            names = self.environment.filesystem.list_dir(path, self.cwd)
        if not long:
            return "  ".join(names) + "\n", []
        lines = ["total 16"]
        for child in names:
            child_path = posixpath.join(normalized, child) if entry.kind == "dir" else normalized
            child_entry = self.environment.filesystem.entry(child_path, "/")
            prefix = "d" if child_entry and child_entry.kind == "dir" else "-"
            mode = "rwxr-xr-x" if prefix == "d" else "rw-r--r--"
            size = len(child_entry.content.encode("utf-8")) if child_entry else 0
            lines.append(f"{prefix}{mode} 1 {child_entry.owner if child_entry else 'root'} {child_entry.owner if child_entry else 'root'} {size:5d} Sep 18 10:42 {child}")
        return "\n".join(lines) + "\n", []

    def _cd(self, args):
        target = args[0] if args else f"/home/{self.username}"
        entry = self.environment.filesystem.entry(target, self.cwd)
        if entry is None:
            return f"bash: cd: {target}: No such file or directory\n", []
        if entry.kind != "dir":
            return f"bash: cd: {target}: Not a directory\n", []
        self.cwd = self.environment.filesystem.normalize(target, self.cwd)
        return "", []

    def _find(self, args):
        target = next((arg for arg in args if not arg.startswith("-")), ".")
        try:
            paths = self.environment.filesystem.descendants(target, self.cwd)
        except ValueError:
            return f"find: '{target}': No such file or directory\n", []
        base = self.environment.filesystem.normalize(target, self.cwd)
        rendered = ["." + path[len(base) :] if target == "." else path for path in paths]
        return "\n".join(rendered) + "\n", []

    def _tree(self, args):
        target = next((arg for arg in args if not arg.startswith("-")), ".")
        try:
            paths = self.environment.filesystem.descendants(target, self.cwd)
        except ValueError:
            return f"{target} [error opening dir]\n", []
        base = self.environment.filesystem.normalize(target, self.cwd)
        lines = [target]
        for path in paths[1:]:
            relative = path[len(base) :].strip("/")
            depth = relative.count("/")
            lines.append(f"{'    ' * depth}├── {PurePosixPath(path).name}")
        return "\n".join(lines) + f"\n\n{max(0, len(paths) - 1)} entries\n", []

    def _read_file(self, args, command: str):
        paths = [arg for arg in args if not arg.startswith("-")]
        if not paths:
            return f"{command}: missing file operand\n", []
        path = paths[-1]
        try:
            normalized, content = self.environment.filesystem.read(path, self.cwd)
        except ValueError as exc:
            reason = "Is a directory" if str(exc) == "directory" else "No such file or directory"
            return f"{command}: {path}: {reason}\n", []
        sensitive = [normalized] if normalized.startswith("/opt/company-portal/config/") or normalized.endswith("service-access.txt") else []
        return content, sensitive

    def _cat(self, args):
        return self._read_file(args, "cat")

    def _head(self, args):
        content, sensitive = self._read_file(args, "head")
        return "\n".join(content.splitlines()[:10]) + ("\n" if content else ""), sensitive

    def _tail(self, args):
        content, sensitive = self._read_file(args, "tail")
        return "\n".join(content.splitlines()[-10:]) + ("\n" if content else ""), sensitive

    def _grep(self, args):
        values = [arg for arg in args if not arg.startswith("-")]
        if len(values) < 2:
            return "grep: missing pattern or file\n", []
        pattern, path = values[0], values[-1]
        content, sensitive = self._read_file([path], "grep")
        if content.startswith("grep:"):
            return content, sensitive
        return "\n".join(line for line in content.splitlines() if pattern in line) + "\n", sensitive

    def _stat(self, args):
        if not args:
            return "stat: missing operand\n", []
        normalized = self.environment.filesystem.normalize(args[-1], self.cwd)
        entry = self.environment.filesystem.entry(normalized, "/")
        if entry is None:
            return f"stat: cannot statx '{args[-1]}': No such file or directory\n", []
        size = len(entry.content.encode("utf-8")) if entry.kind == "file" else 4096
        kind = "directory" if entry.kind == "dir" else "regular file"
        return (
            f"  File: {normalized}\n  Size: {size}\tBlocks: 8\tIO Block: 4096 {kind}\n"
            f"Access: ({entry.mode})  Uid: ( 1001/ {entry.owner})   Gid: ( 1001/ {entry.owner})\n"
            f"Modify: {entry.modified}\n"
        ), []

    def _whoami(self, args):
        return f"{self.username}\n", []

    def _id(self, args):
        return f"uid=1001({self.username}) gid=1001({self.username}) groups=1001({self.username}),27(sudo)\n", []

    def _hostname(self, args):
        return "portal-app-01\n", []

    def _uname(self, args):
        return ("Linux portal-app-01 6.8.0-71-generic #71-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\n" if "-a" in args else "Linux\n"), []

    def _uptime(self, args):
        return " 10:44:18 up 37 days,  3:12,  1 user,  load average: 0.08, 0.04, 0.01\n", []

    def _date(self, args):
        return datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y\n"), []

    def _ps(self, args):
        return (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1  22540 12040 ?        Ss   Sep18   0:18 /sbin/init\n"
            "www-data   642  0.1  1.8 248120 73920 ?        Ssl  Sep18   8:42 gunicorn portal:app\n"
            "root       701  0.0  0.1  15420  7936 ?        Ss   Sep18   0:07 sshd: /usr/sbin/sshd -D\n"
        ), []

    def _ss(self, args):
        return (
            "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
            "tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*\n"
            "tcp   LISTEN 0      256          0.0.0.0:8080      0.0.0.0:*\n"
            "tcp   LISTEN 0      128        127.0.0.1:9000      0.0.0.0:*\n"
        ), []

    def _ip(self, args):
        return (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: ens18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
            "    inet 10.40.8.17/24 brd 10.40.8.255 scope global ens18\n"
        ), []

    def _sudo(self, args):
        if args == ["-l"]:
            return f"User {self.username} may run the following commands on portal-app-01:\n    (root) /bin/systemctl status company-portal\n", []
        return "sudo: a password is required\n", []

    def _curl(self, args):
        url = next((arg for arg in args if arg.startswith(("http://", "https://"))), "")
        if "portal.intra.example" in url or "127.0.0.1" in url or "localhost" in url:
            return "<html><title>Northbridge Operations</title><body>302 Found</body></html>\n", []
        return "curl: (6) Could not resolve host\n", []

    def _wget(self, args):
        url = next((arg for arg in args if arg.startswith(("http://", "https://"))), "")
        if "portal.intra.example" in url:
            return "HTTP request sent, awaiting response... 302 Found\nLocation: /login [following]\n", []
        return "wget: unable to resolve host address\n", []

    def _systemctl(self, args):
        if args[:1] == ["status"]:
            unit = args[1] if len(args) > 1 else "company-portal"
            return (
                f"● {unit}.service - Northbridge company portal\n"
                "     Loaded: loaded (/etc/systemd/system/company-portal.service; enabled)\n"
                "     Active: active (running) since Thu 2026-09-18 10:40:11 UTC\n"
            ), []
        return "System has not been booted with a writable service manager.\n", []

    def _history(self, args):
        return "".join(f"{index:5d}  {item}\n" for index, item in enumerate(self.history[-30:], start=1)), []


def _safe_telemetry_text(value: str) -> str:
    value = _HONEYTOKEN_PATTERN.sub(HONEYTOKEN_REDACTION, value)
    return _INLINE_SECRET_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[credentials omitted]", value
    )


def _read_http_request(connection: socket.socket) -> bytes:
    raw = bytearray()
    header_end = -1
    expected = None
    while len(raw) < MAX_HTTP_REQUEST:
        chunk = connection.recv(min(4096, MAX_HTTP_REQUEST - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
        if header_end < 0:
            header_end = raw.find(b"\r\n\r\n")
            if header_end >= 0:
                header = bytes(raw[:header_end]).decode("iso-8859-1", errors="replace")
                match = re.search(r"(?im)^Content-Length:\s*(\d+)\s*$", header)
                content_length = min(int(match.group(1)), MAX_HTTP_BODY) if match else 0
                expected = header_end + 4 + content_length
        if expected is not None and len(raw) >= expected:
            break
    return bytes(raw)


def _parse_http_request(raw: bytes):
    header_bytes, _, body = raw.partition(b"\r\n\r\n")
    lines = header_bytes.decode("iso-8859-1", errors="replace").split("\r\n")
    request_parts = lines[0].split(" ", 2) if lines else []
    method, path, version = (request_parts + ["", "", ""])[:3]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()[:80]] = value.strip()[:500]
    return method[:16].upper(), path[:2048], version[:20], headers, body[:MAX_HTTP_BODY]


def _cookie_value(header: str, name: str) -> str | None:
    parsed = cookies.SimpleCookie()
    try:
        parsed.load(header)
    except cookies.CookieError:
        return None
    morsel = parsed.get(name)
    return morsel.value if morsel else None


def _page(title: str, content: str, *, active: str = "") -> bytes:
    links = [
        ("/", "Обзор"), ("/services", "Сервисы"), ("/users", "Пользователи"),
        ("/servers", "Серверы"), ("/audit", "Журнал"), ("/config", "Конфигурации"),
        ("/backups", "Резервные копии"), ("/documents", "Документы"),
    ]
    navigation = "".join(
        f'<a class="{"active" if href == active else ""}" href="{href}">{label}</a>' for href, label in links
    )
    document = f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{html.escape(title)} — Northbridge Operations</title><style>
body{{margin:0;font:14px Arial,sans-serif;background:#f3f5f8;color:#172033}}header{{background:#17233c;color:#fff;padding:18px 28px}}header b{{font-size:20px}}nav{{background:#fff;padding:10px 24px;border-bottom:1px solid #dce2ea;display:flex;gap:7px;flex-wrap:wrap}}nav a{{color:#34435f;text-decoration:none;padding:8px 11px;border-radius:5px}}nav a.active{{background:#e8eef8;color:#183a72}}main{{max-width:1120px;margin:24px auto;padding:0 20px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}}.card,table{{background:#fff;border:1px solid #dce2ea;border-radius:8px;padding:17px;box-shadow:0 2px 7px #1b2b4710}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;text-align:left;border-bottom:1px solid #e7ebf1}}.ok{{color:#147449}}.warn{{color:#9a5a08}}code{{background:#edf1f6;padding:2px 5px;border-radius:4px}}footer{{color:#6e788b;margin-top:28px}}</style></head>
<body><header><b>Northbridge Operations</b><div>Внутренняя инфраструктура</div></header><nav>{navigation}</nav><main><h1>{html.escape(title)}</h1>{content}<footer>IT Operations · Internal use only</footer></main></body></html>"""
    return document.encode("utf-8")


def _login_page(error: bool = False) -> bytes:
    message = '<p class="warn">Неверное имя пользователя или пароль.</p>' if error else ""
    return _page(
        "Вход",
        f"{message}<div class='card' style='max-width:420px'><form method='post' action='/login'>"
        "<label>Пользователь<br><input name='username' maxlength='80'></label><br><br>"
        "<label>Пароль<br><input name='password' type='password' maxlength='128'></label><br><br>"
        "<button type='submit'>Войти</button></form></div>",
    )


def _portal_content(path: str) -> tuple[str, bytes] | None:
    pages = {
        "/": ("Обзор", "<div class='grid'><div class='card'><b>Сервисы</b><h2>6 / 6</h2><span class='ok'>Работают штатно</span></div><div class='card'><b>Серверы</b><h2>3</h2><span class='ok'>Доступны</span></div><div class='card'><b>Архивы</b><h2>18</h2><span>Последний: сегодня 02:15</span></div></div>"),
        "/services": ("Сервисы", "<table><tr><th>Сервис</th><th>Узел</th><th>Состояние</th></tr><tr><td>company-portal</td><td>portal-app-01</td><td class='ok'>Работает</td></tr><tr><td>document-index</td><td>portal-app-02</td><td class='ok'>Работает</td></tr><tr><td>backup-worker</td><td>storage-01</td><td class='warn'>Ожидает</td></tr></table>"),
        "/users": ("Пользователи и роли", "<table><tr><th>Учётная запись</th><th>Роль</th><th>Последняя активность</th></tr><tr><td>deploy</td><td>Deployment Operator</td><td>сегодня, 10:40</td></tr><tr><td>analyst</td><td>Security Analyst</td><td>вчера, 18:12</td></tr><tr><td>backup-svc</td><td>Service Account</td><td>сегодня, 02:15</td></tr></table>"),
        "/servers": ("Серверы", "<div class='grid'><div class='card'><b>portal-app-01</b><p>10.40.8.17 · Ubuntu 24.04</p><span class='ok'>Online</span></div><div class='card'><b>portal-app-02</b><p>10.40.8.18 · Ubuntu 24.04</p><span class='ok'>Online</span></div><div class='card'><b>storage-01</b><p>10.40.8.31 · Debian 12</p><span class='ok'>Online</span></div></div>"),
        "/audit": ("Журнал действий", "<table><tr><th>Время</th><th>Пользователь</th><th>Действие</th></tr><tr><td>10:40</td><td>deploy</td><td>Применена конфигурация portal-web</td></tr><tr><td>09:18</td><td>analyst</td><td>Просмотрены ошибки авторизации</td></tr><tr><td>02:15</td><td>backup-svc</td><td>Создан архив portal-20260918.enc</td></tr></table>"),
        "/config": ("Конфигурации", "<div class='card'><p><b>Приложение:</b> company-portal</p><p><b>Окружение:</b> production</p><p><b>Конфигурация:</b> <code>/opt/company-portal/config/application.env</code></p><p><b>Версия:</b> 2026.09.18</p></div>"),
        "/backups": ("Резервные копии", "<table><tr><th>Архив</th><th>Размер</th><th>Статус</th></tr><tr><td>portal-20260918.enc</td><td>684 MB</td><td class='ok'>Проверен</td></tr><tr><td>portal-20260917.enc</td><td>681 MB</td><td class='ok'>Проверен</td></tr></table>"),
        "/documents": ("Документы", "<div class='grid'><div class='card'><b>Регламент восстановления</b><p>Обновлён 12 сентября</p></div><div class='card'><b>Матрица доступа</b><p>Обновлена 8 сентября</p></div><div class='card'><b>План обслуживания</b><p>Обновлён 15 сентября</p></div></div>"),
    }
    item = pages.get(path)
    return (item[0], _page(item[0], item[1], active=path)) if item else None


def build_http_handler(instance: dict, service: dict, writer: EventWriter, environment: HighEnvironment):
    class HighHTTPHandler:
        def __init__(self, request: socket.socket, client_address, server):
            self.request = request
            self.client_address = client_address
            self.handle()

        def _send(self, status: str, body: bytes, headers: list[tuple[str, str]] | None = None) -> None:
            headers = headers or []
            has_content_type = any(key.lower() == "content-type" for key, _ in headers)
            response_headers = [
                ("Server", safe_banner(str(service.get("banner", "")), "nginx")),
                ("Content-Length", str(len(body))),
                ("Connection", "close"),
                ("X-Frame-Options", "SAMEORIGIN"),
            ]
            if not has_content_type:
                response_headers.insert(1, ("Content-Type", "text/html; charset=utf-8"))
            response_headers.extend(headers)
            encoded = f"HTTP/1.1 {status}\r\n".encode("ascii")
            encoded += b"".join(f"{key}: {value}\r\n".encode("utf-8") for key, value in response_headers)
            try:
                self.request.sendall(encoded + b"\r\n" + body)
            except OSError:
                pass

        def handle(self) -> None:
            started = time.monotonic()
            source_ip, source_port = self.client_address[0], self.client_address[1]
            self.request.settimeout(4)
            try:
                source_ip, source_port = proxy_peer(self.request, source_ip, source_port)
                raw = _read_http_request(self.request)
            except (OSError, TimeoutError, ValueError):
                return
            method, raw_path, version, headers, body = _parse_http_request(raw)
            parsed = urlsplit(raw_path)
            path = parsed.path or "/"
            telemetry_path = redact_sensitive_query_values(_safe_telemetry_text(raw_path))
            session_cookie = _cookie_value(headers.get("cookie", ""), "NBSESSION")
            authenticated = environment.valid_web_session(session_cookie, source_ip)
            session_id = session_cookie[:12] if authenticated and session_cookie else None
            status = "200 OK"
            response_headers: list[tuple[str, str]] = []
            auth_event = None
            honeytoken_used = False

            if path == "/login" and method == "GET":
                page = _login_page()
            elif path == "/login" and method == "POST":
                form = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
                username = (form.get("username") or [""])[0][:80]
                password = (form.get("password") or [""])[0][:128]
                accepted = secrets.compare_digest(username, environment.portal_username) and secrets.compare_digest(password, environment.portal_password)
                auth_event = {
                    "engine": "high", "service": "http", "source_port": source_port,
                    "destination_port": int(service["port"]), "username": _safe_telemetry_text(username),
                    "password": "[credentials omitted]", "result": "accepted_decoy" if accepted else "rejected",
                    "path": "/login", "session_id": None,
                }
                if accepted:
                    token = environment.create_web_session(source_ip)
                    session_id = token[:12]
                    status = "303 See Other"
                    response_headers.extend([
                        ("Location", "/"),
                        ("Set-Cookie", f"NBSESSION={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={HTTP_SESSION_TIMEOUT_SECONDS}"),
                    ])
                    page = b""
                else:
                    status = "401 Unauthorized"
                    page = _login_page(error=True)
            elif path == "/api/internal/status":
                query = parse_qs(parsed.query, keep_blank_values=True)
                supplied = (query.get("token") or [headers.get("x-service-token", "")])[0]
                honeytoken_used = bool(supplied) and secrets.compare_digest(supplied, environment.honeytoken)
                if honeytoken_used:
                    page = json.dumps({"status": "ok", "nodes": 3}, separators=(",", ":")).encode("utf-8")
                    response_headers.append(("Content-Type", "application/json; charset=utf-8"))
                else:
                    status = "403 Forbidden"
                    page = json.dumps({"error": "forbidden"}).encode("utf-8")
                    response_headers.append(("Content-Type", "application/json; charset=utf-8"))
            elif not authenticated:
                status = "302 Found"
                response_headers.append(("Location", "/login"))
                page = b""
            else:
                portal = _portal_content(path)
                if portal is None:
                    status = "404 Not Found"
                    page = _page("Страница не найдена", "<div class='card'>Запрошенный раздел не существует.</div>")
                else:
                    _, page = portal

            apply_response_delay(instance)
            self._send(status, page, response_headers)
            event_data = {
                "engine": "high", "service": "http", "protocol": "tcp",
                "source_port": source_port, "destination_port": int(service["port"]),
                "method": method, "path": telemetry_path, "http_version": version,
                "status": int(status.split()[0]), "session_id": session_id,
                "bytes_received": len(raw), "duration_ms": round((time.monotonic() - started) * 1000, 2),
            }
            if honeytoken_used:
                event_data["_high_honeytoken_use"] = True
            if logging_enabled(instance, "capture_connections") or logging_enabled(instance, "capture_commands") or honeytoken_used:
                writer.emit(str(instance["instance_id"]), "high.http_request", source_ip, event_data)
            if auth_event is not None:
                auth_event["session_id"] = session_id
                writer.emit(str(instance["instance_id"]), "high.http_auth", source_ip, auth_event)

    return HighHTTPHandler


class HighSSHServer(paramiko.ServerInterface):
    def __init__(self, instance: dict, service: dict, writer: EventWriter, source_ip: str, source_port: int):
        self.instance = instance
        self.service = service
        self.writer = writer
        self.source_ip = source_ip
        self.source_port = source_port
        self.username = "deploy"
        self.shell_requested = False
        self.exec_command: str | None = None
        self.session_id = secrets.token_hex(8)

    def check_auth_password(self, username: str, password: str):
        self.username = username[:80]
        accepted, configured = evaluate_bait_credentials(self.instance, self.username, password[:128])
        apply_response_delay(self.instance)
        if logging_enabled(self.instance, "capture_credentials"):
            self.writer.emit(
                str(self.instance["instance_id"]), "high.ssh_auth", self.source_ip,
                {
                    "engine": "high", "service": "ssh", "source_port": self.source_port,
                    "destination_port": int(self.service["port"]), "username": _safe_telemetry_text(self.username),
                    "password": "[credentials omitted]",
                    "result": "accepted_decoy" if accepted and configured else "accepted_fake_session" if accepted else "rejected",
                    "session_id": self.session_id,
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
        if len(command) > MAX_COMMAND:
            return False
        self.exec_command = command.decode("utf-8", errors="replace")
        return True


def _emit_ssh_command(server: HighSSHServer, command: str, sensitive_paths: list[str]) -> None:
    if logging_enabled(server.instance, "capture_commands"):
        server.writer.emit(
            str(server.instance["instance_id"]), "high.ssh_command", server.source_ip,
            {
                "engine": "high", "service": "ssh", "source_port": server.source_port,
                "destination_port": int(server.service["port"]), "username": server.username,
                "command": _safe_telemetry_text(command)[:MAX_COMMAND], "execution": "virtual_only",
                "session_id": server.session_id,
            },
        )
    for path in sensitive_paths:
        server.writer.emit(
            str(server.instance["instance_id"]), "high.ssh_sensitive_file", server.source_ip,
            {
                "engine": "high", "service": "ssh", "username": server.username,
                "path": path, "action": "read", "session_id": server.session_id,
            },
        )


def build_ssh_handler(instance: dict, service: dict, writer: EventWriter, host_key: paramiko.PKey, environment: HighEnvironment):
    class HighSSHHandler:
        def __init__(self, request: socket.socket, client_address, server):
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
            configured_banner = safe_banner(
                str(service.get("banner", "")),
                "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
            )
            transport.local_version = (
                configured_banner
                if configured_banner.startswith(("SSH-2.0-", "SSH-1.99-"))
                else "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"
            )
            transport.add_server_key(host_key)
            server = HighSSHServer(instance, service, writer, source_ip, source_port)
            channel = None
            session_opened = False
            opened_at = 0.0
            command_count = 0
            try:
                transport.start_server(server=server)
                channel = transport.accept(10)
                if channel is None:
                    return
                opened_at = time.monotonic()
                session_opened = True
                request_deadline = time.monotonic() + 3
                while not server.shell_requested and server.exec_command is None and time.monotonic() < request_deadline:
                    time.sleep(0.05)
                writer.emit(
                    str(instance["instance_id"]), "high.ssh_session", source_ip,
                    {
                        "engine": "high", "service": "ssh", "source_port": source_port,
                        "destination_port": int(service["port"]), "username": server.username,
                        "action": "opened", "session_id": server.session_id,
                    },
                )
                shell = HighShell(environment, server.username)
                if server.exec_command is not None:
                    output, sensitive_paths = shell.run(server.exec_command)
                    _emit_ssh_command(server, server.exec_command, sensitive_paths)
                    channel.sendall(output.encode("utf-8")[:MAX_OUTPUT])
                    channel.send_exit_status(0 if not output.startswith(("bash:", "cat:", "stat:")) else 1)
                    return
                prompt = lambda: f"{server.username}@portal-app-01:{'~' if shell.cwd.startswith('/home/') else shell.cwd}$ "
                channel.sendall(("Ubuntu 24.04.3 LTS\r\n" + prompt()).encode("utf-8"))
                buffer = bytearray()
                escape_state = 0
                swallow_lf = False
                session_deadline = opened_at + SSH_SESSION_TIMEOUT_SECONDS
                while transport.is_active() and command_count < MAX_COMMANDS_PER_SESSION:
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
                    for value in chunk:
                        if swallow_lf:
                            swallow_lf = False
                            if value == 0x0A:
                                continue
                        if escape_state:
                            if escape_state == 1 and value in (0x5B, 0x4F):
                                escape_state = 2
                            elif escape_state == 1 or 0x40 <= value <= 0x7E:
                                escape_state = 0
                            continue
                        if value == 0x1B:
                            escape_state = 1
                            continue
                        if value in (0x08, 0x7F):
                            if buffer:
                                buffer.pop()
                                while buffer and buffer[-1] & 0xC0 == 0x80:
                                    buffer.pop()
                                if buffer and buffer[-1] >= 0xC0:
                                    buffer.pop()
                                channel.sendall(b"\b \b")
                            continue
                        if value == 0x03:
                            buffer.clear()
                            channel.sendall(("^C\r\n" + prompt()).encode("utf-8"))
                            continue
                        if value == 0x04 and not buffer:
                            channel.sendall(b"logout\r\n")
                            return
                        if value in (0x0A, 0x0D):
                            if value == 0x0D:
                                swallow_lf = True
                            channel.sendall(b"\r\n")
                            command = bytes(buffer).decode("utf-8", errors="replace").strip()
                            buffer.clear()
                            command_count += 1
                            if command_count > MAX_COMMANDS_PER_SESSION:
                                return
                            if command in ("exit", "logout"):
                                _emit_ssh_command(server, command, [])
                                channel.sendall(b"logout\r\n")
                                return
                            output, sensitive_paths = shell.run(command)
                            _emit_ssh_command(server, command, sensitive_paths)
                            rendered = output.replace("\r\n", "\n").replace("\n", "\r\n") + prompt()
                            channel.sendall(rendered.encode("utf-8")[:MAX_OUTPUT])
                            continue
                        if value >= 0x20:
                            buffer.append(value)
                            channel.sendall(bytes((value,)))
                            if len(buffer) > MAX_COMMAND:
                                return
            except (OSError, EOFError, paramiko.SSHException):
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
                if session_opened:
                    writer.emit(
                        str(instance["instance_id"]), "high.ssh_session", source_ip,
                        {
                            "engine": "high", "service": "ssh", "username": server.username,
                            "action": "closed", "session_id": server.session_id,
                            "command_count": command_count,
                            "duration_ms": round((time.monotonic() - opened_at) * 1000, 2),
                        },
                    )

    return HighSSHHandler


def make_service_factory(host_key: paramiko.PKey):
    environments: dict[str, HighEnvironment] = {}

    def service_factory(instance: dict, service: dict, writer: EventWriter) -> ServiceHandle:
        instance_id = str(instance["instance_id"])
        environment = environments.get(instance_id)
        if environment is None:
            environment = HighEnvironment(instance)
            environments[instance_id] = environment
        name = str(service.get("name", "")).lower()
        port = int(service["port"])
        if name == "http":
            handler = build_http_handler(instance, service, writer, environment)
        elif name == "ssh":
            handler = build_ssh_handler(instance, service, writer, host_key, environment)
        else:
            raise ValueError(f"unsupported high service: {name}")
        server = ThreadedTCPServer(("0.0.0.0", port), handler)
        return start_server(server, f"high-{name}-{instance_id}-{port}")

    return service_factory


if __name__ == "__main__":
    key = load_or_create_host_key(Path("/var/lib/honeyforge-high/ssh_host.key"))
    RuntimeSupervisor(
        "high",
        "/run/honeyforge-config/config.json",
        "/var/lib/honeyforge-events",
        make_service_factory(key),
    ).run()
