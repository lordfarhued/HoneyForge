from __future__ import annotations

import json
import logging
import os
import secrets
import socket
import socketserver
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

logger = logging.getLogger("honeyforge-engine")

LOGGING_DEFAULTS = {
    "capture_connections": True,
    "capture_credentials": True,
    "capture_commands": True,
    "capture_payloads": False,
}


def logging_enabled(instance: dict, setting: str) -> bool:
    default = LOGGING_DEFAULTS[setting]
    logging_config = instance.get("logging")
    if not isinstance(logging_config, dict):
        return default
    value = logging_config.get(setting, default)
    return value if isinstance(value, bool) else default


def evaluate_bait_credentials(instance: dict, username: str, password: str) -> tuple[bool, bool]:
    """Return (accepted, configured) without authenticating against the real OS."""
    configured: list[tuple[str, str]] = []
    raw_credentials = instance.get("bait_credentials")
    if isinstance(raw_credentials, list):
        for item in raw_credentials:
            if not isinstance(item, dict):
                continue
            bait_username = item.get("username")
            bait_password = item.get("password")
            if isinstance(bait_username, str) and isinstance(bait_password, str):
                configured.append((bait_username, bait_password))
    if not configured:
        return True, False
    accepted = any(
        secrets.compare_digest(username, bait_username)
        and secrets.compare_digest(password, bait_password)
        for bait_username, bait_password in configured
    )
    return accepted, True


def apply_response_delay(instance: dict) -> None:
    masking = instance.get("masking")
    raw_delay = masking.get("response_delay_ms", 0) if isinstance(masking, dict) else 0
    if isinstance(raw_delay, bool) or not isinstance(raw_delay, (int, float)):
        return
    delay_ms = min(max(float(raw_delay), 0.0), 2000.0)
    if delay_ms:
        time.sleep(delay_ms / 1000.0)


def proxy_peer(connection: socket.socket, source_ip: str, source_port: int) -> tuple[str, int]:
    if os.environ.get("HF_PROXY_PROTOCOL") != "1":
        return source_ip, source_port
    header = bytearray()
    while not header.endswith(b"\r\n"):
        if len(header) >= 216:
            raise ValueError("invalid PROXY protocol header")
        chunk = connection.recv(1)
        if not chunk:
            raise ValueError("missing PROXY protocol header")
        header.extend(chunk)
    parts = bytes(header).decode("ascii", errors="strict").strip().split()
    if len(parts) != 6 or parts[0] != "PROXY" or parts[1] not in ("TCP4", "TCP6"):
        raise ValueError("invalid PROXY protocol header")
    return parts[2], int(parts[4])


def proxy_datagram(
    datagram: bytes,
    source_ip: str,
    source_port: int,
    destination_ip: str,
    destination_port: int,
) -> tuple[bytes, str, int, str, int]:
    if os.environ.get("HF_PROXY_PROTOCOL") != "1":
        return datagram, source_ip, source_port, destination_ip, destination_port
    header_end = datagram.find(b"\r\n")
    if header_end < 0 or header_end > 216:
        raise ValueError("invalid UDP proxy header")
    parts = datagram[:header_end].decode("ascii", errors="strict").split()
    if len(parts) != 6 or parts[0] != "PROXY" or parts[1] not in ("UDP4", "UDP6"):
        raise ValueError("invalid UDP proxy header")
    proxied_source_port = int(parts[4])
    proxied_destination_port = int(parts[5])
    if not 1 <= proxied_source_port <= 65535 or not 1 <= proxied_destination_port <= 65535:
        raise ValueError("invalid UDP proxy port")
    return (
        datagram[header_end + 2 :],
        parts[2],
        proxied_source_port,
        parts[3],
        proxied_destination_port,
    )


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


class EventWriter:
    def __init__(self, directory: str):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.max_files = int(os.environ.get("HF_EVENT_SPOOL_MAX_FILES", "20000"))
        self.max_bytes = int(os.environ.get("HF_EVENT_SPOOL_MAX_BYTES", "268435456"))
        if not 1 <= self.max_files <= 1_000_000:
            raise ValueError("event spool file limit is invalid")
        if not 1_048_576 <= self.max_bytes <= 10_737_418_240:
            raise ValueError("event spool byte limit is invalid")
        self._lock = threading.Lock()
        self._usage_checked_at = 0.0
        self._file_count = 0
        self._byte_count = 0
        self._last_capacity_warning = 0.0

    def _refresh_usage(self, now: float) -> None:
        if now - self._usage_checked_at < 1.0:
            return
        count = 0
        size = 0
        with os.scandir(self.directory) as entries:
            for entry in entries:
                if not entry.name.endswith(".event.json") or not entry.is_file(follow_symlinks=False):
                    continue
                count += 1
                size += entry.stat(follow_symlinks=False).st_size
        self._file_count = count
        self._byte_count = size
        self._usage_checked_at = now

    def _has_capacity(self, payload_size: int, now: float) -> bool:
        self._refresh_usage(now)
        return self._file_count < self.max_files and self._byte_count + payload_size <= self.max_bytes

    def emit(self, instance_id: str, event_type: str, source_ip: str | None, data: dict) -> str:
        event_id = str(uuid.uuid4())
        event = {
            "external_id": event_id,
            "instance_id": instance_id,
            "event_type": event_type,
            "source_ip": source_ip,
            "occurred_at": utc_iso(),
            "data": data,
            "is_test": False,
        }
        payload_size = len(json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        with self._lock:
            now = time.monotonic()
            if not self._has_capacity(payload_size, now):
                if now - self._last_capacity_warning >= 60:
                    logger.warning("Event spool capacity reached; newest telemetry is not persisted")
                    self._last_capacity_warning = now
                return ""
            try:
                atomic_json(self.directory / f"{event_id}.event.json", event)
            except OSError:
                # Telemetry failures must not alter the network protocol result;
                # in particular, an auth callback must still answer the client.
                self._usage_checked_at = 0.0
                logger.exception("Event spool write failed; telemetry was not persisted")
                return ""
            self._file_count += 1
            self._byte_count += payload_size
        return event_id


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True
    max_packet_size = 65_535


@dataclass
class ServiceHandle:
    server: socketserver.BaseServer
    thread: threading.Thread

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def start_server(server: socketserver.BaseServer, name: str) -> ServiceHandle:
    thread = threading.Thread(target=server.serve_forever, name=name, daemon=True)
    thread.start()
    return ServiceHandle(server=server, thread=thread)


ServiceFactory = Callable[[dict, dict, EventWriter], ServiceHandle]


class RuntimeSupervisor:
    def __init__(
        self,
        level: str,
        config_path: str,
        event_directory: str,
        service_factory: ServiceFactory,
        poll_seconds: float = 0.5,
        supported_protocols: set[str] | None = None,
    ):
        self.level = level
        self.config_path = Path(config_path)
        self.event_directory = Path(event_directory)
        self.status_path = self.event_directory / "status.json"
        self.alive_path = Path("/tmp/honeyforge-engine-alive")
        self.service_factory = service_factory
        self.poll_seconds = poll_seconds
        self.supported_protocols = supported_protocols or ({"tcp", "udp"} if level == "low" else {"tcp"})
        self.writer = EventWriter(event_directory)
        self.handles: list[ServiceHandle] = []
        self.last_config_bytes: bytes | None = None

    def stop_services(self) -> None:
        for handle in reversed(self.handles):
            try:
                handle.stop()
            except Exception:
                logger.exception("Service shutdown failed")
        self.handles.clear()

    def load_config(self) -> tuple[bytes, dict]:
        if not self.config_path.exists():
            return b"", {"schema_version": 1, "interaction_level": self.level, "instances": []}
        raw = self.config_path.read_bytes()
        if len(raw) > 262_144:
            raise ValueError("engine configuration exceeds 256 KiB")
        payload = json.loads(raw)
        if payload.get("schema_version") != 1 or payload.get("interaction_level") != self.level:
            raise ValueError("engine configuration schema or interaction level is invalid")
        if not isinstance(payload.get("instances"), list) or len(payload["instances"]) > 64:
            raise ValueError("engine instance list is invalid")
        return raw, payload

    def apply(self, raw: bytes, payload: dict) -> None:
        self.stop_services()
        statuses: dict[str, dict] = {}
        for instance in payload["instances"]:
            instance_id = str(instance.get("instance_id", ""))
            version = int(instance.get("config_version", 0))
            if not instance_id:
                continue
            if not instance.get("enabled", False):
                statuses[instance_id] = {
                    "state": "offline",
                    "config_version": version,
                    "ports": [],
                    "error": None,
                }
                continue
            created: list[ServiceHandle] = []
            try:
                services = instance.get("services")
                if not isinstance(services, list) or not services:
                    raise ValueError("no services configured")
                for service in services:
                    if service.get("protocol") not in self.supported_protocols:
                        raise ValueError(f"unsupported {self.level} service protocol")
                    created.append(self.service_factory(instance, service, self.writer))
                self.handles.extend(created)
                statuses[instance_id] = {
                    "state": "online",
                    "config_version": version,
                    "ports": [int(service["port"]) for service in services],
                    "endpoints": [
                        {"protocol": str(service["protocol"]), "port": int(service["port"])}
                        for service in services
                    ],
                    "error": None,
                }
            except Exception as exc:
                for handle in reversed(created):
                    handle.stop()
                statuses[instance_id] = {
                    "state": "error",
                    "config_version": version,
                    "ports": [],
                    "error": str(exc)[:240],
                }
        atomic_json(
            self.status_path,
            {"engine": self.level, "updated_at": utc_iso(), "instances": statuses},
        )
        self.last_config_bytes = raw
        logger.info("Applied %s engine configuration for %d instance(s)", self.level, len(statuses))

    def run(self) -> None:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
        try:
            while True:
                self.alive_path.touch()
                try:
                    raw, payload = self.load_config()
                    if raw != self.last_config_bytes:
                        self.apply(raw, payload)
                except Exception as exc:
                    atomic_json(
                        self.status_path,
                        {"engine": self.level, "updated_at": utc_iso(), "instances": {}, "error": str(exc)[:240]},
                    )
                    self.last_config_bytes = None
                    logger.warning("Engine configuration rejected: %s", type(exc).__name__)
                time.sleep(self.poll_seconds)
        finally:
            self.stop_services()
