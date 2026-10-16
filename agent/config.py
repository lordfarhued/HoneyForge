from dataclasses import dataclass
import os
from pathlib import Path
from urllib.parse import urlparse


def _runtime_value(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class IdentityPaths:
    key: Path
    certificate: Path
    metadata: Path
    csr: Path


@dataclass(frozen=True)
class AgentSettings:
    base_url: str = _runtime_value("RUNTIME_CONTROL_ORIGIN", "https://agent-gateway:8443")
    server_name: str = _runtime_value("RUNTIME_TLS_SERVER_NAME", "agent-gateway")
    ca_cert: str = _runtime_value("RUNTIME_CA_FILE", "/run/runtime-trust/ca.crt")
    server_pin_file: str = _runtime_value("RUNTIME_PIN_FILE", "/run/runtime-trust/server.pin")
    transport_prefix: str = _runtime_value("RUNTIME_TRANSPORT_PREFIX", "/assets/runtime")
    enrollment_token_file: str = _runtime_value("RUNTIME_BOOTSTRAP_FILE", "/run/runtime-bootstrap/enrollment.token")
    state_dir: str = _runtime_value("RUNTIME_STATE_DIR", "/var/lib/system-metrics")
    low_config_file: str = _runtime_value("RUNTIME_LOW_CONFIG_FILE", "/run/runtime-control/low/config.json")
    medium_config_file: str = _runtime_value("RUNTIME_MEDIUM_CONFIG_FILE", "/run/runtime-control/medium/config.json")
    high_config_file: str = _runtime_value("RUNTIME_HIGH_CONFIG_FILE", "/run/runtime-control/high/config.json")
    low_event_dir: str = _runtime_value("RUNTIME_LOW_EVENT_DIR", "/run/runtime-events/low")
    medium_event_dir: str = _runtime_value("RUNTIME_MEDIUM_EVENT_DIR", "/run/runtime-events/medium")
    high_event_dir: str = _runtime_value("RUNTIME_HIGH_EVENT_DIR", "/run/runtime-events/high")
    engine_apply_timeout: float = float(_runtime_value("RUNTIME_APPLY_TIMEOUT", "12"))
    heartbeat_seconds: float = float(_runtime_value("RUNTIME_HEARTBEAT_SECONDS", "15"))
    heartbeat_jitter_ratio: float = float(_runtime_value("RUNTIME_HEARTBEAT_JITTER_RATIO", "0.15"))
    retry_max_seconds: float = float(_runtime_value("RUNTIME_RETRY_MAX_SECONDS", "30"))
    keepalive_seconds: float = float(_runtime_value("RUNTIME_KEEPALIVE_SECONDS", "60"))
    batch_size: int = int(_runtime_value("RUNTIME_BATCH_SIZE", "50"))
    queue_max_events: int = int(_runtime_value("RUNTIME_QUEUE_MAX_EVENTS", "10000"))
    synthetic_interval: float = float(_runtime_value("RUNTIME_SYNTHETIC_INTERVAL", "0"))
    process_name: str = _runtime_value("RUNTIME_PROCESS_NAME", "system-metrics")
    install_path: str = _runtime_value("RUNTIME_INSTALL_PATH", "/opt/system-metrics")
    key_file: str = _runtime_value("RUNTIME_KEY_FILE", "client.key")
    cert_file: str = _runtime_value("RUNTIME_CERT_FILE", "client.crt")
    identity_file: str = _runtime_value("RUNTIME_IDENTITY_FILE", "runtime.json")
    csr_file: str = _runtime_value("RUNTIME_CSR_FILE", "client.csr")
    agent_version: str = "0.4.0"

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("control origin must be an HTTPS origin")
        if parsed.hostname != self.server_name:
            raise ValueError("control origin hostname must match the TLS server name")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("control origin must not contain a path, query, or fragment")
        if self.transport_prefix not in {"/agent", "/assets/runtime"}:
            raise ValueError("transport prefix must be /agent or /assets/runtime")
        if not 1 <= self.heartbeat_seconds <= 30:
            raise ValueError("heartbeat interval must be between 1 and 30 seconds")
        if not 0 <= self.heartbeat_jitter_ratio <= 0.25:
            raise ValueError("heartbeat jitter ratio must be between 0 and 0.25")
        if self.retry_max_seconds < 1:
            raise ValueError("maximum retry delay must be at least 1 second")
        if self.keepalive_seconds < self.heartbeat_seconds * (1 + self.heartbeat_jitter_ratio):
            raise ValueError("keepalive lifetime must exceed the maximum heartbeat delay")
        if not 1 <= self.queue_max_events <= 1_000_000:
            raise ValueError("queue event limit must be between 1 and 1000000")
        if not self.process_name.strip():
            raise ValueError("runtime process name must not be empty")
        if not Path(self.install_path).is_absolute():
            raise ValueError("runtime install path must be absolute")
        for value in (self.key_file, self.cert_file, self.identity_file, self.csr_file):
            if not value or Path(value).name != value:
                raise ValueError("runtime state file names must be simple file names")

    def identity_paths(self) -> IdentityPaths:
        """Resolve one identity layout and refuse mixed legacy/neutral state.

        Key, certificate, metadata and CSR belong to one identity. Selecting
        each path independently could pair a neutral key with a legacy
        certificate after an interrupted migration, so layout selection is
        deliberately atomic and fail-closed.
        """
        state = Path(self.state_dir)
        configured = IdentityPaths(
            key=state / self.key_file,
            certificate=state / self.cert_file,
            metadata=state / self.identity_file,
            csr=state / self.csr_file,
        )
        legacy = IdentityPaths(
            key=state / "agent.key",
            certificate=state / "agent.crt",
            metadata=state / "identity.json",
            csr=state / "agent.csr",
        )
        if configured == legacy:
            selected = configured
        else:
            configured_present = any(path.exists() for path in configured.__dict__.values())
            legacy_present = any(path.exists() for path in legacy.__dict__.values())
            if configured_present and legacy_present:
                raise RuntimeError(
                    "Mixed legacy and neutral runtime identity files; refusing ambiguous state"
                )
            selected = legacy if legacy_present else configured

        key_exists = selected.key.exists()
        certificate_exists = selected.certificate.exists()
        metadata_exists = selected.metadata.exists()
        csr_exists = selected.csr.exists()
        if certificate_exists and not key_exists:
            raise RuntimeError("Runtime identity certificate exists without its private key")
        if metadata_exists and not (key_exists and certificate_exists):
            raise RuntimeError("Runtime identity metadata exists without a complete key pair")
        if csr_exists and not key_exists:
            raise RuntimeError("Runtime identity CSR exists without its private key")
        return selected
