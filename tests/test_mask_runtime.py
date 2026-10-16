from pathlib import Path

import pytest
import yaml

from agent.bootstrap import store_enrollment_token
from agent.client import AgentClient
from agent.config import AgentSettings
from agent.main import apply_runtime_masking
from agent.queue import DurableQueue
from agent.engines import EngineController
from honeypots.common import EventWriter
from agent.runtime_masking import normalize_process_name, select_profile_value, set_process_name


ROOT = Path(__file__).resolve().parents[1]


def settings_for(state: Path, **overrides) -> AgentSettings:
    values = {
        "base_url": "https://localhost",
        "server_name": "localhost",
        "state_dir": str(state),
        "keepalive_seconds": 60,
    }
    values.update(overrides)
    return AgentSettings(**values)


def test_new_identity_files_are_neutral_and_existing_legacy_identity_is_reused(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    fresh = AgentClient(settings_for(state), client_factory=lambda authenticated: None)
    assert fresh.key_path.name == "client.key"
    assert fresh.cert_path.name == "client.crt"

    (state / "agent.key").write_text("legacy-key", encoding="ascii")
    (state / "agent.crt").write_text("legacy-cert", encoding="ascii")
    existing = AgentClient(settings_for(state), client_factory=lambda authenticated: None)
    assert existing.key_path == state / "agent.key"
    assert existing.cert_path == state / "agent.crt"
    assert existing.identity_paths.metadata == state / "identity.json"
    assert existing.identity_paths.csr == state / "agent.csr"


def test_identity_layout_refuses_mixed_legacy_and_neutral_files(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "agent.key").write_text("legacy-key", encoding="ascii")
    (state / "agent.crt").write_text("legacy-cert", encoding="ascii")
    (state / "client.csr").write_text("neutral-csr", encoding="ascii")

    with pytest.raises(RuntimeError, match="Mixed legacy and neutral"):
        AgentClient(settings_for(state), client_factory=lambda authenticated: None)


@pytest.mark.parametrize(
    ("files", "message"),
    [
        (("client.crt",), "certificate exists without"),
        (("runtime.json",), "metadata exists without"),
        (("client.csr",), "CSR exists without"),
    ],
)
def test_identity_layout_refuses_incomplete_state(tmp_path, files, message):
    state = tmp_path / "state"
    state.mkdir()
    for name in files:
        (state / name).write_text("incomplete", encoding="ascii")

    with pytest.raises(RuntimeError, match=message):
        AgentClient(settings_for(state), client_factory=lambda authenticated: None)


def test_pending_queue_and_wal_stay_in_the_same_state_volume(tmp_path):
    state = tmp_path / "mounted-volume"
    queue_path = state / "queue.sqlite3"
    first = DurableQueue(str(queue_path))
    first.connection.execute("PRAGMA wal_autocheckpoint=0")
    event = {"external_id": "00000000-0000-4000-8000-000000000099", "value": "pending"}
    first.enqueue(event)

    assert queue_path.exists()
    assert queue_path.with_name("queue.sqlite3-wal").exists()
    second = DurableQueue(str(queue_path))
    assert second.pending(10) == [event]
    second.connection.close()
    first.connection.close()

    restarted = DurableQueue(str(queue_path))
    assert restarted.pending(10) == [event]
    restarted.connection.close()


def test_durable_queue_applies_backpressure_and_recovers_in_order_after_restart(tmp_path):
    queue_path = tmp_path / "state" / "queue.sqlite3"
    events = [
        {"external_id": f"00000000-0000-4000-8000-{index:012d}", "sequence": index}
        for index in range(4)
    ]
    first = DurableQueue(str(queue_path), max_events=3)
    assert all(first.enqueue(event) for event in events[:3])
    assert first.enqueue(events[1]) is True
    assert first.enqueue(events[3]) is False
    first.connection.close()

    restarted = DurableQueue(str(queue_path), max_events=3)
    assert [item["sequence"] for item in restarted.pending(10)] == [0, 1, 2]
    restarted.acknowledge([events[0]["external_id"], events[1]["external_id"]])
    assert restarted.enqueue(events[3]) is True
    assert [item["sequence"] for item in restarted.pending(10)] == [2, 3]
    restarted.connection.close()


def test_engine_event_is_not_deleted_when_durable_queue_is_full(tmp_path):
    instance_id = "00000000-0000-4000-8000-000000000111"
    settings = settings_for(
        tmp_path / "state",
        low_config_file=str(tmp_path / "control-low/config.json"),
        medium_config_file=str(tmp_path / "control-medium/config.json"),
        high_config_file=str(tmp_path / "control-high/config.json"),
        low_event_dir=str(tmp_path / "events-low"),
        medium_event_dir=str(tmp_path / "events-medium"),
        high_event_dir=str(tmp_path / "events-high"),
    )
    queue = DurableQueue(str(tmp_path / "state/queue.sqlite3"), max_events=1)
    queue.store_configuration(
        instance_id,
        1,
        {"instance_id": instance_id, "profile": {"interaction_level": "low"}},
    )
    assert queue.enqueue({"external_id": "00000000-0000-4000-8000-000000000112"})
    writer = EventWriter(settings.low_event_dir)
    event_id = writer.emit(instance_id, "low.connection", "192.0.2.20", {"service": "http"})
    event_path = Path(settings.low_event_dir) / f"{event_id}.event.json"

    assert EngineController(settings).ingest_events(queue) == 0
    assert event_path.exists()
    assert queue.depth() == 1
    queue.connection.close()


def test_engine_spool_has_explicit_file_capacity(monkeypatch, tmp_path):
    monkeypatch.setenv("HF_EVENT_SPOOL_MAX_FILES", "2")
    monkeypatch.setenv("HF_EVENT_SPOOL_MAX_BYTES", "1048576")
    writer = EventWriter(str(tmp_path / "events"))
    first = writer.emit("instance", "low.connection", "192.0.2.1", {})
    second = writer.emit("instance", "low.connection", "192.0.2.2", {})
    rejected = writer.emit("instance", "low.connection", "192.0.2.3", {})

    assert first and second
    assert rejected == ""
    assert len(list((tmp_path / "events").glob("*.event.json"))) == 2


@pytest.mark.parametrize("identity_name", ["client.key", "client.crt", "runtime.json"])
def test_bootstrap_refuses_neutral_identity_files(tmp_path, identity_name):
    state = tmp_path / "state"
    state.mkdir()
    (state / identity_name).write_text("present", encoding="ascii")
    with pytest.raises(RuntimeError, match="identity already exists"):
        store_enrollment_token(tmp_path / "bootstrap" / "enrollment.token", state, "a" * 48)


def test_profile_process_name_is_applied_only_when_instances_agree(monkeypatch, tmp_path):
    settings = settings_for(tmp_path, process_name="system-metrics")
    applied: list[str] = []
    monkeypatch.setattr("agent.main.set_process_name", lambda value: applied.append(value) or value)
    first = {"profile": {"masking": {"process_name": "telemetry-cache"}}}
    second = {"profile": {"masking": {"process_name": "telemetry-cache"}}}
    conflicting = {"profile": {"masking": {"process_name": "node-helper"}}}

    assert apply_runtime_masking(settings, [first, second]) == "telemetry-cache"
    assert apply_runtime_masking(settings, [first, conflicting]) == "system-metrics"
    assert applied == ["telemetry-cache", "system-metrics"]


def test_profile_install_path_is_selected_only_when_instances_agree():
    first = {"profile": {"masking": {"install_path": "/opt/telemetry-cache"}}}
    second = {"profile": {"masking": {"install_path": "/opt/telemetry-cache"}}}
    conflicting = {"profile": {"masking": {"install_path": "/opt/node-helper"}}}
    assert select_profile_value([first, second], "install_path", "/opt/system-metrics") == "/opt/telemetry-cache"
    assert select_profile_value([first, conflicting], "install_path", "/opt/system-metrics") == "/opt/system-metrics"


def test_linux_process_name_is_bounded_and_set_through_runtime_hook():
    observed: list[bytes] = []
    result = set_process_name("telemetry-cache-worker", lambda value: observed.append(value) or 0)
    assert result == "telemetry-cache"
    assert observed == [b"telemetry-cache"]
    assert len(observed[0]) <= 15
    assert normalize_process_name("   ") == "system-metrics"


def test_ubuntu_runtime_names_and_paths_are_neutral_with_legacy_project_fallback():
    compose = yaml.safe_load((ROOT / "compose.ubuntu-agent.yaml").read_text(encoding="utf-8"))
    services = compose["services"]
    assert "runtime-worker" in services
    assert "runtime-bootstrap" in services
    assert "ubuntu-agent" not in services
    assert "bootstrap-agent" not in services
    assert services["runtime-worker"]["container_name"] == "${RUNTIME_CONTAINER_NAME:-system-metrics}"
    assert compose["name"] == "${RUNTIME_PROJECT_NAME:-${HF_AGENT_PROJECT_NAME:-honeyforge-ubuntu-agent}}"

    worker = services["runtime-worker"]
    runtime_text = "\n".join([*worker["volumes"], *worker["environment"].keys()]).lower()
    assert "/var/lib/honeyforge-agent" not in runtime_text
    assert "/run/honeyforge-" not in runtime_text
    assert not any(name.startswith("HF_AGENT_") for name in worker["environment"])

    assert set(compose["volumes"]) == {
        "ubuntu_agent_state",
        "ubuntu_agent_bootstrap",
        "ubuntu_low_control",
        "ubuntu_medium_control",
        "ubuntu_high_control",
        "ubuntu_low_events",
        "ubuntu_medium_events",
        "ubuntu_high_events",
        "ubuntu_medium_state",
        "ubuntu_high_state",
    }
    agent_network = compose["networks"]["agent_egress"]
    assert agent_network["name"] == "${AGENT_EGRESS_NETWORK_NAME:-system-metrics-agent}"
    assert agent_network["enable_ipv6"] is False
    assert agent_network["driver_opts"]["com.docker.network.bridge.name"] == (
        "${AGENT_EGRESS_BRIDGE_NAME:-np-agent}"
    )


def test_agent_image_uses_neutral_account_entrypoint_and_locations():
    dockerfile = (ROOT / "Dockerfile.agent").read_text(encoding="utf-8")
    assert "USER svc-metrics" in dockerfile
    assert 'CMD ["/usr/local/bin/system-metrics"]' in dockerfile
    assert "/opt/system-metrics" in dockerfile
    assert "/var/lib/system-metrics" in dockerfile
    assert "honeyforge-agent" not in dockerfile.lower()
    assert 'CMD ["python", "-m", "agent.main"]' not in dockerfile


def test_runtime_log_messages_do_not_expose_product_or_control_role():
    source = "\n".join(
        (ROOT / name).read_text(encoding="utf-8")
        for name in ("agent/main.py", "agent/engines.py", "agent/bootstrap.py")
    ).lower()
    assert "honeyforge" not in source
    assert "honeypot" not in source
    assert "c2" not in source
    assert "agent cycle" not in source
