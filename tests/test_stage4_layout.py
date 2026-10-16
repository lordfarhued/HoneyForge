from pathlib import Path

import pytest
import yaml

from agent.bootstrap import store_enrollment_token


ROOT = Path(__file__).resolve().parents[1]


def load_compose(name: str) -> dict:
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


def test_center_and_ubuntu_are_separate_compose_projects():
    center = load_compose("compose.center.yaml")
    ubuntu = load_compose("compose.ubuntu-agent.yaml")
    center_services = set(center["services"])
    ubuntu_services = set(ubuntu["services"])

    assert {"db", "api", "nginx", "agent-gateway"} <= center_services
    assert not {"ubuntu-agent", "low-honeypot", "medium-honeypot", "high-honeypot"} & center_services
    assert {"runtime-worker", "runtime-bootstrap", "low-honeypot", "medium-honeypot", "high-honeypot"} <= ubuntu_services
    assert not {"db", "api", "nginx", "agent-gateway"} & ubuntu_services
    assert center["name"] == "honeyforge"
    assert ubuntu["name"] != center["name"]


def test_network_publication_defaults_are_loopback_and_agent_tls_is_strict():
    center = load_compose("compose.center.yaml")
    ubuntu = load_compose("compose.ubuntu-agent.yaml")
    assert center["services"]["agent-gateway"]["ports"] == [
        "${AGENT_BIND_IP:-127.0.0.1}:${AGENT_PORT:-8443}:8443"
    ]
    assert ubuntu["services"]["low-ingress"]["ports"][0].startswith(
        "${LOW_BIND_IP:-127.0.0.1}:"
    )
    low_udp = ubuntu["services"]["low-udp-ingress"]
    assert low_udp["ports"] == ["${LOW_BIND_IP:-127.0.0.1}:${LOW_UDP_PORT:-8083}:8083/udp"]
    assert low_udp["environment"]["HF_RELAY_PROTOCOL"] == "udp"
    assert set(low_udp["networks"]) == {"low_ingress", "public_ingress"}
    assert "agent_egress" not in low_udp["networks"]
    for service in ("medium-http-ingress", "medium-ssh-ingress"):
        assert ubuntu["services"][service]["ports"][0].startswith(
            "${TRAP_BIND_IP:-127.0.0.1}:"
        )
        assert ubuntu["services"][service]["profiles"] == ["medium"]
    assert ubuntu["services"]["medium-honeypot"]["profiles"] == ["medium"]
    for service in ("high-http-ingress", "high-ssh-ingress"):
        assert ubuntu["services"][service]["ports"][0].startswith(
            "${TRAP_BIND_IP:-127.0.0.1}:"
        )
        assert ubuntu["services"][service]["profiles"] == ["high"]
    high = ubuntu["services"]["high-honeypot"]
    assert high["profiles"] == ["high"]
    assert high["read_only"] is True
    assert high["mem_limit"] == "512m"
    assert high["pids_limit"] == 128
    assert "ALL" in high["cap_drop"]
    assert "docker.sock" not in " ".join(high["volumes"])
    assert "medium-honeypot" not in ubuntu["services"]["runtime-worker"]["depends_on"]
    assert "high-honeypot" not in ubuntu["services"]["runtime-worker"].get("depends_on", {})
    environment = ubuntu["x-agent-environment"]
    assert environment["RUNTIME_CONTROL_ORIGIN"].endswith(":${CONTROL_PORT:-${AGENT_GATEWAY_PORT:-8443}}")
    assert environment["RUNTIME_TLS_SERVER_NAME"] == "${CONTROL_TLS_NAME:-${AGENT_SERVER_NAME:-agent-gateway}}"
    assert environment["RUNTIME_TRANSPORT_PREFIX"] == "${TRANSPORT_PREFIX:-${AGENT_CLIENT_TRANSPORT_PREFIX:-/assets/runtime}}"
    assert ubuntu["services"]["runtime-worker"]["extra_hosts"] == [
        "${CONTROL_TLS_NAME:-${AGENT_SERVER_NAME:-agent-gateway}}=${CONTROL_ENDPOINT_IP:-${HONEYFORGE_CENTER_IP:-127.0.0.1}}"
    ]
    assert environment["RUNTIME_CA_FILE"].endswith("/ca.crt")
    assert environment["RUNTIME_PIN_FILE"].endswith("/server.pin")


def test_low_udp_ingress_is_isolated_in_both_agent_compose_projects():
    for compose_name in ("compose.yaml", "compose.ubuntu-agent.yaml"):
        compose = load_compose(compose_name)
        relay = compose["services"]["low-udp-ingress"]
        assert relay["read_only"] is True
        assert "ALL" in relay["cap_drop"]
        assert "no-new-privileges:true" in relay["security_opt"]
        assert "docker.sock" not in " ".join(relay.get("volumes", []))
        assert relay["ports"][0].startswith("${LOW_BIND_IP:-127.0.0.1}:")
        assert relay["ports"][0].endswith("/udp")
        assert set(relay["networks"]) == {"low_ingress", "public_ingress"}


@pytest.mark.parametrize("compose_name", ["compose.center.yaml", "compose.yaml"])
def test_center_gateway_has_minimal_pki_mounts_and_private_backend(compose_name):
    center = load_compose(compose_name)
    api = center["services"]["api"]
    gateway = center["services"]["agent-gateway"]
    gateway_mounts = " ".join(gateway["volumes"])
    api_mounts = " ".join(api["volumes"])

    assert "ca.key:/etc/nginx/pki" not in gateway_mounts
    assert "server.crt:/etc/nginx/pki/server.crt:ro" in gateway_mounts
    assert "server.key:/etc/nginx/pki/server.key:ro" in gateway_mounts
    assert "ca.crt:/etc/nginx/pki/ca.crt:ro" in gateway_mounts
    assert "server.key:/run/honeyforge-pki" not in api_mounts
    assert "ca.crt:/run/honeyforge-pki/ca.crt:ro" in api_mounts
    assert "ca.key:/run/honeyforge-pki/ca.key:ro" in api_mounts

    assert gateway["read_only"] is True
    assert "ALL" in gateway["cap_drop"]
    assert set(gateway["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "SETGID", "SETUID"}
    assert "no-new-privileges:true" in gateway["security_opt"]
    assert set(gateway["networks"]) == {"agent_ingress", "agent_backend", "agent_channel"}
    assert "agent_backend" in api["networks"]
    assert "agent_backend" not in center["services"]["nginx"]["networks"]
    assert center["networks"]["agent_backend"]["internal"] is True
    assert not (center["networks"]["agent_ingress"] or {}).get("internal", False)
    assert all(
        service_name == "agent-gateway" or "agent_ingress" not in service.get("networks", [])
        for service_name, service in center["services"].items()
    )
    assert "127.0.0.1:8080/internal-health" in gateway["healthcheck"]["test"][-1]


def test_public_agent_health_is_removed_and_api_does_not_trust_forwarded_peer_ip():
    gateway_config = (ROOT / "docker/agent-gateway.conf").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "/agent-health" not in gateway_config
    assert "listen 127.0.0.1:8080" in gateway_config
    assert "/internal-health" in gateway_config
    assert "--no-proxy-headers" in dockerfile
    assert "--forwarded-allow-ips=*" not in dockerfile


def test_ubuntu_state_is_project_scoped_and_services_are_not_privileged():
    ubuntu = load_compose("compose.ubuntu-agent.yaml")
    agent = ubuntu["services"]["runtime-worker"]
    mounts = " ".join(agent["volumes"])
    assert "ubuntu_agent_state:/var/lib/system-metrics" in mounts
    assert "ubuntu_agent_bootstrap:/run/runtime-bootstrap" in mounts
    assert "agent_state:" not in mounts.replace("ubuntu_agent_state:", "")
    assert "docker.sock" not in (ROOT / "compose.ubuntu-agent.yaml").read_text(encoding="utf-8")
    for service in ubuntu["services"].values():
        assert not service.get("privileged", False)
        assert "ALL" in service.get("cap_drop", [])
        assert "no-new-privileges:true" in service.get("security_opt", [])
        assert "apparmor=${RUNTIME_APPARMOR_PROFILE:-docker-default}" in service.get("security_opt", [])
        assert service["pids_limit"] > 0
        assert service["mem_limit"]
        assert service["cpus"] > 0
        assert service["logging"]["options"]["max-size"] == "10m"
        assert service["logging"]["options"]["max-file"] == "3"
    assert agent["read_only"] is True
    assert any(item.startswith("/tmp:rw,noexec,nosuid,") for item in agent["tmpfs"])


def test_bootstrap_token_is_exclusive_and_refuses_existing_identity(tmp_path):
    state = tmp_path / "state"
    bootstrap = tmp_path / "bootstrap"
    state.mkdir()
    token_file = bootstrap / "enrollment.token"
    token = "a" * 48
    store_enrollment_token(token_file, state, token)
    assert token_file.read_text(encoding="utf-8") == token
    assert token not in repr(token_file)
    with pytest.raises(FileExistsError):
        store_enrollment_token(token_file, state, "b" * 48)

    token_file.unlink()
    (state / "identity.json").write_text("{}", encoding="utf-8")
    with pytest.raises(RuntimeError, match="identity already exists"):
        store_enrollment_token(token_file, state, "c" * 48)
    assert not token_file.exists()
