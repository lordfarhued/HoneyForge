from pathlib import Path

import pytest
import yaml
from cryptography import x509
from cryptography.x509.oid import NameOID

from app.pki import ensure_local_pki


ROOT = Path(__file__).resolve().parents[1]


def load_compose(name: str) -> dict:
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("compose_name", ["compose.center.yaml", "compose.yaml"])
def test_gateway_template_and_transport_prefix_are_configured_safely(compose_name):
    gateway = load_compose(compose_name)["services"]["agent-gateway"]
    assert gateway["environment"]["AGENT_TRANSPORT_PREFIX"] == "${AGENT_TRANSPORT_PREFIX:-/assets/runtime}"
    assert "./docker/agent-gateway.conf:/etc/nginx/templates/default.conf.template:ro" in gateway["volumes"]
    assert any(item.startswith("/etc/nginx/conf.d:rw,noexec,nosuid,") for item in gateway["tmpfs"])
    assert gateway["environment"]["AGENT_TLS_SERVER_NAME"] == "${PKI_SERVER_NAME:-agent-gateway}"


def test_fresh_pki_can_use_neutral_public_certificate_names(monkeypatch, tmp_path):
    monkeypatch.setenv("PKI_SERVER_NAME", "telemetry-cache.example")
    monkeypatch.setenv("PKI_CA_COMMON_NAME", "Local Service CA")
    ensure_local_pki(tmp_path)

    server = x509.load_pem_x509_certificate((tmp_path / "server.crt").read_bytes())
    ca = x509.load_pem_x509_certificate((tmp_path / "ca.crt").read_bytes())
    names = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert server.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "telemetry-cache.example"
    assert names.get_values_for_type(x509.DNSName) == ["telemetry-cache.example", "localhost"]
    assert ca.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Local Service CA"
    exposed_names = " ".join(
        [server.subject.rfc4514_string(), server.issuer.rfc4514_string(), *names.get_values_for_type(x509.DNSName)]
    ).lower()
    assert "honeyforge" not in exposed_names


def test_fresh_pki_defaults_do_not_expose_the_product_name(monkeypatch, tmp_path):
    monkeypatch.delenv("PKI_SERVER_NAME", raising=False)
    monkeypatch.delenv("PKI_CA_COMMON_NAME", raising=False)
    ensure_local_pki(tmp_path)

    server = x509.load_pem_x509_certificate((tmp_path / "server.crt").read_bytes())
    ca = x509.load_pem_x509_certificate((tmp_path / "ca.crt").read_bytes())
    exposed_names = " ".join(
        [server.subject.rfc4514_string(), server.issuer.rfc4514_string(), ca.subject.rfc4514_string()]
    ).lower()
    assert "honeyforge" not in exposed_names
    assert "honeypot" not in exposed_names


def test_public_gateway_responses_are_neutral_and_backend_headers_are_hidden():
    config = (ROOT / "docker/agent-gateway.conf").read_text(encoding="utf-8")
    public_response_lines = [line for line in config.splitlines() if "return 200" in line or "return 404 '" in line]
    assert public_response_lines
    assert all("honeyforge" not in line.lower() for line in public_response_lines)
    assert all("nginx" not in line.lower() for line in public_response_lines)
    assert "proxy_intercept_errors on;" in config
    error_line = next(line for line in config.splitlines() if line.strip().startswith("error_page "))
    for status in (400, 401, 403, 404, 405, 409, 410, 413, 422, 429, 494, 495, 496, 497, 500, 502, 503, 504):
        assert str(status) in error_line.split()
    assert "=404 @neutral_not_found;" in error_line
    assert "proxy_hide_header Server;" in config
    assert "proxy_hide_header X-Powered-By;" in config


def test_legacy_and_alias_routes_share_the_same_authentication_boundary():
    config = (ROOT / "docker/agent-gateway.conf").read_text(encoding="utf-8")
    assert "location /agent/v1/" in config
    assert "location ${AGENT_TRANSPORT_PREFIX}/v1/" in config
    assert "proxy_pass http://api:8000/agent/v1/;" in config
    assert config.count("if ($ssl_client_verify != SUCCESS) { return 496; }") == 2
    assert "location = /agent/v1/enroll" in config
    assert "location = ${AGENT_TRANSPORT_PREFIX}/v1/enroll" in config


def test_internal_health_is_not_part_of_public_tls_server():
    config = (ROOT / "docker/agent-gateway.conf").read_text(encoding="utf-8")
    assert config.count("location = /internal-health") == 1
    assert "listen 127.0.0.1:8080;" in config


def test_new_agents_default_to_neutral_transport_while_legacy_route_remains():
    ubuntu = load_compose("compose.ubuntu-agent.yaml")
    local = load_compose("compose.yaml")
    assert ubuntu["x-agent-environment"]["RUNTIME_TRANSPORT_PREFIX"] == (
        "${TRANSPORT_PREFIX:-${AGENT_CLIENT_TRANSPORT_PREFIX:-/assets/runtime}}"
    )
    assert local["services"]["local-agent"]["environment"]["RUNTIME_TRANSPORT_PREFIX"] == (
        "${AGENT_CLIENT_TRANSPORT_PREFIX:-/assets/runtime}"
    )
    config = (ROOT / "docker/agent-gateway.conf").read_text(encoding="utf-8")
    assert "location /agent/v1/" in config
