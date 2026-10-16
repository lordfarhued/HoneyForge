import json
import http.client
import os
import re
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

os.environ.setdefault("SECRET_KEY", "test-only-secret-key-that-is-longer-than-32-characters")

from tests.database_safety import configure_test_database_environment, reset_test_schema

configure_test_database_environment()

import pytest
import paramiko
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from agent.config import AgentSettings
from agent.engines import EngineController
from agent.main import flush_events, sync_configuration
from agent.queue import DurableQueue
from app.config import get_settings
from app.agent_auth import peer_address_matches
from app.database import Base, SessionLocal, engine
from app.event_view import REDACTED_VALUE
from app.main import app
from app.honeytokens import HONEYTOKEN_REDACTION
from app.models import Alert, AuditEntry, EnrollmentToken, Event, Honeytoken, HoneypotInstance, Host, HostStatus, Job, TrapProfile, User, UserRole, utcnow
from app.pki import ensure_local_pki
from app.security import hash_password, token_hash
from honeypots.common import RuntimeSupervisor, start_server
from honeypots.high import make_service_factory as make_high_service_factory
from honeypots.low import service_factory as low_service_factory
from honeypots.medium import load_or_create_host_key, make_service_factory
from honeypots.relay import UDPRelayServer


@pytest.fixture(autouse=True)
def stage2_database(tmp_path):
    reset_test_schema(Base, engine)
    pki_dir = tmp_path / "pki"
    ensure_local_pki(pki_dir)
    settings = get_settings()
    settings.ca_cert_path = str(pki_dir / "ca.crt")
    settings.ca_key_path = str(pki_dir / "ca.key")
    with SessionLocal() as db:
        db.add(
            User(
                username="admin",
                email="admin@example.com",
                role=UserRole.ADMIN,
                password_hash=hash_password("Correct-Horse-123"),
            )
        )
        db.commit()
    yield


@pytest.fixture
def client():
    with TestClient(app) as value:
        yield value


def login(
    client: TestClient,
    username: str = "admin",
    password: str = "Correct-Horse-123",
):
    page = client.get("/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return response


def csr_pem():
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "stage2-test-agent")]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def gateway_headers(certificate: str | None = None):
    headers = {"X-HoneyForge-Gateway": "agent-gateway", "X-Forwarded-Proto": "https"}
    if certificate:
        headers.update(
            {
                "X-HoneyForge-Client-Verify": "SUCCESS",
                "X-HoneyForge-Client-Cert": quote(certificate, safe=""),
            }
        )
    return headers


def test_gateway_peer_matching_and_forged_headers_are_rejected(client, monkeypatch):
    monkeypatch.setattr(
        "app.agent_auth.socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("172.30.0.3", 0))],
    )
    assert peer_address_matches("172.30.0.3", "agent-gateway")
    assert not peer_address_matches("172.30.0.4", "agent-gateway")

    settings = get_settings()
    monkeypatch.setattr(settings, "environment", "local")
    response = client.get("/agent/v1/config", headers=gateway_headers())
    assert response.status_code == 404


def provision(db, suffix="one"):
    profile = TrapProfile(
        name=f"profile-{suffix}",
        interaction_level="low",
        services=[{"name": "http", "protocol": "tcp", "port": 8081, "banner": "nginx"}],
        bait_credentials=[],
        logging={"capture_connections": True, "capture_credentials": True, "capture_commands": True, "capture_payloads": False},
        masking={"endpoint_path": "/assets/telemetry", "process_name": "system-metrics", "install_path": "/opt/system-metrics"},
    )
    host = Host(name=f"host-{suffix}", management_address=f"host-{suffix}.local")
    instance = HoneypotInstance(name=f"trap-{suffix}", host=host, profile=profile)
    raw_token = f"token-{suffix}-" + "x" * 48
    enrollment = EnrollmentToken(
        host=host,
        token_hash=token_hash(raw_token),
        expires_at=utcnow() + timedelta(minutes=15),
    )
    db.add_all([profile, host, instance, enrollment])
    db.commit()
    return profile, host, instance, raw_token


def enroll(client: TestClient, token: str):
    response = client.post(
        "/agent/v1/enroll",
        headers=gateway_headers(),
        json={"token": token, "csr_pem": csr_pem(), "agent_version": "test"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def free_tcp_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def wait_for_engine_event(directory: Path) -> dict:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        paths = list(directory.glob("*.event.json"))
        if paths:
            return json.loads(paths[0].read_text(encoding="utf-8"))
        time.sleep(0.05)
    raise AssertionError("expected a UDP engine event")


def test_enrollment_is_single_use_and_agent_has_no_operator_session(client):
    with SessionLocal() as db:
        _, _, _, token = provision(db)
    identity = enroll(client, token)
    with SessionLocal() as db:
        assert db.scalar(
            select(AuditEntry).where(
                AuditEntry.action == "agent.registered",
                AuditEntry.entity_id == identity["identity_id"],
            )
        )
    reused = client.post(
        "/agent/v1/enroll",
        headers=gateway_headers(),
        json={"token": token, "csr_pem": csr_pem(), "agent_version": "test"},
    )
    assert reused.status_code == 409
    assert client.get("/api/v1/profiles", headers=gateway_headers(identity["certificate_pem"])).status_code == 401

    with SessionLocal() as db:
        _, _, _, expired_token = provision(db, "expired")
        expired = db.scalar(
            select(EnrollmentToken).where(EnrollmentToken.token_hash == token_hash(expired_token))
        )
        expired.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    expired_response = client.post(
        "/agent/v1/enroll",
        headers=gateway_headers(),
        json={"token": expired_token, "csr_pem": csr_pem(), "agent_version": "test"},
    )
    assert expired_response.status_code == 410


def test_config_version_foreign_trap_rejection_event_dedup_and_websocket(client):
    with SessionLocal() as db:
        profile, host, instance, token = provision(db, "owned")
        second_profile = TrapProfile(
            name="profile-owned-second",
            interaction_level="medium",
            services=[{"name": "ssh", "protocol": "tcp", "port": 2222, "banner": "OpenSSH"}],
            bait_credentials=[],
            logging=profile.logging,
            masking=profile.masking,
        )
        second_instance = HoneypotInstance(name="trap-owned-second", host=host, profile=second_profile)
        db.add_all([second_profile, second_instance])
        db.commit()
        _, _, foreign_instance, _ = provision(db, "foreign")
        owned_id, foreign_id, profile_id = instance.id, foreign_instance.id, profile.id
    identity = enroll(client, token)
    headers = gateway_headers(identity["certificate_pem"])

    config = client.get("/agent/v1/config", headers=headers)
    assert config.status_code == 200
    assert len(config.json()["configurations"]) == 2
    assert {item["instance_name"] for item in config.json()["configurations"]} == {"trap-owned", "trap-owned-second"}
    assert all(item["profile"]["config_version"] == 1 for item in config.json()["configurations"])
    with SessionLocal() as db:
        profile = db.get(TrapProfile, profile_id)
        profile.description = "updated"
        profile.bait_credentials = [{"username": "operator", "password": "decoy-only"}]
        profile.logging = {
            "capture_connections": True,
            "capture_credentials": False,
            "capture_commands": True,
            "capture_payloads": True,
        }
        profile.masking = {
            "endpoint_path": "/assets/telemetry",
            "process_name": "system-metrics",
            "install_path": "/opt/system-metrics",
            "response_delay_ms": 175,
        }
        profile.config_version += 1
        db.commit()
    updated_configurations = client.get("/agent/v1/config", headers=headers).json()["configurations"]
    versions = {item["instance_name"]: item["profile"]["config_version"] for item in updated_configurations}
    assert versions == {"trap-owned": 2, "trap-owned-second": 1}
    updated_profile = next(item["profile"] for item in updated_configurations if item["instance_name"] == "trap-owned")
    assert updated_profile["bait_credentials"] == [{"username": "operator", "password": "decoy-only"}]
    assert updated_profile["logging"]["capture_credentials"] is False
    assert updated_profile["logging"]["capture_payloads"] is True
    assert updated_profile["masking"]["response_delay_ms"] == 175

    foreign_event = {
        "external_id": str(uuid.uuid4()),
        "instance_id": str(foreign_id),
        "event_type": "test.foreign",
        "source_ip": "192.0.2.10",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "data": {},
        "is_test": True,
    }
    assert client.post("/agent/v1/events", headers=headers, json={"events": [foreign_event]}).status_code == 403
    oversized = {
        **foreign_event,
        "external_id": str(uuid.uuid4()),
        "instance_id": str(owned_id),
        "data": {"blob": "x" * 17_000},
    }
    assert client.post("/agent/v1/events", headers=headers, json={"events": [oversized]}).status_code == 422
    naive_time = {
        **foreign_event,
        "external_id": str(uuid.uuid4()),
        "instance_id": str(owned_id),
        "occurred_at": datetime.now().isoformat(),
    }
    assert client.post("/agent/v1/events", headers=headers, json={"events": [naive_time]}).status_code == 422

    login(client)
    event_id = str(uuid.uuid4())
    event = {
        "external_id": event_id,
        "instance_id": str(owned_id),
        "event_type": "agent.synthetic_test",
        "source_ip": "192.0.2.11",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "data": {"origin": "pytest"},
        "is_test": True,
    }
    with client.websocket_connect("/ws/events") as websocket:
        accepted = client.post("/agent/v1/events", headers=headers, json={"events": [event]})
        assert accepted.status_code == 200
        assert accepted.json()["accepted_ids"] == [event_id]
        streamed = websocket.receive_json()
        assert streamed["external_id"] == event_id
        assert streamed["is_test"] is True
    with client.websocket_connect(f"/ws/events?since={quote(streamed['created_at'], safe='')}") as websocket:
        restored = websocket.receive_json()
        assert restored["external_id"] == event_id
    duplicate = client.post("/agent/v1/events", headers=headers, json={"events": [event]})
    assert duplicate.json()["duplicate_ids"] == [event_id]
    with SessionLocal() as db:
        assert len(list(db.scalars(select(Event).where(Event.external_id == event_id)))) == 1
    filtered = client.get(
        f"/api/v1/events?instance_id={owned_id}&source_ip=192.0.2.11&event_type=agent.synthetic_test"
    )
    assert filtered.status_code == 200
    assert [item["external_id"] for item in filtered.json()] == [event_id]


def test_event_list_requires_operator_auth(client):
    assert client.get("/api/v1/events").status_code == 401
    with pytest.raises(WebSocketDisconnect) as closed:
        with client.websocket_connect("/ws/events"):
            pass
    assert closed.value.code == 4401


def test_websocket_masks_sensitive_event_data_by_role_without_changing_storage(client):
    observer_password = "Observer-WebSocket-123"
    operator_password = "Operator-WebSocket-123"
    with SessionLocal() as db:
        _, _, instance, token = provision(db, "websocket-redaction")
        instance_id = instance.id
        db.add_all(
            [
                User(
                    username="websocket-observer",
                    email="websocket-observer@example.com",
                    role=UserRole.OBSERVER,
                    password_hash=hash_password(observer_password),
                ),
                User(
                    username="websocket-operator",
                    email="websocket-operator@example.com",
                    role=UserRole.OPERATOR,
                    password_hash=hash_password(operator_password),
                ),
            ]
        )
        db.commit()

    identity = enroll(client, token)
    headers = gateway_headers(identity["certificate_pem"])
    original_data = {
        "password": "websocket-password-secret",
        "nested": {"access_token": "websocket-token-secret"},
        "url": "https://demo:websocket-url-secret@example.invalid/status",
        "command": "whoami",
    }

    def assert_masked(event_payload):
        serialized = json.dumps(event_payload, ensure_ascii=False)
        assert event_payload["data"]["command"] == "whoami"
        assert event_payload["data"]["password"] == REDACTED_VALUE
        assert event_payload["data"]["nested"]["access_token"] == REDACTED_VALUE
        assert "websocket-password-secret" not in serialized
        assert "websocket-token-secret" not in serialized
        assert "websocket-url-secret" not in serialized

    stored_event_ids = []
    role_events = []
    for username, password in (
        ("websocket-observer", observer_password),
        ("websocket-operator", operator_password),
    ):
        client.cookies.clear()
        assert login(client, username, password).status_code == 303
        event_id = str(uuid.uuid4())
        event = {
            "external_id": event_id,
            "instance_id": str(instance_id),
            "event_type": "medium.ssh_command",
            "source_ip": "192.0.2.44",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": original_data,
            "is_test": False,
        }
        since = datetime.now(timezone.utc).isoformat()
        with client.websocket_connect(f"/ws/events?since={quote(since, safe='')}") as websocket:
            response = client.post("/agent/v1/events", headers=headers, json={"events": [event]})
            assert response.status_code == 200
            live_event = websocket.receive_json()
        assert live_event["external_id"] == event_id
        assert_masked(live_event)

        with client.websocket_connect(
            f"/ws/events?since={quote(live_event['created_at'], safe='')}"
        ) as websocket:
            backlog_event = websocket.receive_json()
        assert backlog_event["external_id"] == event_id
        assert_masked(backlog_event)
        stored_event_ids.append(event_id)
        role_events.append(live_event)

    client.cookies.clear()
    assert login(client).status_code == 303
    with client.websocket_connect(
        f"/ws/events?since={quote(role_events[-1]['created_at'], safe='')}"
    ) as websocket:
        admin_event = websocket.receive_json()
    assert admin_event["external_id"] == stored_event_ids[-1]
    assert admin_event["data"] == original_data

    with SessionLocal() as db:
        stored_events = list(
            db.scalars(select(Event).where(Event.external_id.in_(stored_event_ids)))
        )
        assert len(stored_events) == 2
        assert all(stored.data == original_data for stored in stored_events)


def test_honeytoken_detection_alert_dedup_and_secret_protection(client, tmp_path):
    with SessionLocal() as db:
        _, _, instance, enrollment_token = provision(db, "honeytoken")
        instance_id = instance.id
    identity = enroll(client, enrollment_token)
    agent_headers = gateway_headers(identity["certificate_pem"])
    login(client)
    csrf_token = client.get("/api/v1/auth/me").json()["csrf_token"]

    created = client.post(
        "/honeytokens",
        data={"name": "admin-query-canary", "severity": "high", "csrf_token": csrf_token},
    )
    assert created.status_code == 200
    raw_token = re.search(r'<textarea[^>]*token-output[^>]*>([^<]+)</textarea>', created.text).group(1)
    assert raw_token.startswith("hft_")
    assert created.text.count(raw_token) == 1
    assert raw_token not in client.get("/honeytokens").text

    with SessionLocal() as db:
        honeytoken = db.scalar(select(Honeytoken).where(Honeytoken.name == "admin-query-canary"))
        assert honeytoken.token_hash == token_hash(raw_token)
        assert raw_token not in json.dumps(honeytoken.metadata_json)
        audit = db.scalar(select(AuditEntry).where(AuditEntry.action == "honeytoken.create"))
        assert raw_token not in json.dumps(audit.after_state)
        honeytoken_id = honeytoken.id
        honeytoken_digest = honeytoken.token_hash

    def medium_http_event(external_id: uuid.UUID, source_ip: str, path: str) -> dict:
        return {
            "external_id": str(external_id),
            "instance_id": str(instance_id),
            "event_type": "medium.http_request",
            "source_ip": source_ip,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": {
                "engine": "medium",
                "service": "http",
                "method": "GET",
                "path": path,
                "http_version": "HTTP/1.1",
                "nested": {"authorization": f"Bearer {raw_token}"},
            },
            "is_test": True,
        }

    medium_port = free_tcp_port()
    engine_events = tmp_path / "medium-events"
    supervisor = RuntimeSupervisor(
        "medium",
        str(tmp_path / "medium.json"),
        str(engine_events),
        make_service_factory(load_or_create_host_key(tmp_path / "medium-host.key")),
    )
    medium_config = {
        "schema_version": 1,
        "interaction_level": "medium",
        "instances": [
            {
                "instance_id": str(instance_id),
                "instance_name": "honeytoken-medium-http",
                "config_version": 1,
                "enabled": True,
                "services": [
                    {"name": "http", "protocol": "tcp", "port": medium_port, "banner": "nginx"}
                ],
                "bait_credentials": [],
                "logging": {
                    "capture_connections": True,
                    "capture_credentials": True,
                    "capture_commands": True,
                    "capture_payloads": False,
                },
                "masking": {},
            }
        ],
    }
    encoded_config = json.dumps(medium_config).encode()
    supervisor.apply(encoded_config, medium_config)
    try:
        with socket.create_connection(("127.0.0.1", medium_port), timeout=2) as connection:
            connection.sendall(
                (
                    f"GET /admin/status?view=status&canary={raw_token} HTTP/1.1\r\n"
                    "Host: localhost\r\nX-HoneyForge-Verification: stage3\r\n\r\n"
                ).encode("ascii")
            )
            assert b"200 OK" in connection.recv(4096)
        first = wait_for_engine_event(engine_events)
    finally:
        supervisor.stop_services()
    first_id = uuid.UUID(first["external_id"])
    assert first["event_type"] == "medium.http_request"
    assert first["data"]["path"].endswith(HONEYTOKEN_REDACTION)
    assert first["data"]["_honeytoken_hashes"] == [honeytoken_digest]
    assert raw_token not in json.dumps(first)
    assert all(raw_token not in path.read_text(encoding="utf-8") for path in engine_events.glob("*.event.json"))
    with client.websocket_connect("/ws/events") as websocket:
        accepted = client.post("/agent/v1/events", headers=agent_headers, json={"events": [first]})
        assert accepted.status_code == 200
        streamed = websocket.receive_json()
    assert raw_token not in json.dumps(streamed)
    assert streamed["data"]["path"] == f"/admin/status?view=status&canary={HONEYTOKEN_REDACTION}"
    assert "_honeytoken_hashes" not in streamed["data"]

    second_id = uuid.uuid4()
    second = medium_http_event(second_id, first["source_ip"], f"/admin/status?view=status&canary={raw_token}")
    assert client.post("/agent/v1/events", headers=agent_headers, json={"events": [second]}).status_code == 200
    duplicate = client.post("/agent/v1/events", headers=agent_headers, json={"events": [first]})
    assert duplicate.json()["duplicate_ids"] == [str(first_id)]

    unknown_token = "hft_" + "z" * 43
    harmless_id = uuid.uuid4()
    harmless = medium_http_event(harmless_id, first["source_ip"], f"/public?view=status&canary={unknown_token}")
    harmless["data"].pop("nested")
    assert client.post("/agent/v1/events", headers=agent_headers, json={"events": [harmless]}).status_code == 200

    with SessionLocal() as db:
        stored = list(db.scalars(select(Event).order_by(Event.created_at)))
        alerts = list(db.scalars(select(Alert)))
        assert {event.external_id for event in stored} == {str(first_id), str(second_id), str(harmless_id)}
        assert len(alerts) == 1
        assert alerts[0].event_id == next(event.id for event in stored if event.external_id == str(first_id))
        assert alerts[0].severity == "high"
        assert alerts[0].details["reason"]
        second_event = next(event for event in stored if event.external_id == str(second_id))
        assert second_event.data["nested"]["authorization"] == f"Bearer {HONEYTOKEN_REDACTION}"
        assert next(event for event in stored if event.external_id == str(harmless_id)).data["path"].endswith(unknown_token)
        persisted = json.dumps(
            {
                "events": [event.data for event in stored],
                "alerts": [alert.details for alert in alerts],
            }
        )
        assert raw_token not in persisted
        assert honeytoken_digest not in persisted

    deactivated = client.post(
        f"/honeytokens/{honeytoken_id}/state",
        data={"active": "false", "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert deactivated.status_code == 303
    inactive_id = uuid.uuid4()
    inactive = medium_http_event(inactive_id, "198.51.100.90", f"/admin?canary={raw_token}")
    assert client.post("/agent/v1/events", headers=agent_headers, json={"events": [inactive]}).status_code == 200
    with SessionLocal() as db:
        inactive_event = db.scalar(select(Event).where(Event.external_id == str(inactive_id)))
        assert HONEYTOKEN_REDACTION in inactive_event.data["path"]
        assert len(list(db.scalars(select(Alert)))) == 1

    non_http_id = uuid.uuid4()
    non_http = medium_http_event(non_http_id, "203.0.113.19", f"/ignored?canary={raw_token}")
    non_http["event_type"] = "medium.ssh_command"
    assert client.post("/agent/v1/events", headers=agent_headers, json={"events": [non_http]}).status_code == 200
    with SessionLocal() as db:
        stored_non_http = db.scalar(select(Event).where(Event.external_id == str(non_http_id)))
        assert raw_token not in json.dumps(stored_non_http.data)
        assert len(list(db.scalars(select(Alert)))) == 1

    reactivated = client.post(
        f"/honeytokens/{honeytoken_id}/state",
        data={"active": "true", "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert reactivated.status_code == 303
    reactivated_id = uuid.uuid4()
    reactivated_event = medium_http_event(
        reactivated_id,
        "203.0.113.20",
        f"/admin/reactivated?canary={raw_token}",
    )
    assert client.post(
        "/agent/v1/events", headers=agent_headers, json={"events": [reactivated_event]}
    ).status_code == 200
    with SessionLocal() as db:
        assert len(list(db.scalars(select(Alert)))) == 2

    api_events = client.get("/api/v1/events").json()
    events_page = client.get("/events")
    alerts_page = client.get("/alerts", params={"state": "open", "severity": "high"})
    empty_filter = client.get("/alerts", params={"severity": "low"})
    assert raw_token not in json.dumps(api_events)
    assert raw_token not in events_page.text
    assert raw_token not in alerts_page.text
    assert "admin-query-canary" in alerts_page.text
    assert "Найдено: 0" in empty_filter.text


def test_high_honeytoken_signal_creates_one_safe_alert_without_changing_events(client):
    with SessionLocal() as db:
        profile, _, instance, enrollment_token = provision(db, "high-honeytoken")
        profile.interaction_level = "high"
        profile.services = [
            {"name": "http", "protocol": "tcp", "port": 8084, "banner": "nginx"},
            {"name": "ssh", "protocol": "tcp", "port": 2223, "banner": "OpenSSH"},
        ]
        db.commit()
        instance_id = instance.id
    identity = enroll(client, enrollment_token)
    headers = gateway_headers(identity["certificate_pem"])

    def high_event(external_id: uuid.UUID, *, triggered: bool) -> dict:
        data = {
            "engine": "high",
            "service": "http",
            "method": "GET",
            "path": "/api/internal/status?token=%5Bcredentials+omitted%5D",
            "status": 200 if triggered else 403,
            "session_id": None,
        }
        if triggered:
            data["_high_honeytoken_use"] = True
        return {
            "external_id": str(external_id),
            "instance_id": str(instance_id),
            "event_type": "high.http_request",
            "source_ip": "198.51.100.140",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": data,
            "is_test": False,
        }

    first_id, second_id, harmless_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    first = high_event(first_id, triggered=True)
    second = high_event(second_id, triggered=True)
    harmless = high_event(harmless_id, triggered=False)
    assert client.post("/agent/v1/events", headers=headers, json={"events": [first]}).status_code == 200
    assert client.post("/agent/v1/events", headers=headers, json={"events": [second, harmless]}).status_code == 200

    with SessionLocal() as db:
        stored = list(db.scalars(select(Event).order_by(Event.created_at)))
        alerts = list(db.scalars(select(Alert)))
        assert {event.external_id for event in stored} == {str(first_id), str(second_id), str(harmless_id)}
        assert all("_high_honeytoken_use" not in event.data for event in stored)
        assert len(alerts) == 1
        assert alerts[0].event_id == next(event.id for event in stored if event.external_id == str(first_id))
        assert alerts[0].severity == "critical"
        assert alerts[0].details["kind"] == "honeytoken_use"

    login(client)
    api_payload = client.get("/api/v1/events", params={"event_type": "high.http_request"}).json()
    exported = client.get("/events/export.json", params={"event_type": "high.http_request"})
    assert exported.status_code == 200
    serialized = json.dumps({"api": api_payload, "export": exported.json()}, ensure_ascii=False)
    assert "_high_honeytoken_use" not in serialized
    assert "hft_" not in serialized
    assert exported.json()["event_count"] == 3


def test_high_live_ssh_http_collector_alert_timeline_and_exports(client, tmp_path):
    http_port, ssh_port = free_tcp_port(), free_tcp_port()
    with SessionLocal() as db:
        profile, _, instance, enrollment_token = provision(db, "high-live-chain")
        profile.interaction_level = "high"
        profile.services = [
            {"name": "http", "protocol": "tcp", "port": http_port, "banner": "nginx"},
            {"name": "ssh", "protocol": "tcp", "port": ssh_port, "banner": "OpenSSH"},
        ]
        profile.bait_credentials = [
            {"username": "deploy", "password": "Live-Decoy-Only-2026!"}
        ]
        profile.config_version = 2
        db.commit()
        instance_id = instance.id

    identity = enroll(client, enrollment_token)
    agent_headers = gateway_headers(identity["certificate_pem"])
    config_response = client.get("/agent/v1/config", headers=agent_headers)
    assert config_response.status_code == 200

    settings = AgentSettings(
        state_dir=str(tmp_path / "agent-state"),
        low_config_file=str(tmp_path / "low-control" / "config.json"),
        medium_config_file=str(tmp_path / "medium-control" / "config.json"),
        high_config_file=str(tmp_path / "high-control" / "config.json"),
        low_event_dir=str(tmp_path / "low-events"),
        medium_event_dir=str(tmp_path / "medium-events"),
        high_event_dir=str(tmp_path / "high-events"),
    )
    queue = DurableQueue(str(tmp_path / "agent-state" / "queue.sqlite3"))

    class ConfigurationClient:
        def configuration(self):
            return config_response.json()

    sync_configuration(ConfigurationClient(), queue)
    queue.set_engine_enabled(str(instance_id), True)
    controller = EngineController(settings)
    assert controller.render(queue)["high"] is True
    rendered_path = Path(settings.high_config_file)
    rendered = json.loads(rendered_path.read_text(encoding="utf-8"))
    host_key = load_or_create_host_key(tmp_path / "high-host.key")
    supervisor = RuntimeSupervisor(
        "high",
        str(rendered_path),
        settings.high_event_dir,
        make_high_service_factory(host_key),
    )
    supervisor.apply(rendered_path.read_bytes(), rendered)

    raw_honeytoken = ""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            "127.0.0.1",
            ssh_port,
            username="deploy",
            password="Live-Decoy-Only-2026!",
            allow_agent=False,
            look_for_keys=False,
            timeout=3,
        )
        _, stdout, _ = ssh.exec_command(
            "cat /opt/company-portal/backups/service-access.txt", timeout=3
        )
        document = stdout.read().decode("utf-8")
        ssh.close()
        match = re.search(r"^token=(hft_[A-Za-z0-9_-]+)$", document, re.MULTILINE)
        assert match is not None
        raw_honeytoken = match.group(1)

        connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=3)
        connection.request("GET", f"/api/internal/status?token={raw_honeytoken}")
        response = connection.getresponse()
        assert response.status == 200
        assert json.loads(response.read()) == {"status": "ok", "nodes": 3}
        connection.close()

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            pending_files = list(Path(settings.high_event_dir).glob("*.event.json"))
            pending_types = {
                json.loads(path.read_text(encoding="utf-8"))["event_type"]
                for path in pending_files
            }
            if "high.http_request" in pending_types:
                break
            time.sleep(0.05)
        assert "high.http_request" in pending_types
        assert controller.ingest_events(queue) >= 5

        class CollectorClient:
            def send_events(self, events):
                result = client.post(
                    "/agent/v1/events", headers=agent_headers, json={"events": events}
                )
                assert result.status_code == 200, result.text
                return result.json()

        flush_events(CollectorClient(), queue, 100)
        assert queue.depth() == 0

        with SessionLocal() as db:
            stored = list(
                db.scalars(
                    select(Event)
                    .where(Event.instance_id == instance_id)
                    .order_by(Event.occurred_at, Event.id)
                )
            )
            alerts = list(db.scalars(select(Alert).where(Alert.event_id.in_([row.id for row in stored]))))
            before = [(row.external_id, row.event_type, row.data) for row in stored]
        assert {"high.ssh_command", "high.ssh_sensitive_file", "high.http_request"}.issubset(
            {row.event_type for row in stored}
        )
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"
        serialized_storage = json.dumps(before, ensure_ascii=False)
        assert raw_honeytoken not in serialized_storage
        assert "Live-Decoy-Only-2026!" not in serialized_storage
        assert "_high_honeytoken_use" not in serialized_storage

        login(client)
        events_page = client.get("/events", params={"source_ip": "127.0.0.1"})
        api_events = client.get("/api/v1/events", params={"source_ip": "127.0.0.1"})
        json_export = client.get("/events/export.json", params={"source_ip": "127.0.0.1"})
        csv_export = client.get("/events/export.csv", params={"source_ip": "127.0.0.1"})
        alerts_page = client.get("/alerts")
        assert all(
            response.status_code == 200
            for response in (events_page, api_events, json_export, csv_export, alerts_page)
        )
        assert 'data-source-ip="127.0.0.1"' in events_page.text
        public_output = "\n".join(
            [events_page.text, api_events.text, json_export.text, csv_export.text, alerts_page.text]
        )
        assert raw_honeytoken not in public_output
        assert "Live-Decoy-Only-2026!" not in public_output
        assert "_high_honeytoken_use" not in public_output

        with SessionLocal() as db:
            after_rows = list(
                db.scalars(
                    select(Event)
                    .where(Event.instance_id == instance_id)
                    .order_by(Event.occurred_at, Event.id)
                )
            )
            after = [(row.external_id, row.event_type, row.data) for row in after_rows]
        assert after == before
    finally:
        supervisor.stop_services()
        queue.connection.close()


def test_low_udp_configuration_queue_and_collector_delivery_without_duplicates(client, tmp_path, monkeypatch):
    udp_port = free_udp_port()
    udp_ingress_port = free_udp_port()
    http_port = free_tcp_port()
    with SessionLocal() as db:
        http_profile, host, http_instance, token = provision(db, "udp-delivery")
        http_profile.services = [
            {"name": "http", "protocol": "tcp", "port": http_port, "banner": "nginx"}
        ]
        http_profile.config_version = 2
        udp_profile = TrapProfile(
            name="profile-udp-vps-only",
            interaction_level="low",
            services=[
                {"name": "discovery", "protocol": "udp", "port": udp_port, "banner": "udp-ready"}
            ],
            bait_credentials=[],
            logging={
                "capture_connections": True,
                "capture_credentials": False,
                "capture_commands": False,
                "capture_payloads": True,
            },
            masking={
                "endpoint_path": "/assets/telemetry",
                "process_name": "system-metrics",
                "install_path": "/opt/system-metrics",
            },
        )
        udp_instance = HoneypotInstance(name="trap-udp-vps-only", host=host, profile=udp_profile)
        db.add_all([udp_profile, udp_instance])
        db.commit()
        http_profile_id = http_profile.id
        http_instance_id = http_instance.id
        instance_id = udp_instance.id

    identity = enroll(client, token)
    agent_headers = gateway_headers(identity["certificate_pem"])
    response = client.get("/agent/v1/config", headers=agent_headers)
    assert response.status_code == 200
    configurations = {
        item["instance_id"]: item for item in response.json()["configurations"]
    }
    assert configurations[str(http_instance_id)]["profile"]["services"] == [
        {"name": "http", "protocol": "tcp", "port": http_port, "banner": "nginx"}
    ]
    configuration = configurations[str(instance_id)]
    assert configuration["profile"]["services"] == [
        {"name": "discovery", "protocol": "udp", "port": udp_port, "banner": "udp-ready"}
    ]

    settings = AgentSettings(
        state_dir=str(tmp_path / "agent-state"),
        low_config_file=str(tmp_path / "low-control" / "config.json"),
        medium_config_file=str(tmp_path / "medium-control" / "config.json"),
        low_event_dir=str(tmp_path / "low-events"),
        medium_event_dir=str(tmp_path / "medium-events"),
    )
    queue = DurableQueue(str(tmp_path / "agent-state" / "queue.sqlite3"))

    class ConfigurationClient:
        def configuration(self):
            return response.json()

    sync_configuration(ConfigurationClient(), queue)
    queue.set_engine_enabled(str(http_instance_id), True)
    queue.set_engine_enabled(str(instance_id), True)
    controller = EngineController(settings)
    assert controller.render(queue)["low"] is True
    rendered_path = Path(settings.low_config_file)
    rendered = json.loads(rendered_path.read_text(encoding="utf-8"))
    rendered_by_id = {item["instance_id"]: item for item in rendered["instances"]}
    assert rendered_by_id[str(http_instance_id)]["services"][0]["protocol"] == "tcp"
    assert rendered_by_id[str(instance_id)]["services"][0]["protocol"] == "udp"

    supervisor = RuntimeSupervisor("low", str(rendered_path), settings.low_event_dir, low_service_factory)
    supervisor.apply(rendered_path.read_bytes(), rendered)
    relay_handle = None
    try:
        statuses = {item["instance_id"]: item for item in controller.read_statuses(queue)}
        assert statuses[str(http_instance_id)]["details"]["endpoints"] == [
            {"protocol": "tcp", "port": http_port}
        ]
        assert statuses[str(instance_id)]["details"]["endpoints"] == [
            {"protocol": "udp", "port": udp_port}
        ]
        status_response = client.post(
            "/agent/v1/status",
            headers=agent_headers,
            json={"statuses": list(statuses.values())},
        )
        assert status_response.status_code == 200

        monkeypatch.setenv("HF_PROXY_PROTOCOL", "1")
        relay_handle = start_server(
            UDPRelayServer(("127.0.0.1", udp_ingress_port), "127.0.0.1", udp_port),
            "test-low-udp-ingress-delivery",
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(3)
            udp.bind(("127.0.0.1", 0))
            source_port = udp.getsockname()[1]
            udp.sendto(b"collector-path", ("127.0.0.1", udp_ingress_port))
            reply, _ = udp.recvfrom(1024)
        assert reply == b"udp-ready"
        engine_event = wait_for_engine_event(Path(settings.low_event_dir))
        assert engine_event["event_type"] == "low.udp_datagram"
        assert engine_event["instance_id"] == str(instance_id)
        assert engine_event["source_ip"] == "127.0.0.1"
        assert engine_event["data"]["source_port"] == source_port
        assert controller.ingest_events(queue) == 1
        assert queue.depth() == 1

        class CollectorClient:
            def send_events(self, events):
                result = client.post("/agent/v1/events", headers=agent_headers, json={"events": events})
                assert result.status_code == 200, result.text
                return result.json()

        collector = CollectorClient()
        flush_events(collector, queue, 100)
        assert queue.depth() == 0
        queue.enqueue(engine_event)
        flush_events(collector, queue, 100)
        assert queue.depth() == 0

        with SessionLocal() as db:
            stored = list(db.scalars(select(Event).where(Event.external_id == engine_event["external_id"])))
            assert len(stored) == 1
            assert stored[0].event_type == "low.udp_datagram"
            assert stored[0].data["protocol"] == "udp"

        login(client)
        api_events = client.get("/api/v1/events", params={"event_type": "low.udp_datagram"})
        assert api_events.status_code == 200
        assert [item["external_id"] for item in api_events.json()] == [engine_event["external_id"]]
        events_page = client.get("/events", params={"event_type": "low.udp_datagram"})
        assert events_page.status_code == 200
        assert "low.udp_datagram" in events_page.text

        monkeypatch.delenv("HF_PROXY_PROTOCOL")
        connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=3)
        try:
            connection.request("GET", "/")
            assert connection.getresponse().status == 200
        finally:
            connection.close()
        with SessionLocal() as db:
            assert db.get(TrapProfile, http_profile_id).services == [
                {"name": "http", "protocol": "tcp", "port": http_port, "banner": "nginx"}
            ]
    finally:
        if relay_handle is not None:
            relay_handle.stop()
        supervisor.stop_services()
        queue.connection.close()


def test_agent_status_is_host_scoped_and_operator_can_queue_allowlisted_job(client):
    with SessionLocal() as db:
        _, _, owned, token = provision(db, "status-owned")
        _, _, foreign, _ = provision(db, "status-foreign")
        owned_id, foreign_id = owned.id, foreign.id
    identity = enroll(client, token)
    headers = gateway_headers(identity["certificate_pem"])
    foreign_status = client.post(
        "/agent/v1/status",
        headers=headers,
        json={"statuses": [{"instance_id": str(foreign_id), "state": "online", "config_version": 1}]},
    )
    assert foreign_status.status_code == 403
    owned_status = client.post(
        "/agent/v1/status",
        headers=headers,
        json={"statuses": [{"instance_id": str(owned_id), "state": "online", "config_version": 1}]},
    )
    assert owned_status.json() == {"status": "ok", "updated": 1}
    with SessionLocal() as db:
        assert db.get(HoneypotInstance, owned_id).status.value == "online"

    login(client)
    csrf_token = client.get("/api/v1/auth/me").json()["csrf_token"]
    queued = client.post(
        f"/api/v1/traps/{owned_id}/jobs",
        headers={"X-CSRF-Token": csrf_token},
        json={"command": "start_trap", "payload": {}},
    )
    assert queued.status_code == 201
    assert queued.json()["command"] == "start_trap"
    with SessionLocal() as db:
        assert db.scalar(select(AuditEntry).where(AuditEntry.action == "trap.job_created"))


def test_jobs_are_host_scoped_idempotent_and_only_allowlisted_commands_can_succeed(client):
    with SessionLocal() as db:
        _, host, instance, token = provision(db, "jobs")
        job = Job(
            host_id=host.id,
            instance_id=instance.id,
            command="start_trap",
            payload={},
            idempotency_key="start-jobs-once",
        )
        db.add(job)
        db.commit()
        job_id = job.id
    identity = enroll(client, token)
    headers = gateway_headers(identity["certificate_pem"])
    delivered = client.get("/agent/v1/jobs", headers=headers)
    assert delivered.status_code == 200
    assert [item["id"] for item in delivered.json()] == [str(job_id)]
    assert client.post(
        f"/agent/v1/jobs/{job_id}/ack",
        headers=headers,
        json={"state": "succeeded", "result": {"state": "online"}},
    ).status_code == 200
    repeated = client.post(
        f"/agent/v1/jobs/{job_id}/ack",
        headers=headers,
        json={"state": "failed", "result": {"reason": "duplicate"}},
    )
    assert repeated.json() == {"status": "succeeded", "idempotent": True}
    with SessionLocal() as db:
        unsafe = Job(
            host_id=host.id,
            instance_id=instance.id,
            command="shell",
            payload={"command": "whoami"},
            idempotency_key="unsafe-shell-job",
        )
        db.add(unsafe)
        db.commit()
        unsafe_id = unsafe.id
    rejected = client.post(
        f"/agent/v1/jobs/{unsafe_id}/ack",
        headers=headers,
        json={"state": "succeeded", "result": {}},
    )
    assert rejected.status_code == 409


def test_stale_heartbeat_becomes_offline_on_authorized_read(client):
    with SessionLocal() as db:
        _, host, _, _ = provision(db, "stale")
        host.status = HostStatus.ONLINE
        host.last_seen_at = utcnow() - timedelta(minutes=10)
        db.commit()
        host_id = host.id
    login(client)
    response = client.get("/api/v1/hosts")
    assert response.status_code == 200
    stale = next(item for item in response.json() if item["id"] == str(host_id))
    assert stale["status"] == "offline"


def test_trap_status_tracks_agent_availability_and_recovers_for_multiple_instances(client):
    with SessionLocal() as db:
        profile, host, first, token = provision(db, "availability")
        second = HoneypotInstance(name="trap-availability-second", host=host, profile=profile)
        db.add(second)
        db.commit()
        host_id = host.id
        first_id = first.id
        second_id = second.id

    identity = enroll(client, token)
    agent_headers = gateway_headers(identity["certificate_pem"])
    online_report = {
        "statuses": [
            {"instance_id": str(first_id), "state": "online", "config_version": 1},
            {"instance_id": str(second_id), "state": "online", "config_version": 1},
        ]
    }
    assert client.post("/agent/v1/status", headers=agent_headers, json=online_report).status_code == 200
    login(client)

    active = {item["id"]: item for item in client.get("/api/v1/traps").json()}
    for instance_id in (first_id, second_id):
        item = active[str(instance_id)]
        assert item["status"] == "online"
        assert item["reported_status"] == "online"
        assert item["host_status"] == "online"
        assert item["status_stale"] is False

    stale_at = utcnow() - timedelta(minutes=10)
    with SessionLocal() as db:
        host = db.get(Host, host_id)
        host.status = HostStatus.ONLINE
        host.last_seen_at = stale_at
        db.get(HoneypotInstance, first_id).last_seen_at = stale_at
        db.get(HoneypotInstance, second_id).last_seen_at = stale_at
        db.commit()

    unavailable = {item["id"]: item for item in client.get("/api/v1/traps").json()}
    for instance_id in (first_id, second_id):
        item = unavailable[str(instance_id)]
        assert item["status"] == "unknown"
        assert item["reported_status"] == "online"
        assert item["host_status"] == "offline"
        assert item["status_stale"] is True
    with SessionLocal() as db:
        assert db.get(Host, host_id).status == HostStatus.OFFLINE
        assert db.get(HoneypotInstance, first_id).status.value == "online"
        assert db.get(HoneypotInstance, second_id).status.value == "online"

    traps_page = client.get("/traps")
    assert traps_page.status_code == 200
    assert traps_page.text.count("Неизвестно") >= 2
    assert "Движок: Онлайн · агент: Офлайн" in traps_page.text

    assert client.post(
        "/agent/v1/heartbeat",
        headers=agent_headers,
        json={"agent_version": "test", "queue_depth": 0},
    ).status_code == 200
    heartbeat_only = {item["id"]: item for item in client.get("/api/v1/traps").json()}
    assert heartbeat_only[str(first_id)]["status"] == "unknown"
    assert heartbeat_only[str(first_id)]["host_status"] == "online"

    recovered_report = {
        "statuses": [
            {"instance_id": str(first_id), "state": "online", "config_version": 1},
            {"instance_id": str(second_id), "state": "offline", "config_version": 1},
        ]
    }
    assert client.post("/agent/v1/status", headers=agent_headers, json=recovered_report).status_code == 200
    recovered = {item["id"]: item for item in client.get("/api/v1/traps").json()}
    assert recovered[str(first_id)]["status"] == "online"
    assert recovered[str(second_id)]["status"] == "offline"
    assert recovered[str(second_id)]["reported_status"] == "offline"

    assert client.post("/agent/v1/status", headers=agent_headers, json=online_report).status_code == 200
    restored = {item["id"]: item for item in client.get("/api/v1/traps").json()}
    assert {restored[str(item_id)]["status"] for item_id in (first_id, second_id)} == {"online"}


def test_status_pages_include_authenticated_automatic_refresh(client):
    with SessionLocal() as db:
        _, _, instance, _ = provision(db, "status-ui")
        instance_id = instance.id
    login(client)

    hosts = client.get("/hosts")
    traps = client.get("/traps")
    console = client.get("/static/console.js")
    dashboard_script = client.get("/static/events.js")

    assert hosts.status_code == traps.status_code == 200
    assert 'data-host-status-id=' in hosts.text
    assert f'data-trap-status-id="{instance_id}"' in traps.text
    assert 'fetch("/api/v1/hosts"' in console.text
    assert 'fetch("/api/v1/traps"' in console.text
    assert "window.setInterval(refreshStatusTables, 15000)" in console.text
    assert "window.setInterval" in dashboard_script.text
    assert "loadHosts();" in dashboard_script.text


def test_sqlite_queue_survives_restart_and_deletes_only_acknowledged(tmp_path):
    path = tmp_path / "agent-state" / "queue.sqlite3"
    first = DurableQueue(str(path))
    event_one = {"external_id": str(uuid.uuid4()), "value": 1}
    event_two = {"external_id": str(uuid.uuid4()), "value": 2}
    first.enqueue(event_one)
    first.enqueue(event_two)
    first.connection.close()

    restarted = DurableQueue(str(path))
    assert [item["external_id"] for item in restarted.pending(10)] == [event_one["external_id"], event_two["external_id"]]
    restarted.acknowledge([event_one["external_id"]])
    restarted.connection.close()

    again = DurableQueue(str(path))
    assert [item["external_id"] for item in again.pending(10)] == [event_two["external_id"]]
