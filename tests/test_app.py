import csv
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from html import unescape
from io import StringIO
from time import perf_counter
from types import SimpleNamespace

os.environ.setdefault("SECRET_KEY", "test-only-secret-key-that-is-longer-than-32-characters")

from tests.database_safety import configure_test_database_environment, reset_test_schema

configure_test_database_environment()

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.database import Base, SessionLocal, engine
from app.event_view import assess_source_risk
from app.main import app
from app.models import Alert, AgentIdentity, AuditEntry, Event, HoneypotInstance, Host, HostStatus, TrapProfile, TrapStatus, User, UserRole
from app.routes import ui as ui_routes
from app.security import hash_password


@pytest.fixture(autouse=True)
def clean_database():
    reset_test_schema(Base, engine)
    with SessionLocal() as db:
        db.add_all(
            [
                User(
                    username="admin",
                    email="admin@example.com",
                    role=UserRole.ADMIN,
                    password_hash=hash_password("Correct-Horse-123"),
                ),
                User(
                    username="observer",
                    email="observer@example.com",
                    role=UserRole.OBSERVER,
                    password_hash=hash_password("Observer-Pass-123"),
                ),
            ]
        )
        db.commit()
    yield


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient, username="admin", password="Correct-Horse-123"):
    page = client.get("/login")
    assert page.status_code == 200
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=False,
    )


def csrf(client: TestClient) -> str:
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 200
    return response.json()["csrf_token"]


def profile_payload(name="SSH Low"):
    return {
        "name": name,
        "description": "Изолированная тестовая конфигурация",
        "interaction_level": "low",
        "services": [{"name": "ssh", "protocol": "tcp", "port": 22, "banner": "OpenSSH"}],
        "bait_credentials": [{"username": "service", "password": "decoy-only"}],
        "logging": {
            "capture_connections": True,
            "capture_credentials": True,
            "capture_commands": True,
            "capture_payloads": False,
        },
        "masking": {
            "endpoint_path": "/assets/telemetry",
            "process_name": "system-metrics",
            "install_path": "/opt/system-metrics",
            "response_delay_ms": 0,
        },
    }


def seed_ui_events(count=25):
    timestamp = datetime(2026, 1, 2, 3, 0, 0, tzinfo=timezone.utc)
    with SessionLocal() as db:
        profile = TrapProfile(
            name="Events UI profile",
            interaction_level="medium",
            services=[],
            bait_credentials=[],
            logging={},
            masking={},
        )
        host = Host(name="events-ui-host", management_address="192.0.2.20")
        primary = HoneypotInstance(name="events-primary", host=host, profile=profile)
        secondary = HoneypotInstance(name="events-secondary", host=host, profile=profile)
        db.add_all([profile, host, primary, secondary])
        db.flush()
        events = []
        for index in range(count):
            is_http = index % 2 == 0
            data = (
                {
                    "url": f"/private/report-{index}?password=url-secret-{index}",
                    "method": "GET",
                    "password": f"web-secret-{index}",
                }
                if is_http
                else {
                    "command": f"whoami-{index}",
                    "credentials": {"username": "guest", "password": f"ssh-secret-{index}"},
                }
            )
            event = Event(
                external_id=f"events-ui-{index:03d}",
                instance_id=primary.id if index < count - 1 else secondary.id,
                event_type="medium.http_request" if is_http else "medium.ssh_command",
                source_ip="192.0.2.10" if index < count - 1 else "198.51.100.25",
                occurred_at=timestamp + timedelta(minutes=index),
                created_at=timestamp + timedelta(minutes=index),
                data=data,
                is_test=False,
            )
            db.add(event)
            events.append(event)
        db.commit()
        return {
            "primary_id": primary.id,
            "secondary_id": secondary.id,
            "first_event_id": events[0].id,
            "second_event_id": events[1].id if len(events) > 1 else events[0].id,
        }


def test_health_and_unauthorized_access(client):
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").status_code == 200
    assert client.get("/api/v1/profiles").status_code == 401
    ui = client.get("/profiles", follow_redirects=False)
    assert ui.status_code == 303
    assert ui.headers["location"] == "/login"


def test_login_correct_and_incorrect_password(client):
    failed = login(client, password="definitely-wrong")
    assert failed.status_code == 401
    assert "Неверное имя пользователя или пароль" in failed.text

    successful = login(client)
    assert successful.status_code == 303
    assert successful.headers["location"] == "/"
    assert client.get("/").status_code == 200
    assert "Подозрительно тихо" in client.get("/").text
    assert "Подозрительно тихо" in client.get("/events").text


def test_ui_uses_one_moscow_time_format_without_changing_api_utc(client):
    timestamp = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    with SessionLocal() as db:
        profile = TrapProfile(
            name="Moscow time profile",
            interaction_level="low",
            services=[{"name": "http", "protocol": "tcp", "port": 18081, "banner": "nginx"}],
            bait_credentials=[],
            logging={},
            masking={},
            updated_at=timestamp,
        )
        host = Host(
            name="moscow-time-host",
            management_address="192.0.2.50",
            last_seen_at=timestamp,
        )
        trap = HoneypotInstance(
            name="moscow-time-trap",
            host=host,
            profile=profile,
            last_seen_at=timestamp,
        )
        db.add_all([profile, host, trap])
        db.flush()
        profile_id = profile.id
        db.add_all(
            [
                Event(
                    external_id=str(uuid.uuid4()),
                    instance_id=trap.id,
                    event_type="low.http_request",
                    source_ip="192.0.2.10",
                    occurred_at=timestamp,
                    created_at=timestamp,
                    data={},
                    is_test=False,
                ),
                AuditEntry(
                    action="ui.time_test",
                    entity_type="test",
                    created_at=timestamp,
                ),
            ]
        )
        db.commit()

    assert login(client).status_code == 303
    expected = "02.01.2026 06:04:05 МСК"
    dashboard = client.get("/")
    assert expected in dashboard.text
    assert "Подтверждено БД" not in dashboard.text
    assert "Мониторинг ловушек, подключённых агентов и событий безопасности в реальном времени" in dashboard.text
    assert expected in client.get("/profiles").text
    assert expected in client.get("/hosts").text
    assert expected in client.get("/traps").text

    api_event = client.get("/api/v1/events").json()[0]
    assert api_event["occurred_at"].startswith("2026-01-02T03:04:05")
    assert "06:04:05" not in api_event["occurred_at"]

    enrollment = client.post(
        "/hosts/enroll",
        data={
            "host_name": "moscow-enrollment-host",
            "management_address": "192.0.2.51",
            "instance_name": "moscow-enrollment-trap",
            "profile_id": str(profile_id),
            "ttl_minutes": "15",
            "csrf_token": csrf(client),
        },
    )
    assert enrollment.status_code == 200
    assert re.search(r"Истекает: \d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2} МСК", enrollment.text)


def test_center_ui_redesign_preserves_navigation_data_and_trap_controls(client):
    seed_ui_events(2)

    login_page = client.get("/login")
    assert "СЫРНЫЕ ШАРИКИ" in login_page.text
    assert "Центр управления" in login_page.text
    assert "Совершенно обычная инфраструктура." in login_page.text
    assert "НЕ ПАЛИМСЯ" not in login_page.text
    assert "HoneyForge" not in login_page.text
    assert login(client).status_code == 303

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "СЫРНЫЕ ШАРИКИ" in dashboard.text
    assert "Центр управления" in dashboard.text
    assert "НЕ ПАЛИМСЯ" not in dashboard.text
    assert "HoneyForge" not in dashboard.text
    assert '/static/styles.css?v=20261015.3' in dashboard.text
    for asset in ("stage2.css", "events-page.css"):
        expected_version = "20261015.3" if asset == "stage2.css" else "20261015.2"
        assert f'/static/{asset}?v={expected_version}' in dashboard.text
    assert '/static/console.js?v=20261012.1' in dashboard.text
    assert '/static/events.js?v=20261015.1' in dashboard.text
    for path, label in (("/", "Обзор"), ("/infrastructure", "Карта"), ("/analytics", "Аналитика"), ("/events", "События"), ("/profiles", "Профили"), ("/hosts", "Хосты"), ("/traps", "Ловушки")):
        assert f'href="{path}"' in dashboard.text
        assert label in dashboard.text
    assert dashboard.text.count('class="nav-icon" width="17" height="17"') == 9
    assert "/attack-geography" not in dashboard.text
    assert "GeoIP" not in dashboard.text
    assert client.get("/attack-geography").status_code == 404
    assert client.get("/static/attack-geography.css").status_code == 404
    assert client.get("/static/attack-geography.js").status_code == 404
    assert 'src="/static/honeyforge-mark.jpg?v=20261011.13" width="72" height="72"' in dashboard.text
    assert dashboard.text.count('action="/logout"') == 1
    topbar = dashboard.text.split('<header class="topbar">', 1)[1].split("</header>", 1)[0]
    assert "Быстрый поиск" in topbar
    assert 'id="stream-status"' in topbar
    assert "admin" not in topbar
    assert 'action="/logout"' not in topbar
    sidebar_footer = dashboard.text.split('<div class="sidebar-footer">', 1)[1].split("</aside>", 1)[0]
    assert "admin" in sidebar_footer
    assert "Администратор" in sidebar_footer
    assert 'action="/logout"' in sidebar_footer
    assert 'id="command-palette"' in dashboard.text
    assert 'id="shortcuts-dialog"' in dashboard.text
    assert 'id="sidebar-toggle"' in dashboard.text
    assert 'id="activity-chart"' in dashboard.text
    assert 'id="period-switch"' in dashboard.text
    assert 'data-period="1"' in dashboard.text
    assert 'data-period="7" aria-pressed="true"' in dashboard.text
    assert 'data-period="30"' in dashboard.text
    assert 'id="protocol-content"' in dashboard.text
    assert 'id="source-chart"' in dashboard.text
    assert 'id="top-sources"' in dashboard.text
    assert 'id="host-summary"' in dashboard.text
    assert 'id="period-event-count">—<' in dashboard.text
    assert 'id="unique-source-count">—<' in dashboard.text
    assert "Оперативная сводка" not in dashboard.text
    assert 'class="kpi-strip"' in dashboard.text
    for category in ("hosts", "traps", "events", "sources"):
        assert f'class="kpi-item kpi-{category}"' in dashboard.text
    assert dashboard.text.count('class="kpi-icon" width="18" height="18"') == 4
    assert "Последние события" in dashboard.text
    assert "Последние административные действия" in dashboard.text
    assert dashboard.text.index("Активность событий") < dashboard.text.index("Последние события")
    assert dashboard.text.index("Последние события") < dashboard.text.index("Уникальные источники")
    assert dashboard.text.index("Топ источников") < dashboard.text.index("Состояние хостов")
    assert "event-type event-type-http" in dashboard.text
    assert "event-type event-type-ssh" in dashboard.text

    events = client.get("/events")
    assert "События — СЫРНЫЕ ШАРИКИ" in events.text
    assert "HoneyForge" not in events.text
    assert 'aria-current="page"' in events.text
    assert 'id="event-filters"' in events.text
    assert 'class="filter-panel-heading"' in events.text
    assert 'class="panel data-panel events-table-panel"' in events.text
    assert 'class="events-table sticky-last-column"' in events.text
    assert "event-type event-type-http" in events.text
    assert "event-type event-type-ssh" in events.text
    assert "Открыть" in events.text
    assert 'class="event-table-row ' in events.text
    assert 'data-detail-url=' in events.text

    profiles = client.get("/profiles")
    assert "Профили — СЫРНЫЕ ШАРИКИ" in profiles.text
    assert "HoneyForge" not in profiles.text
    assert "Events UI profile" in profiles.text
    assert "Версия" in profiles.text
    assert 'class="panel data-panel profiles-panel"' in profiles.text
    assert 'class="data-table profiles-table sticky-last-column"' in profiles.text
    profile_form = client.get("/profiles/new")
    assert profile_form.status_code == 200
    assert 'class="profile-form configuration-form"' in profile_form.text
    assert profile_form.text.count('class="form-section-heading"') == 3

    hosts = client.get("/hosts")
    assert "Хосты — СЫРНЫЕ ШАРИКИ" in hosts.text
    assert "HoneyForge" not in hosts.text
    assert "events-ui-host" in hosts.text
    assert 'class="status-pill status-offline"' in hosts.text
    assert 'class="panel data-panel hosts-panel"' in hosts.text
    enrollment = client.get("/hosts/enroll")
    assert enrollment.status_code == 200
    assert 'class="profile-form configuration-form"' in enrollment.text

    traps = client.get("/traps")
    assert "Ловушки — СЫРНЫЕ ШАРИКИ" in traps.text
    assert "HoneyForge" not in traps.text
    for command in ("start_trap", "stop_trap", "apply_config"):
        assert f'value="{command}"' in traps.text
    assert 'class="panel data-panel traps-panel"' in traps.text
    assert 'class="data-table traps-table sticky-last-column"' in traps.text
    assert 'class="button success small"' in traps.text
    trap_form = client.get("/traps/new")
    assert trap_form.status_code == 200
    assert 'class="panel form-panel compact-form-panel"' in trap_form.text
    assert '<button class="button primary" type="submit">Создать</button>' in trap_form.text

    stylesheet = client.get("/static/styles.css")
    assert stylesheet.status_code == 200
    for color in (
        "#0b0d12", "#101724", "#191e29", "#232c3d", "#35445a", "#283548",
        "#f2f6ff", "#b5c4da", "#8496b0", "#6495ff", "#3b9eff",
        "#a78bfa", "#f3b85c", "#e879b9", "#42d69a", "#f16d7a",
    ):
        assert color in stylesheet.text
    for old_color in ("#151d24", "#19242d", "#263541", "#2d3d4b", "#465866", "#34d3b1"):
        assert old_color not in stylesheet.text
    for stat_color in ("#ffca58", "#f77f50", "#ef476f", "#84cc75", "#e9c46a"):
        assert stat_color in stylesheet.text
    for protocol_color in ("#38bdf8", "#f59e0b", "#94a3b8"):
        assert protocol_color in stylesheet.text
    assert "--stat-protocol-http: var(--protocol-http)" in stylesheet.text
    assert "--stat-protocol-ssh: var(--protocol-ssh)" in stylesheet.text
    assert "--stat-protocol-unknown: var(--protocol-unknown)" in stylesheet.text
    assert "rgba(132, 204, 117, 0.14)" in stylesheet.text
    assert "#2db8a6" not in stylesheet.text
    assert "svg.nav-icon" in stylesheet.text
    assert "object-fit: cover" in stylesheet.text
    assert ".brand .brand-image" in stylesheet.text
    assert "width: 72px" in stylesheet.text
    assert "flex-direction: column" in stylesheet.text
    assert ".button.success" in stylesheet.text
    assert ".configuration-form" in stylesheet.text
    assert ".data-table td" in stylesheet.text
    assert ".sticky-last-column th:last-child" in stylesheet.text
    assert ".alert-event-link" in stylesheet.text
    assert ".status-offline { color: var(--error)" in stylesheet.text
    assert "linear-gradient" not in stylesheet.text
    assert "radial-gradient" not in stylesheet.text

    assert ".kpi-events { --kpi-accent: var(--accent-events); }" in stylesheet.text
    assert "tbody tr:nth-child(even)" in stylesheet.text
    assert "max-width: none" in stylesheet.text
    assert "font-size: 25px" in stylesheet.text
    assert 'font: 750 33px/1.05 "Cascadia Code"' in stylesheet.text

    console_script = client.get("/static/console.js?v=20261012.1")
    assert console_script.status_code == 200
    assert "nePalimsyaSidebarCollapsed" in console_script.text
    assert 'timeZone: "Europe/Moscow"' in console_script.text
    assert "window.centerTime" in console_script.text
    assert "Control+K" not in console_script.text
    assert 'event.key === "/"' in console_script.text

    analytics_script = client.get("/static/events.js?v=20261015.1")
    assert analytics_script.status_code == 200
    assert 'const API_LIMIT = 500' in analytics_script.text
    assert 'from_time: new Date(start).toISOString()' in analytics_script.text
    assert 'to_time: new Date(now).toISOString()' in analytics_script.text
    assert 'fetch(`/api/v1/events?' in analytics_script.text
    assert 'fetch("/api/v1/hosts"' in analytics_script.text
    assert 'const { parseTimestamp, formatMoscowTime } = window.centerTime' in analytics_script.text
    assert 'payload.length === API_LIMIT' in analytics_script.text
    assert 'Math.random' not in analytics_script.text
    assert 'HTTP: themeColor("--stat-protocol-http")' in analytics_script.text
    assert 'SSH: themeColor("--stat-protocol-ssh")' in analytics_script.text
    assert 'TCP: themeColor("--stat-protocol-tcp")' in analytics_script.text
    assert 'UDP: themeColor("--stat-protocol-udp")' in analytics_script.text
    assert 'UNKNOWN: themeColor("--stat-protocol-unknown")' in analytics_script.text
    assert 'protocol === "Не определён"' in analytics_script.text
    assert "РќРµ РѕРїСЂРµРґРµР»С‘РЅ" not in analytics_script.text
    assert 'themeColor("--protocol-http")' not in analytics_script.text
    assert "protocolColors[protocol]" in analytics_script.text
    assert "protocolColors[index" not in analytics_script.text
    assert 'preserveAspectRatio: "xMidYMid meet"' in analytics_script.text
    assert '"ResizeObserver" in window' in analytics_script.text
    assert 'querySelectorAll(".event-row").length > 8' in analytics_script.text
    assert 'totalLabel.textContent = "СОБЫТИЙ"' in analytics_script.text
    assert 'event-type-${eventProtocolClass}' in analytics_script.text

    technical_styles = client.get("/static/stage2.css?v=20261015.3")
    assert technical_styles.status_code == 200
    assert ".protocol-row > span" in technical_styles.text
    assert "white-space: nowrap" in technical_styles.text
    assert ".protocol-content { grid-template-columns: 1fr; justify-items: center" in technical_styles.text
    assert ".honeytoken-workspace.is-empty" in technical_styles.text
    assert "grid-template-columns: minmax(350px, .95fr) minmax(280px, 1.05fr)" in technical_styles.text
    assert ".honeytoken-create-form" in technical_styles.text

    source_analytics_styles = client.get("/static/source-analytics.css?v=20261015.2")
    assert source_analytics_styles.status_code == 200
    assert "background: var(--protocol-http)" in source_analytics_styles.text
    assert "background: var(--protocol-ssh)" in source_analytics_styles.text
    assert "background: var(--protocol-unknown)" in source_analytics_styles.text
    assert ".protocol-bar-row" in source_analytics_styles.text
    assert "grid-template-columns: minmax(90px, 1fr) minmax(92px, auto) 64px" in source_analytics_styles.text
    assert ".protocol-row > div:first-child" not in source_analytics_styles.text
    assert ".analytics-grid" in technical_styles.text
    assert ".protocol-segment" in technical_styles.text
    assert ".host-summary-row" in technical_styles.text
    assert ".chart-bar { fill: var(--stat-activity)" in technical_styles.text
    assert ".chart-line { fill: none; stroke: var(--stat-green)" in technical_styles.text
    assert ".chart-area { fill: var(--stat-source-area)" in technical_styles.text
    for index, color in enumerate(("yellow", "orange", "coral", "green", "gold"), start=1):
        assert f".source-rank:nth-child({index}) .source-rank-bar i {{ background: var(--stat-{color}); }}" in technical_styles.text
    assert ".chart-bar { fill: var(--accent-events)" not in technical_styles.text
    assert ".chart-line { fill: none; stroke: var(--accent-hosts)" not in technical_styles.text
    assert ".protocol-total" in technical_styles.text
    assert ".event-type-http::before" in technical_styles.text
    assert ".operational-grid { align-items: start; }" in technical_styles.text
    assert ".host-summary { padding: 5px 14px; }" in technical_styles.text
    assert ".event-feed { overflow: visible; }" in technical_styles.text
    assert "@media (max-width: 1100px)" in technical_styles.text
    assert ".honeytoken-workspace.is-empty .honeytoken-create-form" in technical_styles.text
    assert "linear-gradient" not in technical_styles.text
    assert "radial-gradient" not in technical_styles.text

    events_styles = client.get("/static/events-page.css?v=20261015.2")
    assert events_styles.status_code == 200
    assert ".filter-panel-heading" in events_styles.text
    assert ".events-table .event-type" in events_styles.text
    assert "width: min(600px, 94vw)" in events_styles.text
    assert ".event-drawer.event-detail-test" in events_styles.text
    assert ".timeline-columns," in events_styles.text
    assert "max-height: 344px" in events_styles.text
    assert "grid-template-columns: 74px 84px 74px minmax(150px, .8fr)" in events_styles.text

    mark = client.get("/static/honeyforge-mark.jpg?v=20261011.13")
    assert mark.status_code == 200
    assert mark.headers["content-type"] == "image/jpeg"
    assert mark.content.startswith(b"\xff\xd8\xff")

    client.post("/logout", data={"csrf_token": csrf(client)})
    assert login(client, username="observer", password="Observer-Pass-123").status_code == 303
    forbidden = client.get("/traps/new")
    assert forbidden.status_code == 403
    assert "Ошибка — СЫРНЫЕ ШАРИКИ" in forbidden.text
    assert "HoneyForge" not in forbidden.text


def test_dashboard_limits_visible_recent_events_without_changing_event_storage(client):
    seed_ui_events(12)
    assert login(client).status_code == 303

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert dashboard.text.count('class="event-row"') == 8
    assert 'data-event-id="events-ui-011"' in dashboard.text
    assert 'data-event-id="events-ui-004"' in dashboard.text
    assert 'data-event-id="events-ui-003"' not in dashboard.text

    with SessionLocal() as db:
        assert len(list(db.scalars(select(Event)))) == 12


def test_events_api_masks_sensitive_data_by_role_without_changing_storage(client):
    seeded = seed_ui_events(2)
    operator_password = "Operator-Pass-123"
    with SessionLocal() as db:
        db.add(
            User(
                username="operator",
                email="operator@example.com",
                role=UserRole.OPERATOR,
                password_hash=hash_password(operator_password),
            )
        )
        events = list(db.scalars(select(Event).order_by(Event.occurred_at)))
        for index, event in enumerate(events):
            event.external_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"events-api-rbac-{index}"))
        db.commit()
        stored_before = {event.id: event.data for event in events}

    assert client.get("/api/v1/events").status_code == 401

    sensitive_values = ("web-secret-0", "url-secret-0", "ssh-secret-1")
    leaked_values_by_role = {}
    for username, password in (
        ("observer", "Observer-Pass-123"),
        ("operator", operator_password),
    ):
        assert login(client, username=username, password=password).status_code == 303
        response = client.get("/api/v1/events")
        assert response.status_code == 200
        leaked_values_by_role[username] = [
            value for value in sensitive_values if value in response.text
        ]

        events_by_id = {event["id"]: event for event in response.json()}
        assert set(events_by_id) == {
            str(seeded["first_event_id"]),
            str(seeded["second_event_id"]),
        }
        http_event = events_by_id[str(seeded["first_event_id"])]
        ssh_event = events_by_id[str(seeded["second_event_id"])]
        assert http_event["event_type"] == "medium.http_request"
        assert http_event["source_ip"] == "192.0.2.10"
        assert http_event["data"]["method"] == "GET"
        assert "/private/report-0" in http_event["data"]["url"]
        assert ssh_event["event_type"] == "medium.ssh_command"
        assert ssh_event["data"]["command"] == "whoami-1"
        assert ssh_event["data"]["credentials"]["username"] == "guest"

        client.post("/logout", data={"csrf_token": csrf(client)})

    assert login(client).status_code == 303
    admin_response = client.get("/api/v1/events")
    assert admin_response.status_code == 200
    admin_events = {event["id"]: event for event in admin_response.json()}
    assert admin_events[str(seeded["first_event_id"])]["data"] == stored_before[seeded["first_event_id"]]
    assert admin_events[str(seeded["second_event_id"])]["data"] == stored_before[seeded["second_event_id"]]

    with SessionLocal() as db:
        stored_after = {
            event.id: event.data
            for event in db.scalars(select(Event).order_by(Event.occurred_at))
        }
    assert stored_after == stored_before
    assert leaked_values_by_role == {"observer": [], "operator": []}


def test_dashboard_analytics_sources_are_existing_authorized_apis(client):
    seed_ui_events(4)
    expected_external_ids = {
        index: str(uuid.uuid5(uuid.NAMESPACE_URL, f"events-ui-{index:03d}"))
        for index in range(4)
    }
    with SessionLocal() as db:
        seeded_events = list(db.scalars(select(Event).order_by(Event.occurred_at)))
        for index, event in enumerate(seeded_events):
            event.external_id = expected_external_ids[index]
        db.commit()
    assert login(client, username="observer", password="Observer-Pass-123").status_code == 303

    events = client.get(
        "/api/v1/events",
        params={
            "from_time": "2026-01-02T03:01:00+00:00",
            "to_time": "2026-01-02T03:02:00+00:00",
            "limit": 500,
        },
    )
    assert events.status_code == 200
    assert [event["external_id"] for event in events.json()] == [expected_external_ids[2], expected_external_ids[1]]

    hosts = client.get("/api/v1/hosts")
    assert hosts.status_code == 200
    assert [host["name"] for host in hosts.json()] == ["events-ui-host"]


def test_events_page_requires_login_and_preserves_read_rbac(client):
    seeded = seed_ui_events(2)
    unauthorized = client.get("/events", follow_redirects=False)
    assert unauthorized.status_code == 303
    assert unauthorized.headers["location"] == "/login"

    assert login(client, username="observer", password="Observer-Pass-123").status_code == 303
    listing = client.get("/events")
    assert listing.status_code == 200
    assert 'href="/events"' in listing.text
    assert "События" in listing.text
    detail = client.get(f"/events?event_id={seeded['second_event_id']}")
    assert detail.status_code == 200
    assert 'id="event-detail" role="dialog"' in detail.text
    assert 'class="drawer-backdrop"' in detail.text
    assert 'data-copy-target="#event-json-data"' in detail.text
    assert "whoami-1" in detail.text
    assert "[СКРЫТО]" in detail.text
    assert "ssh-secret-1" not in detail.text

    client.post("/logout", data={"csrf_token": csrf(client)})
    assert login(client).status_code == 303
    admin_detail = client.get(f"/events?event_id={seeded['second_event_id']}")
    assert admin_detail.status_code == 200
    assert "ssh-secret-1" in admin_detail.text


def test_events_page_correlates_attack_timelines_without_changing_events(client):
    timestamp = datetime(2026, 2, 3, 10, 0, 0, tzinfo=timezone.utc)
    source_a = "203.0.113.10"
    source_b = "198.51.100.40"
    operator_password = "Timeline-Operator-123"
    event_specs = [
        (0, source_a, "medium.http_request", {"method": "GET", "path": "/admin?password=timeline-secret"}),
        (
            1,
            source_a,
            "medium.http_auth",
            {"path": "/admin/login", "username": "guest", "password": "auth-secret-1", "result": "rejected"},
        ),
        (
            2,
            source_a,
            "medium.ssh_auth",
            {"username": "guest", "password": "auth-secret-2", "result": "rejected"},
        ),
        (3, source_a, "medium.ssh_session", {"action": "opened"}),
        (4, source_a, "medium.ssh_command", {"command": "whoami"}),
        (5, source_b, "medium.http_request", {"method": "GET", "path": "/status?view=public"}),
        (16, source_a, "medium.ssh_command", {"command": "pwd"}),
    ]
    with SessionLocal() as db:
        profile = TrapProfile(
            name="Correlation profile",
            interaction_level="medium",
            services=[],
            bait_credentials=[],
            logging={},
            masking={},
        )
        host = Host(name="correlation-host", management_address="192.0.2.70")
        trap = HoneypotInstance(name="correlation-trap", host=host, profile=profile)
        db.add_all(
            [
                profile,
                host,
                trap,
                User(
                    username="timeline-operator",
                    email="timeline-operator@example.com",
                    role=UserRole.OPERATOR,
                    password_hash=hash_password(operator_password),
                ),
            ]
        )
        db.flush()
        seeded_events = []
        for index, (minutes, source_ip, event_type, data) in enumerate(event_specs):
            event = Event(
                external_id=f"correlation-{index:03d}",
                instance_id=trap.id,
                event_type=event_type,
                source_ip=source_ip,
                occurred_at=timestamp + timedelta(minutes=minutes),
                created_at=timestamp + timedelta(minutes=minutes),
                data=data,
                is_test=False,
            )
            db.add(event)
            seeded_events.append(event)
        db.commit()
        first_event_id = seeded_events[0].id
        stored_before = {
            event.id: (event.external_id, event.data)
            for event in seeded_events
        }

    for username, password in (
        ("observer", "Observer-Pass-123"),
        ("timeline-operator", operator_password),
    ):
        assert login(client, username=username, password=password).status_code == 303
        response = client.get("/events")
        assert response.status_code == 200
        assert 'id="attack-correlation"' in response.text
        assert "IP — наблюдаемый сетевой адрес, а не подтверждённая личность" in response.text
        assert response.text.count(f'data-source-ip="{source_a}"') == 2
        assert response.text.count(f'data-source-ip="{source_b}"') == 1
        for earlier, later in zip(range(4), range(1, 5)):
            assert response.text.index(f'data-timeline-event-id="correlation-{earlier:03d}"') < response.text.index(
                f'data-timeline-event-id="correlation-{later:03d}"'
            )
        assert 'data-signal="repeated_failed_auth"' in response.text
        assert 'data-signal="admin_path"' in response.text
        assert 'data-signal="ssh_commands"' in response.text
        assert 'class="timeline-columns"' in response.text
        assert 'class="timeline-date event-time"' in response.text
        assert 'class="timeline-clock event-time"' in response.text
        assert 'class="timeline-protocol event-type event-type-http">HTTP</span>' in response.text
        assert 'class="timeline-protocol event-type event-type-ssh">SSH</span>' in response.text
        assert 'class="timeline-action">HTTP-запрос</span>' in response.text
        assert "whoami" in response.text
        assert "view=public" in response.text
        for secret in ("timeline-secret", "auth-secret-1", "auth-secret-2"):
            assert secret not in response.text
        client.post("/logout", data={"csrf_token": csrf(client)})

    assert login(client).status_code == 303
    admin_response = client.get("/events", params={"event_id": str(first_event_id)})
    assert admin_response.status_code == 200
    assert "timeline-secret" in admin_response.text

    with SessionLocal() as db:
        stored_after = {
            event.id: (event.external_id, event.data)
            for event in db.scalars(select(Event).order_by(Event.occurred_at))
        }
    assert stored_after == stored_before


def test_events_page_filters_and_moscow_time_range(client):
    seeded = seed_ui_events(4)
    assert login(client).status_code == 303

    filtered = client.get(
        "/events",
        params={
            "event_type": "medium.ssh_command",
            "instance_id": str(seeded["primary_id"]),
            "source_ip": "192.0.2.10",
            "from_time": "2026-01-02T06:01:00",
            "to_time": "2026-01-02T06:01:00",
        },
    )
    assert filtered.status_code == 200
    assert "Найдено: 1" in filtered.text
    assert "whoami-1" in filtered.text
    assert "02.01.2026 06:01:00 МСК" in filtered.text
    assert "report-0" not in filtered.text
    assert "whoami-3" not in filtered.text

    invalid = client.get("/events", params={"from_time": "2026-01-03T00:00", "to_time": "2026-01-02T00:00"})
    assert invalid.status_code == 422


def test_events_page_searches_http_urls_and_ssh_commands(client):
    seed_ui_events(5)
    assert login(client).status_code == 303

    by_url = client.get("/events", params={"q": "/private/report-2"})
    assert by_url.status_code == 200
    assert "Найдено: 1" in by_url.text
    assert "/private/report-2" in by_url.text
    assert "/private/report-0" not in by_url.text
    assert "url-secret-2" not in by_url.text

    by_command = client.get("/events", params={"q": "whoami-3"})
    assert by_command.status_code == 200
    assert "Найдено: 1" in by_command.text
    assert "whoami-3" in by_command.text

    literal_wildcard = client.get("/events", params={"q": "%"})
    assert literal_wildcard.status_code == 200
    assert "Найдено: 0" in literal_wildcard.text


def test_events_page_ignores_empty_optional_filters_and_finds_only_hfcheck_86(client):
    seed_ui_events(5)
    with SessionLocal() as db:
        matched = db.scalar(select(Event).where(Event.external_id == "events-ui-001"))
        matched.data = {"command": "printf hfcheck_86", "session": "verification"}
        db.commit()
    assert login(client).status_code == 303

    response = client.get(
        "/events",
        params={
            "event_type": "",
            "instance_id": "",
            "source_ip": "",
            "from_time": "",
            "to_time": "",
            "q": "hfcheck_86",
            "event_id": "",
        },
    )
    assert response.status_code == 200
    assert "Найдено: 1" in response.text
    assert "printf hfcheck_86" in response.text
    assert "whoami-3" not in response.text
    assert "/private/report-2" not in response.text
    assert 'id="event-filters"' in response.text
    assert 'src="/static/event-filters.js?v=20261011.13"' in response.text
    assert '>Сбросить</a>' in response.text


def test_events_page_uses_server_side_pagination(client):
    seed_ui_events(25)
    assert login(client).status_code == 303

    first = client.get("/events", params={"page": 1, "page_size": 10})
    assert first.status_code == 200
    assert "Страница 1 из 3" in first.text
    assert "/private/report-24" in first.text
    assert "whoami-15" in first.text
    assert "/private/report-14" not in first.text
    event_links = re.findall(r'href="(/events\?[^\"]+)"', first.text)
    assert event_links
    assert all("instance_id=" not in link for link in event_links)

    third = client.get("/events", params={"page": 3, "page_size": 10})
    assert third.status_code == 200
    assert "Страница 3 из 3" in third.text
    assert "/private/report-4" in third.text
    assert "/private/report-24" not in third.text


def test_events_page_combines_search_filter_pagination_and_details(client):
    seeded = seed_ui_events(25)
    assert login(client).status_code == 303

    filtered = client.get(
        "/events",
        params={
            "event_type": "medium.http_request",
            "instance_id": str(seeded["primary_id"]),
            "source_ip": "192.0.2.10",
            "q": "report-2",
            "page": 1,
            "page_size": 10,
        },
    )
    assert filtered.status_code == 200
    assert "Найдено: 3" in filtered.text
    assert "/private/report-22" in filtered.text
    assert "/private/report-20" in filtered.text
    assert "/private/report-2" in filtered.text

    detail = client.get(
        "/events",
        params={
            "event_type": "medium.http_request",
            "instance_id": str(seeded["primary_id"]),
            "source_ip": "192.0.2.10",
            "q": "report-0",
            "page": 1,
            "page_size": 10,
            "event_id": str(seeded["first_event_id"]),
        },
    )
    assert detail.status_code == 200
    assert "Исходный JSON" in detail.text
    assert "events-ui-000" in detail.text
    assert 'href="/events?event_type=medium.http_request' in detail.text


def test_events_page_rejects_nonempty_invalid_uuid_filters(client):
    seed_ui_events(1)
    assert login(client).status_code == 303
    assert client.get("/events", params={"instance_id": "not-a-uuid"}).status_code == 422
    assert client.get("/events", params={"event_id": "not-a-uuid"}).status_code == 422


def test_observer_cannot_create_profile(client):
    assert login(client, username="observer", password="Observer-Pass-123").status_code == 303
    response = client.post(
        "/api/v1/profiles",
        headers={"X-CSRF-Token": csrf(client)},
        json=profile_payload(),
    )
    assert response.status_code == 403
    assert client.get("/api/v1/profiles").status_code == 200


def test_admin_can_create_valid_high_profile_and_invalid_service_sets_are_rejected(client):
    assert login(client).status_code == 303
    token = csrf(client)
    payload = profile_payload("Northbridge High")
    payload["interaction_level"] = "high"
    payload["services"] = [
        {"name": "http", "protocol": "tcp", "port": 8084, "banner": "nginx"},
        {"name": "ssh", "protocol": "tcp", "port": 2223, "banner": "SSH-2.0-OpenSSH_9.6p1"},
    ]
    created = client.post("/api/v1/profiles", json=payload, headers={"X-CSRF-Token": token})
    assert created.status_code == 201
    assert created.json()["interaction_level"] == "high"
    assert {service["name"] for service in created.json()["services"]} == {"http", "ssh"}
    assert "High (планируется)" not in client.get(f"/profiles/{created.json()['id']}/edit").text

    invalid = {**payload, "name": "Incomplete High", "services": payload["services"][:1]}
    rejected = client.post("/api/v1/profiles", json=invalid, headers={"X-CSRF-Token": token})
    assert rejected.status_code == 422
    assert "ровно сервисы http и ssh" in rejected.text


def test_infrastructure_map_uses_real_topology_states_counts_and_safe_fields(client):
    now = datetime.now(timezone.utc)
    operator_password = "Map-Operator-Pass-123"
    with SessionLocal() as db:
        low_profile = TrapProfile(
            name="Map Low",
            interaction_level="low",
            services=[],
            bait_credentials=[],
            logging={},
            masking={},
        )
        medium_profile = TrapProfile(
            name="Map Medium",
            interaction_level="medium",
            services=[],
            bait_credentials=[],
            logging={},
            masking={},
        )
        online_a = Host(
            name="map-agent-a",
            management_address="secret-management-a.internal",
            status=HostStatus.ONLINE,
            last_seen_at=now,
        )
        online_b = Host(
            name="map-agent-b",
            management_address="secret-management-b.internal",
            status=HostStatus.ONLINE,
            last_seen_at=now,
        )
        offline = Host(
            name="map-agent-offline",
            management_address="secret-management-offline.internal",
            status=HostStatus.OFFLINE,
            last_seen_at=now - timedelta(hours=2),
        )
        unregistered = Host(
            name="map-agent-unregistered",
            management_address="secret-management-unregistered.internal",
            status=HostStatus.OFFLINE,
        )
        low_trap = HoneypotInstance(
            name="map-low-trap",
            host=online_a,
            profile=low_profile,
            status=TrapStatus.ONLINE,
            last_seen_at=now,
        )
        medium_trap = HoneypotInstance(
            name="map-medium-trap",
            host=online_b,
            profile=medium_profile,
            status=TrapStatus.ONLINE,
            last_seen_at=now,
        )
        offline_trap = HoneypotInstance(
            name="map-offline-trap",
            host=offline,
            profile=medium_profile,
            status=TrapStatus.OFFLINE,
            last_seen_at=now - timedelta(hours=2),
        )
        db.add_all(
            [
                low_profile,
                medium_profile,
                online_a,
                online_b,
                offline,
                unregistered,
                low_trap,
                medium_trap,
                offline_trap,
                User(
                    username="map-operator",
                    email="map-operator@example.com",
                    role=UserRole.OPERATOR,
                    password_hash=hash_password(operator_password),
                ),
            ]
        )
        db.flush()
        identity_secrets = []
        for index, host in enumerate((online_a, online_b, offline), start=1):
            serial = f"private-certificate-serial-{index}"
            fingerprint = str(index) * 64
            pin = f"private-public-key-pin-{index}"
            identity_secrets.extend((serial, fingerprint, pin))
            db.add(
                AgentIdentity(
                    host=host,
                    certificate_serial=serial,
                    certificate_fingerprint_sha256=fingerprint,
                    public_key_pin_sha256=pin,
                    status="active",
                    issued_at=now,
                    expires_at=now + timedelta(days=30),
                    last_seen_at=host.last_seen_at,
                )
            )
        for index in range(2):
            db.add(
                Event(
                    external_id=f"map-event-{index}",
                    instance_id=low_trap.id,
                    event_type="medium.http_request",
                    source_ip="192.0.2.80",
                    occurred_at=now + timedelta(seconds=index),
                    data={"path": f"/map/{index}"},
                )
            )
        db.commit()
        ids = {
            "online_a": online_a.id,
            "online_b": online_b.id,
            "offline": offline.id,
            "unregistered": unregistered.id,
            "low_trap": low_trap.id,
            "medium_trap": medium_trap.id,
            "offline_trap": offline_trap.id,
        }

    assert client.get("/infrastructure", follow_redirects=False).status_code == 303
    assert login(client).status_code == 303
    response = client.get("/infrastructure")
    assert response.status_code == 200
    assert "Карта инфраструктуры — СЫРНЫЕ ШАРИКИ" in response.text
    assert response.text.count('data-center-connected="true"') == 2
    assert response.text.count('data-edge-from="center"') == 2
    assert f'data-agent-id="{ids["offline"]}" data-center-connected="false"' in response.text
    assert f'data-agent-id="{ids["unregistered"]}" data-center-connected="false"' in response.text
    assert f'data-edge-to="agent-{ids["offline"]}"' not in response.text
    assert f'data-edge-to="agent-{ids["unregistered"]}"' not in response.text
    assert f'data-assignment-trap-id="{ids["low_trap"]}"' in response.text
    assert f'data-assignment-trap-id="{ids["medium_trap"]}"' in response.text
    assert f'data-assignment-trap-id="{ids["offline_trap"]}"' in response.text
    low_node = response.text.split(f'data-node-id="trap-{ids["low_trap"]}"', 1)[1].split("</button>", 1)[0]
    assert 'data-node-kind="Ловушка LOW"' in low_node
    assert 'data-node-events="2"' in low_node
    assert "map-agent-offline" in response.text
    assert "Офлайн" in response.text
    assert "map-agent-unregistered" in response.text
    assert "Не зарегистрирован" in response.text
    assert f'href="/hosts#host-{ids["online_a"]}"' in response.text
    assert f'href="/traps#trap-{ids["low_trap"]}"' in response.text
    assert f'data-events-url="/events?instance_id={ids["low_trap"]}"' in response.text
    for secret in [
        *identity_secrets,
        "secret-management-a.internal",
        "secret-management-b.internal",
        "secret-management-offline.internal",
        "secret-management-unregistered.internal",
    ]:
        assert secret not in response.text
    assert '/static/infrastructure-map.css?v=20261015.2' in response.text
    assert '/static/infrastructure-map.js?v=20261014.1' in response.text
    assert client.get("/static/infrastructure-map.css").status_code == 200
    script = client.get("/static/infrastructure-map.js")
    assert script.status_code == 200
    assert "textContent" in script.text
    assert "innerHTML" not in script.text

    client.post("/logout", data={"csrf_token": csrf(client)})
    assert login(client, username="observer", password="Observer-Pass-123").status_code == 303
    assert client.get("/infrastructure").status_code == 200
    client.post("/logout", data={"csrf_token": csrf(client)})
    assert login(client, username="map-operator", password=operator_password).status_code == 303
    assert client.get("/infrastructure").status_code == 200


def test_infrastructure_map_has_truthful_empty_state(client):
    assert login(client).status_code == 303
    response = client.get("/infrastructure")
    assert response.status_code == 200
    assert "Агенты ещё не зарегистрированы" in response.text
    assert 'data-node-id="center"' in response.text
    assert 'data-agent-id=' not in response.text
    assert 'data-edge-from="center"' not in response.text
    assert "Хостов <strong>0</strong>" in response.text
    assert "Ловушек <strong>0</strong>" in response.text


def _risk_event(index, event_type, data):
    return SimpleNamespace(
        id=uuid.uuid5(uuid.NAMESPACE_URL, f"risk-event-{index}"),
        event_type=event_type,
        data=data,
    )


def test_source_risk_rules_are_deterministic_bounded_and_duplicate_safe():
    assert assess_source_risk([])["score"] == 0
    assert assess_source_risk(
        [_risk_event(1, "medium.ssh_auth", {"result": "rejected"})]
    )["score"] == 0

    two_failures = [
        _risk_event(index, "medium.ssh_auth", {"result": "rejected"})
        for index in range(2)
    ]
    five_failures = [
        _risk_event(index, "medium.ssh_auth", {"result": "failed"})
        for index in range(5)
    ]
    ten_failures = [
        _risk_event(index, "medium.http_auth", {"result": "denied"})
        for index in range(10)
    ]
    assert assess_source_risk(two_failures)["score"] == 15
    assert assess_source_risk(five_failures)["score"] == 25
    assert assess_source_risk(ten_failures)["score"] == 30

    admin_events = [
        _risk_event(100 + index, "medium.http_request", {"path": "/admin/settings"})
        for index in range(20)
    ]
    ssh_events = [
        _risk_event(200 + index, "medium.ssh_command", {"command": "whoami"})
        for index in range(20)
    ]
    assert assess_source_risk(admin_events)["score"] == 20
    assert assess_source_risk(ssh_events)["score"] == 25
    honeytoken_id = uuid.uuid5(uuid.NAMESPACE_URL, "risk-honeytoken-event")
    assert assess_source_risk([], honeytoken_event_ids=[honeytoken_id] * 20)["score"] == 40

    combined = ten_failures + admin_events + ssh_events
    forward = assess_source_risk(combined, honeytoken_event_ids=[honeytoken_id])
    reversed_order = assess_source_risk(reversed(combined), honeytoken_event_ids=[honeytoken_id])
    duplicated_same_events = assess_source_risk(combined * 3, honeytoken_event_ids=[honeytoken_id] * 3)
    assert forward == reversed_order == duplicated_same_events
    assert forward["score"] == 100
    assert [reason["code"] for reason in forward["reasons"]] == [
        "repeated_failed_auth",
        "admin_path",
        "ssh_commands",
        "honeytoken_use",
    ]


def test_source_analytics_uses_events_alerts_rbac_and_keeps_sensitive_storage(client):
    timestamp = datetime(2026, 10, 14, 8, 0, 0, tzinfo=timezone.utc)
    source_a = "203.0.113.70"
    source_b = "198.51.100.90"
    operator_password = "Analytics-Operator-Pass-123"
    specs = [
        ("analytics-a-auth-1", source_a, "medium.http_auth", {"result": "rejected", "password": "analytics-auth-secret-1"}),
        ("analytics-a-auth-2", source_a, "medium.http_auth", {"result": "failed", "password": "analytics-auth-secret-2"}),
        ("analytics-a-admin", source_a, "medium.http_request", {"path": "/admin/settings?token=analytics-url-secret"}),
        ("analytics-a-ssh", source_a, "medium.ssh_command", {"command": "whoami", "private_key": "analytics-key-secret"}),
        ("analytics-b-1", source_b, "medium.http_request", {"path": "/status"}),
        ("analytics-b-2", source_b, "medium.http_request", {"path": "/health"}),
        ("analytics-b-3", source_b, "medium.http_request", {"path": "/about"}),
        ("analytics-no-source", None, "low.tcp_connection", {"marker": "analytics-marker-secret"}),
    ]
    with SessionLocal() as db:
        profile = TrapProfile(name="Analytics profile", interaction_level="medium", services=[], bait_credentials=[], logging={}, masking={})
        host = Host(name="analytics-host", management_address="192.0.2.99")
        trap = HoneypotInstance(name="analytics-trap", host=host, profile=profile)
        db.add_all(
            [
                profile,
                host,
                trap,
                User(
                    username="analytics-operator",
                    email="analytics-operator@example.com",
                    role=UserRole.OPERATOR,
                    password_hash=hash_password(operator_password),
                ),
            ]
        )
        db.flush()
        events = []
        for index, (external_id, source_ip, event_type, data) in enumerate(specs):
            event = Event(
                external_id=external_id,
                instance_id=trap.id,
                event_type=event_type,
                source_ip=source_ip,
                occurred_at=timestamp + timedelta(minutes=index),
                data=data,
            )
            db.add(event)
            events.append(event)
        db.flush()
        honeytoken_event = events[2]
        db.add(
            Alert(
                event_id=honeytoken_event.id,
                severity="critical",
                title="secret-honeytoken-name-must-not-render",
                state="open",
                details={
                    "kind": "honeytoken_use",
                    "honeytoken_id": "service-marker-must-not-render",
                    "reason": "alert-secret-must-not-render",
                },
            )
        )
        db.commit()
        stored_before = {event.external_id: (event.source_ip, event.data) for event in events}
        evidence_ids = {event.external_id: event.id for event in events}

    assert client.get("/analytics", follow_redirects=False).status_code == 303
    for username, password in (
        ("observer", "Observer-Pass-123"),
        ("analytics-operator", operator_password),
        ("admin", "Correct-Horse-123"),
    ):
        assert login(client, username=username, password=password).status_code == 303
        response = client.get("/analytics")
        assert response.status_code == 200
        assert "Аналитика — СЫРНЫЕ ШАРИКИ" in response.text
        assert "эвристический показатель подозрительности" in response.text
        assert "не вероятность компрометации" in response.text
        assert '<article class="source-risk-card" data-source-ip="203.0.113.70" data-risk-score="65">' in response.text
        assert '<article class="source-risk-card" data-source-ip="198.51.100.90" data-risk-score="0">' in response.text
        assert "Повторные отказы авторизации: 2" in response.text
        assert "Обращения к административным путям: 1" in response.text
        assert "SSH-команды: 1" in response.text
        assert "Подтверждённое использование honeytoken: 1" in response.text
        assert "События</span><strong>8</strong>" in response.text
        assert "Наблюдаемые источники</span><strong>2</strong>" in response.text
        assert "Активные предупреждения</span><strong>1</strong>" in response.text
        assert '<strong class="protocol-bar-name">HTTP</strong>' in response.text
        assert '<span class="protocol-bar-count">6 событий</span>' in response.text
        assert '<span class="protocol-bar-percent">75.0%</span>' in response.text
        assert '<strong class="protocol-bar-name">SSH</strong>' in response.text
        assert '<span class="protocol-bar-count">1 событий</span>' in response.text
        assert '<span class="protocol-bar-percent">12.5%</span>' in response.text
        assert f'/events?event_id={evidence_ids["analytics-a-admin"]}' in response.text
        assert 'href="/events?source_ip=203.0.113.70"' in response.text
        for secret in (
            "analytics-auth-secret-1",
            "analytics-auth-secret-2",
            "analytics-url-secret",
            "analytics-key-secret",
            "analytics-marker-secret",
            "secret-honeytoken-name-must-not-render",
            "service-marker-must-not-render",
            "alert-secret-must-not-render",
        ):
            assert secret not in response.text
        client.post("/logout", data={"csrf_token": csrf(client)})

    with SessionLocal() as db:
        stored_after = {
            event.external_id: (event.source_ip, event.data)
            for event in db.scalars(select(Event).order_by(Event.external_id))
        }
    assert stored_after == stored_before


def test_source_analytics_empty_state(client):
    assert login(client, username="observer", password="Observer-Pass-123").status_code == 303
    response = client.get("/analytics")
    assert response.status_code == 200
    assert "История источников пуста" in response.text
    assert "События</span><strong>0</strong>" in response.text
    assert "Наблюдаемые источники</span><strong>0</strong>" in response.text
    assert "Активные предупреждения</span><strong>0</strong>" in response.text


def test_source_analytics_queries_reasonable_event_volume_without_rendering_every_event(client):
    timestamp = datetime(2026, 10, 1, tzinfo=timezone.utc)
    with SessionLocal() as db:
        profile = TrapProfile(name="Analytics volume profile", interaction_level="medium", services=[], bait_credentials=[], logging={}, masking={})
        host = Host(name="analytics-volume-host", management_address="192.0.2.100")
        trap = HoneypotInstance(name="analytics-volume-trap", host=host, profile=profile)
        db.add_all([profile, host, trap])
        db.flush()
        db.add_all(
            [
                Event(
                    external_id=f"analytics-volume-{index:04d}",
                    instance_id=trap.id,
                    event_type="medium.http_request",
                    source_ip=f"198.18.{index % 40}.{(index % 200) + 1}",
                    occurred_at=timestamp + timedelta(seconds=index),
                    data={"path": "/status", "password": "bulk-secret-must-not-render"},
                )
                for index in range(1200)
            ]
        )
        db.commit()

    assert login(client).status_code == 303
    started = perf_counter()
    response = client.get("/analytics")
    elapsed = perf_counter() - started
    assert response.status_code == 200
    assert elapsed < 5.0
    assert "События</span><strong>1200</strong>" in response.text
    assert "Наблюдаемые источники</span><strong>200</strong>" in response.text
    assert response.text.count('class="source-risk-card"') == 12
    assert "bulk-secret-must-not-render" not in response.text


def test_event_json_export_filters_orders_redacts_alerts_and_preserves_storage(client):
    seeded = seed_ui_events(4)
    operator_password = "Export-Operator-Pass-123"
    with SessionLocal() as db:
        db.add(
            User(
                username="export-operator",
                email="export-operator@example.com",
                role=UserRole.OPERATOR,
                password_hash=hash_password(operator_password),
            )
        )
        first_event = db.get(Event, seeded["first_event_id"])
        first_event.data = {
            **first_event.data,
            "private_key": "-----BEGIN PRIVATE KEY-----export-private-key",
            "certificate_pem": "-----BEGIN CERTIFICATE-----export-certificate",
            "storage_path": "/private/internal/export/path",
            "access_token": "export-internal-token",
        }
        db.add(
            Alert(
                event_id=first_event.id,
                severity="high",
                state="open",
                title="Безопасное предупреждение экспорта",
                details={
                    "kind": "honeytoken_use",
                    "honeytoken_id": "raw-marker-must-not-export",
                    "reason": "internal-alert-detail-must-not-export",
                },
            )
        )
        db.commit()
        stored_before = {
            event.id: (event.external_id, event.data)
            for event in db.scalars(select(Event).order_by(Event.id))
        }

    params = {
        "event_type": "medium.http_request",
        "instance_id": str(seeded["primary_id"]),
        "source_ip": "192.0.2.10",
        "from_time": "2026-01-02T06:00:00",
        "to_time": "2026-01-02T06:02:00",
        "q": "report",
    }
    assert client.get("/events/export.json", follow_redirects=False).status_code == 303
    for username, password in (
        ("observer", "Observer-Pass-123"),
        ("export-operator", operator_password),
    ):
        assert login(client, username=username, password=password).status_code == 303
        response = client.get("/events/export.json", params=params)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert re.fullmatch(
            r'attachment; filename="honeyforge-attack-report-\d{8}-\d{6}Z\.json"',
            response.headers["content-disposition"],
        )
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-honeyforge-export-limit"] == "5000"
        report = response.json()
        assert report["schema"] == "honeyforge.attack-report.v1"
        assert report["event_count"] == 2
        assert report["filters"] == {
            "event_type": "medium.http_request",
            "trap_id": str(seeded["primary_id"]),
            "source_ip": "192.0.2.10",
            "from_time": "2026-01-02T06:00:00",
            "to_time": "2026-01-02T06:02:00",
            "search_applied": True,
        }
        assert [event["external_id"] for event in report["events"]] == [
            "events-ui-000",
            "events-ui-002",
        ]
        exported = report["events"][0]
        assert exported["trap"] == {"id": str(seeded["primary_id"]), "name": "events-primary"}
        assert exported["data"]["method"] == "GET"
        assert exported["data"]["password"] == "[СКРЫТО]"
        assert "url-secret-0" not in json.dumps(exported, ensure_ascii=False)
        assert set(exported["alerts"][0]) == {
            "id",
            "event_id",
            "severity",
            "state",
            "title",
            "created_at",
        }
        assert exported["alerts"][0]["title"] == "Безопасное предупреждение экспорта"
        for forbidden in (
            "export-private-key",
            "export-certificate",
            "/private/internal/export/path",
            "export-internal-token",
            "raw-marker-must-not-export",
            "internal-alert-detail-must-not-export",
        ):
            assert forbidden not in response.text
        client.post("/logout", data={"csrf_token": csrf(client)})

    assert login(client).status_code == 303
    admin = client.get("/events/export.json", params=params)
    assert admin.status_code == 200
    admin_event = admin.json()["events"][0]
    assert admin_event["data"]["password"] == "[СКРЫТО]"
    assert "url-secret-0" not in admin_event["data"]["url"]
    for key in ("private_key", "certificate_pem", "storage_path", "access_token"):
        assert admin_event["data"][key] == "[СКРЫТО]"

    empty = client.get("/events/export.json", params={"source_ip": "203.0.113.254"})
    assert empty.status_code == 200
    assert empty.json()["event_count"] == 0
    assert empty.json()["events"] == []
    invalid = client.get(
        "/events/export.json",
        params={"from_time": "2026-01-03T00:00", "to_time": "2026-01-02T00:00"},
    )
    assert invalid.status_code == 422

    with SessionLocal() as db:
        stored_after = {
            event.id: (event.external_id, event.data)
            for event in db.scalars(select(Event).order_by(Event.id))
        }
    assert stored_after == stored_before


def test_event_csv_export_neutralizes_formula_injection_and_is_chronological(client):
    timestamp = datetime(2026, 10, 14, 9, 0, 0, tzinfo=timezone.utc)
    with SessionLocal() as db:
        profile = TrapProfile(name="CSV export profile", interaction_level="medium", services=[], bait_credentials=[], logging={}, masking={})
        host = Host(name="csv-export-host", management_address="192.0.2.110")
        trap = HoneypotInstance(name="=HYPERLINK(\"https://invalid\")", host=host, profile=profile)
        db.add_all([profile, host, trap])
        db.flush()
        earlier = Event(
            external_id="+SUM(1,1)",
            instance_id=trap.id,
            event_type="@dangerous-event",
            source_ip="-1+1",
            occurred_at=timestamp,
            data={"password": "csv-secret", "command": "=cmd|' /C calc'!A0"},
        )
        later = Event(
            external_id="\t=CONTROLLED",
            instance_id=trap.id,
            event_type="medium.http_request",
            source_ip="198.51.100.111",
            occurred_at=timestamp + timedelta(minutes=1),
            data={"path": "/status"},
        )
        db.add_all([later, earlier])
        db.flush()
        db.add(
            Alert(
                event_id=earlier.id,
                severity="high",
                state="open",
                title="=ALERT-FORMULA",
                details={"kind": "honeytoken_use", "secret": "csv-alert-detail"},
            )
        )
        db.commit()

    assert login(client, username="observer", password="Observer-Pass-123").status_code == 303
    response = client.get("/events/export.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert response.headers["content-disposition"].endswith('.csv"')
    assert response.content.startswith(b"\xef\xbb\xbf")
    assert "csv-secret" not in response.text
    assert "csv-alert-detail" not in response.text

    rows = list(csv.DictReader(StringIO(response.content.decode("utf-8-sig"))))
    assert len(rows) == 2
    assert [row["occurred_at"] for row in rows] == sorted(row["occurred_at"] for row in rows)
    assert rows[0]["external_id"].startswith("'+")
    assert rows[0]["event_type"].startswith("'@")
    assert rows[0]["source_ip"].startswith("'-")
    assert rows[0]["trap_name"].startswith("'=")
    assert rows[1]["external_id"].startswith("' ")
    for row in rows:
        for value in row.values():
            candidate = value.lstrip("' ")
            if value.startswith("'"):
                continue
            assert not candidate.startswith(("=", "+", "-", "@"))


def test_event_export_buttons_preserve_filters_and_analytics_links_to_exports(client):
    seeded = seed_ui_events(2)
    assert login(client).status_code == 303
    response = client.get(
        "/events",
        params={
            "event_type": "medium.http_request",
            "instance_id": str(seeded["primary_id"]),
            "source_ip": "192.0.2.10",
            "from_time": "2026-01-02T06:00:00",
            "to_time": "2026-01-02T06:02:00",
            "q": "report",
            "page_size": 10,
        },
    )
    markup = unescape(response.text)
    expected_query = (
        f"event_type=medium.http_request&instance_id={seeded['primary_id']}&source_ip=192.0.2.10"
        "&from_time=2026-01-02T06%3A00%3A00&to_time=2026-01-02T06%3A02%3A00&q=report"
    )
    assert f'href="/events/export.json?{expected_query}"' in markup
    assert f'href="/events/export.csv?{expected_query}"' in markup
    assert "page_size=" not in markup.split('data-export-format="json"', 1)[0].rsplit('href="', 1)[1]

    analytics = client.get("/analytics")
    assert 'href="/events/export.json"' in analytics.text
    assert 'href="/events/export.csv"' in analytics.text


def test_event_export_rejects_oversized_selection_without_changing_events(client, monkeypatch):
    seed_ui_events(3)
    monkeypatch.setattr(ui_routes, "EVENT_EXPORT_LIMIT", 2)
    assert login(client).status_code == 303
    response = client.get("/events/export.json")
    assert response.status_code == 413
    assert "ограничен 2 событиями" in response.json()["detail"]
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Event.id))) == 3


def test_honeytoken_management_is_admin_only_and_alerts_follow_read_policy(client):
    operator_password = "Operator-Pass-123"
    with SessionLocal() as db:
        db.add(
            User(
                username="alerts-operator",
                email="alerts-operator@example.com",
                role=UserRole.OPERATOR,
                password_hash=hash_password(operator_password),
            )
        )
        db.commit()

    for username, password in (
        ("observer", "Observer-Pass-123"),
        ("alerts-operator", operator_password),
    ):
        assert login(client, username=username, password=password).status_code == 303
        alerts = client.get("/alerts")
        assert alerts.status_code == 200
        assert 'href="/alerts"' in alerts.text
        assert 'href="/honeytokens"' not in alerts.text
        assert client.get("/honeytokens").status_code == 403
        assert client.post(
            "/honeytokens",
            data={"name": "forbidden-token", "severity": "high", "csrf_token": csrf(client)},
        ).status_code == 403
        client.post("/logout", data={"csrf_token": csrf(client)})

    assert login(client).status_code == 303
    admin_page = client.get("/honeytokens")
    assert admin_page.status_code == 200
    assert 'href="/honeytokens"' in admin_page.text
    assert 'class="honeytoken-workspace is-empty"' in admin_page.text
    assert 'class="panel form-panel compact-form-panel honeytoken-create-panel"' in admin_page.text
    assert 'class="panel honeytoken-empty-panel"' in admin_page.text
    assert 'class="stacked-form honeytoken-create-form"' in admin_page.text


def test_profile_crud_validation_and_audit(client):
    assert login(client).status_code == 303
    token = csrf(client)

    invalid = profile_payload("Invalid Port")
    invalid["services"][0]["port"] = 70000
    assert client.post("/api/v1/profiles", headers={"X-CSRF-Token": token}, json=invalid).status_code == 422

    invalid_masking = profile_payload("Invalid Masking")
    invalid_masking["masking"]["response_delay_ms"] = 2001
    assert client.post(
        "/api/v1/profiles", headers={"X-CSRF-Token": token}, json=invalid_masking
    ).status_code == 422

    created = client.post(
        "/api/v1/profiles",
        headers={"X-CSRF-Token": token},
        json=profile_payload(),
    )
    assert created.status_code == 201
    profile_id = created.json()["id"]

    duplicate = client.post(
        "/api/v1/profiles",
        headers={"X-CSRF-Token": token},
        json=profile_payload(),
    )
    assert duplicate.status_code == 409

    changed = profile_payload("SSH Medium")
    changed["interaction_level"] = "medium"
    changed["bait_credentials"] = [{"username": "operator", "password": "decoy-only"}]
    changed["logging"]["capture_payloads"] = True
    changed["masking"]["response_delay_ms"] = 125
    updated = client.put(
        f"/api/v1/profiles/{profile_id}",
        headers={"X-CSRF-Token": token},
        json=changed,
    )
    assert updated.status_code == 200
    assert updated.json()["interaction_level"] == "medium"
    assert updated.json()["bait_credentials"] == changed["bait_credentials"]
    assert updated.json()["logging"]["capture_payloads"] is True
    assert updated.json()["masking"]["response_delay_ms"] == 125

    listed = client.get("/api/v1/profiles")
    assert [item["name"] for item in listed.json()] == ["SSH Medium"]

    deleted = client.delete(f"/api/v1/profiles/{profile_id}", headers={"X-CSRF-Token": token})
    assert deleted.status_code == 204
    assert client.get("/api/v1/profiles").json() == []

    with SessionLocal() as db:
        actions = list(db.scalars(select(AuditEntry.action).where(AuditEntry.action.like("profile.%"))))
    assert sorted(actions) == ["profile.create", "profile.delete", "profile.update"]


def test_low_udp_profile_validation_and_round_trip(client):
    assert login(client).status_code == 303
    token = csrf(client)
    payload = profile_payload("Low UDP discovery")
    payload["services"] = [
        {"name": "discovery", "protocol": "udp", "port": 8083, "banner": "ready"}
    ]
    payload["logging"]["capture_payloads"] = True

    created = client.post("/api/v1/profiles", headers={"X-CSRF-Token": token}, json=payload)
    assert created.status_code == 201
    assert created.json()["interaction_level"] == "low"
    assert created.json()["services"] == payload["services"]
    assert created.json()["logging"]["capture_payloads"] is True

    listed = client.get("/api/v1/profiles")
    stored = next(item for item in listed.json() if item["id"] == created.json()["id"])
    assert stored["services"][0]["protocol"] == "udp"

    invalid = profile_payload("Invalid datagram protocol")
    invalid["services"] = [{"name": "discovery", "protocol": "sctp", "port": 8083, "banner": "ready"}]
    rejected = client.post("/api/v1/profiles", headers={"X-CSRF-Token": token}, json=invalid)
    assert rejected.status_code == 422


def test_csrf_is_required_for_mutation(client):
    assert login(client).status_code == 303
    response = client.post("/api/v1/profiles", json=profile_payload())
    assert response.status_code == 403

def test_multiple_trap_instances_can_share_one_host_identity_scope(client):
    assert login(client).status_code == 303
    token = csrf(client)
    profile = client.post(
        "/api/v1/profiles",
        headers={"X-CSRF-Token": token},
        json=profile_payload("Multi host low"),
    )
    assert profile.status_code == 201
    second_payload = profile_payload("Multi host second")
    second_payload["services"][0]["port"] = 2222
    second_profile = client.post(
        "/api/v1/profiles",
        headers={"X-CSRF-Token": token},
        json=second_payload,
    )
    assert second_profile.status_code == 201
    enrollment = client.post(
        "/api/v1/enrollments",
        headers={"X-CSRF-Token": token},
        json={
            "host_name": "ubuntu-agent-one",
            "management_address": "192.0.2.151",
            "instance_name": "ubuntu-low-one",
            "profile_id": profile.json()["id"],
            "ttl_minutes": 15,
        },
    )
    assert enrollment.status_code == 201
    created = client.post(
        "/api/v1/traps",
        headers={"X-CSRF-Token": token},
        json={
            "name": "ubuntu-low-two",
            "host_id": enrollment.json()["host_id"],
            "profile_id": second_profile.json()["id"],
        },
    )
    assert created.status_code == 201
    assert created.json()["host_id"] == enrollment.json()["host_id"]

    duplicate = client.post(
        "/api/v1/traps",
        headers={"X-CSRF-Token": token},
        json={
            "name": "ubuntu-low-two",
            "host_id": enrollment.json()["host_id"],
            "profile_id": profile.json()["id"],
        },
    )
    assert duplicate.status_code == 409
    with SessionLocal() as db:
        host = db.get(Host, enrollment.json()["host_id"])
        instances = list(db.scalars(select(HoneypotInstance).where(HoneypotInstance.host_id == host.id)))
        assert {item.name for item in instances} == {"ubuntu-low-one", "ubuntu-low-two"}
        assert db.scalar(select(AuditEntry).where(AuditEntry.action == "trap.create"))


def test_observer_cannot_provision_trap_instance(client):
    assert login(client, username="observer", password="Observer-Pass-123").status_code == 303
    assert client.get("/traps/new").status_code == 403
    response = client.post(
        "/api/v1/traps",
        headers={"X-CSRF-Token": csrf(client)},
        json={
            "name": "forbidden-trap",
            "host_id": "00000000-0000-0000-0000-000000000001",
            "profile_id": "00000000-0000-0000-0000-000000000002",
        },
    )
    assert response.status_code == 403
