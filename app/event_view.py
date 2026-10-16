from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
import re
from typing import Any, Iterable

from app.models import UserRole


REDACTED_VALUE = "[СКРЫТО]"
SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "authorization",
    "cookie",
    "private_key",
    "access_key",
)
SUMMARY_KEYS = ("request_line", "url", "path", "command", "action")
CORRELATION_WINDOW = timedelta(minutes=15)
ADMIN_PATH_MARKERS = ("/admin", "/administrator", "/wp-admin", "/login")
INLINE_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|passphrase|secret|token|authorization|cookie|api[_-]?key|access[_-]?key)"
    r"(\s*(?:=|:)\s*|\s+)([^\s&]+)"
)
URL_USERINFO_RE = re.compile(r"(?i)(https?://[^:/@\s]+:)([^@\s]+)(@)")
EXPORT_FORBIDDEN_KEY_PARTS = (
    "token",
    "authorization",
    "cookie",
    "private_key",
    "access_key",
    "certificate",
    "enrollment",
    "honeytoken",
    "marker",
    "storage_path",
    "recording_path",
)
EXPORT_INLINE_SECRET_RE = re.compile(
    r"(?i)\b(token|authorization|cookie|api[_-]?key|access[_-]?key)"
    r"(\s*(?:=|:)\s*|\s+)([^\s&]+)"
)
RISK_EVIDENCE_LIMIT = 3
RISK_RULES = {
    "repeated_failed_auth": {"maximum": 30},
    "admin_path": {"points_per_event": 5, "maximum": 20},
    "ssh_commands": {"points_per_event": 5, "maximum": 25},
    "honeytoken_use": {"fixed": 40},
}


def can_view_sensitive_event_data(role: UserRole) -> bool:
    return role == UserRole.ADMIN


def _is_sensitive_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return any(part in normalized for part in SENSITIVE_KEY_PARTS)


def _redact_inline_secrets(value: str) -> str:
    value = INLINE_SECRET_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED_VALUE}", value)
    return URL_USERINFO_RE.sub(lambda match: f"{match.group(1)}{REDACTED_VALUE}{match.group(3)}", value)


def redact_event_data(value: Any, *, allow_sensitive: bool) -> Any:
    """Return JSON-compatible event data with secrets hidden for non-admin readers."""
    if allow_sensitive:
        return deepcopy(value)
    if isinstance(value, dict):
        return {
            key: REDACTED_VALUE if _is_sensitive_key(key) else redact_event_data(item, allow_sensitive=False)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_event_data(item, allow_sensitive=False) for item in value]
    if isinstance(value, str):
        return _redact_inline_secrets(value)
    return value


def redact_export_event_data(value: Any, *, allow_sensitive: bool) -> Any:
    """Apply role rules and the stricter no-secrets policy used by file exports."""
    visible = redact_event_data(value, allow_sensitive=allow_sensitive)
    export_safe = redact_event_data(visible, allow_sensitive=False)
    return _redact_export_only_fields(export_safe)


def _redact_export_only_fields(value: Any) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if any(part in normalized for part in EXPORT_FORBIDDEN_KEY_PARTS):
                result[key] = REDACTED_VALUE
            else:
                result[key] = _redact_export_only_fields(item)
        return result
    if isinstance(value, list):
        return [_redact_export_only_fields(item) for item in value]
    if isinstance(value, str):
        if "-----BEGIN PRIVATE KEY-----" in value or "-----BEGIN CERTIFICATE-----" in value:
            return REDACTED_VALUE
        return EXPORT_INLINE_SECRET_RE.sub(
            lambda match: f"{match.group(1)}{match.group(2)}{REDACTED_VALUE}", value
        )
    return value


def event_summary(data: dict, *, max_length: int = 120) -> str:
    """Build a deliberately allow-listed table preview that never includes credentials."""
    for key in SUMMARY_KEYS:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            compact = " ".join(_redact_inline_secrets(value).split())
            return compact if len(compact) <= max_length else f"{compact[: max_length - 1]}…"
    return "—"


def _timeline_event_label(event_type: str) -> str:
    normalized = event_type.lower()
    if normalized.endswith("http_request"):
        return "HTTP-запрос"
    if normalized.endswith("http_auth"):
        return "HTTP-аутентификация"
    if normalized.endswith("ssh_auth"):
        return "SSH-аутентификация"
    if normalized.endswith("ssh_session"):
        return "SSH-сессия"
    if normalized.endswith("ssh_command"):
        return "SSH-команда"
    return event_type


def _uses_admin_path(data: dict) -> bool:
    candidates = [data.get(key) for key in ("request_line", "url", "path")]
    return any(
        marker in candidate.lower()
        for candidate in candidates
        if isinstance(candidate, str)
        for marker in ADMIN_PATH_MARKERS
    )


def event_signal_codes(event: Any) -> set[str]:
    """Classify one stored event using the same rules as the attack timeline."""
    normalized_type = str(event.event_type).lower()
    data = event.data or {}
    result = str(data.get("result", "")).lower()
    signals = set()
    if normalized_type.endswith("_auth") and result in {"rejected", "failed", "denied", "invalid"}:
        signals.add("failed_auth")
    if "http" in normalized_type and _uses_admin_path(data):
        signals.add("admin_path")
    if normalized_type.endswith("ssh_command"):
        signals.add("ssh_commands")
    return signals


class SourceRiskAccumulator:
    """Order-independent, capped heuristic score for one observed source."""

    def __init__(self):
        self.counts = {"failed_auth": 0, "admin_path": 0, "ssh_commands": 0, "honeytoken_use": 0}
        self._evidence: dict[str, list[tuple[str, str]]] = {
            key: [] for key in self.counts
        }
        self._seen_event_ids: set[str] = set()
        self._seen_honeytoken_event_ids: set[str] = set()

    def add_event(self, event: Any) -> None:
        event_id = str(event.id)
        if event_id in self._seen_event_ids:
            return
        self._seen_event_ids.add(event_id)
        for signal in event_signal_codes(event):
            self.counts[signal] += 1
            self._remember(signal, event.id)

    def add_honeytoken_event(self, event_id: Any) -> None:
        value = str(event_id)
        if value in self._seen_honeytoken_event_ids:
            return
        self._seen_honeytoken_event_ids.add(value)
        self.counts["honeytoken_use"] += 1
        self._remember("honeytoken_use", event_id)

    def _remember(self, signal: str, event_id: Any) -> None:
        value = str(event_id)
        evidence = self._evidence[signal]
        if any(item[1] == value for item in evidence):
            return
        evidence.append((value, value))
        evidence.sort()
        del evidence[RISK_EVIDENCE_LIMIT:]

    def assessment(self) -> dict[str, Any]:
        reasons = []
        failed_auth_count = self.counts["failed_auth"]
        if failed_auth_count >= 10:
            failed_auth_points = 30
        elif failed_auth_count >= 5:
            failed_auth_points = 25
        elif failed_auth_count >= 2:
            failed_auth_points = 15
        else:
            failed_auth_points = 0
        if failed_auth_points:
            reasons.append(
                self._reason(
                    "repeated_failed_auth",
                    f"Повторные отказы авторизации: {failed_auth_count}",
                    failed_auth_points,
                    failed_auth_count,
                    "2–4: 15; 5–9: 25; 10 и более: 30",
                    "failed_auth",
                )
            )

        admin_count = self.counts["admin_path"]
        admin_points = min(
            admin_count * RISK_RULES["admin_path"]["points_per_event"],
            RISK_RULES["admin_path"]["maximum"],
        )
        if admin_points:
            reasons.append(
                self._reason(
                    "admin_path",
                    f"Обращения к административным путям: {admin_count}",
                    admin_points,
                    admin_count,
                    "5 баллов за событие, максимум 20",
                    "admin_path",
                )
            )

        ssh_count = self.counts["ssh_commands"]
        ssh_points = min(
            ssh_count * RISK_RULES["ssh_commands"]["points_per_event"],
            RISK_RULES["ssh_commands"]["maximum"],
        )
        if ssh_points:
            reasons.append(
                self._reason(
                    "ssh_commands",
                    f"SSH-команды: {ssh_count}",
                    ssh_points,
                    ssh_count,
                    "5 баллов за событие, максимум 25",
                    "ssh_commands",
                )
            )

        honeytoken_count = self.counts["honeytoken_use"]
        if honeytoken_count:
            reasons.append(
                self._reason(
                    "honeytoken_use",
                    f"Подтверждённое использование honeytoken: {honeytoken_count}",
                    RISK_RULES["honeytoken_use"]["fixed"],
                    honeytoken_count,
                    "фиксированные 40 баллов независимо от числа повторных alerts",
                    "honeytoken_use",
                )
            )

        score = min(100, sum(reason["points"] for reason in reasons))
        if score >= 75:
            level, level_label = "critical", "Критический"
        elif score >= 50:
            level, level_label = "high", "Высокий"
        elif score >= 25:
            level, level_label = "medium", "Умеренный"
        else:
            level, level_label = "low", "Низкий"
        return {"score": score, "level": level, "level_label": level_label, "reasons": reasons}

    def _reason(
        self,
        code: str,
        label: str,
        points: int,
        count: int,
        rule: str,
        evidence_key: str,
    ) -> dict[str, Any]:
        return {
            "code": code,
            "label": label,
            "points": points,
            "count": count,
            "rule": rule,
            "event_ids": [item[1] for item in self._evidence[evidence_key]],
        }


def assess_source_risk(
    events: Iterable[Any], *, honeytoken_event_ids: Iterable[Any] = ()
) -> dict[str, Any]:
    accumulator = SourceRiskAccumulator()
    for event in events:
        accumulator.add_event(event)
    for event_id in honeytoken_event_ids:
        accumulator.add_honeytoken_event(event_id)
    return accumulator.assessment()


def correlate_events(events: list[Any], *, allow_sensitive: bool) -> list[dict[str, Any]]:
    """Build ephemeral, fixed-window timelines without changing stored events."""
    ordered = sorted(
        (event for event in events if event.source_ip),
        key=lambda event: (event.source_ip, event.occurred_at, str(event.id)),
    )
    timelines: list[dict[str, Any]] = []
    active_by_source: dict[str, dict[str, Any]] = {}

    for event in ordered:
        source_ip = str(event.source_ip)
        timeline = active_by_source.get(source_ip)
        if timeline is None or event.occurred_at - timeline["started_at"] > CORRELATION_WINDOW:
            timeline = {
                "source_ip": source_ip,
                "started_at": event.occurred_at,
                "ended_at": event.occurred_at,
                "events": [],
                "failed_auth_count": 0,
                "admin_path_count": 0,
                "ssh_command_count": 0,
            }
            active_by_source[source_ip] = timeline
            timelines.append(timeline)

        data = event.data or {}
        visible_data = redact_event_data(data, allow_sensitive=allow_sensitive)
        summary = event_summary(visible_data)
        if summary == "—" and event.event_type.lower().endswith("_auth"):
            result = visible_data.get("result")
            if isinstance(result, str) and result:
                summary = f"Результат: {result}"
        timeline["events"].append(
            {
                "id": event.id,
                "external_id": event.external_id,
                "event_type": event.event_type,
                "occurred_at": event.occurred_at,
                "label": _timeline_event_label(event.event_type),
                "summary": summary,
            }
        )
        timeline["ended_at"] = event.occurred_at

        signals = event_signal_codes(event)
        if "failed_auth" in signals:
            timeline["failed_auth_count"] += 1
        if "admin_path" in signals:
            timeline["admin_path_count"] += 1
        if "ssh_commands" in signals:
            timeline["ssh_command_count"] += 1

    for timeline in timelines:
        signals = []
        if timeline["failed_auth_count"] >= 2:
            signals.append(
                {
                    "code": "repeated_failed_auth",
                    "label": f"Повторные отказы авторизации: {timeline['failed_auth_count']}",
                }
            )
        if timeline["admin_path_count"]:
            signals.append(
                {
                    "code": "admin_path",
                    "label": f"Административные пути: {timeline['admin_path_count']}",
                }
            )
        if timeline["ssh_command_count"]:
            signals.append(
                {
                    "code": "ssh_commands",
                    "label": f"SSH-команды: {timeline['ssh_command_count']}",
                }
            )
        timeline["signals"] = signals
        timeline["event_count"] = len(timeline["events"])
        del timeline["failed_auth_count"]
        del timeline["admin_path_count"]
        del timeline["ssh_command_count"]

    return sorted(timelines, key=lambda timeline: timeline["started_at"], reverse=True)
