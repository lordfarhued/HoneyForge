from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo


MOSCOW_TIMEZONE = ZoneInfo("Europe/Moscow")
MOSCOW_TIME_FORMAT = "%d.%m.%Y %H:%M:%S МСК"


def format_moscow_time(value: datetime | None, fallback: str = "—") -> str:
    """Format a UI timestamp in Moscow time without changing API/DB values.

    PostgreSQL returns timezone-aware values. SQLite and some DB adapters may
    return a naive value for the same UTC column, so naive values are treated
    as UTC exactly once before conversion.
    """
    if value is None:
        return fallback
    if not isinstance(value, datetime):
        raise TypeError("format_moscow_time expects datetime or None")
    source = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return source.astimezone(MOSCOW_TIMEZONE).strftime(MOSCOW_TIME_FORMAT)


def parse_moscow_time(value: str | None) -> datetime | None:
    """Parse an HTML datetime value as Moscow time and return an aware UTC datetime."""
    if value is None or not value.strip():
        return None
    parsed = datetime.fromisoformat(value.strip())
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=MOSCOW_TIMEZONE)
    return parsed.astimezone(timezone.utc)
