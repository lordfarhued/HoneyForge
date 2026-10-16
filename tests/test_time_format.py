from datetime import datetime, timedelta, timezone

import pytest

from app.time_format import format_moscow_time, parse_moscow_time


def test_format_moscow_time_converts_aware_utc_timestamp():
    value = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert format_moscow_time(value) == "02.01.2026 06:04:05 МСК"


def test_format_moscow_time_does_not_shift_moscow_timestamp_twice():
    moscow_offset = timezone(timedelta(hours=3))
    value = datetime(2026, 1, 2, 6, 4, 5, tzinfo=moscow_offset)
    assert format_moscow_time(value) == "02.01.2026 06:04:05 МСК"


def test_format_moscow_time_treats_naive_database_value_as_utc_once():
    value = datetime(2026, 1, 2, 3, 4, 5)
    assert format_moscow_time(value) == "02.01.2026 06:04:05 МСК"


def test_format_moscow_time_supports_empty_value_and_rejects_other_types():
    assert format_moscow_time(None, "Никогда") == "Никогда"
    with pytest.raises(TypeError):
        format_moscow_time("2026-01-02T03:04:05Z")  # type: ignore[arg-type]


def test_parse_moscow_time_converts_local_and_aware_values_to_utc_once():
    assert parse_moscow_time("2026-01-02T06:04:05") == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert parse_moscow_time("2026-01-02T03:04:05+00:00") == datetime(
        2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc
    )
    assert parse_moscow_time("") is None
