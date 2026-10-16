from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase

from tests.database_safety import (
    UnsafeTestDatabaseError,
    assert_safe_test_database,
    configure_test_database_environment,
    reset_test_schema,
)


def safe_memory_environment() -> dict[str, str]:
    return {
        "ENVIRONMENT": "test",
        "TEST_DATABASE_URL": "sqlite://",
        "TEST_DATABASE_CONFIRMATION": ":memory:",
        "DATABASE_URL": "sqlite://",
    }


@pytest.mark.parametrize(
    "environ, message",
    [
        (
            {
                "ENVIRONMENT": "test",
                "TEST_DATABASE_URL": "postgresql+psycopg://user:password@db:5432/honeyforge",
                "TEST_DATABASE_CONFIRMATION": "honeyforge",
            },
            "test-only",
        ),
        ({"ENVIRONMENT": "test"}, "TEST_DATABASE_URL"),
        (
            {"ENVIRONMENT": "test", "TEST_DATABASE_URL": "sqlite://"},
            "TEST_DATABASE_CONFIRMATION",
        ),
        (
            {
                "ENVIRONMENT": "local",
                "TEST_DATABASE_URL": "sqlite://",
                "TEST_DATABASE_CONFIRMATION": ":memory:",
            },
            "ENVIRONMENT",
        ),
    ],
)
def test_configuration_rejects_unsafe_or_incomplete_database(environ, message):
    with pytest.raises(UnsafeTestDatabaseError, match=message):
        configure_test_database_environment(environ)


def test_configuration_rejects_active_dsn_mismatch():
    environ = safe_memory_environment()
    environ["DATABASE_URL"] = "postgresql+psycopg://user:password@db:5432/honeyforge"
    with pytest.raises(UnsafeTestDatabaseError, match="does not match"):
        configure_test_database_environment(environ)


def test_engine_dsn_must_match_confirmed_test_dsn():
    environ = safe_memory_environment()
    engine = create_engine("sqlite:///unexpected.db")
    try:
        with pytest.raises(UnsafeTestDatabaseError, match="engine does not use"):
            assert_safe_test_database(engine, environ)
    finally:
        engine.dispose()


def test_schema_reset_is_allowed_only_for_confirmed_in_memory_database():
    class TestBase(DeclarativeBase):
        pass

    environ = safe_memory_environment()
    engine = create_engine("sqlite://")
    try:
        reset_test_schema(TestBase, engine, environ)
    finally:
        engine.dispose()
