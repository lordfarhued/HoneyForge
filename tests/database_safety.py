from __future__ import annotations

import os
import re
from collections.abc import MutableMapping

from sqlalchemy import text
from sqlalchemy.engine import Engine, URL, make_url


class UnsafeTestDatabaseError(RuntimeError):
    """Raised before a destructive test database operation is attempted."""


def _expected_database(environ: MutableMapping[str, str]) -> tuple[URL, str]:
    if environ.get("ENVIRONMENT") != "test":
        raise UnsafeTestDatabaseError("Refusing database reset: ENVIRONMENT must be exactly 'test'")

    raw_url = environ.get("TEST_DATABASE_URL", "").strip()
    if not raw_url:
        raise UnsafeTestDatabaseError("Refusing database reset: TEST_DATABASE_URL is not explicitly configured")
    try:
        url = make_url(raw_url)
    except Exception as exc:
        raise UnsafeTestDatabaseError("Refusing database reset: TEST_DATABASE_URL is invalid") from exc

    backend = url.get_backend_name()
    if backend == "sqlite":
        if url.database not in (None, "", ":memory:"):
            raise UnsafeTestDatabaseError("Refusing database reset: only in-memory SQLite is allowed for tests")
        database_name = ":memory:"
    elif backend == "postgresql":
        database_name = (url.database or "").strip()
        if not re.fullmatch(r"(?:test(?:[_-][a-z0-9]+)*|[a-z0-9]+(?:[_-][a-z0-9]+)*[_-]test)", database_name):
            raise UnsafeTestDatabaseError(
                "Refusing database reset: PostgreSQL database name must be explicitly test-only"
            )
    else:
        raise UnsafeTestDatabaseError(
            f"Refusing database reset: unsupported test database backend '{backend}'"
        )

    confirmation = environ.get("TEST_DATABASE_CONFIRMATION", "").strip()
    if confirmation != database_name:
        raise UnsafeTestDatabaseError(
            "Refusing database reset: TEST_DATABASE_CONFIRMATION must exactly match the test database name"
        )
    return url, database_name


def configure_test_database_environment(
    environ: MutableMapping[str, str] | None = None,
) -> str:
    """Validate the declared test DSN before app.database creates its engine."""
    environ = os.environ if environ is None else environ
    expected_url, _ = _expected_database(environ)
    configured = environ.get("DATABASE_URL", "").strip()
    if configured:
        try:
            configured_url = make_url(configured)
        except Exception as exc:
            raise UnsafeTestDatabaseError("Refusing database reset: DATABASE_URL is invalid") from exc
        if configured_url != expected_url:
            raise UnsafeTestDatabaseError(
                "Refusing database reset: DATABASE_URL does not match TEST_DATABASE_URL"
            )
    else:
        environ["DATABASE_URL"] = expected_url.render_as_string(hide_password=False)
    return environ["DATABASE_URL"]


def assert_safe_test_database(
    engine: Engine,
    environ: MutableMapping[str, str] | None = None,
) -> None:
    """Verify both configured and connected database identities without mutating them."""
    environ = os.environ if environ is None else environ
    expected_url, expected_name = _expected_database(environ)
    configured = environ.get("DATABASE_URL", "").strip()
    if not configured or make_url(configured) != expected_url:
        raise UnsafeTestDatabaseError(
            "Refusing database reset: active DATABASE_URL does not match TEST_DATABASE_URL"
        )
    if engine.url != expected_url:
        raise UnsafeTestDatabaseError(
            "Refusing database reset: SQLAlchemy engine does not use the confirmed test DSN"
        )

    backend = engine.url.get_backend_name()
    with engine.connect() as connection:
        if backend == "postgresql":
            actual_name = connection.execute(text("SELECT current_database()")).scalar_one()
        elif backend == "sqlite":
            rows = connection.execute(text("PRAGMA database_list")).all()
            actual_name = ":memory:" if rows and all(not row[2] for row in rows) else "file-backed"
        else:  # Defensive: _expected_database already rejects other backends.
            raise UnsafeTestDatabaseError("Refusing database reset: unsupported active database backend")
    if actual_name != expected_name:
        raise UnsafeTestDatabaseError(
            "Refusing database reset: connected database name does not match the explicit confirmation"
        )


def reset_test_schema(
    base,
    engine: Engine,
    environ: MutableMapping[str, str] | None = None,
) -> None:
    """Reset a schema only after every fail-closed test database check succeeds."""
    assert_safe_test_database(engine, environ)
    base.metadata.drop_all(engine)
    base.metadata.create_all(engine)
