from __future__ import annotations

import getpass
import os
from pathlib import Path

from agent.config import AgentSettings


IDENTITY_FILES = (
    "client.key",
    "client.crt",
    "runtime.json",
    "agent.key",
    "agent.crt",
    "identity.json",
)


def store_enrollment_token(token_path: Path, state_dir: Path, token: str) -> None:
    """Store a one-time token without ever echoing it or replacing agent state."""
    value = token.strip()
    if value != token or not 32 <= len(value) <= 256 or any(char.isspace() for char in value):
        raise ValueError("Enrollment token has an invalid format")
    if any((state_dir / name).exists() for name in IDENTITY_FILES):
        raise RuntimeError("Runtime identity already exists; refusing to bootstrap this state")
    token_path.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with token_path.open("x", encoding="utf-8") as handle:
            created = True
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        token_path.chmod(0o600)
    except Exception:
        if created and token_path.exists() and token_path.stat().st_size == 0:
            token_path.unlink()
        raise


def main() -> None:
    settings = AgentSettings()
    token = getpass.getpass("One-time enrollment token: ")
    store_enrollment_token(
        Path(settings.enrollment_token_file),
        Path(settings.state_dir),
        token,
    )
    print("Enrollment token stored. Start the runtime service to complete enrollment.")


if __name__ == "__main__":
    main()
