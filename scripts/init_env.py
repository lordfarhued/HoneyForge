"""Safely initialize .env from .env.example without printing secret values."""

from __future__ import annotations

import secrets
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_PATH = ROOT / ".env.example"
ENV_PATH = ROOT / ".env"
SECRET_KEYS = ("POSTGRES_PASSWORD", "SECRET_KEY")


def parse_assignment(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in line:
        return None
    key, value = line.split("=", 1)
    key = key.strip()
    if not key:
        return None
    return key, value


def main() -> None:
    if not EXAMPLE_PATH.is_file():
        raise SystemExit(".env.example not found")

    example_lines = EXAMPLE_PATH.read_text(encoding="utf-8").splitlines()
    created = not ENV_PATH.exists()
    lines = (
        example_lines.copy()
        if created
        else ENV_PATH.read_text(encoding="utf-8").splitlines()
    )

    existing_keys = {
        parsed[0]
        for line in lines
        if (parsed := parse_assignment(line)) is not None
    }
    missing_lines = [
        line
        for line in example_lines
        if (parsed := parse_assignment(line)) is not None
        and parsed[0] not in existing_keys
    ]
    if missing_lines:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend(missing_lines)

    generated: list[str] = []
    result: list[str] = []
    for line in lines:
        parsed = parse_assignment(line)
        if parsed is None:
            result.append(line)
            continue
        key, value = parsed
        if key in SECRET_KEYS and not value.strip():
            result.append(f"{key}={secrets.token_hex(32)}")
            generated.append(key)
        else:
            result.append(line)

    ENV_PATH.write_text("\n".join(result) + "\n", encoding="utf-8", newline="\n")
    action = "created" if created else "updated"
    generated_label = ", ".join(generated) if generated else "none"
    print(f".env {action}; generated keys: {generated_label}; secret values were not printed")


if __name__ == "__main__":
    main()
