from __future__ import annotations

import re
import secrets
from collections.abc import Mapping
from typing import Any

from app.models import Honeytoken
from app.security import token_hash

HONEYTOKEN_PREFIX = "hft_"
HONEYTOKEN_REDACTION = "[honeytoken omitted]"
_HONEYTOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9_-])hft_[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")


def generate_honeytoken() -> str:
    return HONEYTOKEN_PREFIX + secrets.token_urlsafe(32)


def candidate_hashes(data: Any) -> set[str]:
    hashes: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, str):
            hashes.update(token_hash(match.group(0)) for match in _HONEYTOKEN_PATTERN.finditer(value))
        elif isinstance(value, Mapping):
            for nested in value.values():
                visit(nested)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                visit(nested)

    visit(data)
    return hashes


def redact_known_honeytokens(
    data: dict,
    tokens_by_hash: Mapping[str, Honeytoken],
) -> tuple[dict, list[Honeytoken]]:
    matched: dict[str, Honeytoken] = {}

    def redact(value: Any) -> Any:
        if isinstance(value, str):
            def replace(match: re.Match[str]) -> str:
                digest = token_hash(match.group(0))
                token = tokens_by_hash.get(digest)
                if token is None:
                    return match.group(0)
                matched[str(token.id)] = token
                return HONEYTOKEN_REDACTION

            return _HONEYTOKEN_PATTERN.sub(replace, value)
        if isinstance(value, Mapping):
            return {key: redact(nested) for key, nested in value.items()}
        if isinstance(value, (list, tuple)):
            return [redact(nested) for nested in value]
        return value

    return redact(data), list(matched.values())
