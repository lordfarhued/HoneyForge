from __future__ import annotations

import ctypes
import os
from collections.abc import Callable, Iterable


LINUX_COMM_MAX_BYTES = 15


def normalize_process_name(value: str, fallback: str = "system-metrics") -> str:
    candidate = value.strip() or fallback
    encoded = candidate.encode("utf-8")[:LINUX_COMM_MAX_BYTES]
    while encoded:
        try:
            return encoded.decode("utf-8")
        except UnicodeDecodeError:
            encoded = encoded[:-1]
    return fallback[:LINUX_COMM_MAX_BYTES]


def select_profile_value(
    configurations: Iterable[dict],
    key: str,
    fallback: str,
) -> str:
    """Use a profile value only when every configured instance agrees on it."""
    values = {
        str(item.get("profile", {}).get("masking", {}).get(key, "")).strip()
        for item in configurations
    }
    values.discard("")
    return values.pop() if len(values) == 1 else fallback


def set_process_name(
    value: str,
    setter: Callable[[bytes], int] | None = None,
) -> str:
    """Set Linux task comm without changing argv, returning the applied value."""
    name = normalize_process_name(value)
    encoded = name.encode("utf-8")
    if setter is not None:
        result = setter(encoded)
    elif os.name == "posix":
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.prctl(15, ctypes.c_char_p(encoded), 0, 0, 0)
    else:
        return name
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return name
