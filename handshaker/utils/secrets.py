"""Redact secrets and parse Retry-After without leaking credentials."""

from __future__ import annotations

import re
import time
from email.utils import parsedate_to_datetime

_BEARER_RE = re.compile(r"(Bearer\s+)(\S+)", re.IGNORECASE)
_NVAPI_RE = re.compile(r"nvapi-[A-Za-z0-9_-]+")
_SK_RE = re.compile(r"sk-[A-Za-z0-9_-]{8,}")
_KEY_ASSIGN_RE = re.compile(
    r"(NIM_API_KEY|api[_-]?key)\s*[=:]\s*\S+",
    re.IGNORECASE,
)


def redact(text: object) -> str:
    """Return ``text`` with API keys / Bearer tokens replaced by ``***``."""
    s = "" if text is None else str(text)
    s = _BEARER_RE.sub(r"\1***", s)
    s = _NVAPI_RE.sub("nvapi-***", s)
    s = _SK_RE.sub("sk-***", s)
    s = _KEY_ASSIGN_RE.sub(r"\1=***", s)
    return s


def parse_retry_after(value: str | None, *, now: float | None = None) -> float | None:
    """Parse ``Retry-After`` as delta-seconds or HTTP-date. None if unusable."""
    if not value:
        return None
    raw = value.strip()
    try:
        seconds = float(raw)
        return max(0.0, seconds)
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(raw)
        stamp = dt.timestamp()
        base = now if now is not None else time.time()
        return max(0.0, stamp - base)
    except (TypeError, ValueError, OverflowError):
        return None
