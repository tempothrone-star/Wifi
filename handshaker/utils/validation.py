"""Runtime value validators and parsers.

Every value entering the strategy / verification layers is parsed with an
explicit, lenient-by-design parser that returns ``None`` on garbage rather
than guessing. This is the anti-hallucination backbone: "I don't know" is a
valid and safe answer.
"""

from __future__ import annotations

import re
from typing import Iterable

# A canonical BSSID / MAC address (colon-separated).
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")
_HEX12_RE = re.compile(r"^[0-9A-Fa-f]{12}$")
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def parse_mac(value: str) -> str | None:
    """Normalise a MAC address to lowercase colon-separated form, or None.

    Accepts ``aa:bb:cc:dd:ee:ff``, ``aa-bb-cc-dd-ee-ff``, Cisco
    ``aabb.ccdd.eeff``, and bare ``aabbccddeeff``. Returns ``None`` on
    garbage instead of guessing.
    """
    if not value:
        return None
    raw = value.strip()
    # Strip common separators, then re-insert colons if we have exactly 12 hex.
    compact = raw.replace("-", "").replace(":", "").replace(".", "")
    if _HEX12_RE.match(compact):
        candidate = ":".join(compact[i:i + 2] for i in range(0, 12, 2)).lower()
        return candidate
    candidate = raw.replace("-", ":").lower()
    if not _MAC_RE.match(candidate):
        return None
    return candidate


def sanitize_filename(value: str, *, fallback: str = "target", max_len: int = 32) -> str:
    """Make a string safe to embed in a filesystem path.

    ESSIDs can contain ``/``, ``..``, spaces, or control chars; using them
    raw in capture prefixes is a path-traversal / invalid-path bug.
    """
    cleaned = _SAFE_NAME_RE.sub("_", (value or "").strip()).strip("._")
    cleaned = cleaned[:max_len].rstrip("._")
    return cleaned or fallback


def parse_int(value: object, default: int | None = None) -> int | None:
    """Parse an int strictly; return ``default`` (None) on failure."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def parse_signal_dbm(value: str) -> int | None:
    """Parse a signal reading like '-57' into an int dBm, or None."""
    v = value.strip()
    if not v or v in {"-1", "--", "N/A"}:
        return None
    try:
        return int(float(v))
    except ValueError:
        return None


def parse_channel(value: str) -> int | None:
    """Parse a channel like '6', '36', or '11,' into an int, or None."""
    v = value.strip().rstrip(",")
    n = parse_int(v)
    return n if n is not None and 1 <= n <= 233 else None


def unique_macs(values: Iterable[str]) -> list[str]:
    """Return a deduplicated, ordered list of valid MACs from an iterable."""
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        mac = parse_mac(v)
        if mac and mac not in seen:
            seen.add(mac)
            out.append(mac)
    return out
