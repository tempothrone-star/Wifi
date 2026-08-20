"""API key validation, expiration, and invalid-key detection (NVIDIA NIM).

Validation is honest and layered:

1. **Format check** — non-empty, and (for NIM) prefixed with ``nvapi-``.
2. **Live probe** — an HTTP ``GET /v1/models`` against the NIM endpoint is the
   authoritative check. NVIDIA NIM keys do NOT embed a readable expiry
   timestamp, so the live probe is the only truthful way to detect an expired
   or revoked key:
     * 200        → VALID
     * 401 / 403  → INVALID (expired, revoked, or wrong)
     * 429        → RATE-LIMITED (key works but is throttled)
     * network err→ UNKNOWN (offline / can't verify)

No key is ever logged or stored — it is read from the environment/config and
used only for the probe.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

log = logging.getLogger("handshaker.apikey")

VALID = "VALID"
INVALID = "INVALID"
RATE_LIMITED = "RATE_LIMITED"
UNKNOWN = "UNKNOWN"
NOT_PRESENT = "NOT_PRESENT"

DEFAULT_NIM_URL = "https://integrate.api.nvidia.com/v1"


@dataclass
class ApiKeyStatus:
    """The honest status of an API key."""

    status: str
    reason: str
    http_code: int | None = None
    models_visible: int | None = None
    latency_ms: int | None = None

    @property
    def ok(self) -> bool:
        return self.status == VALID

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "reason": self.reason,
            "http_code": self.http_code,
            "models_visible": self.models_visible,
            "latency_ms": self.latency_ms,
        }


def load_nim_key(config: dict | None = None) -> str | None:
    """Resolve the NIM API key from config, else ``NIM_API_KEY`` env var."""
    cfg_key = None
    if config and config.get("nim", {}).get("api_key"):
        cfg_key = config["nim"]["api_key"]
    return cfg_key or os.environ.get("NIM_API_KEY")


def format_check(key: str | None) -> ApiKeyStatus | None:
    """Static format validation. Returns None if the key looks plausible."""
    if not key:
        return ApiKeyStatus(NOT_PRESENT, "no API key provided")
    key = key.strip()
    if len(key) < 20:
        return ApiKeyStatus(INVALID, "key too short to be a valid NIM key")
    if key.lower().startswith("nvapi-") and len(key) < 40:
        return ApiKeyStatus(INVALID, "nvapi- key appears truncated")
    return None


def probe_nim_key(key: str, base_url: str = DEFAULT_NIM_URL, timeout: int = 20) -> ApiKeyStatus:
    """Live-validate a NIM API key against ``GET /v1/models``.

    This is the authoritative expiration/invalid-key check: NVIDIA does not
    expose key expiry client-side, so a 401/403 response is the truthful signal
    that a key is expired or revoked.
    """
    import time
    req = urllib.request.Request(
        base_url.rstrip("/") + "/models",
        headers={"Authorization": f"Bearer {key}"},
        method="GET",
    )
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            code = resp.getcode()
            latency = int((time.monotonic() - start) * 1000)
            if code == 200:
                models = 0
                try:
                    data = json.loads(body)
                    models = len(data.get("data", []))
                except json.JSONDecodeError:
                    models = None
                return ApiKeyStatus(VALID, "key accepted by NIM endpoint",
                                    http_code=200, models_visible=models, latency_ms=latency)
            return ApiKeyStatus(UNKNOWN, f"unexpected HTTP {code}",
                                http_code=code, latency_ms=latency)
    except urllib.error.HTTPError as exc:
        latency = int((time.monotonic() - start) * 1000)
        if exc.code in (401, 403):
            return ApiKeyStatus(INVALID, f"key rejected (HTTP {exc.code}) — expired, revoked, or wrong",
                                http_code=exc.code, latency_ms=latency)
        if exc.code == 429:
            return ApiKeyStatus(RATE_LIMITED, "key rate-limited (HTTP 429)",
                                http_code=exc.code, latency_ms=latency)
        return ApiKeyStatus(UNKNOWN, f"HTTP {exc.code}", http_code=exc.code, latency_ms=latency)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return ApiKeyStatus(UNKNOWN, f"cannot reach NIM endpoint ({exc.__class__.__name__})")


def validate_nim_key(key: str | None, base_url: str = DEFAULT_NIM_URL,
                     timeout: int = 20) -> ApiKeyStatus:
    """Full validation: static format check, then live probe."""
    static = format_check(key)
    if static is not None:
        return static
    return probe_nim_key(key.strip(), base_url=base_url, timeout=timeout)
