"""NVIDIA NIM model registry and smart model selection.

The registry is a curated, honest list of real NIM model IDs (from
build.nvidia.com) plus dynamic discovery against the ``/v1/models`` endpoint.
Selection is deterministic and preference-ordered:

1. Explicit ``nim.model`` from config (authoritative override).
2. A fast, low-latency model tier for frequent strategy hints (so the capture
   loop stays responsive and cheap).
3. A large, capable tier as fallback when the fast tier is degraded (rate
   limited / errors).

A model that returns 429/5xx is marked **degraded** and deprioritized with a
cooldown, so the selector "learns" which models are currently usable — based
only on measured HTTP outcomes, never on guesses.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("handshaker.nim.models")

# Curated real model IDs (OpenAI-compatible ``model`` strings for NIM).
# Tiers: "fast" = small/fast/cheap for frequent hints; "large" = capable.
_MODEL_CATALOG: list[dict[str, Any]] = [
    # --- fast tier ----------------------------------------------------- #
    {"id": "meta/llama-3.1-8b-instruct", "tier": "fast", "context": 128000},
    {"id": "ibm/granite-3.3-8b-instruct", "tier": "fast", "context": 128000},
    {"id": "mistralai/mistral-small-4-119b-2603", "tier": "fast", "context": 128000},
    # --- large tier ---------------------------------------------------- #
    {"id": "meta/llama-3.3-70b-instruct", "tier": "large", "context": 128000},
    {"id": "meta/llama-3.1-405b-instruct", "tier": "large", "context": 128000},
    {"id": "nvidia/llama-3.1-nemotron-70b-instruct", "tier": "large", "context": 128000},
    {"id": "nvidia/llama-3.3-nemotron-super-49b-v1", "tier": "large", "context": 128000},
    {"id": "mistralai/mistral-large-2-instruct", "tier": "large", "context": 128000},
    {"id": "mistralai/mixtral-8x22b-instruct-v0.1", "tier": "large", "context": 64000},
    {"id": "qwen/qwen2.5-coder-32b-instruct", "tier": "large", "context": 128000},
    {"id": "qwen/qwen3-coder-480b-a35b-instruct", "tier": "large", "context": 256000},
    {"id": "deepseek-ai/deepseek-r1", "tier": "large", "context": 128000},
    {"id": "deepseek-ai/deepseek-v3.1", "tier": "large", "context": 128000},
    {"id": "moonshotai/kimi-k2-instruct", "tier": "large", "context": 128000},
    {"id": "meta/llama-4-maverick-17b-128e-instruct", "tier": "large", "context": 1000000},
]


@dataclass
class ModelHealth:
    """Measured status of one model (degraded with cooldown after errors)."""

    failures: int = 0
    successes: int = 0
    degraded_until: float = 0.0

    @property
    def degraded(self) -> bool:
        return time.time() < self.degraded_until


class ModelRegistry:
    """Holds the catalog, optional dynamic discovery, and per-model health."""

    def __init__(self, explicit: str | None = None, prefer_tier: str = "fast") -> None:
        self.explicit = explicit
        self.prefer_tier = prefer_tier
        self._catalog: list[dict[str, Any]] = list(_MODEL_CATALOG)
        self._health: dict[str, ModelHealth] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def all_ids(self) -> list[str]:
        return [m["id"] for m in self._catalog]

    def ordered(self) -> list[str]:
        """Model IDs ordered by preference (explicit > tier > health)."""
        if self.explicit:
            return [self.explicit]
        fast = [m["id"] for m in self._catalog if m["tier"] == "fast"]
        large = [m["id"] for m in self._catalog if m["tier"] == "large"]
        if self.prefer_tier == "large":
            ordered = large + fast
        else:
            ordered = fast + large
        with self._lock:
            # Demote degraded models to the end (stable, measured only).
            ordered.sort(key=lambda mid: (0 if not self._health.get(mid, ModelHealth()).degraded else 1))
        return ordered

    def mark_success(self, model_id: str) -> None:
        with self._lock:
            h = self._health.setdefault(model_id, ModelHealth())
            h.successes += 1
            h.failures = 0
            h.degraded_until = 0.0

    def mark_failure(self, model_id: str, *, retry_after: float | None = None,
                     cooldown: float = 30.0) -> None:
        with self._lock:
            h = self._health.setdefault(model_id, ModelHealth())
            h.failures += 1
            backoff = retry_after if retry_after else min(cooldown * (2 ** (h.failures - 1)), 300.0)
            h.degraded_until = time.time() + backoff
            log.info("model %s degraded for %.0fs (failures=%d)", model_id, backoff, h.failures)

    def merge_discovered(self, discovered_ids: list[str]) -> None:
        """Add models discovered from ``/v1/models`` that are not already known.

        Discovered models are appended to the fast tier so they can be selected
        without overriding the curated ordering.
        """
        known = {m["id"] for m in self._catalog}
        for mid in discovered_ids:
            if mid not in known:
                self._catalog.append({"id": mid, "tier": "fast", "context": None})
                known.add(mid)
