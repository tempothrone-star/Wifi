"""Token-bucket rate limiter + exponential backoff for the NIM API.

The limiter is deterministic and self-documenting: every request must acquire a
token, and any request that fails with a rate-limit (429) or server (5xx) error
triggers backoff. This prevents the tool from hammering the API and lets it
degrade gracefully under NIM's per-key request caps.

NVIDIA NIM is OpenAI-compatible; it returns HTTP 429 with an optional
``Retry-After`` header when a key exceeds its rate limit. We honor that header
and, absent one, fall back to exponential backoff with jitter.
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field


@dataclass
class BackoffPolicy:
    """Exponential backoff state shared across requests to the same model."""

    base_delay: float = 1.0
    max_delay: float = 60.0
    factor: float = 2.0
    jitter: float = 0.1
    _delay: float = 0.0
    _rng: random.Random = field(default_factory=lambda: random.Random())

    def on_success(self) -> None:
        self._delay = 0.0

    def on_failure(self, retry_after: float | None = None) -> None:
        if retry_after is not None and retry_after > 0:
            self._delay = min(self.max_delay, retry_after)
        elif self._delay <= 0:
            self._delay = self.base_delay
        else:
            self._delay = min(self.max_delay, self._delay * self.factor)

    @property
    def current(self) -> float:
        if self._delay <= 0:
            return 0.0
        j = self._delay * self.jitter * self._rng.random()
        return self._delay + j


class TokenBucket:
    """Thread-safe token bucket limiting requests per window."""

    def __init__(self, rate: float, burst: int | None = None) -> None:
        """``rate`` = tokens per second; ``burst`` = max bucket size."""
        self.rate = float(rate)
        self.capacity = float(burst if burst is not None else max(1.0, rate))
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0, timeout: float | None = None) -> bool:
        """Block until ``tokens`` are available. Returns False on timeout."""
        if self.rate <= 0:
            with self._lock:
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True
            return False
        deadline = (time.monotonic() + timeout) if timeout is not None else None
        while True:
            with self._lock:
                self._refill()
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True
                # Compute wait until enough tokens are available.
                needed = tokens - self.tokens
                wait = needed / self.rate if self.rate > 0 else float("inf")
            if deadline is not None and time.monotonic() + wait > deadline:
                return False
            if wait > 0:
                time.sleep(min(wait, 0.2))

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.updated
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.updated = now
