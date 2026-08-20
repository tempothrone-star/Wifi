"""Persistent learning state: per-AP profiles of measured outcomes.

The store is a plain JSON file keyed by BSSID. Every entry is a *measured*
fact (what tool, what burst, did we get a verified handshake, when). There is
no derived "score" stored — scores are recomputed on demand by the policy layer.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..constants import LEARNING_DIR
from ..exceptions import LearningStateError

_STATE_FILE = LEARNING_DIR / "state.json"


@dataclass(frozen=True)
class ActionKey:
    """The identity of a deauth action that was tried."""

    tool: str
    burst: int
    reason: int

    @property
    def id(self) -> str:
        return f"{self.tool}|{self.burst}|{self.reason}"


class LearningStore:
    """Thread-safe append-only record of measured capture outcomes."""

    def __init__(self, path: Path | str | None = None, decay: float = 0.95,
                 enabled: bool = True) -> None:
        # ``path=None`` is in-memory only (no filesystem side effects) — same
        # contract as ``WpsHistory``. Persistence requires an explicit path
        # (the engine passes ``LEARNING_DIR / "state.json"``).
        self.path = Path(path) if path is not None else None
        self.decay = decay
        # ``enabled=False`` makes every record method a no-op, so the runtime
        # honestly honours ``learning.enabled: false`` (no learning is stored,
        # the policy simply has no evidence and explores uniformly).
        self.enabled = enabled
        # RLock: record() -> ensure_ap() re-enters the lock on the same thread.
        self._lock = threading.RLock()
        self._data: dict[str, Any] = {"version": 1, "aps": {}}
        if self.enabled:
            self._load()

    # ------------------------------------------------------------------ #
    def _load(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
            if isinstance(raw, dict) and isinstance(raw.get("aps"), dict):
                self._data = raw
        except (json.JSONDecodeError, OSError) as exc:
            raise LearningStateError(f"Corrupt learning state {self.path}: {exc}") from exc

    def save(self) -> None:
        if not self.enabled or not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with self._lock:
            tmp.write_text(json.dumps(self._data, indent=2))
            tmp.replace(self.path)

    # ------------------------------------------------------------------ #
    def ensure_ap(self, bssid: str, *, essid: str = "", channel: int = 0,
                  security: str = "", vendor: str = "", band: str = "") -> None:
        if not self.enabled:
            return
        with self._lock:
            ap = self._data["aps"].setdefault(bssid, {
                "essid": essid, "channel": channel, "security": security,
                "vendor": vendor, "band": band,
                "actions": [],
            })
            # Update static metadata when we learn better values.
            if essid:
                ap["essid"] = essid
            if channel:
                ap["channel"] = channel
            if security:
                ap["security"] = security
            if vendor:
                ap["vendor"] = vendor
            if band:
                ap["band"] = band

    def record(self, bssid: str, action: ActionKey, success: bool,
               reward: float | None = None) -> None:
        """Record a measured outcome.

        ``success`` must be backed by verification (the binary "did we capture
        a real handshake" signal). ``reward`` is the optional *graded* reward in
        [0, 1] (see ``graded_reward``); when omitted it defaults to 1.0/0.0 so
        the bandit still works in binary mode.
        """
        if not self.enabled:
            return
        r = reward if reward is not None else (1.0 if success else 0.0)
        r = max(0.0, min(1.0, float(r)))
        with self._lock:
            self.ensure_ap(bssid)
            ap = self._data["aps"][bssid]
            ap["actions"].append({
                "tool": action.tool,
                "burst": action.burst,
                "reason": action.reason,
                "success": bool(success),
                "reward": r,
                "ts": time.time(),
            })

    def record_pmkid(self, bssid: str, success: bool) -> None:
        """Record a measured PMKID outcome (separate track from handshakes).

        A PMKID capture is NOT a handshake, so it must never be recorded as the
        deauth action's reward — that would pollute the bandit with a misleading
        signal. This separate track lets the strategist learn PMKID-vs-handshake
        preference independently.
        """
        if not self.enabled:
            return
        with self._lock:
            self.ensure_ap(bssid)
            ap = self._data["aps"][bssid]
            ap.setdefault("pmkid", []).append({
                "success": bool(success),
                "ts": time.time(),
            })

    def record_latency(self, bssid: str, seconds: float) -> None:
        """Record a measured reconnection latency (deauth -> first EAPOL M1).

        Clamped to [0, 60] to bound a single bad reading. Used by the engine to
        adapt the post-deauth verify-wait to the target's *real* behaviour
        instead of a hardcoded sleep.
        """
        if not self.enabled:
            return
        s = max(0.0, min(60.0, float(seconds)))
        with self._lock:
            self.ensure_ap(bssid)
            ap = self._data["aps"][bssid]
            ap.setdefault("latencies", []).append({"value": s, "ts": time.time()})

    def latency_seconds(self, bssid: str, *, now: float | None = None) -> float | None:
        """Decayed mean reconnection latency for an AP, or None if unmeasured."""
        now = now if now is not None else time.time()
        ap = self.profile(bssid)
        if not ap:
            return None
        lat = ap.get("latencies", [])
        if not lat:
            return None
        total = 0.0
        weight_sum = 0.0
        for r in lat:
            age = max(0.0, now - float(r.get("ts", now)))
            w = self.decay ** (age / 60.0)
            total += float(r["value"]) * w
            weight_sum += w
        return total / weight_sum if weight_sum > 0 else None

    def record_capture_engine(self, bssid: str, engine: str, success: bool) -> None:
        """Record whether a capture *engine* (hcxdumptool/airodump) succeeded.

        Lets the capturer learn which engine works best per AP/context, instead
        of always preferring hcxdumptool blindly.
        """
        if not self.enabled:
            return
        with self._lock:
            self.ensure_ap(bssid)
            ap = self._data["aps"][bssid]
            ap.setdefault("engines", []).append({
                "engine": engine, "success": bool(success), "ts": time.time(),
            })

    def engine_success(self, bssid: str, engine: str, *, now: float | None = None) -> dict[str, float]:
        """Decayed ``{trials, wins, rate}`` for one capture engine on an AP."""
        now = now if now is not None else time.time()
        ap = self.profile(bssid)
        trials = wins = 0.0
        for e in (ap or {}).get("engines", []):
            if e.get("engine") != engine:
                continue
            age = max(0.0, now - float(e.get("ts", now)))
            w = self.decay ** (age / 60.0)
            trials += w
            if e.get("success"):
                wins += w
        return {"trials": trials, "wins": wins,
                "rate": (wins / trials) if trials > 0 else 0.0}

    def profile(self, bssid: str) -> dict[str, Any] | None:
        with self._lock:
            ap = self._data["aps"].get(bssid)
            return dict(ap) if ap else None

    def actions_for(self, bssid: str) -> list[dict[str, Any]]:
        ap = self.profile(bssid)
        return ap.get("actions", []) if ap else []

    def pmkid_outcomes(self, bssid: str) -> list[dict[str, Any]]:
        ap = self.profile(bssid)
        return ap.get("pmkid", []) if ap else []

    def all_bssids(self) -> list[str]:
        with self._lock:
            return list(self._data["aps"].keys())

    # ------------------------------------------------------------------ #
    # Context (cross-AP transfer) helpers
    # ------------------------------------------------------------------ #
    def context_key(self, bssid: str) -> str:
        """Derive a measured feature key for an AP: ``security|band|vendor``.

        Empty components fall back to ``?``. The vendor is the OUI (first three
        octets) — a measured fact, never a guessed manufacturer name.
        """
        ap = self.profile(bssid) or {}
        security = (ap.get("security") or "?").strip() or "?"
        band = (ap.get("band") or "?").strip() or "?"
        vendor = (ap.get("vendor") or "?").strip() or "?"
        return f"{security}|{band}|{vendor}"

    def bssids_with_context(self, context_key: str) -> list[str]:
        return [b for b in self.all_bssids() if self.context_key(b) == context_key]

    def context_action_stats(self, context_key: str, *,
                             now: float | None = None,
                             exclude_bssid: str | None = None) -> dict[str, dict[str, float]]:
        """Aggregate action stats across APs sharing ``context_key``.

        This is the transfer-learning substrate: a new AP inherits measured
        outcomes from structurally similar APs (same security × band × vendor),
        so it does not start cold. Weights decay exactly like per-AP stats.

        ``exclude_bssid`` drops that AP from the aggregate so a posterior that
        already counted the AP's own evidence does not double-count it via
        the context prior (``eff = own + λ · context``).
        """
        now = now if now is not None else time.time()
        agg: dict[str, dict[str, float]] = {}
        for bssid in self.bssids_with_context(context_key):
            if exclude_bssid and bssid == exclude_bssid:
                continue
            for act in self.actions_for(bssid):
                aid = f"{act['tool']}|{act['burst']}|{act['reason']}"
                age = max(0.0, now - float(act.get("ts", now)))
                weight = self.decay ** (age / 60.0)
                s = agg.setdefault(aid, {"trials": 0.0, "wins": 0.0, "rate": 0.0})
                s["trials"] += weight
                s["wins"] += weight * float(act.get("reward", 1.0 if act.get("success") else 0.0))
        for s in agg.values():
            s["rate"] = (s["wins"] / s["trials"]) if s["trials"] > 0 else 0.0
        return agg

    # ------------------------------------------------------------------ #
    # PMKID outcome statistics (decayed, per-AP and per-context)
    # ------------------------------------------------------------------ #
    def pmkid_stats(self, bssid: str, *, now: float | None = None) -> dict[str, float]:
        """Return ``{trials, wins, rate}`` for PMKID outcomes on one AP."""
        now = now if now is not None else time.time()
        trials = wins = 0.0
        for o in self.pmkid_outcomes(bssid):
            age = max(0.0, now - float(o.get("ts", now)))
            weight = self.decay ** (age / 60.0)
            trials += weight
            if o.get("success"):
                wins += weight
        return {"trials": trials, "wins": wins,
                "rate": (wins / trials) if trials > 0 else 0.0}

    def context_pmkid_stats(self, context_key: str, *,
                            now: float | None = None) -> dict[str, float]:
        """Aggregate PMKID outcomes across APs sharing ``context_key``."""
        now = now if now is not None else time.time()
        trials = wins = 0.0
        for bssid in self.bssids_with_context(context_key):
            for o in self.pmkid_outcomes(bssid):
                age = max(0.0, now - float(o.get("ts", now)))
                weight = self.decay ** (age / 60.0)
                trials += weight
                if o.get("success"):
                    wins += weight
        return {"trials": trials, "wins": wins,
                "rate": (wins / trials) if trials > 0 else 0.0}

    # ------------------------------------------------------------------ #
    # Recomputed statistics (never stored; derived fresh on every call).
    # ------------------------------------------------------------------ #
    def action_stats(self, bssid: str, *, now: float | None = None) -> dict[str, dict[str, float]]:
        """Return {action_id: {trials, wins, rate}} with time-decayed weights.

        ``wins`` is the sum of *graded rewards* (fractional wins), so a crackable
        pair (reward 0.4) contributes 0.4 of a win rather than nothing — the
        bandit learns from partial progress, not just full success. Older
        observations contribute less weight.
        """
        now = now if now is not None else time.time()
        stats: dict[str, dict[str, float]] = {}
        for act in self.actions_for(bssid):
            aid = f"{act['tool']}|{act['burst']}|{act['reason']}"
            age = max(0.0, now - float(act.get("ts", now)))
            weight = self.decay ** (age / 60.0)  # decay per minute
            s = stats.setdefault(aid, {"trials": 0.0, "wins": 0.0, "rate": 0.0})
            s["trials"] += weight
            # Graded reward when present; fall back to the binary success flag.
            s["wins"] += weight * float(act.get("reward", 1.0 if act.get("success") else 0.0))
        for s in stats.values():
            s["rate"] = (s["wins"] / s["trials"]) if s["trials"] > 0 else 0.0
        return stats
