"""Strategist — decides *what* to attack and *how*, grounded in measurement.

Decisions are deterministic and evidence-based:

* Targets are prioritized by a weighted, multi-dimensional score derived from the
  *actual* scan (signal, WPA suite, client count, learning history).
* A **per-target strategy** is chosen: client-based deauth (best when active
  clients exist) vs PMKID (best for clientless APs; N/A for WPA3/SAE).
* Deauth actions are selected only from tools the registry proves are installed,
  via the adaptive bandit (bounded exploration).
* Every decision carries a rationale for auditability.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..constants import SECURITY_OPEN, SECURITY_WEP
from ..learning.model import ActionPolicy, PolicyDecision
from ..learning.state import ActionKey, LearningStore
from ..tools.registry import ToolRegistry
from .deauth import reason_supported, scapy_available
from .scanner import AccessPoint, ScanResult

log = logging.getLogger("handshaker.strategist")


@dataclass
class TargetStrategy:
    """The chosen approach for a single AP."""

    ap: AccessPoint
    priority: float
    prefer_pmkid: bool
    deauth_tools: list[str]
    reasons: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        mode = "PMKID" if self.prefer_pmkid else "client-deauth handshake"
        return f"{self.ap.essid or self.ap.bssid} (priority={self.priority:.1f}, mode={mode})"


class Strategist:
    def __init__(self, registry: ToolRegistry, store: LearningStore, config: dict) -> None:
        self.registry = registry
        self.store = store
        self.config = config
        learn_cfg = config["learning"]
        self.policy = ActionPolicy(
            store,
            exploration=float(learn_cfg["exploration"]),
            min_observations=int(learn_cfg["min_observations"]),
            strategy=learn_cfg.get("strategy", "thompson"),
            transfer=float(learn_cfg.get("transfer", 0.5)),
        )

    @staticmethod
    def _vendor_oui(bssid: str) -> str:
        """First three octets of a BSSID (the OUI) — a measured vendor hint."""
        return bssid.replace(":", "").replace("-", "")[:6].lower()

    # ------------------------------------------------------------------ #
    # Target prioritization
    # ------------------------------------------------------------------ #
    def prioritize(self, scan: ScanResult) -> list[AccessPoint]:
        """Rank in-scope APs into an ordered target list (weighted scoring)."""
        tg = self.config["targets"]
        wpa_only = bool(self.config["capture"]["wpa_only"])
        min_signal = int(self.config["scan"]["min_signal"])
        exclude = {b.lower() for b in tg.get("exclude", [])}

        explicit_bssids = {b.lower() for b in tg.get("bssid", [])}
        explicit_essids = [e.lower() for e in tg.get("essid", [])]
        explicit_channels = {int(c) for c in tg.get("channel", [])}

        candidates: list[AccessPoint] = []
        for ap in scan.aps.values():
            if ap.bssid.lower() in exclude:
                continue
            # An explicit operator target (by BSSID) is authoritative: it
            # bypasses the automatic scope filters (signal / enterprise / WPA
            # / ESSID / channel). Automatic discovery still applies them.
            is_explicit = ap.bssid.lower() in explicit_bssids
            if not is_explicit:
                # Enterprise (802.1X/MGT) APs are out of scope: their handshakes
                # are capturable but NOT recoverable to a PSK, so attacking them
                # wastes airtime. Explicitly skipped (still visible in raw scan).
                if ap.is_enterprise:
                    log.info("skipping enterprise AP %s (out of PSK scope)", ap.essid or ap.bssid)
                    continue
                if wpa_only and ap.security_label in (SECURITY_WEP, SECURITY_OPEN):
                    continue
                if ap.power < min_signal:
                    continue
                if explicit_essids and ap.essid.lower() not in explicit_essids:
                    continue
                if explicit_channels and ap.channel not in explicit_channels:
                    continue
            candidates.append(ap)

        candidates.sort(key=lambda ap: self._score(ap, scan), reverse=True)
        max_targets = int(tg.get("max_targets", 0) or 0)
        if max_targets > 0:
            candidates = candidates[:max_targets]
        return candidates

    def _score(self, ap: AccessPoint, scan: ScanResult) -> float:
        """Weighted, multi-dimensional target score (deterministic).

        Now includes **learned** success signals: APs that historically yielded
        PMKIDs (clientless capture) or handshakes are ranked higher, so the
        strategist spends time on targets it can actually capture.
        """
        clients = len(scan.clients_of(ap.bssid))
        explicit = {b.lower() for b in self.config["targets"].get("bssid", [])}
        # Transition mode (WPA2/WPA3) is high value: capturable via downgrade.
        suite_bonus = {"WPA3": 25.0, "WPA2/WPA3": 24.0, "WPA2": 20.0, "WPA": 10.0}.get(
            ap.security_label, 0.0)
        score = (
            100.0 if ap.bssid.lower() in explicit else 0.0
        )
        score += suite_bonus
        score += max(0.0, float(ap.power) + 100.0) * 1.0     # signal strength
        score += min(clients, 15) * 4.0                        # client availability
        # Learned handshake history: proven-successful APs get a boost.
        if self.store.actions_for(ap.bssid):
            score += 5.0
        # Learned PMKID history: APs that reliably yield PMKIDs get a boost.
        pmkid = self.store.pmkid_stats(ap.bssid)
        if pmkid.get("rate", 0.0) > 0.5:
            score += 8.0
        elif pmkid.get("rate", 0.0) > 0.0:
            score += 3.0
        return score

    # ------------------------------------------------------------------ #
    # Per-target strategy
    # ------------------------------------------------------------------ #
    def strategy_for(self, ap: AccessPoint, scan: ScanResult) -> TargetStrategy:
        """Choose client-deauth vs PMKID for this AP, and the deauth tool chain.

        WPA3 transition-mode APs (``WPA2/WPA3``) are capturable via a WPA2
        downgrade, so they are treated as handshake-capturable — only a *pure*
        WPA3/SAE AP excludes PMKID.
        """
        clients = scan.clients_of(ap.bssid)
        is_pure_wpa3 = ap.is_pure_wpa3
        is_transition = ap.is_transition_mode
        pmkid_enabled = bool(self.config["pmkid"]["enabled"])

        # Pure WPA3/SAE: PMKID does not apply — aim for the (SAE) handshake.
        # Transition mode: WPA2 downgrade makes it capturable like WPA2.
        # No clients -> PMKID is the only clientless option.
        prefer_pmkid = (not is_pure_wpa3) and (not clients) and pmkid_enabled

        reasons = []
        if is_pure_wpa3:
            reasons.append("WPA3/SAE: PMKID not applicable; targeting SAE handshake")
        elif is_transition:
            reasons.append("WPA3 transition mode: capturable via WPA2 downgrade")
        if not clients:
            reasons.append("no associated clients observed; PMKID (clientless) preferred")

        tools = self._deauth_chain()
        return TargetStrategy(
            ap=ap,
            priority=self._score(ap, scan),
            prefer_pmkid=prefer_pmkid,
            deauth_tools=tools,
            reasons=reasons,
        )

    def _available_deauth_tools(self) -> list[str]:
        """Configured deauth tools that are actually usable right now.

        "scapy" is a Python library, not a PATH binary, so it is checked via
        ``scapy_available()``; every other tool is checked against the registry.
        """
        configured = self.config["deauth"]["tools"]
        out: list[str] = []
        for t in configured:
            if t == "scapy":
                if scapy_available():
                    out.append(t)
            elif self.registry.has(t):
                out.append(t)
        return out

    def available_deauth_tools(self) -> list[str]:
        """Public alias — the ordered, usable deauth tool chain.

        Exposes the same data as the (now-private) ``_deauth_chain`` without
        coupling the engine to private Strategist internals.
        """
        return self._available_deauth_tools()

    def _deauth_chain(self) -> list[str]:
        """Ordered deauth tool chain (installed/usable tools only).

        Returns an empty list when no deauth tool is usable — the engine treats
        that as "cannot deauth" and skips active attacks rather than pretending
        a tool exists.
        """
        return self._available_deauth_tools()

    # ------------------------------------------------------------------ #
    # Action selection
    # ------------------------------------------------------------------ #
    def candidate_actions(self) -> list[ActionKey]:
        """All deauth actions the installed toolset can perform.

        **Capability-aware**: ``reason`` is only varied (and thus learned) for
        tools that actually honour an arbitrary reason code (scapy). For
        aireplay-ng/mdk4/bettercap a single canonical reason is used, so the
        bandit does not treat "same tool, same burst, different reason" as
        distinct arms when the reason is not causal.
        """
        tools = self._available_deauth_tools()
        bursts = _burst_options(int(self.config["deauth"]["burst_size"]))
        reasons = [int(r) for r in self.config["deauth"]["reason_codes"]]
        actions: list[ActionKey] = []
        for tool in tools:
            for burst in bursts:
                # Only scapy honours the reason code; others use one canonical value.
                rs = reasons if reason_supported(tool) else [7]
                for reason in rs:
                    actions.append(ActionKey(tool=tool, burst=burst, reason=reason))
        return actions

    def choose_action(self, bssid: str, candidates: list[ActionKey],
                      ap: AccessPoint | None = None) -> PolicyDecision:
        """Choose a deauth action, optionally passing the AP's context for
        cross-AP transfer learning."""
        context_key = None
        if ap is not None:
            # Record measured context so similar APs share a prior.
            self.store.ensure_ap(ap.bssid, essid=ap.essid, channel=ap.channel,
                                 security=ap.security_label,
                                 vendor=self._vendor_oui(ap.bssid),
                                 band=ap.band)
            context_key = self.store.context_key(ap.bssid)
        return self.policy.choose(bssid, candidates, context_key=context_key)


def _burst_options(base: int) -> list[int]:
    """A small, ordered set of burst sizes around ``base`` for the bandit."""
    if base <= 0:
        base = 10
    return sorted({base, base * 2, max(1, base // 2)})
