"""Wireless adapter management: detect, monitor mode, injection test, reset.

The adapter layer never guesses adapter state — it interrogates the system
(``iw``/``iwconfig``/``airmon-ng``/``rfkill``) and reports what it observes.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from ..constants import TOOL_AIRMON_NG, TOOL_AIREPLAY_NG, TOOL_IW, TOOL_RFKILL
from ..exceptions import AdapterError, NoAdapterError
from ..tools.registry import ToolRegistry
from ..utils.proc import run

log = logging.getLogger("handshaker.adapter")

_INTERFACE_RE = re.compile(r"^\s*(?:phy#\d+\s+)?(wlan\w+|wl\w+|mon\w+)\s+", re.MULTILINE)
_MONITOR_HINT_RE = re.compile(r"Type:\s*monitor", re.IGNORECASE)


@dataclass
class AdapterInfo:
    """Observed facts about a wireless adapter (no inferred fields)."""

    interface: str
    monitor_mode: bool = False
    injection_ok: bool | None = None   # None == not tested
    channels: list[int] = field(default_factory=list)


class AdapterManager:
    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry
        self._killed_services = False

    # ------------------------------------------------------------------ #
    # Detection
    # ------------------------------------------------------------------ #
    def detect_interfaces(self) -> list[str]:
        """List wireless interfaces present on the system."""
        found: set[str] = set()
        # iw dev is authoritative when present.
        if self.registry.has(TOOL_IW):
            res = run([self.registry.iw().path, "dev"], timeout=15, check=False)
            for line in res.stdout.splitlines():
                m = re.match(r"^\s*Interface\s+(\S+)", line)
                if m:
                    found.add(m.group(1))
        else:
            res = run(["iwconfig"], timeout=15, check=False)
            for line in res.stdout.splitlines():
                m = re.match(r"^(\S+)\s+IEEE\s+802\.11", line)
                if m:
                    found.add(m.group(1))
        # airmon-ng's own listing can reveal monitor interfaces too.
        if self.registry.has(TOOL_AIRMON_NG):
            res = run([self.registry.airmon().path], timeout=15, check=False)
            for line in res.stdout.splitlines():
                m = re.search(r"^\s*(?:phy\d+\s+)?Interface\s+(mon\w+|wlan\w+|wl\w+)", line)
                if m:
                    found.add(m.group(1))
        return sorted(found)

    def select_interface(self, requested: str | None = None) -> str:
        """Pick a working interface; prefer an explicit request, else auto-detect."""
        ifaces = self.detect_interfaces()
        if not ifaces:
            raise NoAdapterError("No wireless adapter detected. Is it plugged in / unblocked?")
        if requested and requested in ifaces:
            return requested
        if requested:
            raise NoAdapterError(
                f"Requested interface '{requested}' not found. Available: {', '.join(ifaces)}"
            )
        # Prefer managed (non-mon) interfaces for the starting point.
        # airmon-ng names vary: wlan0mon, wlan1mon, mon0, wlp3s0mon, …
        managed = [i for i in ifaces if not _looks_like_monitor(i)]
        return (managed or ifaces)[0]

    # ------------------------------------------------------------------ #
    # Mode control
    # ------------------------------------------------------------------ #
    def is_monitor(self, interface: str) -> bool:
        if self.registry.has(TOOL_IW):
            res = run([self.registry.iw().path, "dev", interface, "info"], timeout=15, check=False)
            return bool(_MONITOR_HINT_RE.search(res.stdout))
        res = run(["iwconfig", interface], timeout=15, check=False)
        return "Mode:Monitor" in res.output

    def enable_monitor(self, interface: str, stop_services: bool = True) -> str:
        """Enable monitor mode, returning the (possibly new) interface name.

        ``stop_services`` controls whether conflicting processes (NetworkManager,
        wpa_supplicant, …) are killed via ``airmon-ng check kill``. This is a
        *disruptive* side effect, so it is explicit and configurable rather than
        hidden inside the abstraction. When False, monitor mode is attempted
        without killing anything (may fail if the interface is in use).
        """
        if self.is_monitor(interface):
            log.info("%s already in monitor mode", interface)
            return interface
        if self.registry.has(TOOL_AIRMON_NG):
            if stop_services:
                self.registry.airmon().check_kill()
                self._killed_services = True
            res = self.registry.airmon().start_monitor(interface)
            new_iface = _parse_monitor_interface(res.output)
            if new_iface:
                return new_iface
            # airmon-ng may have created a monitor iface we failed to parse.
            # Do not blindly `iw set type` the original name in that case.
            for cand in self.detect_interfaces():
                if cand != interface and _looks_like_monitor(cand) and self.is_monitor(cand):
                    return cand
            if self.is_monitor(interface):
                return interface
        # Fallback: raw iw set type monitor (no TX-power or other hidden changes).
        if self.registry.has(TOOL_IW):
            self.registry.iw().set_mode(interface, "monitor")
            if self.is_monitor(interface):
                return interface
            raise AdapterError(f"iw set type monitor did not put {interface} into monitor mode")
        raise AdapterError(f"Could not enable monitor mode on {interface} (airmon-ng/iw unavailable).")

    def reset(self, interface: str) -> None:
        """Restore managed mode and restart network services."""
        if self.registry.has(TOOL_AIRMON_NG):
            self.registry.airmon().stop_monitor(interface)
        if self.registry.has(TOOL_IW):
            self.registry.iw().set_mode(interface, "managed")
        # Only restart services we actually stopped.
        if self._killed_services:
            run(["service", "NetworkManager", "restart"], timeout=30, check=False)
            run(["service", "wpa_supplicant", "restart"], timeout=30, check=False)
            self._killed_services = False
        log.info("Adapter %s reset to managed mode", interface)

    def check_injection(self, interface: str) -> bool:
        """Run aireplay-ng --test; return True only on observed success."""
        if not self.registry.has(TOOL_AIREPLAY_NG):
            log.warning("aireplay-ng missing; cannot test injection.")
            return False
        res = self.registry.aireplay().test_injection(interface)
        ok = "Injection is working!" in res.output
        log.info("Injection test: %s", "PASS" if ok else "FAIL/UNKNOWN")
        return ok

    def unblock_rfkill(self) -> None:
        if self.registry.has(TOOL_RFKILL):
            self.registry.rfkill().unblock_all()


def _looks_like_monitor(name: str) -> bool:
    """True for typical monitor-mode interface names (wlan0mon, mon0, …)."""
    n = (name or "").lower()
    return n.startswith("mon") or n.endswith("mon")


def _parse_monitor_interface(output: str) -> str | None:
    """Extract the NEW monitor interface name from airmon-ng's output.

    airmon-ng prints, for mac80211 drivers:
        ``(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)``
    The monitor interface is the token AFTER ``on [phyN]`` (e.g. ``wlan0mon``),
    NOT the interface in the ``for [phyN]`` clause (the original ``wlan0``).
    """
    # Primary mac80211 form: "...vif enabled for [phy0]wlan0 on [phy0]wlan0mon"
    m = re.search(r"vif enabled for .*?\bon\s+\[?[^\]\s]+\]?\s*(\S+)", output)
    if m:
        return m.group(1).strip("[]()")
    # Alternate form: "...vif enabled on [phy1]wlan0mon"
    m = re.search(r"vif enabled on\s+\[?[^\]\s]+\]?\s*(\S+)", output)
    if m:
        return m.group(1).strip("[]()")
    return None
