"""Guided hardware self-test ("lab validation").

This is the workflow that closes the loop between "correctly implemented logic"
and "proven working on real WiFi". It walks the operator through a real,
in-order validation on their own network:

  1. root privileges
  2. Kali toolchain completeness (doctor)
  3. wireless adapter detection
  4. monitor-mode enablement
  5. packet-injection test (aireplay-ng --test)
  6. live scan (finds real APs)
  7. (optional) capture + strong verification of your own network
  8. (optional) WPS detection (wash)

Every step is a *measured* pass/fail — nothing is assumed. The result is a
``SelfTestReport`` with a per-step status and a truthful overall verdict.

For authorized security testing only — run against networks you own.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..doctor import Doctor
from ..exceptions import HandshakerError
from ..tools.registry import ToolRegistry
from ..utils.system import detect_root

log = logging.getLogger("handshaker.selftest")


@dataclass
class Step:
    """One self-test step and its measured outcome."""

    name: str
    passed: bool
    detail: str = ""
    skipped: bool = False

    @property
    def status(self) -> str:
        if self.skipped:
            return "SKIPPED"
        return "PASS" if self.passed else "FAIL"


@dataclass
class SelfTestReport:
    """Complete, honest self-test result."""

    steps: list[Step] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Overall pass = every non-skipped step passed."""
        return all(s.passed or s.skipped for s in self.steps)

    def add(self, name: str, passed: bool, detail: str = "", skipped: bool = False) -> None:
        self.steps.append(Step(name=name, passed=passed, detail=detail, skipped=skipped))

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "steps": [{"name": s.name, "status": s.status, "detail": s.detail}
                      for s in self.steps],
        }


class SelfTester:
    """Runs the ordered hardware validation workflow."""

    def __init__(self, engine) -> None:
        self.engine = engine
        self.registry: ToolRegistry = engine.registry
        self.config = engine.config

    # ------------------------------------------------------------------ #
    def run(self, *, do_capture: bool = False, do_wps: bool = False,
            scan_duration: int = 10) -> SelfTestReport:
        rep = SelfTestReport()

        # 1) root
        rep.add("root privileges", detect_root(),
                "required for monitor mode, injection, and deauth" if not detect_root() else "ok")

        # 2) toolchain
        doc = Doctor(self.config).run(check_api_key=False)
        rep.add("core toolchain", doc.core_ready,
                f"{len(doc.tools)}/{len(doc.tools) + len(doc.missing)} tools present" if doc.core_ready
                else f"missing: {', '.join(doc.missing[:6])}")

        # 3) adapter detection (may fail if iw/iwconfig are missing — report, don't crash)
        try:
            ifaces = self.engine.adapter.detect_interfaces()
        except HandshakerError as exc:
            rep.add("wireless adapter", False, str(exc))
            return rep
        rep.add("wireless adapter", bool(ifaces),
                ", ".join(ifaces) if ifaces else "no wireless interface found")
        if not ifaces:
            return rep

        iface = self.engine.adapter.select_interface(self.config["general"].get("interface"))
        rep.add("interface selected", True, iface)

        mon_iface = None
        try:
            # 4) monitor mode
            try:
                mon_iface = self.engine.adapter.enable_monitor(iface)
                rep.add("monitor mode", True, mon_iface)
            except HandshakerError as exc:
                rep.add("monitor mode", False, str(exc))
                return rep

            # 5) injection
            inj = self.engine.adapter.check_injection(mon_iface)
            rep.add("packet injection", inj,
                    "aireplay-ng --test confirmed injection" if inj else "injection not confirmed")

            # 6) live scan
            try:
                scan = self.engine.scanner.scan(mon_iface, scan_duration)
                n = len(scan.aps)
                rep.add("live scan", n > 0, f"{n} access point(s) seen")
            except HandshakerError as exc:
                rep.add("live scan", False, str(exc))
                return rep

            # 7) optional capture + verify (needs a target; pick the strongest AP)
            if do_capture and scan.aps:
                ap = max(scan.aps.values(), key=lambda a: a.power)
                rep.add("capture target", True, f"{ap.essid or ap.bssid} (ch {ap.channel})")
                try:
                    session = self.engine.capturer.start(mon_iface, ap.bssid, ap.channel,
                                                         essid=ap.essid)
                    import time
                    time.sleep(5)
                    session.stop()
                    files = self.engine.capturer.output_files(session)
                    if files:
                        rpt = self.engine.verify(str(files[0]))
                        rep.add("handshake verify", rpt.passed, rpt.reason)
                    else:
                        rep.add("handshake verify", False, "no capture output produced")
                except HandshakerError as exc:
                    rep.add("handshake verify", False, str(exc))
            elif do_capture:
                rep.add("capture target", False, "no APs found to capture", skipped=True)

            # 8) optional WPS detection
            if do_wps:
                try:
                    aps = self.engine.wps.detect(mon_iface)
                    rep.add("WPS detection", True, f"{len(aps)} WPS-enabled AP(s)")
                except HandshakerError as exc:
                    rep.add("WPS detection", False, str(exc))
        finally:
            # Always restore the adapter if we enabled monitor mode, even on
            # unexpected exceptions (HandshakerError early-returns still hit this).
            if mon_iface and self.config["adapter"]["reset_on_exit"]:
                try:
                    self.engine.adapter.reset(mon_iface)
                except HandshakerError as exc:
                    rep.add("adapter reset", False, str(exc))
                else:
                    # Don't duplicate the row if we already recorded a reset.
                    if not any(s.name == "adapter reset" for s in rep.steps):
                        rep.add("adapter reset", True, "restored managed mode")

        return rep
