"""hcxdumptool / hcxpcapngtool / hcxlabtool wrappers.

hcxdumptool is the primary PMKID + EAPOL capture engine. Its CLI **changed in
v6.3.0 (May 2023)**, so this wrapper is *version-adaptive*: it probes
``hcxdumptool --help`` once and selects the correct flag family, never assuming
a version.

Flag families (verified against ZerBea's own docs/changelog):

* output pcapng  : v6.3+ ``-w``          | <6.3 ``-o``
* status display : v6.3+ ``--rds=N``     | <6.3 ``--enable_status=N``
* disable client : v6.3+ ``--attemptclientmax=0`` | <6.3 ``--disable_client_attacks``
* disable AP     : v6.3+ ``--attemptapmax=0``     | <6.3 ``--disable_ap_attacks``
* AP target filter: v6.3+ removed (use ``--bpf=``); <6.3 ``--filtermode=2 --filterlist_ap=``
* channel pin    : ``-c CH`` (both)
* duration       : ``-t SECONDS`` (both)

hcxpcapngtool converts the pcapng to hashcat 22000 and independently reports
EAPOL/PMKID presence. NOTE: ``-E`` (ESSID wordlist) is intentionally NOT used —
we never extract password candidates; this tool is capture-only.
"""

from __future__ import annotations

import re

from ..constants import (
    TOOL_HCXDUMPTOOL,
    TOOL_HCXLABTOOL,
    TOOL_HCXPCAPNGTOOL,
    TOOL_HCXPSCKTOOL,
)
from ..utils.proc import ProcResult, run
from .base import Tool


def _has_short_flag(out: str, flag: str) -> bool:
    """Word-boundary match for short flags (so ``-w`` isn't confused with
    ``--weakcandidate``, ``-o`` with ``--proberesponsetx``, etc.)."""
    return bool(re.search(rf"(?<![-\\w]){re.escape(flag)}\\b", out))


class Hcxdumptool(Tool):
    name = TOOL_HCXDUMPTOOL

    def __init__(self, override: str | None = None) -> None:
        super().__init__(override)
        self._caps: dict[str, bool] | None = None

    def capabilities(self) -> dict[str, bool]:
        """Detect which flag family this hcxdumptool version uses.

        Runs ``hcxdumptool --help`` once and caches the result. Each flag is
        verified against the binary's own help output — nothing is assumed, so
        the wrapper is robust across pre- and post-6.3 builds.
        """
        if self._caps is None:
            res = run([self.path, "--help"], timeout=20, check=False)
            out = res.stdout + res.stderr
            self._caps = {
                # New (v6.3+) flag family.
                "new_output_w": _has_short_flag(out, "-w"),
                "rds": "--rds" in out,
                "attemptclientmax": "--attemptclientmax" in out,
                "attemptapmax": "--attemptapmax" in out,
                # Old (<6.3) flag family.
                "old_output_o": _has_short_flag(out, "-o"),
                "enable_status": "--enable_status" in out,
                "disable_client_attacks": "--disable_client_attacks" in out,
                "disable_ap_attacks": "--disable_ap_attacks" in out,
                "disable_deauth": "--disable_deauthentication" in out,
                "filtermode": "--filtermode" in out or "--filter_mode" in out,
                "filterlist_ap": "--filterlist_ap" in out,
            }
        return self._caps

    def capture_args(
        self,
        interface: str,
        out_file: str,
        *,
        channel: str | None = None,
        bssid: str | None = None,
        duration: int | None = None,
        disable_deauth: bool = True,
        ap_only: bool = False,
        status: int = 1,
    ) -> list[str]:
        """Build the version-adaptive argv (shared by ``capture`` and the
        background capturer, which Popen()s these args directly).

        ``bssid`` filtering only works on <6.3 (via ``--filterlist_ap``); on
        6.3+ single-AP filtering requires a compiled BPF (``--bpf=``), which the
        engine achieves by pinning one channel per target instead — a safe,
        honest degradation.
        """
        caps = self.capabilities()

        # Output flag: -w (6.3+) or -o (<6.3).
        if caps.get("new_output_w"):
            args = [self.path, "-i", interface, "-w", out_file]
        else:
            args = [self.path, "-i", interface, "-o", out_file]

        if channel is not None:
            args += ["-c", channel]

        # AP target filter (<6.3 only).
        if bssid is not None and caps.get("filterlist_ap") and caps.get("filtermode"):
            args += ["--filtermode=2", "--filterlist_ap=" + bssid.replace(":", "")]

        # Disable deauth (strategist drives deauth with aireplay/mdk4/bettercap).
        if disable_deauth and caps.get("disable_deauth"):
            args += ["--disable_deauthentication"]

        # AP-only attack: PMKID + clientless EAPOL.
        if ap_only:
            if caps.get("attemptclientmax"):
                args += ["--attemptclientmax=0"]      # v6.3+
            elif caps.get("disable_client_attacks"):
                args += ["--disable_client_attacks"]   # <6.3

        # Real-time status display.
        if caps.get("rds"):
            args += ["--rds=" + str(status)]
        elif caps.get("enable_status"):
            args += ["--enable_status=" + str(status)]

        if duration is not None:
            args += ["-t", str(duration)]

        return args

    def capture(
        self,
        interface: str,
        out_file: str,
        *,
        channel: str | None = None,
        bssid: str | None = None,
        duration: int | None = None,
        disable_deauth: bool = True,
        ap_only: bool = False,
        status: int = 1,
    ) -> ProcResult:
        """Capture PMKIDs + EAPOL with hcxdumptool (flags adapted to version)."""
        args = self.capture_args(
            interface, out_file, channel=channel, bssid=bssid, duration=duration,
            disable_deauth=disable_deauth, ap_only=ap_only, status=status,
        )
        return run(args, timeout=(duration or 300) + 30, check=False)


class Hcxpcapngtool(Tool):
    name = TOOL_HCXPCAPNGTOOL

    def convert(self, capture_file: str, out_file: str) -> ProcResult:
        """Convert a pcapng capture to hashcat 22000 format (no wordlist)."""
        return run(
            [self.path, "-o", out_file, capture_file],
            timeout=120,
            check=False,
        )


class Hcxlabtool(Tool):
    name = TOOL_HCXLABTOOL

    def convert(self, capture_file: str, out_file: str) -> ProcResult:
        return run([self.path, "-o", out_file, capture_file], timeout=120, check=False)


class Hcxpsktool(Tool):
    name = TOOL_HCXPSCKTOOL

    def convert(self, capture_file: str, out_file: str) -> ProcResult:
        return run([self.path, "-o", out_file, capture_file], timeout=120, check=False)
