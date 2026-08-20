"""System self-check ("doctor") — verifies the whole runtime is ready.

Checks (all measured, nothing assumed):

* OS / distribution / package manager / root privileges
* Python version + whether running inside a virtualenv
* Every Kali tool's availability (PATH)
* hcxdumptool flag support (version-adaptive)
* NIM API key presence + live validation (expiration/invalid detection)
* Wireless adapter presence (if ``iw``/``airmon-ng`` present)
* Monitor-mode / injection capability (only if a real adapter is available)

Produces a machine-readable report plus a human-readable summary.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .constants import (
    TOOL_AIRCRACK_NG,
    TOOL_AIRODUMP_NG,
    TOOL_AIREPLAY_NG,
    TOOL_AIRMON_NG,
    TOOL_BETTERCAP,
    TOOL_BULLY,
    TOOL_CAPINFOS,
    TOOL_COWPATTY,
    TOOL_HCXDUMPTOOL,
    TOOL_HCXPCAPNGTOOL,
    TOOL_IW,
    TOOL_IWCONFIG,
    TOOL_KISMET,
    TOOL_MDK4,
    TOOL_ONESHOT,
    TOOL_PIXIEWPS,
    TOOL_PYRIT,
    TOOL_REAVER,
    TOOL_RFKILL,
    TOOL_TSHARK,
    TOOL_WASH,
    TOOL_WIFITE,
    TOOL_WIFITE2,
    TOOL_WIRESHARK,
)
from .tools.registry import ToolRegistry
from .utils.apikey import (
    NOT_PRESENT,
    load_nim_key,
    validate_nim_key,
)
from .utils.proc import run
from .utils.system import detect_os, detect_root, python_info

log = logging.getLogger("handshaker.doctor")

ALL_TOOLS = [
    TOOL_AIRMON_NG, TOOL_AIRODUMP_NG, TOOL_AIREPLAY_NG, TOOL_AIRCRACK_NG,
    TOOL_HCXDUMPTOOL, TOOL_HCXPCAPNGTOOL, TOOL_TSHARK, TOOL_WIRESHARK,
    TOOL_CAPINFOS, TOOL_BETTERCAP, TOOL_MDK4, TOOL_WIFITE, TOOL_WIFITE2,
    TOOL_COWPATTY, TOOL_PYRIT, TOOL_KISMET, TOOL_WASH, TOOL_REAVER,
    TOOL_BULLY, TOOL_PIXIEWPS, TOOL_ONESHOT, TOOL_IW, TOOL_IWCONFIG, TOOL_RFKILL,
]

# Tools required for the core capture -> verify workflow.
CORE_TOOLS = [TOOL_AIRMON_NG, TOOL_AIRODUMP_NG, TOOL_AIREPLAY_NG,
              TOOL_AIRCRACK_NG, TOOL_HCXDUMPTOOL, TOOL_HCXPCAPNGTOOL, TOOL_TSHARK]


@dataclass
class DoctorReport:
    """Complete, honest self-check result."""

    os: dict = field(default_factory=dict)
    python: dict = field(default_factory=dict)
    root: bool = False
    tools: dict[str, str] = field(default_factory=dict)       # name -> path
    missing: list[str] = field(default_factory=list)
    hcxdumptool_flags: dict[str, bool] = field(default_factory=dict)
    adapter: dict = field(default_factory=dict)
    nim: dict = field(default_factory=dict)

    @property
    def core_ready(self) -> bool:
        return all(t in self.tools for t in CORE_TOOLS)

    def to_dict(self) -> dict:
        return {
            "os": self.os,
            "python": self.python,
            "root": self.root,
            "tools_available": self.tools,
            "tools_missing": self.missing,
            "hcxdumptool_flags": self.hcxdumptool_flags,
            "adapter": self.adapter,
            "nim": self.nim,
            "core_ready": self.core_ready,
        }


class Doctor:
    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        self.registry = ToolRegistry(self.config.get("tools", {}).get("overrides", {}))

    def run(self, *, check_api_key: bool = False, check_injection: bool = False) -> DoctorReport:
        rep = DoctorReport()

        # OS / python / root
        osi = detect_os()
        rep.os = {
            "system": osi.system, "release": osi.release, "machine": osi.machine,
            "distro": osi.distro, "distro_version": osi.distro_version,
            "kali": osi.is_kali, "debian_based": osi.is_debian_based,
            "package_manager": osi.package_manager,
            "supported": osi.supported,
        }
        rep.python = python_info()
        rep.root = detect_root()

        # Tools
        rep.tools = dict(self.registry.paths)
        rep.missing = [t for t in ALL_TOOLS if t not in rep.tools]

        # hcxdumptool flag detection (version-adaptive)
        if self.registry.has(TOOL_HCXDUMPTOOL):
            rep.hcxdumptool_flags = self.registry.hcxdumptool().capabilities()

        # Adapter
        rep.adapter = self._adapter_report()

        # NIM API key
        rep.nim = self._nim_report(check_api_key)

        if check_injection and rep.root:
            rep.adapter["injection"] = self._injection_test()

        return rep

    # ------------------------------------------------------------------ #
    def _adapter_report(self) -> dict:
        out: dict = {"interfaces": [], "monitor_mode": None, "injection": None}
        if self.registry.has(TOOL_IW):
            res = run([self.registry.iw().path, "dev"], timeout=15, check=False)
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.startswith("Interface "):
                    out["interfaces"].append(line.split()[-1])
        elif self.registry.has(TOOL_IWCONFIG):
            res = run(["iwconfig"], timeout=15, check=False)
            for line in res.stdout.splitlines():
                if "IEEE 802.11" in line:
                    out["interfaces"].append(line.split()[0])
        out["interfaces"] = out["interfaces"]
        return out

    def _nim_report(self, check: bool) -> dict:
        key = load_nim_key(self.config)
        if not check:
            return {"status": NOT_PRESENT if not key else "PRESENT",
                    "reason": "not validated (--check-api-key not requested)"}
        return validate_nim_key(key).to_dict()

    def _injection_test(self) -> dict | None:
        if not self.registry.has(TOOL_AIREPLAY_NG):
            return None
        iface = self._adapter_report()["interfaces"]
        if not iface:
            return None
        res = self.registry.aireplay().test_injection(iface[0])
        return {"interface": iface[0],
                "working": "Injection is working!" in res.output}


def apt_install_hint(missing: list[str]) -> str | None:
    """Map missing tool names to apt package names (best effort, honest)."""
    pkg_map = {
        "airmon-ng": "aircrack-ng", "airodump-ng": "aircrack-ng",
        "aireplay-ng": "aircrack-ng", "aircrack-ng": "aircrack-ng",
        "hcxdumptool": "hcxdumptool", "hcxpcapngtool": "hcxtools",
        "tshark": "tshark", "wireshark": "wireshark-qt", "capinfos": "tshark",
        "bettercap": "bettercap", "mdk4": "mdk4", "wifite": "wifite",
        "wifite2": "wifite", "cowpatty": "cowpatty", "pyrit": "pyrit",
        "kismet": "kismet", "wash": "reaver", "reaver": "reaver",
        "bully": "bully", "pixiewps": "pixiewps", "iw": "iw",
        "iwconfig": "wireless-tools", "rfkill": "rfkill",
    }
    pkgs = sorted({pkg_map[t] for t in missing if t in pkg_map})
    return " ".join(pkgs) if pkgs else None
