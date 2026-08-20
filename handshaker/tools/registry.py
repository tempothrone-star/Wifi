"""Tool registry — discovers which Kali tools are actually installed.

The strategist NEVER assumes a tool exists; it consults this registry, which
reflects the real environment. Missing tools are reported, not guessed around.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..constants import (
    TOOL_AIRCRACK_NG,
    TOOL_AIRODUMP_NG,
    TOOL_AIREPLAY_NG,
    TOOL_AIRMON_NG,
    TOOL_BETTERCAP,
    TOOL_BULLY,
    TOOL_CAPINFOS,
    TOOL_COWPATTY,
    TOOL_HCXDUMPTOOL,
    TOOL_HCXLABTOOL,
    TOOL_HCXPCAPNGTOOL,
    TOOL_HCXPSCKTOOL,
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
from ..utils.proc import discover_tools
from .aircrack import AircrackNg
from .airodump import AirodumpNg
from .aireplay import AireplayNg
from .airmon import AirmonNg
from .hcx import Hcxdumptool, Hcxlabtool, Hcxpcapngtool, Hcxpsktool
from .misc import (
    Bettercap,
    Capinfos,
    Cowpatty,
    Iw,
    Iwconfig,
    Kismet,
    Mdk4,
    Pyrit,
    Rfkill,
    Wash,
    Wifite,
    Wifite2,
    WiresharkGui,
)
from .tshark import Tshark
from .wps import Bully, Oneshot, Pixiewps, Reaver


@dataclass
class ToolRegistry:
    """Snapshot of which tools are available, with instantiated wrappers."""

    paths: dict[str, str] = field(default_factory=dict)

    def __init__(self, overrides: dict[str, str] | None = None) -> None:
        self.paths = discover_tools(_ALL_TOOL_NAMES, overrides)

    def has(self, name: str) -> bool:
        return name in self.paths

    # --- Convenience constructors (each raises ToolNotFoundError if absent) --- #
    def airmon(self) -> AirmonNg:
        return AirmonNg(self.paths[TOOL_AIRMON_NG])

    def airodump(self) -> AirodumpNg:
        return AirodumpNg(self.paths[TOOL_AIRODUMP_NG])

    def aireplay(self) -> AireplayNg:
        return AireplayNg(self.paths[TOOL_AIREPLAY_NG])

    def aircrack(self) -> AircrackNg:
        return AircrackNg(self.paths[TOOL_AIRCRACK_NG])

    def hcxdumptool(self) -> Hcxdumptool:
        return Hcxdumptool(self.paths[TOOL_HCXDUMPTOOL])

    def hcxpcapngtool(self) -> Hcxpcapngtool:
        return Hcxpcapngtool(self.paths[TOOL_HCXPCAPNGTOOL])

    def hcxlabtool(self) -> Hcxlabtool:
        return Hcxlabtool(self.paths[TOOL_HCXLABTOOL])

    def hcxpsktool(self) -> Hcxpsktool:
        return Hcxpsktool(self.paths[TOOL_HCXPSCKTOOL])

    def tshark(self) -> Tshark:
        return Tshark(self.paths[TOOL_TSHARK])

    def bettercap(self) -> Bettercap:
        return Bettercap(self.paths[TOOL_BETTERCAP])

    def mdk4(self) -> Mdk4:
        return Mdk4(self.paths[TOOL_MDK4])

    def wifite(self) -> Wifite:
        return Wifite(self.paths[TOOL_WIFITE])

    def wifite2(self) -> Wifite2:
        return Wifite2(self.paths[TOOL_WIFITE2])

    def cowpatty(self) -> Cowpatty:
        return Cowpatty(self.paths[TOOL_COWPATTY])

    def pyrit(self) -> Pyrit:
        return Pyrit(self.paths[TOOL_PYRIT])

    def wash(self) -> Wash:
        return Wash(self.paths[TOOL_WASH])

    def reaver(self) -> Reaver:
        return Reaver(self.paths[TOOL_REAVER])

    def bully(self) -> Bully:
        return Bully(self.paths[TOOL_BULLY])

    def pixiewps(self) -> Pixiewps:
        return Pixiewps(self.paths[TOOL_PIXIEWPS])

    def oneshot(self) -> Oneshot:
        return Oneshot(self.paths[TOOL_ONESHOT])

    def kismet(self) -> Kismet:
        return Kismet(self.paths[TOOL_KISMET])

    def capinfos(self) -> Capinfos:
        return Capinfos(self.paths[TOOL_CAPINFOS])

    def iw(self) -> Iw:
        return Iw(self.paths[TOOL_IW])

    def iwconfig(self) -> Iwconfig:
        return Iwconfig(self.paths[TOOL_IWCONFIG])

    def rfkill(self) -> Rfkill:
        return Rfkill(self.paths[TOOL_RFKILL])

    def wireshark(self) -> WiresharkGui:
        return WiresharkGui(self.paths[TOOL_WIRESHARK])

    def missing(self) -> list[str]:
        """Names of tools that are absent (for user-visible reporting)."""
        return sorted(set(_ALL_TOOL_NAMES) - set(self.paths))


_ALL_TOOL_NAMES = [
    TOOL_AIRMON_NG,
    TOOL_AIRODUMP_NG,
    TOOL_AIREPLAY_NG,
    TOOL_AIRCRACK_NG,
    TOOL_HCXDUMPTOOL,
    TOOL_HCXPCAPNGTOOL,
    TOOL_HCXLABTOOL,
    TOOL_HCXPSCKTOOL,
    TOOL_TSHARK,
    TOOL_WIRESHARK,
    TOOL_CAPINFOS,
    TOOL_BETTERCAP,
    TOOL_MDK4,
    TOOL_WIFITE,
    TOOL_WIFITE2,
    TOOL_COWPATTY,
    TOOL_PYRIT,
    TOOL_KISMET,
    TOOL_WASH,
    TOOL_REAVER,
    TOOL_BULLY,
    TOOL_PIXIEWPS,
    TOOL_ONESHOT,
    TOOL_IW,
    TOOL_IWCONFIG,
    TOOL_RFKILL,
]
