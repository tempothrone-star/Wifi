"""aircrack-ng wrapper — WPA handshake *detection* only.

aircrack-ng is used here purely as an independent handshake-presence detector
(authoritative "WPA handshake: <bssid>" line). No cracking is performed.
"""

from __future__ import annotations

import re

from ..constants import TOOL_AIRCRACK_NG
from ..utils.proc import ProcResult, run
from ..utils.validation import parse_mac
from .base import Tool

_HANDSHAKE_RE = re.compile(r"WPA handshake:\s*([0-9A-Fa-f:]{17})")


class AircrackNg(Tool):
    name = TOOL_AIRCRACK_NG

    def check_handshakes(self, capture_file: str) -> ProcResult:
        """Run aircrack-ng in detection mode against a capture."""
        return run([self.path, capture_file], timeout=60, check=False)

    @staticmethod
    def parse_handshakes(result: ProcResult) -> set[str]:
        """Extract the set of BSSIDs for which aircrack detected a handshake."""
        found: set[str] = set()
        for line in result.output.splitlines():
            m = _HANDSHAKE_RE.search(line)
            if m:
                mac = parse_mac(m.group(1))
                if mac:
                    found.add(mac)
        return found
