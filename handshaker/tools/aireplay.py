"""aireplay-ng wrapper — injection test and deauthentication."""

from __future__ import annotations

from ..constants import TOOL_AIREPLAY_NG
from ..utils.proc import ProcResult, run
from .base import Tool


class AireplayNg(Tool):
    name = TOOL_AIREPLAY_NG

    def test_injection(self, interface: str) -> ProcResult:
        return run([self.path, "--test", interface], timeout=30, check=False)

    def deauth(
        self,
        interface: str,
        *,
        bssid: str,
        count: int = 10,
        client: str | None = None,
    ) -> ProcResult:
        """Send ``count`` deauth frames to a BSSID (or a specific client).

        aireplay-ng ``--deauth`` uses reason code 7 (class-3 frame from a
        non-associated station). Custom reason codes are handled by mdk4.
        """
        args = [self.path, "--deauth", str(count), "-a", bssid]
        if client:
            args += ["-c", client]
        args += ["--ignore-negative-one", interface]
        return run(args, timeout=60, check=False)

    def deauth_flood(
        self,
        interface: str,
        *,
        bssid: str,
        client: str | None = None,
    ) -> ProcResult:
        """Continuous deauth (count=0) — sustained client eviction."""
        return self.deauth(interface, bssid=bssid, count=0, client=client)
