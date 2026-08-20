"""airmon-ng wrapper — monitor mode management and channel control."""

from __future__ import annotations

from ..constants import TOOL_AIRMON_NG
from ..utils.proc import ProcResult, run
from .base import Tool


class AirmonNg(Tool):
    name = TOOL_AIRMON_NG

    def start_monitor(self, interface: str) -> ProcResult:
        return run([self.path, "start", interface], timeout=30, check=True)

    def stop_monitor(self, interface: str) -> ProcResult:
        return run([self.path, "stop", interface], timeout=30, check=True)

    def check(self) -> ProcResult:
        return run([self.path, "check"], timeout=30)

    def check_kill(self) -> ProcResult:
        return run([self.path, "check", "kill"], timeout=30, check=False)
