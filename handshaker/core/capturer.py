"""Capture session — runs airodump-ng / hcxdumptool in the background.

A ``CaptureSession`` owns one long-running capture process and gives the engine
a deterministic handle to (a) know it is running and (b) stop it cleanly. No
capture state is ever inferred from partial output.
"""

from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .. import constants
from ..constants import TOOL_AIRODUMP_NG, TOOL_HCXDUMPTOOL
from ..exceptions import CaptureError
from ..tools.registry import ToolRegistry
from ..utils.validation import sanitize_filename

log = logging.getLogger("handshaker.capturer")


@dataclass
class CaptureSession:
    """Handle to a running capture process."""

    interface: str
    bssid: str
    out_prefix: str
    process: subprocess.Popen
    engine: str          # "airodump" | "hcxdumptool"
    started_at: float

    @property
    def alive(self) -> bool:
        return self.process.poll() is None

    @property
    def exit_code(self) -> int | None:
        """The capture process's exit code, or None if still running."""
        return self.process.poll()

    @property
    def crashed(self) -> bool:
        """True if the capture process already exited (nonzero) — a crash is a
        *different* learning signal from "ran cleanly but no handshake"."""
        code = self.process.poll()
        return code is not None and code != 0

    def stop(self) -> None:
        """Stop the capture process gracefully (SIGINT then SIGKILL)."""
        if self.process.poll() is not None:
            return
        self.process.send_signal(2)  # SIGINT — makes airodump flush its file
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


class Capturer:
    def __init__(self, registry: ToolRegistry, config: dict) -> None:
        self.registry = registry
        self.config = config
        constants.CAPTURES_DIR.mkdir(parents=True, exist_ok=True)

    def start(
        self,
        interface: str,
        bssid: str,
        channel: int,
        *,
        engine: str | None = None,
        essid: str = "",
        full_attack: bool = False,
    ) -> CaptureSession:
        """Start capturing for a specific BSSID on a specific channel.

        ``full_attack=True`` lets hcxdumptool run its OWN attack vectors (deauth
        + client attacks), which work on PMF/802.11w networks where classic
        deauth fails — used as a last-resort fallback by the engine.
        """
        engine = engine or ("hcxdumptool" if self.registry.has(TOOL_HCXDUMPTOOL) else "airodump")
        # Millisecond timestamp avoids filename collisions across capture rounds.
        # ESSID is sanitised: raw ESSIDs can contain `/`, `..`, or spaces.
        stamp = int(time.time() * 1000)
        safe_essid = sanitize_filename(essid, fallback="target")
        safe_bssid = "".join(c for c in bssid if c.isalnum()) or "target"
        prefix = f"{constants.CAPTURES_DIR}/{safe_bssid}_{safe_essid}_{stamp}"

        if engine == "hcxdumptool" and self.registry.has(TOOL_HCXDUMPTOOL):
            return self._start_hcx(interface, bssid, channel, prefix, full_attack=full_attack)
        if self.registry.has(TOOL_AIRODUMP_NG):
            return self._start_airodump(interface, bssid, channel, prefix)
        raise CaptureError("Neither hcxdumptool nor airodump-ng is available for capture.")

    def _start_hcx(self, interface: str, bssid: str, channel: int, prefix: str,
                   *, full_attack: bool = False) -> CaptureSession:
        tool = self.registry.hcxdumptool()
        out = f"{prefix}.pcapng"
        # Use the version-adaptive argv (correct across hcxdumptool <6.3 and 6.3+).
        # Normal capture: passive PMKID + EAPOL; deauth is driven by the strategist.
        # full_attack: let hcxdumptool run its own (MFP-aware) attack vectors.
        cmd = tool.capture_args(
            interface, out, channel=str(channel), bssid=bssid,
            disable_deauth=not full_attack,
            ap_only=not full_attack,
            status=1,
        )
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as exc:
            # Normalize OS-level failures (binary vanished, exec denied, …) into
            # a domain-level error instead of leaking OSError up the stack.
            raise CaptureError(f"failed to start hcxdumptool: {exc}") from exc
        mode = "full-attack" if full_attack else "passive"
        log.info("hcxdumptool %s capture started for %s (ch=%d)", mode, bssid, channel)
        return CaptureSession(interface, bssid, prefix, proc, "hcxdumptool", time.time())

    def _start_airodump(self, interface: str, bssid: str, channel: int, prefix: str) -> CaptureSession:
        tool = self.registry.airodump()
        write_interval = int(self.config["capture"].get("write_interval", 1))
        cmd = [
            tool.path, interface, "-w", prefix,
            "--band", "abg", "-c", str(channel),
            "--bssid", bssid,
            "--output-format", "pcap,csv",
            "--write-interval", str(write_interval),
        ]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as exc:
            raise CaptureError(f"failed to start airodump-ng: {exc}") from exc
        log.info("airodump-ng capture started for %s (ch=%d)", bssid, channel)
        return CaptureSession(interface, bssid, prefix, proc, "airodump", time.time())

    @staticmethod
    def output_files(session: CaptureSession) -> list[Path]:
        """List the capture files produced so far (that actually exist)."""
        base = Path(session.out_prefix)
        patterns = [base.with_suffix(".pcapng"), base.with_suffix(".cap"),
                    Path(str(base) + "-01.cap"), Path(str(base) + "-01.pcapng"),
                    Path(str(base) + ".pcapng")]
        found: list[Path] = []
        for p in patterns:
            if p.exists() and p.stat().st_size > 0:
                found.append(p)
        return found
