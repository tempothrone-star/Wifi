"""airodump-ng wrapper — passive scanning and capture."""

from __future__ import annotations

from ..constants import TOOL_AIRODUMP_NG
from ..utils.proc import ProcResult, run
from .base import Tool


class AirodumpNg(Tool):
    name = TOOL_AIRODUMP_NG

    def scan(
        self,
        interface: str,
        write_prefix: str,
        *,
        band: str = "abg",
        channel: str | None = None,
        bssid: str | None = None,
    ) -> ProcResult:
        """Scan; ``channel=None`` means hop all channels for ``band``.

        ``--output-format`` takes ONE comma-separated list of formats
        (pcap, ivs, csv, gps, kismet, netxml, logcsv) — not space-separated.
        """
        args = [self.path, interface, "-w", write_prefix, "--band", band]
        if channel is not None:
            args += ["-c", channel]
        if bssid is not None:
            args += ["--bssid", bssid]
        args += ["--output-format", "csv,netxml,kismet"]
        return run(args, check=True)

    def capture(
        self,
        interface: str,
        write_prefix: str,
        *,
        channel: str,
        bssid: str,
        band: str = "abg",
    ) -> ProcResult:
        """Capture on a single channel for a single BSSID (handshake capture)."""
        args = [
            self.path,
            interface,
            "-w",
            write_prefix,
            "--band",
            band,
            "-c",
            channel,
            "--bssid",
            bssid,
            "--output-format",
            "pcap,csv",
            "--write-interval",
            "2",
        ]
        return run(args, check=True)
