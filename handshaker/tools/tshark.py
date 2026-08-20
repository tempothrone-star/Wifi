"""tshark (Wireshark CLI) wrapper — the ground-truth EAPOL parser.

The 4-way handshake verification is anchored on tshark's EAPOL dissection.
Since Wireshark 1.12 the RSNA EAPOL-Key fields live under the
``wlan_rsna_eapol`` prefix (previously ``eapol``). We extract the *decoded*
boolean flags rather than re-decoding the key_info bitfield:

* ``wlan.bssid``                              — the BSS the exchange belongs to
* ``wlan.sa`` / ``wlan.da``                   — transmitter / receiver
* ``wlan_rsna_eapol.keydes.key_info``         — raw key_info (reference only)
* ``...key_info.key_ack``                     — Key ACK flag (boolean)
* ``...key_info.install``                     — Install flag (boolean)
* ``wlan_rsna_eapol.keydes.mic``              — WPA Key MIC content
* ``wlan_rsna_eapol.keydes.nonce``            — WPA Key Nonce content
* ``wlan_rsna_eapol.keydes.msgnr``            — Wireshark's message number (1-4)
* ``eapol.keydes.replay_counter``             — EAPOL replay counter (legacy
  ``eapol`` namespace; there is NO ``wlan_rsna_eapol`` alias for this field)

Nothing here is inferred by us: every classification is derived from fields
Wireshark itself decoded.
"""

from __future__ import annotations

from ..constants import TOOL_TSHARK
from ..utils.proc import ProcResult, run
from ..utils.validation import parse_mac
from .base import Tool

_EAPOL_FIELDS = [
    "-e", "frame.number",
    "-e", "wlan.bssid",
    "-e", "wlan.sa",
    "-e", "wlan.da",
    "-e", "wlan_rsna_eapol.keydes.key_info",
    "-e", "wlan_rsna_eapol.keydes.key_info.key_ack",
    "-e", "wlan_rsna_eapol.keydes.key_info.install",
    "-e", "wlan_rsna_eapol.keydes.mic",
    "-e", "wlan_rsna_eapol.keydes.nonce",
    "-e", "wlan_rsna_eapol.keydes.msgnr",
    "-e", "eapol.keydes.replay_counter",
]


class Tshark(Tool):
    name = TOOL_TSHARK

    def eapol_frames(self, capture_file: str) -> ProcResult:
        """Extract raw EAPOL-Key frames as comma-separated fields."""
        args = [
            self.path,
            "-r", capture_file,
            "-Y", "wlan_rsna_eapol",
            "-T", "fields",
            *_EAPOL_FIELDS,
            "-E", "separator=\t",
            "-E", "occurrence=f",
            "-E", "header=n",
        ]
        return run(args, timeout=120, check=False)

    def eapol_summary(self, capture_file: str) -> ProcResult:
        """Human-readable EAPOL summary for logging/debugging."""
        args = [
            self.path,
            "-r", capture_file,
            "-Y", "wlan_rsna_eapol",
            "-V",
        ]
        return run(args, timeout=120, check=False)

    def frame_count(self, capture_file: str, display_filter: str) -> int | None:
        """Count frames matching a display filter.

        Returns ``None`` when tshark failed (so callers can distinguish a
        tool error from a legitimate zero-frame capture). Returns 0 when the
        command succeeded and matched nothing.
        """
        args = [
            self.path,
            "-r", capture_file,
            "-Y", display_filter,
            "-T", "fields",
            "-e", "frame.number",
        ]
        res = run(args, timeout=120, check=False)
        if not res.ok:
            return None
        lines = [ln for ln in res.stdout.splitlines() if ln.strip()]
        return len(lines)

    def essids(self, capture_file: str) -> dict[str, str]:
        """Map BSSID -> SSID from beacon frames (best-effort, measured only).

        Returns an empty dict if tshark is missing or no beacons are present.
        Used to supply the ESSID that ``cowpatty -s`` requires.
        """
        args = [
            self.path,
            "-r", capture_file,
            "-Y", "wlan.fc.type_subtype == 0x08",
            "-T", "fields",
            "-e", "wlan.bssid",
            "-e", "wlan.ssid",
            "-E", "separator=\t",
            "-E", "occurrence=f",
        ]
        res = run(args, timeout=120, check=False)
        out: dict[str, str] = {}
        for line in res.stdout.splitlines():
            sep = "\t" if "\t" in line else ","
            parts = line.split(sep, 1)
            if len(parts) < 2:
                continue
            bssid = parse_mac(parts[0].strip()) or parts[0].strip().lower()
            ssid = parts[1].strip()
            if bssid and ssid and bssid not in out:
                out[bssid] = ssid
        return out
