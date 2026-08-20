"""Capture analysis for strategic decision-making (via Wireshark/tshark).

The engine uses this module to understand a target's *real* behaviour — which
clients are active, how much data they are moving, whether EAPOL is already
flowing, and whether the AP is reachable — so deauth is **aimed at the right
client at the right moment** rather than sprayed blindly.

Every returned fact is measured by tshark; nothing is inferred or assumed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..tools.registry import ToolRegistry
from ..utils.proc import run

log = logging.getLogger("handshaker.analyzer")


@dataclass
class ClientActivity:
    """Measured activity of one station toward a target BSSID."""

    mac: str
    data_frames: int = 0
    probe_requests: int = 0
    eapol_frames: int = 0
    last_seen_frame: int = 0

    @property
    def active(self) -> bool:
        """A client worth deauthing: it is actually exchanging data."""
        return self.data_frames > 0 or self.eapol_frames > 0

    @property
    def score(self) -> float:
        # Data-heavy clients are the best deauth targets (they reconnect fastest).
        return self.data_frames * 2.0 + self.eapol_frames * 5.0 + self.probe_requests


@dataclass
class CaptureAnalysis:
    """Measured facts about a capture (empty where not measured)."""

    bssid: str
    eapol_count: int = 0
    beacon_count: int = 0
    probe_req_count: int = 0
    data_count: int = 0
    clients: list[ClientActivity] = field(default_factory=list)
    # Distinguishes "tshark failed" from "tshark ran and saw 0 frames".
    ok: bool = True
    skip_reason: str = ""

    @property
    def clients_active(self) -> bool:
        return any(c.active for c in self.clients)

    def best_client(self) -> ClientActivity | None:
        """The single best client to target with deauth (highest activity)."""
        active = [c for c in self.clients if c.active]
        if not active:
            return None
        return max(active, key=lambda c: c.score)

    def summary(self) -> str:
        return (
            f"bssid={self.bssid} eapol={self.eapol_count} beacons={self.beacon_count} "
            f"probes={self.probe_req_count} data={self.data_count} "
            f"clients={[c.mac for c in self.clients]}"
        )


class Analyzer:
    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def analyze(self, capture_file: str, bssid: str) -> CaptureAnalysis:
        """Analyze a capture with tshark; returns measured facts only."""
        a = CaptureAnalysis(bssid=bssid)
        if not self.registry.has("tshark"):
            log.warning("tshark unavailable; analysis skipped.")
            a.ok = False
            a.skip_reason = "tshark unavailable"
            return a

        tshark = self.registry.tshark()
        eapol = tshark.frame_count(capture_file, "wlan_rsna_eapol")
        if eapol is None:
            a.ok = False
            a.skip_reason = "tshark failed"
            return a
        a.eapol_count = eapol
        a.beacon_count = tshark.frame_count(
            capture_file, f"wlan.fc.type_subtype == 0x08 && wlan.bssid == {bssid}"
        ) or 0
        a.probe_req_count = tshark.frame_count(capture_file, "wlan.fc.type_subtype == 0x04") or 0
        a.data_count = tshark.frame_count(capture_file, "wlan.fc.type == 2") or 0

        a.clients = self._client_activity(capture_file, bssid)
        return a

    def first_eapol_time(self, capture_file: str) -> float | None:
        """Return the relative timestamp (seconds) of the first EAPOL frame.

        This is the *measured* reconnection signal: since the capture starts at
        deauth time, the first EAPOL M1's relative time ≈ how long the client
        took to re-authenticate. Returns None when no EAPOL is present.
        """
        if not self.registry.has("tshark"):
            return None
        out = run(
            [
                self.registry.tshark().path,
                "-r", capture_file,
                "-Y", "wlan_rsna_eapol",
                "-T", "fields",
                "-e", "frame.time_relative",
                "-E", "occurrence=a",
            ],
            timeout=120, check=False,
        )
        for line in out.stdout.splitlines():
            line = line.strip()
            if line:
                try:
                    return float(line)
                except ValueError:
                    continue
        return None

    def _client_activity(self, capture_file: str, bssid: str) -> list[ClientActivity]:
        """Per-client data/EAPOL/probe counts toward the target BSSID.

        Uses one tshark pass pulling frame type + SA, then aggregates locally —
        deterministic and cheap.
        """
        out = run(
            [
                self.registry.tshark().path,
                "-r", capture_file,
                "-Y", f"wlan.bssid == {bssid}",
                "-T", "fields",
                "-e", "frame.number",
                "-e", "wlan.fc.type",
                "-e", "wlan.fc.type_subtype",
                "-e", "wlan.sa",
                "-e", "eapol.type",          # non-empty iff the frame is EAPOL
                "-E", "separator=,",
                "-E", "occurrence=a",
            ],
            timeout=120, check=False,
        )
        clients: dict[str, ClientActivity] = {}
        for line in out.stdout.splitlines():
            parts = line.split(",")
            if len(parts) < 5:
                continue
            fnum = int(parts[0]) if parts[0].strip().isdigit() else 0
            ftype = parts[1].strip()
            fsub = parts[2].strip()
            sa = parts[3].strip().lower()
            is_eapol = bool(parts[4].strip())       # explicit EAPOL field
            if not sa or sa == bssid.lower():
                continue  # ignore frames from the AP itself
            c = clients.setdefault(sa, ClientActivity(mac=sa))
            c.last_seen_frame = max(c.last_seen_frame, fnum)
            if is_eapol:                            # EAPOL frames first (most specific)
                c.eapol_frames += 1
            elif ftype == "2":                      # other data frames
                c.data_frames += 1
            elif fsub == "0x04":                    # probe request
                c.probe_requests += 1
        return list(clients.values())
