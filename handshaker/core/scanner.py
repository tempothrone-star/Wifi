"""WiFi scanner — discovers nearby APs and their clients via airodump-ng.

Scan results are parsed from airodump-ng's CSV output with strict parsers that
yield ``None`` on malformed rows. The downstream strategist therefore only ever
sees *measured* APs, never fabricated ones.
"""

from __future__ import annotations

import csv
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..constants import BAND_2G, BAND_5G, TOOL_AIRODUMP_NG
from ..exceptions import CaptureError
from ..tools.registry import ToolRegistry
from ..utils.proc import run
from ..utils.validation import parse_channel, parse_int, parse_mac, parse_signal_dbm

log = logging.getLogger("handshaker.scanner")


@dataclass
class AccessPoint:
    """A measured access point (fields are exactly what airodump reported)."""

    bssid: str
    first_seen: str = ""
    last_seen: str = ""
    channel: int = 0
    speed: int = 0
    privacy: str = ""
    cipher: str = ""
    auth: str = ""
    power: int = -100
    beacons: int = 0
    ivs: int = 0
    lan_ip: str = ""
    id_len: int = 0
    essid: str = ""
    key: str = ""

    @property
    def band(self) -> str:
        if 1 <= self.channel <= 14:
            return BAND_2G
        if 36 <= self.channel <= 177:
            return BAND_5G
        return BAND_5G  # 6GHz channels are uncommon in airodump; fall back 5G

    @property
    def frequency(self) -> int | None:
        """Center frequency in MHz derived from the channel (2.4/5 GHz only).

        Returns None for channels whose frequency cannot be reliably derived
        from the channel number alone (e.g. 6 GHz, which airodump-ng reports
        ambiguously). This is a precision improvement over the bare channel:
        two APs on the same channel number in different bands share a channel
        but have *different* frequencies.
        """
        return channel_to_frequency(self.channel)

    @property
    def is_wpa(self) -> bool:
        joined = (self.privacy + " " + self.auth).upper()
        return "WPA" in joined or "SAE" in joined

    @property
    def is_enterprise(self) -> bool:
        """True when the AP uses 802.1X/EAP (WPA-Enterprise), not PSK/SAE.

        airodump-ng reports enterprise auth as ``MGT`` in the AUTH column (and
        often ``802.1x`` / ``CCMP`` in the CIPHER column). Enterprise handshakes
        are capturable but NOT recoverable to a PSK, so they are out of scope
        for this tool's PSK-focused capture.
        """
        joined = (self.auth + " " + self.cipher + " " + self.privacy).upper()
        return ("MGT" in self.auth.upper()
                or "802.1X" in joined
                or "EAP" in self.auth.upper())

    @property
    def is_transition_mode(self) -> bool:
        """True when the AP advertises BOTH WPA2 and WPA3/SAE (transition mode).

        Transition-mode APs accept WPA2 clients for backwards compatibility, so
        they remain capturable via a WPA2 downgrade (Dragonblood downgrade
        attack). This is a real, security-relevant distinction that the plain
        ``security_label`` would otherwise hide.
        """
        joined = (self.privacy + " " + self.auth).upper()
        has_wpa3 = "WPA3" in joined or "SAE" in joined
        has_wpa2 = "WPA2" in joined or "PSK" in joined
        return has_wpa3 and has_wpa2

    @property
    def is_pure_wpa3(self) -> bool:
        """True only for WPA3-only (SAE) APs with NO WPA2/PSK fallback."""
        joined = (self.privacy + " " + self.auth).upper()
        has_wpa3 = "WPA3" in joined or "SAE" in joined
        has_wpa2 = "WPA2" in joined or "PSK" in joined
        return has_wpa3 and not has_wpa2

    @property
    def security_label(self) -> str:
        """Classify the security suite from airodump's privacy/auth columns.

        airodump-ng reports WPA3 networks with ``SAE`` (personal) or ``MGT``
        (enterprise 802.1X) in the AUTH column and/or ``WPA3`` in the PRIVACY
        column. Transition mode (both WPA2 and WPA3) is labelled distinctly
        because it is capturable via WPA2 downgrade. Enterprise (MGT/802.1X) is
        labelled distinctly because it is out of scope for PSK recovery.
        """
        joined = (self.privacy + " " + self.auth).upper()
        has_wpa3 = "WPA3" in joined or "SAE" in joined
        has_wpa2 = "WPA2" in joined or "PSK" in joined
        if self.is_enterprise:
            return "WPA3-Enterprise" if has_wpa3 else ("WPA2-Enterprise" if has_wpa2 else "WPA-Enterprise")
        if has_wpa3 and has_wpa2:
            return "WPA2/WPA3"      # transition mode — capturable via downgrade
        if has_wpa3:
            return "WPA3"           # pure WPA3/SAE
        if has_wpa2:
            return "WPA2"
        if "WPA" in joined:
            return "WPA"
        if "WEP" in joined:
            return "WEP"
        return "OPN"

    def summary(self) -> str:
        return (
            f"{self.bssid}  ch={self.channel}  sig={self.power}dBm  "
            f"sec={self.security_label}  clients={0}  '{self.essid}'"
        )


@dataclass
class Client:
    """A measured station (client) associated with an AP."""

    station_mac: str
    bssid: str
    power: int = -100
    packets: int = 0
    probed_essids: str = ""


@dataclass
class ScanResult:
    """Full result of one scan pass."""

    aps: dict[str, AccessPoint] = field(default_factory=dict)
    clients: dict[str, Client] = field(default_factory=dict)
    started_at: float = 0.0
    duration: float = 0.0

    def clients_of(self, bssid: str) -> list[Client]:
        return [c for c in self.clients.values() if c.bssid == bssid]


class Scanner:
    def __init__(self, registry: ToolRegistry, config: dict) -> None:
        self.registry = registry
        self.config = config

    def scan(self, interface: str, duration: int | None = None) -> ScanResult:
        """Run airodump-ng for ``duration`` seconds and parse the results."""
        if not self.registry.has(TOOL_AIRODUMP_NG):
            raise CaptureError("airodump-ng is required for scanning but is not installed.")

        dwell = duration if duration is not None else int(self.config["scan"]["dwell"])
        prefix = _temp_prefix(f"handshaker_scan_{int(time.time())}")
        bands = self.config["scan"]["bands"]
        band_flag = _band_flag(bands)

        log.info("Scanning for %ss (band=%s)...", dwell, band_flag)
        started = time.time()
        # --write-interval so the CSV exists even if the process is killed
        # before airodump's normal SIGINT flush. run() now SIGINT-then-kills.
        run(
            [self.registry.airodump().path, interface, "-w", prefix,
             "--band", band_flag, "--output-format", "csv",
             "--write-interval", "1"],
            timeout=dwell + 5,
            check=False,
        )

        result = self._parse(prefix, dwell)
        self._cleanup(prefix)
        result.started_at = started
        result.duration = time.time() - started
        return result

    # ------------------------------------------------------------------ #
    # Adaptive dwell: spend focused time only on channels that have APs.
    # ------------------------------------------------------------------ #
    def scan_adaptive(self, interface: str, *,
                      quick_dwell: int | None = None,
                      focused_dwell: int | None = None) -> ScanResult:
        """Two-pass scan: quick survey to find active channels, then a focused,
        longer dwell on only those channels (so empty channels don't eat airtime).

        Returns a merged :class:`ScanResult`. Falls back to a plain ``scan`` if
        the quick pass finds nothing.
        """
        quick = quick_dwell if quick_dwell is not None else int(self.config["scan"].get("quick_dwell", 5))
        focused = focused_dwell if focused_dwell is not None else int(self.config["scan"]["dwell"])

        survey = self.scan(interface, quick)
        channels = sorted({ap.channel for ap in survey.aps.values() if ap.channel})
        if not channels:
            return survey

        log.info("adaptive scan: %d active channel(s) -> focused dwell %ss", len(channels), focused)
        merged = ScanResult(started_at=survey.started_at)
        merged.aps = dict(survey.aps)
        merged.clients = dict(survey.clients)

        # Focused pass per channel (airodump -c takes one channel reliably).
        for ch in channels:
            res = self._scan_channel(interface, ch, focused)
            for bssid, ap in res.aps.items():
                # Keep the strongest / most-recently-seen AP record.
                if bssid not in merged.aps or ap.power > merged.aps[bssid].power:
                    merged.aps[bssid] = ap
            for mac, cli in res.clients.items():
                merged.clients.setdefault(mac, cli)

        merged.duration = time.time() - merged.started_at
        return merged

    def _scan_channel(self, interface: str, channel: int, dwell: int) -> ScanResult:
        """Run airodump-ng pinned to a single channel and parse it."""
        if not self.registry.has(TOOL_AIRODUMP_NG):
            raise CaptureError("airodump-ng is required for scanning but is not installed.")
        prefix = _temp_prefix(f"handshaker_scan_{int(time.time())}_{channel}")
        started = time.time()
        run(
            [self.registry.airodump().path, interface, "-w", prefix,
             "-c", str(channel), "--output-format", "csv",
             "--write-interval", "1"],
            timeout=dwell + 5,
            check=False,
        )
        result = self._parse(prefix, dwell)
        self._cleanup(prefix)
        result.started_at = started
        result.duration = time.time() - started
        return result

    # ------------------------------------------------------------------ #
    def _parse(self, prefix: str, dwell: int) -> ScanResult:
        result = ScanResult(started_at=time.time())
        csv_path = Path(f"{prefix}-01.csv")
        if not csv_path.exists():
            # airodump sometimes names the first file without -01.
            csv_path = Path(f"{prefix}.csv")
        if not csv_path.exists():
            log.warning("No scan CSV produced at %s", prefix)
            return result

        aps: dict[str, AccessPoint] = {}
        clients: dict[str, Client] = {}
        section: str | None = None

        with csv_path.open(newline="", errors="replace") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if not row:
                    continue
                joined = ",".join(row)
                if joined.startswith("BSSID"):
                    section = "ap"
                    continue
                if joined.startswith("Station MAC"):
                    section = "client"
                    continue
                if section == "ap":
                    ap = _parse_ap_row(row)
                    if ap:
                        aps[ap.bssid] = ap
                elif section == "client":
                    cli = _parse_client_row(row)
                    if cli:
                        clients[cli.station_mac] = cli

        result.aps = aps
        result.clients = clients
        return result

    @staticmethod
    def _cleanup(prefix: str) -> None:
        for suffix in (".csv", "-01.csv", "-01.cap", "-01.kismet.csv",
                       "-01.kismet.netxml", ".cap", ".netxml", ".kismet.csv"):
            p = Path(f"{prefix}{suffix}")
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass


def _temp_prefix(name: str) -> str:
    """A temp-file prefix that respects ``TMPDIR`` (falls back to /tmp)."""
    import os
    return str(Path(os.environ.get("TMPDIR", "/tmp")) / name)


def channel_to_frequency(channel: int) -> int | None:
    """Map a WiFi channel to its center frequency in MHz (2.4/5 GHz only).

    Formulas (IEEE 802.11):
      2.4 GHz: 2412 + 5·(ch − 1), with ch 14 = 2484 (Japan-only, offset).
      5 GHz:   5000 + 5·ch            (ch 36 → 5180, ch 149 → 5745, …).

    Returns None for channel numbers whose frequency cannot be derived from the
    channel alone (0, or 6 GHz which airodump reports ambiguously). Pure and
    deterministic — never guessed.
    """
    if channel == 14:
        return 2484
    if 1 <= channel <= 13:
        return 2412 + 5 * (channel - 1)
    if 36 <= channel <= 177:
        return 5000 + 5 * channel
    return None


def _band_flag(bands: list[str]) -> str:
    """Build the airodump-ng ``--band`` value from the configured bands.

    airodump-ng 1.7 accepts the letters ``a`` (5 GHz), ``b``/``g`` (2.4 GHz),
    or any combination. There is NO 6 GHz band flag — 6 GHz requires kismet or
    hcxdumptool — so it is deliberately ignored rather than emitting an invalid
    flag.
    """
    flags: set[str] = set()
    if "2.4GHz" in bands:
        flags.update("bg")
    if "5GHz" in bands:
        flags.add("a")
    if not flags:
        return "abg"
    return "".join(sorted(flags))


def _parse_ap_row(row: list[str]) -> AccessPoint | None:
    # airodump CSV columns (typical):
    # BSSID, First time, Last time, channel, Speed, Privacy, Cipher, Auth, Power,
    # # beacons, # IV, LAN IP, ID-length, ESSID, Key
    if len(row) < 15:
        return None
    bssid = parse_mac(row[0])
    if not bssid:
        return None
    channel = parse_channel(row[3]) or 0
    return AccessPoint(
        bssid=bssid,
        first_seen=row[1].strip(),
        last_seen=row[2].strip(),
        channel=channel,
        speed=parse_int(row[4]) or 0,
        privacy=row[5].strip(),
        cipher=row[6].strip(),
        auth=row[7].strip(),
        power=parse_signal_dbm(row[8]) or -100,
        beacons=parse_int(row[9]) or 0,
        ivs=parse_int(row[10]) or 0,
        lan_ip=row[11].strip(),
        id_len=parse_int(row[12]) or 0,
        essid=row[13].strip(),
        key=row[14].strip() if len(row) > 14 else "",
    )


def _parse_client_row(row: list[str]) -> Client | None:
    # Station MAC, First time, Last time, Power, # packets, BSSID, Probed ESSIDs
    if len(row) < 6:
        return None
    station = parse_mac(row[0])
    bssid = parse_mac(row[5]) if row[5].strip() != "(not associated)" else None
    if not station:
        return None
    return Client(
        station_mac=station,
        bssid=bssid or "",
        power=parse_signal_dbm(row[3]) or -100,
        packets=parse_int(row[4]) or 0,
        probed_essids=row[6] if len(row) > 6 else "",
    )
