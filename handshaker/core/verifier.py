"""Strong 4-way handshake verifier — the integrity core of the tool.

This module answers one question with high confidence: *"Does this capture
contain a structurally consistent, complete 4-way EAPOL exchange?"*  Nothing is
kept unless the evidence proves it; everything else is rejected (and, per
policy, deleted).

(Note: this establishes structural consistency — the messages, directions,
nonce/MIC lengths, and replay counters are all sound — not mathematical proof
of every semantic property of the handshake, which would require the PSK.)

Verification is **deterministic and multi-tool**, by design immune to
hallucination:

1. **tshark (Wireshark) is the ground truth.** Every EAPOL-Key frame is read and
   classified M1..M4 from the fields Wireshark decoded — the ``key_ack`` /
   ``install`` flags, the MIC / nonce contents, the message number, and the
   replay counter. We never re-implement bit arithmetic that could drift.
2. **aircrack-ng** — independent "WPA handshake" detector.
3. **hcxpcapngtool** — independent EAPOL-pair / PMKID counter.
4. **cowpatty / pyrit** (when present) — further independent checks.

The verdict is **primary structural verification + contradiction checks**.
tshark EAPOL analysis is authoritative; other tools that *run and find no
handshake* reject the capture. A tool being *unavailable* is reported
truthfully and degrades gracefully — never silently assumed to pass.

Advanced, packet-level validation (all derived from dissected fields):

* **Completeness** — M1, M2, M3, M4 must all be present (strict mode).
* **Direction** — M1/M3 must come from the AP, M2/M4 from the STA.
* **Nonce & MIC presence and length** — nonce must be 32 bytes (64 hex chars),
  MIC must be 16 bytes (32 hex chars).
* **Replay-counter monotonicity** — within a message pair, the replay counter
  must not decrease (catches malformed/duplicated retransmissions).
* **Retransmission de-duplication** — repeated identical frames are collapsed
  so a duplicated M2 cannot fake completeness.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..tools.registry import ToolRegistry
from ..utils.validation import parse_mac

log = logging.getLogger("handshaker.verifier")

_INT_RE = re.compile(r"^-?\d+$")
_HEX_INT_RE = re.compile(r"^0x[0-9a-fA-F]+$")

NONCE_HEX_LEN = 64   # 32 bytes
MIC_HEX_LEN = 32     # 16 bytes


@dataclass
class EapolFrame:
    """One EAPOL-Key frame, classified from fields Wireshark decoded."""

    frame_number: int
    bssid: str
    src: str
    dst: str
    key_info: str          # raw key_info hex (reference/debug only)
    has_ack: bool
    has_install: bool
    has_mic: bool
    mic: str               # WPA Key MIC content (hex)
    nonce: str             # WPA Key Nonce content (hex)
    msgnr: int | None      # Wireshark's own message number (1-4), if present
    replay_counter: int | None
    message: int = 0       # 1..4, 0 = unclassified (our classification)

    @property
    def nonce_valid(self) -> bool:
        """Nonce of correct 32-byte length (when expected)."""
        return len(self.nonce) == NONCE_HEX_LEN

    @property
    def mic_valid(self) -> bool:
        """MIC of correct 16-byte length (when expected)."""
        return len(self.mic) == MIC_HEX_LEN


@dataclass
class HandshakeEvidence:
    """Accumulated, classified EAPOL evidence for a single BSSID."""

    bssid: str
    frames: list[EapolFrame] = field(default_factory=list)
    messages: set[int] = field(default_factory=set)
    # Independent tool signals (None = not run).
    aircrack_confirmed: bool | None = None
    hcx_pairs: int | None = None
    hcx_pmkid: bool | None = None
    cowpatty_confirmed: bool | None = None
    pyrit_confirmed: bool | None = None

    @property
    def has_full_handshake(self) -> bool:
        return {1, 2, 3, 4}.issubset(self.messages)

    @property
    def has_crackable_pair(self) -> bool:
        return 2 in self.messages and 3 in self.messages


def handshake_quality(ev: HandshakeEvidence) -> float:
    """Score a handshake 0.0..1.0 from *measured* facts (pure, deterministic).

    This is the graded signal that replaces the coarse pass/fail for the
    learner. Higher is better; each term is derived only from dissected fields:

    * **Completeness** — full M1-M4 (0.7) > crackable M2+M3 (0.4) > partial (0.1×n).
    * **Distinct-message ratio** — reward captures with the 4 messages each
      present exactly once (clean capture) over ones bloated with
      retransmissions (noisy capture).
    * **Nonce consistency** — a real handshake reuses the ANonce across M1 and
      M3, and the SNonce across M2 (a captured retransmit would diverge).
    """
    if not ev.messages:
        return 0.0

    # Completeness component.
    if ev.has_full_handshake:
        completeness = 0.7
    elif ev.has_crackable_pair:
        completeness = 0.4
    else:
        completeness = 0.1 * len(ev.messages)  # partial credit for any EAPOL

    # Distinct-message ratio: 1.0 when each needed message appears once.
    by_msg: dict[int, int] = {}
    for f in ev.frames:
        if f.message:
            by_msg[f.message] = by_msg.get(f.message, 0) + 1
    needed = {1, 2, 3, 4} if ev.has_full_handshake else {2, 3}
    present = [m for m in needed if m in by_msg]
    if not present:
        return round(completeness, 3)
    distinct_ratio = len(present) / max(sum(by_msg[m] for m in present), len(present))
    distinct_ratio = min(1.0, distinct_ratio)

    # Nonce consistency: M1/M3 share ANonce, M2 has a SNonce.
    m1_nonces = {f.nonce for f in ev.frames if f.message == 1 and f.nonce}
    m3_nonces = {f.nonce for f in ev.frames if f.message == 3 and f.nonce}
    nonce_ok = 0.1 if (m1_nonces and m1_nonces & m3_nonces) else 0.0

    return round(min(1.0, completeness + 0.2 * distinct_ratio + nonce_ok), 3)


@dataclass
class VerificationReport:
    """The final, honest verdict for a capture file."""

    file: str
    passed: bool
    reason: str
    evidence: list[HandshakeEvidence] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    tools_missing: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "passed": self.passed,
            "reason": self.reason,
            "handshakes": [
                {
                    "bssid": e.bssid,
                    "messages": sorted(e.messages),
                    "full": e.has_full_handshake,
                    "crackable_pair": e.has_crackable_pair,
                    "quality": handshake_quality(e),
                    "aircrack": e.aircrack_confirmed,
                    "hcx_pairs": e.hcx_pairs,
                    "hcx_pmkid": e.hcx_pmkid,
                    "pyrit": e.pyrit_confirmed,
                    "cowpatty": e.cowpatty_confirmed,
                }
                for e in self.evidence
            ],
            "tools_used": self.tools_used,
            "tools_missing": self.tools_missing,
        }


class HandshakeVerifier:
    def __init__(self, registry: ToolRegistry, config: dict) -> None:
        self.registry = registry
        self.config = config["verify"]
        self._tools = list(self.config.get(
            "tools",
            ["tshark", "aircrack-ng", "hcxpcapngtool", "cowpatty", "pyrit", "capinfos"],
        ))

    def _uses(self, tool: str) -> bool:
        """A tool is used only if it is both configured AND installed."""
        return tool in self._tools and self.registry.has(tool)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def verify_file(self, capture_file: str) -> VerificationReport:
        """Verify a single capture file and return a truthful report."""
        path = Path(capture_file)
        if not path.exists() or path.stat().st_size == 0:
            return VerificationReport(file=capture_file, passed=False,
                                      reason="file missing or empty")

        evidence, tshark_failed = self._gather_evidence(capture_file)
        if tshark_failed and not evidence:
            tools_used, tools_missing = self._tool_status()
            return VerificationReport(
                file=capture_file, passed=False,
                reason="tshark failed; EAPOL evidence unavailable",
                tools_used=tools_used, tools_missing=tools_missing,
            )
        report = self._decide(capture_file, evidence)
        log.info("verify %s -> %s (%s)", Path(capture_file).name,
                 "PASS" if report.passed else "REJECT", report.reason)
        return report

    # ------------------------------------------------------------------ #
    # Evidence gathering
    # ------------------------------------------------------------------ #
    def _gather_evidence(self, capture_file: str) -> tuple[list[HandshakeEvidence], bool]:
        by_bssid: dict[str, HandshakeEvidence] = {}
        tshark_failed = False

        # 1) tshark EAPOL ground truth.
        if self._uses("tshark"):
            parsed = self._parse_tshark(capture_file)
            if parsed is None:
                tshark_failed = True
            else:
                for f in parsed:
                    ev = by_bssid.setdefault(f.bssid, HandshakeEvidence(bssid=f.bssid))
                    ev.frames.append(f)
                    if f.message:
                        ev.messages.add(f.message)

        # 2) aircrack-ng independent check.
        aircrack_bssids: set[str] | None = None
        if self._uses("aircrack-ng"):
            res = self.registry.aircrack().check_handshakes(capture_file)
            aircrack_bssids = self.registry.aircrack().parse_handshakes(res)

        # 3) hcxpcapngtool independent EAPOL pair / PMKID count.
        hcx_pairs, hcx_pmkid = self._hcx_report(capture_file)

        # 4) pyrit — independent handshake-quality analysis (good/workable).
        pyrit_bssids: set[str] | None = self._pyrit_report(capture_file)

        # 5) cowpatty — independent 4-way-frame check, per BSSID (needs ESSID).
        cowpatty_map: dict[str, bool] = self._cowpatty_report(capture_file)

        for bssid, ev in by_bssid.items():
            ev.aircrack_confirmed = (bssid in aircrack_bssids) if aircrack_bssids is not None else None
            ev.hcx_pairs = hcx_pairs
            ev.hcx_pmkid = hcx_pmkid
            ev.pyrit_confirmed = (bssid in pyrit_bssids) if pyrit_bssids is not None else None
            ev.cowpatty_confirmed = cowpatty_map.get(bssid) if cowpatty_map else None

        if aircrack_bssids:
            for b in aircrack_bssids:
                ev = by_bssid.setdefault(b, HandshakeEvidence(bssid=b))
                ev.aircrack_confirmed = True
                ev.hcx_pairs = hcx_pairs
                ev.hcx_pmkid = hcx_pmkid
                ev.pyrit_confirmed = (b in pyrit_bssids) if pyrit_bssids is not None else None
                ev.cowpatty_confirmed = cowpatty_map.get(b) if cowpatty_map else None

        return list(by_bssid.values()), tshark_failed

    # ------------------------------------------------------------------ #
    # Decision
    # ------------------------------------------------------------------ #
    def _decide(self, capture_file: str, evidence: list[HandshakeEvidence]) -> VerificationReport:
        tools_used, tools_missing = self._tool_status()

        if not evidence:
            return VerificationReport(
                file=capture_file, passed=False,
                reason="no EAPOL frames found (not a handshake capture)",
                tools_used=tools_used, tools_missing=tools_missing,
            )

        require_full = bool(self.config["require_full_handshake"])
        min_packets = int(self.config.get("min_packets", 4))
        structural = bool(self.config.get("structural_checks", True))

        # Per-BSSID verdict. A capture is accepted when AT LEAST ONE BSSID holds
        # a genuine handshake — an unrelated, incomplete AP in the same capture
        # (common with channel-level hcxdumptool filtering) must not reject the
        # valid one.
        passed_bssids: list[str] = []
        failures: list[str] = []
        for ev in evidence:
            problem = self._bssid_problem(ev, require_full, min_packets, structural)
            if problem is None:
                passed_bssids.append(ev.bssid)
            else:
                failures.append(f"{ev.bssid}: {problem}")

        if passed_bssids:
            return VerificationReport(
                file=capture_file, passed=True,
                reason=f"valid 4-way handshake for {', '.join(passed_bssids)}",
                evidence=evidence, tools_used=tools_used, tools_missing=tools_missing,
            )
        return VerificationReport(
            file=capture_file, passed=False,
            reason="; ".join(failures) if failures else "no valid handshake found",
            evidence=evidence, tools_used=tools_used, tools_missing=tools_missing,
        )

    def _bssid_problem(self, ev: HandshakeEvidence, require_full: bool,
                       min_packets: int, structural: bool) -> str | None:
        """Return a reason this BSSID's handshake is invalid, or None if valid.

        Checks are all evaluated PER BSSID (not per file): completeness,
        per-BSSID packet count, structural validity, and tool contradictions.
        """
        # Completeness.
        if require_full and not ev.has_full_handshake:
            return (f"incomplete handshake (messages={sorted(ev.messages)}), "
                    "full M1-M4 required")
        if not require_full and not ev.has_crackable_pair:
            return f"no crackable M2+M3 pair (messages={sorted(ev.messages)})"
        if require_full and not _has_correlated_exchange(ev, need_full=True):
            return ("no correlated M1-M4 exchange "
                    "(messages appear to belong to different handshakes)")
        if not require_full and not _has_correlated_exchange(ev, need_full=False):
            return "no correlated M2+M3 pair for the same AP/STA exchange"

        # Per-BSSID minimum EAPOL frames (not a global file total).
        if len(ev.frames) < min_packets:
            return f"too few EAPOL frames ({len(ev.frames)} < {min_packets})"

        # Packet-level structural validation (when enabled).
        if structural:
            problem = _structural_problem(ev)
            if problem:
                return problem

        # Contradiction checks: if a tool explicitly says NO, reject.
        if ev.aircrack_confirmed is False:
            return "aircrack-ng does not confirm a WPA handshake"
        if ev.pyrit_confirmed is False:
            return "pyrit found no good/workable handshake"
        if ev.cowpatty_confirmed is False:
            return "cowpatty does not confirm a complete 4-way handshake"
        return None

    def _tool_status(self) -> tuple[list[str], list[str]]:
        used, missing = [], []
        for name in self._tools:
            (used if self.registry.has(name) else missing).append(name)
        return used, missing

    # ------------------------------------------------------------------ #
    # tshark parsing
    # ------------------------------------------------------------------ #
    def _parse_tshark(self, capture_file: str) -> list[EapolFrame] | None:
        res = self.registry.tshark().eapol_frames(capture_file)
        if not res.ok:
            log.warning("tshark failed (rc=%s); ignoring partial stdout", res.returncode)
            return None
        frames: list[EapolFrame] = []
        seen: set[tuple] = set()  # de-duplicate identical retransmissions
        for line in res.stdout.splitlines():
            # Tab is preferred (tshark `-E separator=\t`); fall back to comma
            # so unit tests and older dumps still parse.
            sep = "\t" if "\t" in line else ","
            parts = line.split(sep)
            if len(parts) < 11:
                continue
            bssid = parse_mac(parts[1])
            if not bssid:
                continue
            frame_number = _parse_int_field(parts[0]) or 0
            src = parse_mac(parts[2]) or parts[2]
            dst = parse_mac(parts[3]) or parts[3]
            key_info = parts[4].strip()
            has_ack = parts[5].strip() == "1"
            has_install = parts[6].strip() == "1"
            mic = parts[7].strip()
            nonce = parts[8].strip()
            msgnr = _parse_int_field(parts[9])
            replay_counter = _parse_counter(parts[10])
            # Optional 12th field: wlan_rsna_eapol.keydes.key_info.key_mic.
            # That boolean is the Key MIC *flag*, distinct from the MIC bytes.
            if len(parts) >= 12 and parts[11].strip() in ("0", "1"):
                has_mic = parts[11].strip() == "1"
            else:
                has_mic = bool(mic)

            frame = EapolFrame(
                frame_number=frame_number, bssid=bssid, src=src, dst=dst,
                key_info=key_info, has_ack=has_ack, has_install=has_install,
                has_mic=has_mic, mic=mic, nonce=nonce, msgnr=msgnr,
                replay_counter=replay_counter,
            )
            frame.message = _classify_message(frame)

            # De-duplicate only truly identical retransmissions. MIC + replay
            # counter are part of identity so two distinct M2s with the same
            # nonce (different MIC/RC) are not collapsed.
            dedup_key = (bssid, src, dst, frame.message, nonce, mic, replay_counter)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            frames.append(frame)
        return frames

    # ------------------------------------------------------------------ #
    # hcxpcapngtool
    # ------------------------------------------------------------------ #
    def _hcx_report(self, capture_file: str) -> tuple[int | None, bool | None]:
        if not self._uses("hcxpcapngtool"):
            return None, None
        import os
        import tempfile
        fd, out = tempfile.mkstemp(prefix="handshaker_hcx_", suffix=".22000")
        os.close(fd)
        try:
            res = self.registry.hcxpcapngtool().convert(capture_file, out)
            pairs = None
            m = re.search(r"EAPOL pairs\s*:\s*(\d+)", res.output, re.IGNORECASE)
            if m:
                pairs = int(m.group(1))
            else:
                m = re.search(r"EAPOL M1M2 messages\s*:\s*(\d+)", res.output, re.IGNORECASE)
                if m:
                    pairs = int(m.group(1))
            pmkid = None
            m = re.search(r"PMKID.*?:\s*(\d+)", res.output, re.IGNORECASE)
            if m:
                pmkid = int(m.group(1)) > 0
            return pairs, pmkid
        finally:
            try:
                os.unlink(out)
            except OSError:
                pass

    # ------------------------------------------------------------------ #
    # pyrit — independent handshake-quality analysis
    # ------------------------------------------------------------------ #
    def _pyrit_report(self, capture_file: str) -> set[str] | None:
        """Return the set of BSSIDs pyrit rates as ``good``/``workable``.

        ``None`` means pyrit was not run (not configured/installed, or it
        errored without producing parseable analysis). An empty set means pyrit
        ran and found no usable handshake — a real signal.
        """
        if not self._uses("pyrit"):
            return None
        res = self.registry.pyrit().check_handshakes(capture_file)
        if not res.ok and "AccessPoint" not in res.output:
            log.info("pyrit did not produce analysis output; treating as not run")
            return None
        return parse_pyrit(res)

    # ------------------------------------------------------------------ #
    # cowpatty — independent 4-way-frame check, per BSSID (needs an ESSID)
    # ------------------------------------------------------------------ #
    def _cowpatty_report(self, capture_file: str) -> dict[str, bool]:
        """Run cowpatty ``-c`` once per BSSID against its own ESSID.

        cowpatty checks a *specific* network, so a single run is NOT valid for a
        multi-AP capture. Returns ``{bssid: confirmed}`` for every BSSID whose
        ESSID is known (empty dict when cowpatty is absent or no ESSID found).
        """
        out: dict[str, bool] = {}
        if not self._uses("cowpatty"):
            return out
        essid_map = self.registry.tshark().essids(capture_file) if self._uses("tshark") else {}
        if not essid_map:
            log.info("cowpatty skipped: no ESSID extracted from capture")
            return out
        from collections import Counter
        essid_counts = Counter(essid_map.values())
        for bssid, essid in essid_map.items():
            if essid_counts[essid] > 1:
                log.info("cowpatty skipped for %s: ESSID %r is shared by multiple BSSIDs",
                         bssid, essid)
                continue
            res = self.registry.cowpatty().check_handshake(capture_file, essid)
            confirmed = parse_cowpatty(res)
            if confirmed is not None:
                out[bssid] = confirmed
        return out

    # ------------------------------------------------------------------ #
    # capinfos — capture metadata sanity (packet count)
    # ------------------------------------------------------------------ #
    def capinfos_packets(self, capture_file: str) -> int | None:
        """Return the packet count from ``capinfos`` (None if unavailable)."""
        if not self._uses("capinfos"):
            return None
        res = self.registry.capinfos().info(capture_file)
        return parse_capinfos_packets(res)


# --------------------------------------------------------------------------- #
# Pure helpers (unit-testable)
# --------------------------------------------------------------------------- #
def _parse_int_field(value: str) -> int | None:
    v = value.strip()
    if _INT_RE.match(v):
        return int(v)
    return None


def _parse_counter(value: str) -> int | None:
    """Parse a replay counter that tshark prints as hex (``0x...``) or decimal.

    Wireshark renders the 8-byte EAPOL replay counter as hex in ``-T fields``
    output, so a plain int parser would silently drop it. Handles both.
    """
    v = value.strip()
    if _INT_RE.match(v):
        return int(v)
    if _HEX_INT_RE.match(v):
        return int(v, 16)
    return None


def _hex_compact(value: str) -> str:
    return (value or "").replace(":", "").replace(" ", "").replace("-", "")


def _is_hex(value: str) -> bool:
    return bool(value) and all(c in "0123456789abcdefABCDEF" for c in value)


def _has_correlated_exchange(ev: HandshakeEvidence, *, need_full: bool) -> bool:
    """True when M1–M4 (or M2+M3) belong to the *same* AP/STA exchange."""
    by_msg: dict[int, list[EapolFrame]] = {1: [], 2: [], 3: [], 4: []}
    for f in ev.frames:
        if f.message in by_msg:
            by_msg[f.message].append(f)
    ap = _ap_mac(ev)
    m1_list = by_msg[1] or [None]
    for m1 in m1_list:
        anonce = m1.nonce if m1 and _nonce_is_present(m1.nonce) else None
        if m1 is None:
            m3_candidates = list(by_msg[3])
        else:
            m3_candidates = [m3 for m3 in by_msg[3]
                             if anonce and m3.nonce == anonce]
            if ap and parse_mac(m1.src) != ap:
                continue
        for m3 in m3_candidates:
            sta = parse_mac(m1.dst) if m1 is not None else parse_mac(m3.dst)
            if m3 is not None:
                if ap and parse_mac(m3.src) != ap:
                    continue
                if sta and parse_mac(m3.dst) not in (None, sta):
                    continue
                if sta is None:
                    sta = parse_mac(m3.dst)
            m2s = [
                f for f in by_msg[2]
                if _nonce_is_present(f.nonce)
                and (not sta or parse_mac(f.src) == sta)
                and (not ap or parse_mac(f.dst) == ap)
            ]
            if not m2s:
                continue
            if not need_full:
                return True
            m4s = [
                f for f in by_msg[4]
                if (not sta or parse_mac(f.src) == sta)
                and (not ap or parse_mac(f.dst) == ap)
            ]
            for m2 in m2s:
                for m4 in m4s:
                    if _nonce_is_present(m4.nonce) and m4.nonce != m2.nonce:
                        continue
                    return True
    return False


def _nonce_is_present(nonce: str) -> bool:
    """True when the nonce field carries a real (non-zero) 802.11 nonce.

    EAPOL-Key frames have a *fixed* 32-byte nonce field. M4 normally fills it
    with zeros rather than omitting it, so ``bool(nonce)`` is the wrong test:
    ``"00"*32`` is truthy in Python and would mis-classify a real M4 as M2.
    """
    if not nonce:
        return False
    compact = nonce.replace(":", "").replace(" ", "").replace("-", "").lower()
    if not compact or set(compact) <= {"0"}:
        return False
    return True


def _classify_from_flags(f: EapolFrame) -> int:
    """Classify from Key ACK / Install / MIC flag + nonce presence.

        M1: Key ACK set, no MIC            (ANonce)
        M3: Key ACK + Install + MIC        (GTK)
        M2: MIC, no ACK/Install, *non-zero* nonce     (SNonce)
        M4: MIC, no ACK/Install, absent *or all-zero* nonce
    """
    if f.has_ack and not f.has_mic:
        return 1
    if f.has_mic and f.has_ack and f.has_install:
        return 3
    if f.has_mic and not f.has_ack and not f.has_install:
        return 2 if _nonce_is_present(f.nonce) else 4
    return 0


def _classify_message(f: EapolFrame) -> int:
    """Classify an EAPOL-Key frame as M1..M4, or 0 if ambiguous.

    Wireshark ``msgnr`` is one piece of evidence, not an override: when it
    contradicts the Key ACK / Install / MIC flags, the flags win. ``msgnr``
    is used when the flags are ambiguous.
    """
    flags = _classify_from_flags(f)
    if f.msgnr in (1, 2, 3, 4):
        if flags in (0, int(f.msgnr)):
            return int(f.msgnr)
        return flags
    return flags


def _structural_problem(ev: HandshakeEvidence) -> str | None:
    """Return a human-readable structural defect, or None if sound.

    Checks (all from dissected fields, no inference):

    1. Direction: M1/M3 originate from the AP; M2/M4 from the STA.
    2. Nonce presence: M1 carries the ANonce, M2 the SNonce.
    3. Nonce / MIC length: 32-byte nonce (64 hex), 16-byte MIC (32 hex).
    4. Replay counter monotonicity — **per direction**. The AP and STA keep
       independent replay counters; comparing across directions would falsely
       reject valid handshakes.
    """
    by_msg: dict[int, list[EapolFrame]] = {1: [], 2: [], 3: [], 4: []}
    for f in ev.frames:
        if f.message in by_msg:
            by_msg[f.message].append(f)

    ap_mac = _ap_mac(ev)
    sta_mac = _sta_mac(ev)

    # Direction checks: source AND destination (AP↔STA pair).
    if ap_mac:
        for msg in (1, 3):
            for f in by_msg[msg]:
                if parse_mac(f.src) != ap_mac:
                    return f"message {msg} did not originate from the AP (src={f.src})"
                dst = parse_mac(f.dst)
                if dst == ap_mac:
                    return f"message {msg} destination is the AP (expected STA) (dst={f.dst})"
        for msg in (2, 4):
            for f in by_msg[msg]:
                if parse_mac(f.dst) != ap_mac:
                    return f"message {msg} destination is not the AP (dst={f.dst})"
                if parse_mac(f.src) == ap_mac:
                    return f"message {msg} originated from the AP (expected STA) (src={f.src})"
    if sta_mac:
        for msg in (2, 4):
            for f in by_msg[msg]:
                if parse_mac(f.src) != sta_mac:
                    return f"message {msg} did not originate from the STA (src={f.src})"

    # Nonce presence: M1 (ANonce) and M2 (SNonce) must carry a *non-zero* nonce.
    if not any(_nonce_is_present(f.nonce) for f in by_msg[1]):
        return "message 1 is missing its ANonce"
    if not any(_nonce_is_present(f.nonce) for f in by_msg[2]):
        return "message 2 is missing its SNonce"

    # Nonce / MIC structural checks (hex + length on the dissected payload).
    for msg in (1, 2, 3):
        for f in by_msg[msg]:
            if f.nonce:
                compact = _hex_compact(f.nonce)
                if len(compact) != NONCE_HEX_LEN or not _is_hex(compact):
                    return f"message {msg} has a malformed nonce ({len(compact)} hex chars)"
    for msg in (2, 3, 4):
        for f in by_msg[msg]:
            if f.mic:
                compact = _hex_compact(f.mic)
                if len(compact) != MIC_HEX_LEN or not _is_hex(compact):
                    return f"message {msg} has a malformed MIC ({len(compact)} hex chars)"

    # Replay-counter monotonicity is checked *per handshake*, not across every
    # EAPOL frame from a MAC in a long capture (a later re-auth legitimately
    # restarts the counter). Pair M1/M3 that share an ANonce, and M2/M4 from
    # the same STA in frame-number order.
    for m1 in by_msg[1]:
        for m3 in by_msg[3]:
            if m1.nonce and m3.nonce and m1.nonce == m3.nonce:
                if (m1.replay_counter is not None and m3.replay_counter is not None
                        and m3.replay_counter < m1.replay_counter):
                    return (f"replay counter decreased within handshake for {m1.src}: "
                            f"{m3.replay_counter} < {m1.replay_counter}")
    if sta_mac:
        m2s = sorted((f for f in by_msg[2] if parse_mac(f.src) == sta_mac),
                     key=lambda f: f.frame_number)
        m4s = sorted((f for f in by_msg[4] if parse_mac(f.src) == sta_mac),
                     key=lambda f: f.frame_number)
        for m2, m4 in zip(m2s, m4s):
            if (m2.replay_counter is not None and m4.replay_counter is not None
                    and m4.replay_counter < m2.replay_counter):
                    return (f"replay counter decreased for {sta_mac}: "
                            f"{m4.replay_counter} < {m2.replay_counter}")

    if {1, 2, 3, 4}.issubset(ev.messages) and not _has_correlated_exchange(ev, need_full=True):
        return "no correlated M1-M4 exchange (ANonce/STA mismatch across messages)"
    return None


def _ap_mac(ev: HandshakeEvidence) -> str | None:
    """Infer the AP MAC from the bssid (the authenticator owns the BSSID)."""
    return ev.bssid


def _sta_mac(ev: HandshakeEvidence) -> str | None:
    """Infer the STA MAC as the M2/M4 transmitter, if observed."""
    for f in ev.frames:
        if f.message in (2, 4):
            mac = parse_mac(f.src)
            if mac and mac != ev.bssid:
                return mac
    return None


# --------------------------------------------------------------------------- #
# Independent-verifier output parsers (pure, unit-testable)
# --------------------------------------------------------------------------- #
_ACCESSPOINT_RE = re.compile(r"AccessPoint\s+([0-9A-Fa-f:]{17})", re.IGNORECASE)
_GOOD_RE = re.compile(r"\b(good|workable)\b", re.IGNORECASE)


def parse_pyrit(result) -> set[str]:
    """Extract BSSIDs pyrit rates as ``good``/``workable`` from ``analyze`` output.

    pyrit prints one ``AccessPoint <bssid>`` line per AP, with per-station
    handshake lines beneath. Only APs that have at least one ``good`` or
    ``workable`` handshake are returned. An empty set means pyrit ran but found
    nothing usable.
    """
    confirmed: set[str] = set()
    current_bssid: str | None = None
    for line in result.output.splitlines():
        m = _ACCESSPOINT_RE.search(line)
        if m:
            current_bssid = parse_mac(m.group(1))
            continue
        # A "good"/"workable" handshake line belongs to the current AP.
        if current_bssid and _GOOD_RE.search(line):
            confirmed.add(current_bssid)
    return confirmed


_COWPATTY_OK_RE = re.compile(r"collected all necessary data", re.IGNORECASE)
_COWPATTY_FAIL_RE = re.compile(r"(no valid|unable to identify|not found)", re.IGNORECASE)


def parse_cowpatty(result) -> bool | None:
    """Interpret cowpatty ``-c`` output.

    * ``True``  — cowpatty found a complete handshake (documented phrase).
    * ``False`` — cowpatty ran and reported no valid handshake.
    * ``None``  — cowpatty errored / produced no parseable output (honest
      "unknown", distinct from a real "no handshake" finding).

    We never claim confirmation without the documented phrase.
    """
    if _COWPATTY_OK_RE.search(result.output):
        return True
    if _COWPATTY_FAIL_RE.search(result.output):
        return False
    if not result.ok and not result.output.strip():
        return None
    return None


_CAPINFOS_PACKETS_RE = re.compile(r"Number of packets:\s*([\d,]+)", re.IGNORECASE)


def parse_capinfos_packets(result) -> int | None:
    """Extract the packet count from capinfos output, or None."""
    m = _CAPINFOS_PACKETS_RE.search(result.output)
    if not m:
        return None
    return int(m.group(1).replace(",", ""))
