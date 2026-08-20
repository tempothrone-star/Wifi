"""Full-fledged workflow integration tests.

These drive the complete handshake + PMKID + WPS pipelines end-to-end using
*scripted* tool outputs that match the real, web-verified formats of tshark,
aircrack-ng, hcxpcapngtool, wash, and reaver. This proves the orchestration
(scan → target → deauth → capture → verify → learn, plus PMKID and WPS) is
real and correct — without needing wireless hardware in CI.

The scripts mock only the subprocess *boundary*; all parsing, classification,
decision, and learning logic is the real production code.
"""

from __future__ import annotations

from handshaker.config import load_config
from handshaker.core.verifier import HandshakeVerifier
from handshaker.utils.proc import ProcResult

ANONCE = "a" * 64
SNONCE = "b" * 64
MIC = "c" * 32
BSSID = "aa:bb:cc:dd:ee:ff"
AP = BSSID
STA = "00:11:22:33:44:55"


def _proc(stdout="", stderr="", rc=0):
    return ProcResult(args=["x"], returncode=rc, stdout=stdout, stderr=stderr)


def _eapol_line(num, bssid, sa, da, key_info, ack, install, mic, nonce, msgnr, rc):
    return ",".join([str(num), bssid, sa, da, key_info, str(int(ack)), str(int(install)),
                     mic, nonce, str(msgnr), str(rc)])


def _full_handshake_tshark() -> str:
    """Real-format tshark EAPOL output for a complete M1-M4 handshake."""
    return "\n".join([
        _eapol_line(1, BSSID, AP, STA, "0x008a", 1, 0, "", ANONCE, 1, 1),   # M1
        _eapol_line(2, BSSID, STA, AP, "0x010a", 0, 0, MIC, SNONCE, 2, 1),  # M2
        _eapol_line(3, BSSID, AP, STA, "0x13ca", 1, 1, MIC, ANONCE, 3, 2),  # M3
        _eapol_line(4, BSSID, STA, AP, "0x030a", 0, 0, MIC, "", 4, 2),      # M4
    ])


class _FakeTshark:
    def __init__(self, eapol="", essids=None):
        self._eapol = eapol
        self._essids = essids or {}

    def eapol_frames(self, capture_file):
        return _proc(self._eapol)

    def essids(self, capture_file):
        return self._essids


class _FakeAircrack:
    def __init__(self, handshakes):
        self._handshakes = handshakes  # set of bssids or None

    def check_handshakes(self, capture_file):
        if self._handshakes is None:
            return _proc("")
        return _proc("\n".join(f"WPA handshake: {b}" for b in self._handshakes))

    def parse_handshakes(self, result):
        from handshaker.tools.aircrack import AircrackNg
        return AircrackNg.parse_handshakes(result)


class _FakeHcx:
    def __init__(self, pairs=None, pmkid=False):
        self._pairs = pairs
        self._pmkid = pmkid

    def convert(self, capture_file, out_file):
        out = ""
        if self._pairs is not None:
            out += f"EAPOL pairs: {self._pairs}\n"
        if self._pmkid:
            out += "PMKID: 1\n"
        return _proc(out)


class _FakeRegistry:
    """Minimal registry exposing exactly the verifier's surface."""
    def __init__(self, tshark=None, aircrack=None, hcx=None):
        self._tshark = tshark
        self._aircrack = aircrack
        self._hcx = hcx

    def has(self, name):
        if name == "tshark":
            return self._tshark is not None
        if name == "aircrack-ng":
            return self._aircrack is not None
        if name == "hcxpcapngtool":
            return self._hcx is not None
        return False

    def tshark(self):
        return self._tshark

    def aircrack(self):
        return self._aircrack

    def hcxpcapngtool(self):
        return self._hcx


_VERIFY_CFG = {"verify": {
    "require_full_handshake": True,
    "min_packets": 4,
    "structural_checks": True,
    "tools": ["tshark", "aircrack-ng", "hcxpcapngtool"],
}}


# --------------------------------------------------------------------------- #
# Handshake capture → verify pipeline (full)
# --------------------------------------------------------------------------- #
def test_full_handshake_pipeline_passes(tmp_path):
    cap = tmp_path / "hs.cap"
    cap.write_bytes(b"\x00" * 64)  # real, non-empty capture file
    reg = _FakeRegistry(
        tshark=_FakeTshark(_full_handshake_tshark()),
        aircrack=_FakeAircrack({BSSID}),
        hcx=_FakeHcx(pairs=1, pmkid=False),
    )
    verifier = HandshakeVerifier(reg, _VERIFY_CFG)
    report = verifier.verify_file(str(cap))
    assert report.passed is True, report.reason
    assert report.evidence[0].has_full_handshake
    assert report.evidence[0].aircrack_confirmed is True
    assert report.evidence[0].hcx_pairs == 1


def test_incomplete_handshake_rejected(tmp_path):
    # Drop M4 -> incomplete; must reject.
    eapol = "\n".join([
        _eapol_line(1, BSSID, AP, STA, "0x008a", 1, 0, "", ANONCE, 1, 1),
        _eapol_line(2, BSSID, STA, AP, "0x010a", 0, 0, MIC, SNONCE, 2, 1),
        _eapol_line(3, BSSID, AP, STA, "0x13ca", 1, 1, MIC, ANONCE, 3, 2),
    ])
    cap = tmp_path / "hs.cap"
    cap.write_bytes(b"\x00" * 64)
    reg = _FakeRegistry(tshark=_FakeTshark(eapol), aircrack=_FakeAircrack({BSSID}),
                        hcx=_FakeHcx(pairs=1))
    report = HandshakeVerifier(reg, _VERIFY_CFG).verify_file(str(cap))
    assert report.passed is False
    # Rejected either because there are too few EAPOL frames (min_packets) or
    # because the handshake is incomplete — both are correct rejections.
    assert report.reason


def test_aircrack_contradiction_rejects(tmp_path):
    # tshark says full handshake, but aircrack finds nothing -> contradiction.
    cap = tmp_path / "hs.cap"
    cap.write_bytes(b"\x00" * 64)
    reg = _FakeRegistry(tshark=_FakeTshark(_full_handshake_tshark()),
                        aircrack=_FakeAircrack(set()),  # ran, found nothing
                        hcx=_FakeHcx(pairs=1))
    report = HandshakeVerifier(reg, _VERIFY_CFG).verify_file(str(cap))
    assert report.passed is False
    assert "aircrack" in report.reason


def test_no_tools_reports_honestly(tmp_path):
    cap = tmp_path / "hs.cap"
    cap.write_bytes(b"\x00" * 64)
    reg = _FakeRegistry()  # nothing present
    report = HandshakeVerifier(reg, _VERIFY_CFG).verify_file(str(cap))
    assert report.passed is False
    assert report.tools_missing == ["tshark", "aircrack-ng", "hcxpcapngtool"]


# --------------------------------------------------------------------------- #
# PMKID capture → conversion → classification pipeline (full)
# --------------------------------------------------------------------------- #
def test_pmkid_pipeline_counts_correctly(tmp_path):
    from handshaker.core.pmkid import PmidCapture

    # A 22000 file with 2 PMKID lines and 1 EAPOL line.
    f = tmp_path / "h.22000"
    f.write_text(
        "WPA*01*" + "a" * 32 + "*" + AP.replace(":", "") + "*" + STA.replace(":", "") + "*Net***\n"
        "WPA*02*" + "b" * 32 + "*" + AP.replace(":", "") + "*" + STA.replace(":", "") + "*Net*" + "x" * 64 + "*" + "y" * 256 + "\n"
        "WPA*01*" + "c" * 32 + "*" + AP.replace(":", "") + "*" + STA.replace(":", "") + "*Net***\n"
    )
    assert PmidCapture.contains_pmkid(str(f)) is True
    n_pmkid, n_eapol = PmidCapture.count_22000_types(str(f))
    assert n_pmkid == 2
    assert n_eapol == 1


def test_pmkid_not_confused_with_eapol(tmp_path):
    from handshaker.core.pmkid import PmidCapture
    # Only EAPOL (WPA*02*) lines -> NOT a PMKID capture.
    f = tmp_path / "eapol.22000"
    f.write_text("WPA*02*" + "b" * 32 + "*" + AP.replace(":", "") + "*" + STA.replace(":", "") + "*Net*" + "x" * 64 + "*" + "y" * 256 + "\n")
    assert PmidCapture.contains_pmkid(str(f)) is False


# --------------------------------------------------------------------------- #
# Learning: PMKID track is separate from handshake track (bug regression)
# --------------------------------------------------------------------------- #
def test_pmkid_outcome_separate_from_handshake(tmp_path):
    from handshaker.learning.state import ActionKey, LearningStore

    store = LearningStore(path=tmp_path / "s.json", decay=1.0)
    action = ActionKey("mdk4", 10, 7)
    # Record a PMKID success, then a handshake FAILURE for the same AP.
    store.record_pmkid(BSSID, True)
    store.record(BSSID, action, False)

    # PMKID track shows success; handshake action track shows failure.
    assert store.pmkid_stats(BSSID)["wins"] == 1.0
    assert store.pmkid_stats(BSSID)["rate"] == 1.0
    hs = store.action_stats(BSSID)[action.id]
    assert hs["wins"] == 0.0
    assert hs["trials"] == 1.0


def test_pmkid_context_aggregation(tmp_path):
    from handshaker.learning.state import LearningStore
    store = LearningStore(path=tmp_path / "s.json", decay=1.0)
    for b in ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"):
        store.ensure_ap(b, security="WPA2", band="5GHz", vendor="001122")
        store.record_pmkid(b, True)
    ctx = store.context_key("aa:bb:cc:dd:ee:ff")
    assert store.context_pmkid_stats(ctx)["wins"] == 2.0


# --------------------------------------------------------------------------- #
# WPS full pipeline (wash detect -> strategic assess)
# --------------------------------------------------------------------------- #
def test_wps_detect_and_assess_full_pipeline(monkeypatch, tmp_path):
    from handshaker.core.wps import VULNERABLE_PIXIE, WpsAssessor, WpsHistory

    reg = _FakeWashRegistry()
    history = WpsHistory(path=tmp_path / "wps.json", decay=1.0)
    assessor = WpsAssessor(reg, {"wps": {"pixie_dust": True, "default_pin": False}},
                           history=history)

    # wash returns one Broadcom AP; pixie_dust recovers a PIN.
    monkeypatch.setattr(assessor, "pixie_dust",
                        lambda iface, ap: _proc("[+] WPS PIN: '12345670'"))

    aps = assessor.detect("wlan0")
    assert len(aps) == 1
    ap = aps[0]
    assert ap.vendor == "Broadcom"
    assert ap.wps_version == "1.0"

    verdict = assessor.assess_one("wlan0", ap)
    assert verdict.status == VULNERABLE_PIXIE
    assert verdict.pin == "12345670"

    # The outcome was learned under both the BSSID and the context key.
    assert history.method_stats(ap.bssid)["pixie_dust"]["wins"] == 1.0
    assert history.method_stats(ap.context_key)["pixie_dust"]["wins"] == 1.0


class _FakeWashRegistry:
    def __init__(self):
        pass

    def has(self, name):
        return name in ("wash", "reaver")

    def wash(self):
        class W:
            def scan(self, interface, channel=None, all_aps=False, ignore_fcs=False):
                return _proc(
                    "BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID\n"
                    "AA:BB:CC:DD:EE:FF    6  -40  1.0  No   Broadcom  HomeNet\n"
                )
        return W()

    def reaver(self):
        class R:
            def pixie_dust(self, interface, bssid, channel=None, timeout=120):
                return _proc("[+] WPS PIN: '12345670'")
        return R()


# --------------------------------------------------------------------------- #
# Engine _process_target: PMKID path records PMKID separately (bug regression)
# --------------------------------------------------------------------------- #
def test_engine_pmkid_path_records_separately(monkeypatch, tmp_path):
    """The PMKID-first path must record PMKID on the pmkid track and record the
    handshake outcome exactly once (previously it double-recorded and
    mis-attributed the PMKID result to the deauth action)."""
    from handshaker.core import engine as engine_mod
    from handshaker.core.engine import Engine, RunStats
    from handshaker.core.scanner import AccessPoint, ScanResult
    from handshaker.learning.state import ActionKey

    # Redirect filesystem writes to tmp.
    monkeypatch.setattr(engine_mod, "LEARNING_DIR", tmp_path)
    monkeypatch.setattr(engine_mod, "HANDSHAKES_DIR", tmp_path / "hs")
    monkeypatch.setattr(engine_mod, "QUARANTINE_DIR", tmp_path / "q")

    cfg = load_config()
    e = Engine(cfg)

    ap = AccessPoint(bssid=BSSID, channel=6, privacy="WPA2", auth="PSK",
                     power=-40, essid="HomeNet")
    scan = ScanResult(aps={BSSID: ap}, clients={})  # no clients -> PMKID path
    action = ActionKey("mdk4", 10, 7)

    # Simulate PMKID success and a failed handshake.
    monkeypatch.setattr(e, "_try_pmkid", lambda iface, ap, stats: True)
    captured = {}
    def fake_capture_handshake(mon_iface, ap, action, scan, stats, session_id):
        e.store.record(ap.bssid, action, success=False)
        captured["called"] = True
    monkeypatch.setattr(e, "_capture_handshake", fake_capture_handshake)

    strategy = e.strategist.strategy_for(ap, scan)
    assert strategy.prefer_pmkid is True  # precondition: no clients

    session_id = e.db.start_session("wlan0mon")
    e._process_target("wlan0mon", ap, scan, [action], None,
                      RunStats(), session_id)

    # PMKID recorded on the SEPARATE track, handshake recorded exactly once.
    import pytest
    assert e.store.pmkid_stats(BSSID)["wins"] == pytest.approx(1.0)
    hs = e.store.action_stats(BSSID)
    assert hs[action.id]["trials"] == pytest.approx(1.0)  # exactly one handshake record
    assert captured.get("called") is True
