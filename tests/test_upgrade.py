"""Tests for the major-upgrade fixes: per-direction replay counter, hex
replay-counter parsing, M1 nonce presence, PMKID-vs-EAPOL 22000 classification,
and scapy availability detection. Pure logic — no hardware or root required."""

from __future__ import annotations

from handshaker.core.adapter import _parse_monitor_interface
from handshaker.core.deauth import Deauther, scapy_available
from handshaker.core.pmkid import PmidCapture
from handshaker.core.scanner import _band_flag
from handshaker.core.verifier import (
    EapolFrame,
    HandshakeEvidence,
    _classify_message,
    _parse_counter,
    _structural_problem,
)
from handshaker.learning.state import ActionKey

BSSID = "aa:bb:cc:dd:ee:ff"
AP = BSSID
STA = "00:11:22:33:44:55"
NONCE64 = "a" * 64
MIC32 = "c" * 32


def _frame(src, *, ack=False, install=False, mic=False, nonce="", rc=None, num=1):
    f = EapolFrame(
        frame_number=num, bssid=BSSID, src=src, dst=STA if src == AP else AP,
        key_info="0x0", has_ack=ack, has_install=install,
        has_mic=bool(mic), mic=(MIC32 if mic else ""), nonce=nonce,
        msgnr=None, replay_counter=rc,
    )
    f.message = _classify_message(f)
    return f


def _evidence(frames):
    ev = HandshakeEvidence(bssid=BSSID)
    ev.frames = list(frames)
    ev.messages = {f.message for f in frames}
    return ev


def _full(ap_rc=(2, 3), sta_rc=(1, 2)):
    """A complete M1-M4 handshake with independent AP and STA replay counters."""
    return _evidence([
        _frame(AP, ack=True, mic=False, nonce=NONCE64, rc=ap_rc[0], num=1),  # M1
        _frame(STA, mic=True, nonce=NONCE64, rc=sta_rc[0], num=2),           # M2
        _frame(AP, ack=True, install=True, mic=True, nonce=NONCE64, rc=ap_rc[1], num=3),  # M3
        _frame(STA, mic=True, nonce="", rc=sta_rc[1], num=4),                # M4
    ])


# --------------------------------------------------------------------------- #
# Replay counter: per-direction (the bug being fixed)
# --------------------------------------------------------------------------- #
def test_replay_counter_is_per_direction():
    # STA counter (1,2) starts BELOW the AP counter (2,3). A global monotonicity
    # check would falsely reject this valid handshake.
    ev = _full(ap_rc=(2, 3), sta_rc=(1, 2))
    assert _structural_problem(ev) is None


def test_replay_counter_decrease_same_direction_is_rejected():
    # AP replay counter decreases within its own direction -> malformed.
    ev = _full(ap_rc=(3, 2), sta_rc=(1, 2))
    problem = _structural_problem(ev)
    assert problem is not None and "replay counter" in problem


def test_replay_counter_sta_decrease_is_rejected():
    ev = _full(ap_rc=(2, 3), sta_rc=(2, 1))
    problem = _structural_problem(ev)
    assert problem is not None and "replay counter" in problem


# --------------------------------------------------------------------------- #
# Replay counter hex parsing
# --------------------------------------------------------------------------- #
def test_parse_counter_hex_and_decimal():
    assert _parse_counter("0x0000000000000001") == 1
    assert _parse_counter("0x2a") == 42
    assert _parse_counter("42") == 42
    assert _parse_counter("garbage") is None
    assert _parse_counter("") is None


# --------------------------------------------------------------------------- #
# M1 nonce presence
# --------------------------------------------------------------------------- #
def test_m1_missing_nonce_is_rejected():
    frames = [
        _frame(AP, ack=True, mic=False, nonce="", rc=1, num=1),          # M1 no ANonce
        _frame(STA, mic=True, nonce=NONCE64, rc=1, num=2),               # M2
        _frame(AP, ack=True, install=True, mic=True, nonce=NONCE64, rc=2, num=3),  # M3
        _frame(STA, mic=True, nonce="", rc=2, num=4),                    # M4
    ]
    problem = _structural_problem(_evidence(frames))
    assert problem is not None and "ANonce" in problem


def test_complete_handshake_still_valid():
    assert _structural_problem(_full()) is None


def test_two_handshakes_with_reset_counter_are_not_rejected():
    """A later re-auth restarts the replay counter; that must not fail the file."""
    first = _full(ap_rc=(2, 3), sta_rc=(1, 2)).frames
    # Second exchange uses a different ANonce so it is a distinct handshake.
    other = "d" * 64
    second = [
        _frame(AP, ack=True, mic=False, nonce=other, rc=1, num=10),
        _frame(STA, mic=True, nonce=other, rc=1, num=11),
        _frame(AP, ack=True, install=True, mic=True, nonce=other, rc=2, num=12),
        _frame(STA, mic=True, nonce="", rc=2, num=13),
    ]
    ev = _evidence(first + second)
    assert _structural_problem(ev) is None


# --------------------------------------------------------------------------- #
# PMKID vs EAPOL in 22000 files
# --------------------------------------------------------------------------- #
def test_contains_pmkid_only_matches_01(tmp_path):
    pmkid_line = "WPA*01*11223344556677889900aabbccddeeff*aa bb cc dd ee ff*00 11 22 33 44 55*MyNet***"
    eapol_line = "WPA*02*11223344556677889900aabbccddeeff*aabbccddeeff*001122334455*MyNet*" + "a" * 64 + "*" + "b" * 256

    f = tmp_path / "pmkid.22000"
    f.write_text(pmkid_line + "\n")
    assert PmidCapture.contains_pmkid(str(f)) is True

    g = tmp_path / "eapol.22000"
    g.write_text(eapol_line + "\n")
    assert PmidCapture.contains_pmkid(str(g)) is False  # was the bug: matched 02


def test_count_22000_types(tmp_path):
    f = tmp_path / "h.22000"
    f.write_text(
        "WPA*01*abc*aa bb cc dd ee ff*00 11 22 33 44 55*Net***\n"
        "WPA*02*def*aabbccddeeff*001122334455*Net*" + "a" * 64 + "*" + "b" * 256 + "\n"
        "WPA*01*ghi*aa bb cc dd ee ff*00 11 22 33 44 55*Net***\n"
        "# comment line\n"
    )
    n_pmkid, n_eapol = PmidCapture.count_22000_types(str(f))
    assert n_pmkid == 2
    assert n_eapol == 1


def test_count_22000_types_missing_file(tmp_path):
    assert PmidCapture.count_22000_types(str(tmp_path / "nope.22000")) == (0, 0)


# --------------------------------------------------------------------------- #
# scapy availability (always returns a bool; never raises)
# --------------------------------------------------------------------------- #
def test_scapy_available_returns_bool():
    assert isinstance(scapy_available(), bool)


# --------------------------------------------------------------------------- #
# Deauth campaign: exactly one engine runs (fallback, not sequential)
# --------------------------------------------------------------------------- #
class _FakeRegistry:
    def __init__(self, present):
        self._present = set(present)

    def has(self, name):
        return name in self._present


def test_campaign_uses_only_first_available_engine(monkeypatch):
    reg = _FakeRegistry({"aireplay-ng", "mdk4", "bettercap"})
    cfg = {
        "deauth": {
            "max_bursts": 3,
            "burst_size": 10,
            "cooldown": 0,
            "reason_codes": [7],
            "tools": ["scapy", "aireplay-ng", "mdk4", "bettercap"],
        }
    }
    deauther = Deauther(reg, cfg)
    calls = []

    def fake_execute(interface, bssid, action, client=None):
        calls.append(action.tool)
        from handshaker.utils.proc import ProcResult
        return ProcResult(args=["x"], returncode=0)

    monkeypatch.setattr(deauther, "execute", fake_execute)

    action = ActionKey("aireplay-ng", 10, 7)
    deauther.campaign("wlan0", "aa:bb:cc:dd:ee:ff", action,
                      fallback_tools=["aireplay-ng", "mdk4", "bettercap"])

    # Only the FIRST available engine runs (all bursts), never the others.
    assert calls and all(c == "aireplay-ng" for c in calls)
    assert len(calls) == 3  # max_bursts


def test_campaign_skips_to_next_when_first_missing(monkeypatch):
    reg = _FakeRegistry({"mdk4"})  # aireplay-ng NOT installed
    cfg = {
        "deauth": {
            "max_bursts": 2,
            "burst_size": 10,
            "cooldown": 0,
            "reason_codes": [7],
            "tools": ["scapy", "aireplay-ng", "mdk4", "bettercap"],
        }
    }
    deauther = Deauther(reg, cfg)
    calls = []

    def fake_execute(interface, bssid, action, client=None):
        calls.append(action.tool)
        from handshaker.utils.proc import ProcResult
        return ProcResult(args=["x"], returncode=0)

    monkeypatch.setattr(deauther, "execute", fake_execute)

    action = ActionKey("aireplay-ng", 10, 7)
    deauther.campaign("wlan0", "aa:bb:cc:dd:ee:ff", action,
                      fallback_tools=["aireplay-ng", "mdk4"])

    # aireplay-ng missing -> mdk4 (next available) runs instead.
    assert calls and all(c == "mdk4" for c in calls)
    assert len(calls) == 2


# --------------------------------------------------------------------------- #
# airmon-ng monitor-interface parsing (was broken: captured "p" instead of "wlan0mon")
# --------------------------------------------------------------------------- #
def test_parse_monitor_interface_primary_form():
    out = "(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)"
    assert _parse_monitor_interface(out) == "wlan0mon"


def test_parse_monitor_interface_alternate_form():
    out = "(mac80211 monitor mode vif enabled on [phy1]wlan0mon"
    assert _parse_monitor_interface(out) == "wlan0mon"


def test_parse_monitor_interface_no_match_returns_none():
    assert _parse_monitor_interface("random output") is None


# --------------------------------------------------------------------------- #
# airodump band flag (no invalid "x" for 6GHz)
# --------------------------------------------------------------------------- #
def test_band_flag_2g_and_5g():
    assert _band_flag(["2.4GHz", "5GHz"]) == "abg"


def test_band_flag_2g_only():
    assert _band_flag(["2.4GHz"]) == "bg"


def test_band_flag_5g_only():
    assert _band_flag(["5GHz"]) == "a"


def test_band_flag_ignores_6ghz():
    # 6GHz has no airodump band letter; must not emit "x".
    assert _band_flag(["6GHz"]) == "abg"
    assert "x" not in _band_flag(["2.4GHz", "6GHz"])


def test_campaign_no_engine_is_noop(monkeypatch):
    reg = _FakeRegistry(set())
    cfg = {
        "deauth": {
            "max_bursts": 3,
            "burst_size": 10,
            "cooldown": 0,
            "reason_codes": [7],
            "tools": ["scapy", "aireplay-ng", "mdk4", "bettercap"],
        }
    }
    deauther = Deauther(reg, cfg)
    executed = []

    def fake_execute(*a, **k):
        executed.append(1)
        from handshaker.utils.proc import ProcResult
        return ProcResult(args=["x"], returncode=0)

    monkeypatch.setattr(deauther, "execute", fake_execute)
    deauther.campaign("wlan0", "aa:bb:cc:dd:ee:ff", ActionKey("aireplay-ng", 10, 7))
    assert executed == []
