"""Verification quality + automation: pairwise keys, MIC zeros, skip-verified."""

from __future__ import annotations

from handshaker.core.verifier import (
    EapolFrame,
    HandshakeEvidence,
    _classify_message,
    _count_22000,
    _nonce_eq,
    _structural_problem,
)

BSSID = "aa:bb:cc:dd:ee:ff"
AP = BSSID
STA = "00:11:22:33:44:55"
ANONCE = "a" * 64
SNONCE = "b" * 64
MIC = "c" * 32


def _frame(src, dst, *, ack=False, install=False, mic=False, nonce="",
           rc=1, num=1, pairwise=None, mic_hex=None):
    f = EapolFrame(
        frame_number=num, bssid=BSSID, src=src, dst=dst, key_info="0x0",
        has_ack=ack, has_install=install, has_mic=bool(mic),
        mic=(mic_hex if mic_hex is not None else (MIC if mic else "")),
        nonce=nonce, msgnr=None, replay_counter=rc, pairwise=pairwise,
    )
    f.message = _classify_message(f)
    return f


def _full(**kw):
    pw = kw.pop("pairwise", None)
    ev = HandshakeEvidence(bssid=BSSID)
    ev.frames = [
        _frame(AP, STA, ack=True, nonce=ANONCE, num=1, rc=1, pairwise=pw),
        _frame(STA, AP, mic=True, nonce=SNONCE, num=2, rc=1, pairwise=pw),
        _frame(AP, STA, ack=True, install=True, mic=True, nonce=ANONCE, num=3, rc=2, pairwise=pw),
        _frame(STA, AP, mic=True, nonce="", num=4, rc=2, pairwise=pw),
    ]
    ev.messages = {f.message for f in ev.frames}
    return ev


def test_group_key_frames_are_not_handshake_messages():
    f = _frame(AP, STA, ack=True, nonce=ANONCE, pairwise=False)
    assert _classify_message(f) == 0


def test_pairwise_frames_still_classify():
    f = _frame(AP, STA, ack=True, nonce=ANONCE, pairwise=True)
    assert _classify_message(f) == 1


def test_colon_nonces_are_equal():
    colon = ":".join(ANONCE[i:i + 2] for i in range(0, 64, 2))
    assert _nonce_eq(colon, ANONCE)
    ev = HandshakeEvidence(bssid=BSSID)
    ev.frames = [
        _frame(AP, STA, ack=True, nonce=colon, num=1, rc=1),
        _frame(STA, AP, mic=True, nonce=SNONCE, num=2, rc=1),
        _frame(AP, STA, ack=True, install=True, mic=True, nonce=ANONCE, num=3, rc=2),
        _frame(STA, AP, mic=True, nonce="", num=4, rc=2),
    ]
    for f in ev.frames:
        f.message = _classify_message(f)
    ev.messages = {f.message for f in ev.frames}
    assert _structural_problem(ev) is None


def test_all_zero_m2_mic_rejected():
    ev = _full()
    ev.frames[1] = _frame(STA, AP, mic=True, nonce=SNONCE, num=2, rc=1, mic_hex="0" * 32)
    ev.frames[1].message = 2
    ev.messages = {1, 2, 3, 4}
    problem = _structural_problem(ev)
    assert problem is not None and "MIC" in problem


def test_count_22000_lines(tmp_path):
    f = tmp_path / "h.22000"
    f.write_text(
        "WPA*01*" + "a" * 32 + "*aabbccddeeff*001122334455*Net***\n"
        "WPA*02*" + "b" * 32 + "*aabbccddeeff*001122334455*Net*" + "x" * 64 + "*" + "y" * 32 + "\n"
    )
    n_eapol, n_pmkid = _count_22000(str(f))
    assert n_eapol == 1
    assert n_pmkid == 1


def test_skip_verified_does_not_reengage(monkeypatch, tmp_path):
    from handshaker import constants
    from handshaker.config import load_config
    from handshaker.core.engine import Engine, RunStats
    from handshaker.core.scanner import AccessPoint, ScanResult

    hs = tmp_path / "hs"
    hs.mkdir()
    (hs / "aabbccddeeff_Home.pcapng").write_bytes(b"\x00" * 8)
    cfg = load_config()
    monkeypatch.setattr(constants, "HANDSHAKES_DIR", hs)
    e = Engine(cfg)
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6, privacy="WPA2",
                     auth="PSK", power=-40, essid="Home")
    scan = ScanResult(aps={ap.bssid: ap}, clients={})
    stats = RunStats()
    e._process_target("wlan0mon", ap, scan, [], None, stats, 1)
    assert stats.targets_attacked == 0


def test_verify_parser_accepts_dir():
    from handshaker.cli import build_parser
    ns = build_parser().parse_args(["verify", "--dir", "/tmp/caps"])
    assert ns.dir == "/tmp/caps"
    assert ns.file is None


def test_ci_script_exists():
    from pathlib import Path
    script = Path("scripts/ci.sh")
    assert script.is_file()
    text = script.read_text()
    assert "pytest" in text
    assert "pyflakes" in text
