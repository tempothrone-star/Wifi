"""Regression tests for the second ChatGPT audit (packaging, config, verifier)."""

from __future__ import annotations

from pathlib import Path

import pytest

from handshaker.core.verifier import (
    EapolFrame,
    HandshakeEvidence,
    _classify_message,
    _structural_problem,
)
from handshaker.exceptions import ConfigError, LearningStateError
from handshaker.utils.proc import ProcResult

BSSID = "aa:bb:cc:dd:ee:ff"
AP = BSSID
STA = "00:11:22:33:44:55"
ANONCE_A = "a" * 64
ANONCE_B = "b" * 64
SNONCE_A = "c" * 64
SNONCE_B = "d" * 64
MIC = "e" * 32


def _frame(src, dst, *, ack=False, install=False, mic=False, nonce="", rc=1, num=1):
    f = EapolFrame(
        frame_number=num, bssid=BSSID, src=src, dst=dst, key_info="0x0",
        has_ack=ack, has_install=install, has_mic=bool(mic),
        mic=(MIC if mic else ""), nonce=nonce, msgnr=None, replay_counter=rc,
    )
    f.message = _classify_message(f)
    return f


def _ev(frames):
    ev = HandshakeEvidence(bssid=BSSID)
    ev.frames = list(frames)
    ev.messages = {f.message for f in frames}
    return ev


def test_missing_config_file_is_error(tmp_path):
    from handshaker.config import load_config
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


def test_general_null_is_config_error(tmp_path):
    from handshaker.config import load_config
    p = tmp_path / "c.yaml"
    p.write_text("general: null\n")
    with pytest.raises(ConfigError, match="general must be a mapping"):
        load_config(p)


def test_targets_bssid_string_is_config_error(tmp_path):
    from handshaker.config import load_config
    p = tmp_path / "c.yaml"
    p.write_text("targets:\n  bssid: aa:bb:cc:dd:ee:ff\n")
    with pytest.raises(ConfigError, match="targets.bssid must be a list"):
        load_config(p)


def test_tools_overrides_list_is_config_error(tmp_path):
    from handshaker.config import load_config
    p = tmp_path / "c.yaml"
    p.write_text("tools:\n  overrides: [mdk4]\n")
    with pytest.raises(ConfigError, match="tools.overrides"):
        load_config(p)


def test_burst_size_string_is_config_error(tmp_path):
    from handshaker.config import load_config
    p = tmp_path / "c.yaml"
    p.write_text("deauth:\n  burst_size: \"15\"\n")
    with pytest.raises(ConfigError, match="burst_size"):
        load_config(p)


def test_6ghz_only_bands_rejected(tmp_path):
    from handshaker.config import load_config
    p = tmp_path / "c.yaml"
    p.write_text("scan:\n  bands: [\"6GHz\"]\n")
    with pytest.raises(ConfigError, match="6GHz-only"):
        load_config(p)


def test_frankenstein_handshake_is_rejected():
    frames = [
        _frame(AP, STA, ack=True, nonce=ANONCE_A, num=1, rc=1),
        _frame(STA, AP, mic=True, nonce=SNONCE_A, num=2, rc=1),
        _frame(AP, STA, ack=True, install=True, mic=True, nonce=ANONCE_B, num=3, rc=2),
        _frame(STA, AP, mic=True, nonce="", num=4, rc=2),
    ]
    problem = _structural_problem(_ev(frames))
    assert problem is not None
    assert "correlated" in problem


def test_wrong_destination_is_rejected():
    frames = [
        _frame(AP, AP, ack=True, nonce=ANONCE_A, num=1, rc=1),  # dst should be STA
        _frame(STA, AP, mic=True, nonce=SNONCE_A, num=2, rc=1),
        _frame(AP, STA, ack=True, install=True, mic=True, nonce=ANONCE_A, num=3, rc=2),
        _frame(STA, AP, mic=True, nonce="", num=4, rc=2),
    ]
    problem = _structural_problem(_ev(frames))
    assert problem is not None
    assert "destination" in problem


def test_non_hex_nonce_is_rejected():
    frames = [
        _frame(AP, STA, ack=True, nonce="g" * 64, num=1, rc=1),
        _frame(STA, AP, mic=True, nonce=SNONCE_A, num=2, rc=1),
        _frame(AP, STA, ack=True, install=True, mic=True, nonce="g" * 64, num=3, rc=2),
        _frame(STA, AP, mic=True, nonce="", num=4, rc=2),
    ]
    problem = _structural_problem(_ev(frames))
    assert problem is not None
    assert "nonce" in problem


def test_tshark_failure_is_not_empty_capture(tmp_path):
    from handshaker.core.verifier import HandshakeVerifier

    cap = tmp_path / "x.pcapng"
    cap.write_bytes(b"\x00" * 16)

    class T:
        def eapol_frames(self, _f):
            return ProcResult(args=["tshark"], returncode=1, stdout="partial")

    class R:
        def has(self, n):
            return n == "tshark"

        def tshark(self):
            return T()

    v = HandshakeVerifier(R(), {"verify": {
        "require_full_handshake": True, "min_packets": 4,
        "structural_checks": True, "tools": ["tshark"],
    }})
    report = v.verify_file(str(cap))
    assert report.passed is False
    assert "tshark failed" in report.reason


def test_aircrack_crash_is_not_negative_verdict():
    from handshaker.tools.aircrack import AircrackNg
    res = ProcResult(args=["aircrack-ng"], returncode=127, stdout="", stderr="not found")
    assert AircrackNg.parse_handshakes(res) is None


def test_suggested_wps_pin_is_not_recovered():
    from handshaker.core.wps import parse_wps_pin
    assert parse_wps_pin(ProcResult(args=["x"], returncode=0,
                                    stdout="Suggested WPS PIN: 12345670\n")) is None


def test_wps_history_corrupt_raises(tmp_path):
    from handshaker.core.wps import WpsHistory
    p = tmp_path / "wps.json"
    p.write_text("{not json")
    with pytest.raises(LearningStateError):
        WpsHistory(path=p)


def test_profile_copy_is_deep(tmp_path):
    from handshaker.learning.state import ActionKey, LearningStore
    store = LearningStore(path=tmp_path / "s.json", decay=1.0)
    store.record("aa:bb:cc:dd:ee:ff", ActionKey("mdk4", 10, 7), True)
    prof = store.profile("aa:bb:cc:dd:ee:ff")
    prof["actions"].clear()
    assert store.actions_for("aa:bb:cc:dd:ee:ff")


def test_token_bucket_zero_rate_does_not_hang():
    from handshaker.nim.ratelimit import TokenBucket
    b = TokenBucket(rate=0.0, burst=1)
    assert b.acquire(timeout=None) is True  # initial token
    assert b.acquire(timeout=None) is False  # cannot refill, must not block


def test_no_setuptools_setup_py():
    assert not Path("setup.py").exists()
    assert Path("bootstrap.py").exists()
    assert Path("pyproject.toml").read_text().find("setuptools.build_meta") >= 0


def test_pep517_metadata_builds(tmp_path):
    """setuptools must be able to prepare metadata without invoking bootstrap.py."""
    import subprocess
    import sys
    r = subprocess.run(
        [sys.executable, "-c",
         "from setuptools import build_meta; "
         "print('ok', hasattr(build_meta, 'prepare_metadata_for_build_wheel'))"],
        capture_output=True, text=True, timeout=30,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ok True" in r.stdout
    text = Path("bootstrap.py").read_text()
    assert "from setuptools" not in text
    assert "setup(" not in text
    assert "raise SystemExit(main())" in text


def test_finish_session_rejects_unknown_status(tmp_path):
    from handshaker.db import ResultsDB
    db = ResultsDB(path=tmp_path / "r.db")
    sid = db.start_session("wlan0")
    with pytest.raises(ValueError):
        db.finish_session(sid, "banana")
