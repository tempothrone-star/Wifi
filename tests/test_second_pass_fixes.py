"""Tests for the second-pass review fixes: multi-BSSID verifier granularity,
per-BSSID min_packets, quarantine retention, engine attribution, latency origin,
explicit-target override, NIM privacy, and DB migration."""

from __future__ import annotations

from handshaker.core.verifier import (
    EapolFrame,
    HandshakeEvidence,
    _classify_message,
)

ANONCE = "a" * 64
SNONCE = "b" * 64
MIC = "c" * 32
AP_A = "aa:bb:cc:dd:ee:ff"
AP_B = "11:22:33:44:55:66"
STA = "00:11:22:33:44:55"


def _frame(bssid, src, *, ack=False, install=False, mic=False, nonce="", msg=None, num=1):
    f = EapolFrame(frame_number=num, bssid=bssid, src=src,
                   dst=STA if src == bssid else bssid, key_info="0x0",
                   has_ack=ack, has_install=install, has_mic=bool(mic),
                   mic=(MIC if mic else ""), nonce=nonce, msgnr=msg,
                   replay_counter=1)
    f.message = _classify_message(f) if msg is None else msg
    return f


def _evidence(bssid, frames):
    ev = HandshakeEvidence(bssid=bssid)
    ev.frames = list(frames)
    ev.messages = {f.message for f in frames}
    return ev


def _full(bssid):
    return _evidence(bssid, [
        _frame(bssid, bssid, ack=True, nonce=ANONCE, msg=1, num=1),
        _frame(bssid, STA, mic=True, nonce=SNONCE, msg=2, num=2),
        _frame(bssid, bssid, ack=True, install=True, mic=True, nonce=ANONCE, msg=3, num=3),
        _frame(bssid, STA, mic=True, nonce="", msg=4, num=4),
    ])


# --------------------------------------------------------------------------- #
# Multi-BSSID verifier granularity (#2) — a valid AP must not be rejected by an
# unrelated incomplete AP in the same capture.
# --------------------------------------------------------------------------- #
class _Reg:
    def has(self, n):
        return False  # no independent tools -> only tshark structural evidence


def test_multi_bssid_one_valid_passes():
    from handshaker.core.verifier import HandshakeVerifier
    v = HandshakeVerifier(_Reg(), {"verify": {
        "require_full_handshake": True, "min_packets": 4,
        "structural_checks": True, "tools": ["tshark"]}})

    # Build a report manually: AP_A complete, AP_B partial.
    ev_a = _full(AP_A)
    ev_b = _evidence(AP_B, [
        _frame(AP_B, AP_B, ack=True, nonce=ANONCE, msg=1, num=1),   # M1 only
        _frame(AP_B, STA, mic=True, nonce=SNONCE, msg=2, num=2),    # M2
    ])
    report = v._decide("/tmp/x.cap", [ev_a, ev_b])
    assert report.passed is True, report.reason
    assert AP_A in report.reason


def test_multi_bssid_all_incomplete_fails():
    from handshaker.core.verifier import HandshakeVerifier
    v = HandshakeVerifier(_Reg(), {"verify": {
        "require_full_handshake": True, "min_packets": 4,
        "structural_checks": True, "tools": ["tshark"]}})
    ev_b = _evidence(AP_B, [
        _frame(AP_B, AP_B, ack=True, nonce=ANONCE, msg=1, num=1),
        _frame(AP_B, STA, mic=True, nonce=SNONCE, msg=2, num=2),
    ])
    report = v._decide("/tmp/x.cap", [ev_b])
    assert report.passed is False


# --------------------------------------------------------------------------- #
# Per-BSSID min_packets (#18)
# --------------------------------------------------------------------------- #
def test_min_packets_is_per_bssid():
    from handshaker.core.verifier import HandshakeVerifier
    v = HandshakeVerifier(_Reg(), {"verify": {
        "require_full_handshake": True, "min_packets": 4,
        "structural_checks": True, "tools": ["tshark"]}})
    # Two BSSIDs with 2 frames each should NOT collectively satisfy min_packets.
    ev_a = _evidence(AP_A, [
        _frame(AP_A, AP_A, ack=True, nonce=ANONCE, msg=1, num=1),
        _frame(AP_A, STA, mic=True, nonce=SNONCE, msg=2, num=2),
    ])
    ev_b = _evidence(AP_B, [
        _frame(AP_B, AP_B, ack=True, nonce=ANONCE, msg=1, num=1),
        _frame(AP_B, STA, mic=True, nonce=SNONCE, msg=2, num=2),
    ])
    report = v._decide("/tmp/x.cap", [ev_a, ev_b])
    assert report.passed is False


# --------------------------------------------------------------------------- #
# Explicit target overrides auto filters (#4)
# --------------------------------------------------------------------------- #
def test_explicit_target_overrides_enterprise_and_signal():
    from handshaker.core.scanner import AccessPoint, ScanResult
    from handshaker.core.strategist import Strategist
    from handshaker.learning.state import LearningStore
    from handshaker.tools.registry import ToolRegistry

    ent = AccessPoint(bssid=AP_A, privacy="WPA2", auth="MGT",  # enterprise
                      channel=6, power=-95, essid="Corp")        # weak signal too
    scan = ScanResult(aps={AP_A: ent}, clients={})
    cfg = {"targets": {"bssid": [AP_A], "exclude": [], "max_targets": 0},
           "capture": {"wpa_only": True}, "scan": {"min_signal": -90},
           "deauth": {"tools": []}, "pmkid": {"enabled": True},
           "learning": {"exploration": 0.25, "decay": 0.95, "min_observations": 2}}
    strat = Strategist(ToolRegistry(), LearningStore(path=None), cfg)
    targets = strat.prioritize(scan)
    # Explicitly requested BSSID is included despite enterprise + weak signal.
    assert [t.bssid for t in targets] == [AP_A]


# --------------------------------------------------------------------------- #
# NIM privacy (#22/#23) — BSSID/ESSID pseudonymized by default
# --------------------------------------------------------------------------- #
def test_context_pseudonymizes_by_default(monkeypatch, tmp_path):
    from handshaker.config import load_config
    from handshaker.core.engine import Engine
    from handshaker.core.scanner import AccessPoint, ScanResult

    e = Engine(load_config())
    assert e.config["nim"]["send_sensitive_context"] is False  # default

    ap = AccessPoint(bssid=AP_A, channel=6, privacy="WPA2", auth="PSK",
                     power=-40, essid="SecretNet")
    scan = ScanResult(aps={AP_A: ap}, clients={})
    ctx = e._context(scan)
    a = ctx["aps"][0]
    assert a["bssid"] != AP_A                    # not the real BSSID
    assert a["essid"] != "SecretNet"             # not the real ESSID


def test_context_sends_sensitive_when_enabled(monkeypatch, tmp_path):
    from handshaker.config import load_config
    from handshaker.core.engine import Engine
    from handshaker.core.scanner import AccessPoint, ScanResult

    cfg = load_config()
    cfg["nim"]["send_sensitive_context"] = True
    e = Engine(cfg)
    ap = AccessPoint(bssid=AP_A, channel=6, privacy="WPA2", auth="PSK",
                     power=-40, essid="SecretNet")
    scan = ScanResult(aps={AP_A: ap}, clients={})
    ctx = e._context(scan)
    a = ctx["aps"][0]
    assert a["bssid"] == AP_A
    assert a["essid"] == "SecretNet"


# --------------------------------------------------------------------------- #
# DB migration + session lifecycle (#20)
# --------------------------------------------------------------------------- #
def test_db_schema_migration_adds_columns(tmp_path):
    import sqlite3
    # Simulate an OLD database missing the new columns.
    p = tmp_path / "old.db"
    conn = sqlite3.connect(p)
    conn.execute("CREATE TABLE sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                 "started_at REAL NOT NULL, interface TEXT)")
    conn.commit()
    conn.close()

    from handshaker.db import ResultsDB
    db = ResultsDB(path=p)
    # start + finish should work against the migrated schema.
    sid = db.start_session("wlan0", env='{"x":1}')
    db.finish_session(sid, "ok")
    cols = {r[1] for r in db._connect().execute("PRAGMA table_info(sessions)")}
    assert {"ended_at", "status", "env"} <= cols


def test_finish_session_records_status(tmp_path):
    from handshaker.db import ResultsDB
    db = ResultsDB(path=tmp_path / "r.db")
    sid = db.start_session("wlan0")
    db.finish_session(sid, "interrupted")
    row = db._connect().execute(
        "SELECT status, ended_at FROM sessions WHERE id=?", (sid,)).fetchone()
    assert row[0] == "interrupted"
    assert row[1] is not None


# --------------------------------------------------------------------------- #
# Quarantine retains (not deletes) rejected captures (#19)
# --------------------------------------------------------------------------- #
def test_quarantine_retains_file(monkeypatch, tmp_path):
    from handshaker.config import load_config
    from handshaker.core.engine import Engine

    from handshaker import constants
    e = Engine(load_config())
    monkeypatch.setattr(constants, "QUARANTINE_DIR", tmp_path / "q")
    (tmp_path / "q").mkdir(parents=True, exist_ok=True)

    cap = tmp_path / "bad.pcapng"
    cap.write_bytes(b"\x00" * 64)

    # Force a failing verify.
    class R:
        passed = False
        reason = "no handshake"
    monkeypatch.setattr(e.verifier, "verify_file", lambda f: R())

    e.enforce_verification(str(cap))
    # The file was moved to quarantine and RETAINED (not deleted).
    assert (tmp_path / "q" / "bad.pcapng").exists()
    assert not cap.exists()
