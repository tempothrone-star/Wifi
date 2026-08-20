"""Tests for the precision/timing/strategy/learning upgrades: handshake-quality
score, graded reward, adaptive wait, round budget, engine-choice learning, and
adaptive scan. Pure logic — no hardware or tools required."""

from __future__ import annotations

from handshaker.core.verifier import (
    EapolFrame,
    HandshakeEvidence,
    _classify_message,
    handshake_quality,
)
from handshaker.learning.model import graded_reward
from handshaker.learning.state import ActionKey, LearningStore

ANONCE = "a" * 64
SNONCE = "b" * 64
MIC = "c" * 32
BSSID = "aa:bb:cc:dd:ee:ff"
AP = BSSID
STA = "00:11:22:33:44:55"


def _frame(src, *, ack=False, install=False, mic=False, nonce="", msg=None, rc=1, num=1):
    f = EapolFrame(frame_number=num, bssid=BSSID, src=src, dst=STA if src == AP else AP,
                   key_info="0x0", has_ack=ack, has_install=install,
                   has_mic=bool(mic), mic=(MIC if mic else ""), nonce=nonce,
                   msgnr=msg, replay_counter=rc)
    f.message = _classify_message(f) if msg is None else msg
    return f


def _evidence(frames):
    ev = HandshakeEvidence(bssid=BSSID)
    ev.frames = list(frames)
    ev.messages = {f.message for f in frames}
    return ev


def _full_handshake():
    return _evidence([
        _frame(AP, ack=True, nonce=ANONCE, msg=1, num=1),
        _frame(STA, mic=True, nonce=SNONCE, msg=2, num=2),
        _frame(AP, ack=True, install=True, mic=True, nonce=ANONCE, msg=3, num=3),
        _frame(STA, mic=True, nonce="", msg=4, num=4),
    ])


# --------------------------------------------------------------------------- #
# Handshake-quality score
# --------------------------------------------------------------------------- #
def test_quality_full_handshake_high():
    q = handshake_quality(_full_handshake())
    assert q >= 0.9, q


def test_quality_crackable_pair_mid():
    ev = _evidence([
        _frame(STA, mic=True, nonce=SNONCE, msg=2, num=2),
        _frame(AP, ack=True, install=True, mic=True, nonce=ANONCE, msg=3, num=3),
    ])
    q = handshake_quality(ev)
    assert 0.4 <= q < 0.9, q


def test_quality_empty_zero():
    assert handshake_quality(HandshakeEvidence(bssid=BSSID)) == 0.0


def test_quality_retransmit_penalized():
    # A noisy full handshake with duplicate M2 should score lower than a clean one.
    clean = _full_handshake()
    noisy_frames = list(clean.frames) + [_frame(STA, mic=True, nonce=SNONCE, msg=2, num=5)]
    noisy = _evidence(noisy_frames)
    assert handshake_quality(clean) > handshake_quality(noisy)


def test_quality_nonce_consistency_bonus():
    # M1 and M3 share the same ANonce -> gets the nonce-consistency bonus.
    ev = _full_handshake()
    ev_bad_nonce = _evidence([
        _frame(AP, ack=True, nonce="d" * 64, msg=1, num=1),   # different ANonce
        _frame(STA, mic=True, nonce=SNONCE, msg=2, num=2),
        _frame(AP, ack=True, install=True, mic=True, nonce="e" * 64, msg=3, num=3),
        _frame(STA, mic=True, nonce="", msg=4, num=4),
    ])
    assert handshake_quality(ev) > handshake_quality(ev_bad_nonce)


# --------------------------------------------------------------------------- #
# Graded reward
# --------------------------------------------------------------------------- #
def test_reward_full_success_high():
    r = graded_reward(quality=1.0, rounds_taken=1, deauth_frames=0, success=True)
    assert r >= 0.95, r


def test_reward_failure_zero():
    assert graded_reward(quality=0.0, rounds_taken=3, deauth_frames=50, success=False) == 0.0


def test_reward_crackable_pair_partial():
    # A crackable pair (quality 0.5) without full success earns partial credit.
    r = graded_reward(quality=0.5, rounds_taken=3, deauth_frames=50, success=False)
    assert 0.0 < r < 0.6, r


def test_reward_speed_and_stealth_bonuses():
    fast = graded_reward(quality=0.9, rounds_taken=1, deauth_frames=5, success=True)
    slow = graded_reward(quality=0.9, rounds_taken=4, deauth_frames=100, success=True)
    assert fast > slow


def test_reward_bounded_one():
    assert graded_reward(quality=1.0, rounds_taken=1, deauth_frames=0, success=True) <= 1.0


# --------------------------------------------------------------------------- #
# Adaptive wait + round budget (engine)
# --------------------------------------------------------------------------- #
def test_round_budget_cold_ap_default(monkeypatch):
    from handshaker.config import load_config
    from handshaker.core.engine import Engine
    from handshaker.core.scanner import AccessPoint

    e = Engine(load_config())
    ap = AccessPoint(bssid=BSSID, channel=6)
    assert e._round_budget(ap) == 3  # cold AP -> config default


def test_round_budget_proven_hard_ap(monkeypatch):
    from handshaker.config import load_config
    from handshaker.core.engine import Engine
    from handshaker.core.scanner import AccessPoint

    e = Engine(load_config())
    ap = AccessPoint(bssid=BSSID, channel=6)
    # Record a prior failure -> budget collapses to 1.
    e.store.record(BSSID, ActionKey("mdk4", 10, 7), success=False)
    assert e._round_budget(ap) == 1


def test_round_budget_prior_success_full():
    from handshaker.config import load_config
    from handshaker.core.engine import Engine
    from handshaker.core.scanner import AccessPoint

    e = Engine(load_config())
    ap = AccessPoint(bssid=BSSID, channel=6)
    e.store.record(BSSID, ActionKey("mdk4", 10, 7), success=True)
    assert e._round_budget(ap) == 3


def test_adaptive_wait_learned(monkeypatch):
    from handshaker.config import load_config
    from handshaker.core.engine import Engine
    from handshaker.core.scanner import AccessPoint

    e = Engine(load_config())
    ap = AccessPoint(bssid=BSSID, channel=6)
    # No latency -> default 2s.
    assert e._adaptive_wait(ap) == 2.0
    # Learned 5s -> ~5*1.5+1 = 8.5s.
    e.store.record_latency(BSSID, 5.0)
    assert 8.0 <= e._adaptive_wait(ap) <= 9.0


def test_adaptive_wait_bounded():
    from handshaker.config import load_config
    from handshaker.core.engine import Engine
    from handshaker.core.scanner import AccessPoint

    e = Engine(load_config())
    ap = AccessPoint(bssid=BSSID, channel=6)
    e.store.record_latency(BSSID, 100.0)  # absurd latency -> clamped
    assert e._adaptive_wait(ap) <= 15.0


# --------------------------------------------------------------------------- #
# Latency + engine-choice learning (store)
# --------------------------------------------------------------------------- #
def test_latency_record_and_read(tmp_path):
    store = LearningStore(path=tmp_path / "s.json", decay=1.0)
    assert store.latency_seconds(BSSID) is None
    store.record_latency(BSSID, 4.0)
    store.record_latency(BSSID, 6.0)
    assert abs(store.latency_seconds(BSSID) - 5.0) < 1e-6


def test_latency_clamped():
    store = LearningStore(path=None, decay=1.0)
    store.record_latency(BSSID, 9999.0)
    assert store.latency_seconds(BSSID) == 60.0  # clamped to max


def test_engine_success_learning(tmp_path):
    store = LearningStore(path=tmp_path / "s.json", decay=1.0)
    store.record_capture_engine(BSSID, "hcxdumptool", True)
    store.record_capture_engine(BSSID, "hcxdumptool", False)
    store.record_capture_engine(BSSID, "airodump", True)
    h = store.engine_success(BSSID, "hcxdumptool")
    a = store.engine_success(BSSID, "airodump")
    assert h["trials"] == 2 and h["wins"] == 1 and h["rate"] == 0.5
    assert a["rate"] == 1.0


# --------------------------------------------------------------------------- #
# Graded reward feeds the bandit (fractional wins)
# --------------------------------------------------------------------------- #
def test_bandit_uses_graded_reward(tmp_path):
    store = LearningStore(path=tmp_path / "s.json", decay=1.0)
    a = ActionKey("mdk4", 10, 7)
    # A crackable pair (partial) is recorded with a fractional reward.
    store.record(BSSID, a, success=False, reward=0.35)
    stats = store.action_stats(BSSID)[a.id]
    assert stats["wins"] == 0.35   # fractional win, not a flat 0
    assert stats["trials"] == 1.0
