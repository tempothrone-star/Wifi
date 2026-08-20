"""Unit tests for the pure-logic parts of the verifier and policy.

These tests exercise the classification and decision logic *without* requiring
Kali tools or root, so the anti-hallucination guarantees are provable in CI.
"""

from __future__ import annotations

from handshaker.core.verifier import EapolFrame, _classify_message
from handshaker.learning.model import ActionPolicy
from handshaker.learning.state import ActionKey, LearningStore


def _frame(*, ack: bool, install: bool, mic: bool, nonce: str, msgnr=None) -> EapolFrame:
    return EapolFrame(
        frame_number=1,
        bssid="aa:bb:cc:dd:ee:ff",
        src="00:11:22:33:44:55",
        dst="aa:bb:cc:dd:ee:ff",
        key_info="0x0000",
        has_ack=ack,
        has_install=install,
        has_mic=mic,
        mic=("c" * 32) if mic else "",
        nonce=nonce,
        msgnr=msgnr,
        replay_counter=1,
    )


def test_classify_four_messages():
    assert _classify_message(_frame(ack=True, install=False, mic=False, nonce="a" * 64)) == 1
    assert _classify_message(_frame(ack=False, install=False, mic=True, nonce="b" * 64)) == 2
    assert _classify_message(_frame(ack=True, install=True, mic=True, nonce="c" * 64)) == 3
    assert _classify_message(_frame(ack=False, install=False, mic=True, nonce="")) == 4


def test_m2_m4_distinguished_by_nonce():
    # Same ACK/Install/MIC flags — only the nonce decides between M2 and M4.
    assert _classify_message(_frame(ack=False, install=False, mic=True, nonce="b" * 64)) == 2
    assert _classify_message(_frame(ack=False, install=False, mic=True, nonce="")) == 4


def test_unclassified_ambiguous_frame():
    # No ACK, no MIC -> not a handshake message.
    assert _classify_message(_frame(ack=False, install=False, mic=False, nonce="")) == 0
    # ACK + MIC but no Install -> ambiguous (not a canonical M1-M4).
    assert _classify_message(_frame(ack=True, install=False, mic=True, nonce="")) == 0


# --------------------------------------------------------------------------- #
# Policy tests
# --------------------------------------------------------------------------- #

def _store(tmp_path) -> LearningStore:
    return LearningStore(path=tmp_path / "state.json", decay=1.0)


def test_policy_requires_observations_before_exploiting(tmp_path):
    store = _store(tmp_path)
    policy = ActionPolicy(store, exploration=0.0, min_observations=3, seed=1)
    actions = [ActionKey("mdk4", 10, 7), ActionKey("aireplay-ng", 10, 7)]
    # No observations -> must explore (uniform) regardless of exploration=0.
    decision = policy.choose("aa:bb:cc:dd:ee:ff", actions)
    assert decision.exploration is True


def test_policy_exploits_best_action(tmp_path):
    store = _store(tmp_path)
    bssid = "aa:bb:cc:dd:ee:ff"
    good = ActionKey("mdk4", 20, 7)
    bad = ActionKey("aireplay-ng", 5, 7)
    for _ in range(5):
        store.record(bssid, good, success=True)
    for _ in range(5):
        store.record(bssid, bad, success=False)

    policy = ActionPolicy(store, exploration=0.0, min_observations=0, seed=1)
    decision = policy.choose(bssid, [good, bad])
    assert decision.action == good
    assert decision.exploration is False


def test_policy_never_returns_untried_unknown_action(tmp_path):
    store = _store(tmp_path)
    bssid = "aa:bb:cc:dd:ee:ff"
    tried = ActionKey("mdk4", 10, 7)
    store.record(bssid, tried, success=True)

    policy = ActionPolicy(store, exploration=0.0, min_observations=0, seed=1)
    # Only the tried action is a candidate, so it must be selected.
    decision = policy.choose(bssid, [tried])
    assert decision.action == tried


def test_available_actions_only_returns_recorded(tmp_path):
    store = _store(tmp_path)
    bssid = "aa:bb:cc:dd:ee:ff"
    a = ActionKey("mdk4", 10, 7)
    b = ActionKey("mdk4", 20, 7)
    store.record(bssid, a, success=True)
    store.record(bssid, b, success=False)
    store.record(bssid, a, success=True)
    avail = ActionPolicy(store).available_actions(bssid)
    assert set(x.id for x in avail) == {a.id, b.id}
