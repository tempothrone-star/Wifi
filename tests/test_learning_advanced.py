"""Tests for the advanced learning engine: Thompson sampling, UCB1, and
cross-AP contextual transfer. Pure logic — no tools or hardware."""

from __future__ import annotations

from handshaker.learning.model import ActionPolicy
from handshaker.learning.state import ActionKey, LearningStore


def _store(tmp_path) -> LearningStore:
    return LearningStore(path=tmp_path / "state.json", decay=1.0)


GOOD = ActionKey("mdk4", 20, 7)
BAD = ActionKey("aireplay-ng", 5, 7)


def _seed_policy(store, **kw):
    kw.setdefault("seed", 1)
    return ActionPolicy(store, **kw)


# --------------------------------------------------------------------------- #
# Deterministic exploit still works (regression)
# --------------------------------------------------------------------------- #
def test_exploit_picks_highest_mean(tmp_path):
    store = _store(tmp_path)
    bssid = "aa:bb:cc:dd:ee:ff"
    for _ in range(5):
        store.record(bssid, GOOD, success=True)
    for _ in range(5):
        store.record(bssid, BAD, success=False)

    p = _seed_policy(store, exploration=0.0, min_observations=0)
    decision = p.choose(bssid, [GOOD, BAD])
    assert decision.action == GOOD
    assert decision.exploration is False


def test_min_observations_gate_explores(tmp_path):
    store = _store(tmp_path)
    p = _seed_policy(store, exploration=0.0, min_observations=5)
    decision = p.choose("aa:bb:cc:dd:ee:ff", [GOOD, BAD])
    assert decision.exploration is True


# --------------------------------------------------------------------------- #
# Thompson sampling is uncertainty-driven (explores untried actions)
# --------------------------------------------------------------------------- #
def test_thompson_explores_when_told(tmp_path):
    store = _store(tmp_path)
    bssid = "aa:bb:cc:dd:ee:ff"
    store.record(bssid, GOOD, success=True)  # only GOOD has data
    p = _seed_policy(store, exploration=1.0, min_observations=0, strategy="thompson")
    # Force exploration every time; the untried BAD has a wide posterior and
    # should be sampled at least sometimes across many trials.
    picks = [p.choose(bssid, [GOOD, BAD]).action.id for _ in range(200)]
    assert GOOD.id in picks and BAD.id in picks


def test_thompson_never_returns_untried_when_only_candidate(tmp_path):
    store = _store(tmp_path)
    bssid = "aa:bb:cc:dd:ee:ff"
    p = _seed_policy(store, exploration=1.0, min_observations=0, strategy="thompson")
    decision = p.choose(bssid, [GOOD])
    assert decision.action == GOOD


# --------------------------------------------------------------------------- #
# UCB1 strategy
# --------------------------------------------------------------------------- #
def test_ucb_explores_untried(tmp_path):
    store = _store(tmp_path)
    bssid = "aa:bb:cc:dd:ee:ff"
    store.record(bssid, GOOD, success=True)
    p = _seed_policy(store, exploration=1.0, min_observations=0, strategy="ucb")
    # UCB gives untried actions a large exploration bonus.
    decision = p.choose(bssid, [GOOD, BAD])
    assert decision.exploration is True


# --------------------------------------------------------------------------- #
# Cross-AP contextual transfer learning
# --------------------------------------------------------------------------- #
def test_transfer_priors_from_similar_ap(tmp_path):
    store = _store(tmp_path)
    # AP "A" (WPA2, 5GHz, OUI 001122) learned that GOOD works.
    store.ensure_ap("aa:bb:cc:dd:ee:ff", security="WPA2", band="5GHz", vendor="001122")
    for _ in range(5):
        store.record("aa:bb:cc:dd:ee:ff", GOOD, success=True)
    for _ in range(5):
        store.record("aa:bb:cc:dd:ee:ff", BAD, success=False)

    # AP "B" has the SAME context but zero of its own observations.
    store.ensure_ap("11:22:33:44:55:66", security="WPA2", band="5GHz", vendor="001122")

    # With transfer, B should inherit A's evidence and prefer GOOD.
    p = _seed_policy(store, exploration=0.0, min_observations=0, transfer=1.0)
    decision = p.choose("11:22:33:44:55:66", [GOOD, BAD])
    assert decision.action == GOOD
    assert decision.exploration is False


def test_no_transfer_starts_cold(tmp_path):
    store = _store(tmp_path)
    store.ensure_ap("aa:bb:cc:dd:ee:ff", security="WPA2", band="5GHz", vendor="001122")
    for _ in range(5):
        store.record("aa:bb:cc:dd:ee:ff", GOOD, success=True)

    store.ensure_ap("11:22:33:44:55:66", security="WPA2", band="5GHz", vendor="001122")
    # transfer=0 -> B does not inherit A's evidence; with min_observations>0 it
    # must explore (honest cold start).
    p = _seed_policy(store, exploration=0.0, min_observations=1, transfer=0.0)
    decision = p.choose("11:22:33:44:55:66", [GOOD, BAD])
    assert decision.exploration is True


def test_context_key_consistency(tmp_path):
    store = _store(tmp_path)
    store.ensure_ap("aa:bb:cc:dd:ee:ff", security="WPA2", band="5GHz", vendor="001122")
    store.ensure_ap("11:22:33:44:55:66", security="WPA2", band="5GHz", vendor="001122")
    store.ensure_ap("ff:ee:dd:cc:bb:aa", security="WPA3", band="2.4GHz", vendor="001122")
    assert store.context_key("aa:bb:cc:dd:ee:ff") == store.context_key("11:22:33:44:55:66")
    assert store.context_key("aa:bb:cc:dd:ee:ff") != store.context_key("ff:ee:dd:cc:bb:aa")


def test_context_action_stats_aggregates(tmp_path):
    store = _store(tmp_path)
    for b in ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"):
        store.ensure_ap(b, security="WPA2", band="5GHz", vendor="001122")
        store.record(b, GOOD, success=True)
    ctx = store.context_key("aa:bb:cc:dd:ee:ff")
    agg = store.context_action_stats(ctx)
    assert agg[GOOD.id]["wins"] == 2.0


# --------------------------------------------------------------------------- #
# scoreboard reporting
# --------------------------------------------------------------------------- #
def test_scoreboard_orders_by_mean(tmp_path):
    store = _store(tmp_path)
    bssid = "aa:bb:cc:dd:ee:ff"
    for _ in range(5):
        store.record(bssid, GOOD, success=True)
    for _ in range(5):
        store.record(bssid, BAD, success=False)
    p = _seed_policy(store, exploration=0.0, min_observations=0)
    board = p.scoreboard(bssid, [GOOD, BAD])
    assert board[0][0] == GOOD
    assert board[0][1] > board[1][1]
