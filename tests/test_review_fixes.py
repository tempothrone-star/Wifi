"""Tests for the fixes made in response to the independent code review:

* deauth failure-based fallback (not just availability)
* deauth subprocess result inspection (only successful bursts counted)
* capability-aware reason codes (only scapy varies reason)
* injection gate / deauth.enabled / auto_monitor / learning.enabled
* transfer weight scaling in the evidence gate
* exception-safe adapter cleanup
* NIM deauth_tool restricted to real deauth engines
"""

from __future__ import annotations

from handshaker.core.deauth import reason_supported
from handshaker.learning.model import ActionPolicy
from handshaker.learning.state import ActionKey, LearningStore
from handshaker.utils.proc import ProcResult

GOOD = ActionKey("mdk4", 20, 7)
BAD = ActionKey("aireplay-ng", 5, 7)


# --------------------------------------------------------------------------- #
# Capability-aware reason codes
# --------------------------------------------------------------------------- #
def test_reason_supported_only_scapy():
    assert reason_supported("scapy") is True
    assert reason_supported("aireplay-ng") is False
    assert reason_supported("mdk4") is False
    assert reason_supported("bettercap") is False


def test_candidate_actions_vary_reason_only_for_scapy(monkeypatch):
    from handshaker.core.strategist import Strategist
    from handshaker.learning.state import LearningStore

    class R:
        def has(self, n):
            return n in ("mdk4", "aireplay-ng")

    cfg = {"deauth": {"tools": ["mdk4"], "burst_size": 10,
                      "reason_codes": [1, 4, 7]},
           "learning": {"exploration": 0.25, "decay": 0.95,
                        "min_observations": 2, "strategy": "thompson",
                        "transfer": 0.5},
           "targets": {"bssid": [], "exclude": [], "max_targets": 0},
           "capture": {"wpa_only": True}, "scan": {"min_signal": -90},
           "pmkid": {"enabled": True}}
    strat = Strategist(R(), LearningStore(path=None), cfg)
    actions = strat.candidate_actions()
    # mdk4 does NOT honour reason codes -> all actions share reason 7.
    reasons = {a.reason for a in actions}
    assert reasons == {7}, reasons


# --------------------------------------------------------------------------- #
# Deauth: failure-based fallback + result inspection
# --------------------------------------------------------------------------- #
class _FakeRegistry:
    def __init__(self, present):
        self._present = set(present)

    def has(self, name):
        return name in self._present


def test_campaign_failure_falls_back_to_next_engine(monkeypatch):
    from handshaker.core.deauth import Deauther

    reg = _FakeRegistry({"aireplay-ng", "mdk4"})
    cfg = {"deauth": {"max_bursts": 2, "burst_size": 10, "cooldown": 0,
                      "reason_codes": [7], "tools": ["aireplay-ng", "mdk4"]}}
    d = Deauther(reg, cfg)
    calls = []

    def fake_execute(interface, bssid, action, client=None):
        calls.append(action.tool)
        # aireplay-ng always FAILS; mdk4 always succeeds.
        ok = action.tool == "mdk4"
        return ProcResult(args=[action.tool], returncode=0 if ok else 1)

    monkeypatch.setattr(d, "execute", fake_execute)
    results = d.campaign("wlan0", "aa:bb:cc:dd:ee:ff", ActionKey("aireplay-ng", 10, 7),
                         fallback_tools=["aireplay-ng", "mdk4"])
    # aireplay-ng failed -> fell back to mdk4, which succeeded.
    assert "mdk4" in calls
    # Only successful bursts are returned (all from mdk4).
    assert all(r.returncode == 0 for r in results)
    assert len(results) == 2  # mdk4 ran 2 successful bursts


def test_campaign_failed_burst_not_returned(monkeypatch):
    from handshaker.core.deauth import Deauther

    reg = _FakeRegistry({"aireplay-ng"})
    cfg = {"deauth": {"max_bursts": 2, "burst_size": 10, "cooldown": 0,
                      "reason_codes": [7], "tools": ["aireplay-ng"]}}
    d = Deauther(reg, cfg)

    def fake_execute(interface, bssid, action, client=None):
        return ProcResult(args=[action.tool], returncode=1)  # always fails

    monkeypatch.setattr(d, "execute", fake_execute)
    results = d.campaign("wlan0", "aa:bb:cc:dd:ee:ff", ActionKey("aireplay-ng", 10, 7))
    assert results == []  # no successful bursts


# --------------------------------------------------------------------------- #
# learning.enabled is honoured (no-op store)
# --------------------------------------------------------------------------- #
def test_learning_disabled_noops(tmp_path):
    store = LearningStore(path=tmp_path / "s.json", decay=1.0, enabled=False)
    store.record("aa:bb:cc:dd:ee:ff", GOOD, success=True)
    store.record_pmkid("aa:bb:cc:dd:ee:ff", True)
    store.record_latency("aa:bb:cc:dd:ee:ff", 3.0)
    store.record_capture_engine("aa:bb:cc:dd:ee:ff", "hcxdumptool", True)
    assert store.actions_for("aa:bb:cc:dd:ee:ff") == []
    assert store.pmkid_stats("aa:bb:cc:dd:ee:ff")["trials"] == 0.0
    assert store.latency_seconds("aa:bb:cc:dd:ee:ff") is None


# --------------------------------------------------------------------------- #
# Transfer weight scales the evidence gate (#42)
# --------------------------------------------------------------------------- #
def test_transfer_zero_does_not_warm_gate(tmp_path):
    store = LearningStore(path=tmp_path / "s.json", decay=1.0)
    store.ensure_ap("aa:bb:cc:dd:ee:ff", security="WPA2", band="5GHz", vendor="001122")
    for _ in range(5):
        store.record("aa:bb:cc:dd:ee:ff", GOOD, success=True)
    store.ensure_ap("11:22:33:44:55:66", security="WPA2", band="5GHz", vendor="001122")

    # transfer=0 -> borrowed evidence does NOT warm the gate -> cold explore.
    p = ActionPolicy(store, exploration=0.0, min_observations=1, transfer=0.0, seed=1)
    assert p.choose("11:22:33:44:55:66", [GOOD, BAD]).exploration is True

    # transfer=1 -> borrowed evidence DOES warm the gate -> exploit.
    p2 = ActionPolicy(store, exploration=0.0, min_observations=1, transfer=1.0, seed=1)
    assert p2.choose("11:22:33:44:55:66", [GOOD, BAD]).exploration is False


# --------------------------------------------------------------------------- #
# NIM deauth_tool restricted to real engines (#15)
# --------------------------------------------------------------------------- #
def test_nim_deauth_tool_not_in_chain_is_ignored(monkeypatch, tmp_path):
    """NIM's deauth_tool is honoured only when it is a REAL deauth engine
    (hcxdumptool is not one and must be ignored)."""
    from handshaker.config import load_config
    from handshaker.core.engine import Engine

    e = Engine(load_config())
    # In the sandbox no deauth tools are installed, so the valid set is empty
    # and hcxdumptool is certainly not in it.
    valid = set(e.strategist.available_deauth_tools())
    assert "hcxdumptool" not in valid

    # Simulate an installed mdk4 + a NIM hint suggesting hcxdumptool: the
    # action must keep its original (valid) tool, not become hcxdumptool.
    from handshaker.nim.client import StrategySuggestion
    from handshaker.learning.state import ActionKey
    from handshaker.core.scanner import AccessPoint, ScanResult

    monkeypatch.setattr(e.strategist, "available_deauth_tools", lambda: ["mdk4"])
    monkeypatch.setattr(e.registry, "has", lambda n: n == "mdk4")

    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6, privacy="WPA2",
                     auth="PSK", power=-40, essid="Net")
    scan = ScanResult(aps={"aa:bb:cc:dd:ee:ff": ap}, clients={})
    candidates = [ActionKey("mdk4", 10, 7)]
    nim_hint = StrategySuggestion(deauth_tool="hcxdumptool")  # invalid

    # Monkeypatch the heavy downstream calls.
    captured = {}
    def fake_capture_handshake(mon, ap, action, scan, stats, sid):
        captured["tool"] = action.tool
    monkeypatch.setattr(e, "_capture_handshake", fake_capture_handshake)
    monkeypatch.setattr(e, "_try_pmkid", lambda *a, **k: False)

    # Force choose_action to return a decision whose action is mdk4.
    class D:
        action = ActionKey("mdk4", 10, 7)
        reason = "x"
    monkeypatch.setattr(e.strategist, "choose_action", lambda *a, **k: D())
    monkeypatch.setattr(e.db, "record_target", lambda *a, **k: None)

    e._process_target("wlan0mon", ap, scan, candidates, nim_hint, _mk_stats(), 1)

    # The deauth tool stays mdk4; hcxdumptool was ignored.
    assert captured["tool"] == "mdk4"


def _mk_stats():
    from handshaker.core.engine import RunStats
    return RunStats()


# --------------------------------------------------------------------------- #
# Bandit tool choice is now authoritative (the learned tool is tried FIRST)
# --------------------------------------------------------------------------- #
def test_campaign_tries_chosen_tool_first(monkeypatch):
    from handshaker.core.deauth import Deauther
    from handshaker.learning.state import ActionKey

    reg = _FakeRegistry({"scapy", "mdk4", "aireplay-ng"})  # all available
    cfg = {"deauth": {"max_bursts": 1, "burst_size": 10, "cooldown": 0,
                      "reason_codes": [7], "tools": ["scapy", "mdk4", "aireplay-ng"]}}
    d = Deauther(reg, cfg)
    order = []

    def fake_execute(interface, bssid, action, client=None):
        order.append(action.tool)
        return ProcResult(args=[action.tool], returncode=0)

    monkeypatch.setattr(d, "execute", fake_execute)
    # The bandit chose "mdk4"; the full chain is provided as fallback.
    d.campaign("wlan0", "aa:bb:cc:dd:ee:ff", ActionKey("mdk4", 10, 7),
               fallback_tools=["scapy", "mdk4", "aireplay-ng"])
    # mdk4 (the chosen tool) must be tried FIRST, not scapy (chain head).
    assert order[0] == "mdk4", order
