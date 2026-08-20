"""Tests for the self-test and report/export modules (pure logic)."""

from __future__ import annotations

from handshaker.core.selftest import SelfTestReport, Step


def test_selftest_report_pass_logic():
    rep = SelfTestReport()
    rep.add("a", True, "ok")
    rep.add("b", True, "ok")
    assert rep.passed is True


def test_selftest_report_fail_logic():
    rep = SelfTestReport()
    rep.add("a", True, "ok")
    rep.add("b", False, "boom")
    assert rep.passed is False


def test_selftest_skipped_does_not_fail():
    rep = SelfTestReport()
    rep.add("a", True, "ok")
    rep.add("b", False, "", skipped=True)
    assert rep.passed is True  # skipped steps don't fail the run


def test_selftest_to_dict():
    rep = SelfTestReport()
    rep.add("root", True, "ok")
    d = rep.to_dict()
    assert d["passed"] is True
    assert d["steps"][0]["status"] == "PASS"


def test_step_status():
    assert Step("x", True).status == "PASS"
    assert Step("x", False).status == "FAIL"
    assert Step("x", False, skipped=True).status == "SKIPPED"


def test_report_build_empty(tmp_path):
    """Report builds with no artifacts present (fresh project)."""
    from handshaker.core.report import build_report
    from handshaker.db import ResultsDB
    from handshaker.learning.state import LearningStore

    store = LearningStore(path=tmp_path / "state.json", decay=1.0)
    db = ResultsDB(path=tmp_path / "results.db")
    rep = build_report(store, db, wps_path=tmp_path / "wps.json")
    d = rep.to_dict()
    assert d["handshakes"] == []
    assert d["sessions"] == 0
    assert d["verified_captures"] == 0


def test_report_reflects_learning(tmp_path):
    from handshaker.core.report import build_report
    from handshaker.db import ResultsDB
    from handshaker.learning.state import ActionKey, LearningStore

    store = LearningStore(path=tmp_path / "state.json", decay=1.0)
    store.ensure_ap("aa:bb:cc:dd:ee:ff", essid="Home", security="WPA2", band="5GHz")
    store.record("aa:bb:cc:dd:ee:ff", ActionKey("mdk4", 10, 7), True)
    store.record_pmkid("aa:bb:cc:dd:ee:ff", True)
    db = ResultsDB(path=tmp_path / "results.db")
    rep = build_report(store, db, wps_path=tmp_path / "wps.json")
    assert len(rep.learned_aps) == 1
    ap = rep.learned_aps[0]
    assert ap["essid"] == "Home"
    assert ap["handshake_actions"] == 1
    assert ap["pmkid_rate"] == 1.0
