"""Regression tests for the 1.6.1 bugfix pass.

Covers MAC parsing, filename sanitisation, in-memory learning store,
transfer-learning self-exclusion, process shutdown, config validation,
and NIM deauth-tool restriction. Pure logic — no hardware required.
"""

from __future__ import annotations

from handshaker.learning.model import ActionPolicy
from handshaker.learning.state import ActionKey, LearningStore
from handshaker.nim.client import NimClient
from handshaker.utils.validation import parse_mac, sanitize_filename

GOOD = ActionKey("mdk4", 20, 7)
BAD = ActionKey("aireplay-ng", 5, 7)


# --------------------------------------------------------------------------- #
# parse_mac: documented forms actually work
# --------------------------------------------------------------------------- #
def test_parse_mac_colon_and_dash():
    assert parse_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert parse_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"


def test_parse_mac_no_separators():
    assert parse_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"


def test_parse_mac_cisco_dotted():
    assert parse_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"


def test_parse_mac_garbage_is_none():
    assert parse_mac("") is None
    assert parse_mac("not-a-mac") is None
    assert parse_mac("aabbccddee") is None  # 10 hex chars


# --------------------------------------------------------------------------- #
# ESSID filename sanitisation (path traversal)
# --------------------------------------------------------------------------- #
def test_sanitize_filename_strips_path_chars():
    assert ".." not in sanitize_filename("../etc/passwd")
    assert "/" not in sanitize_filename("a/b/c")
    assert sanitize_filename("Home Network") == "Home_Network"


def test_sanitize_filename_empty_fallback():
    assert sanitize_filename("") == "target"
    assert sanitize_filename("///") == "target"


# --------------------------------------------------------------------------- #
# LearningStore(path=None) is in-memory (does not touch the default file)
# --------------------------------------------------------------------------- #
def test_learning_store_none_is_memory_only(tmp_path, monkeypatch):
    store = LearningStore(path=None, decay=1.0)
    store.record("aa:bb:cc:dd:ee:ff", GOOD, success=True)
    store.save()  # must be a no-op
    assert store.actions_for("aa:bb:cc:dd:ee:ff")


# --------------------------------------------------------------------------- #
# Transfer learning does not double-count the current AP
# --------------------------------------------------------------------------- #
def test_transfer_excludes_self_from_context(tmp_path):
    store = LearningStore(path=tmp_path / "s.json", decay=1.0)
    store.ensure_ap("aa:bb:cc:dd:ee:ff", security="WPA2", band="5GHz", vendor="001122")
    store.record("aa:bb:cc:dd:ee:ff", GOOD, success=True)

    # Context aggregate WITH self included would be 1; excluding self is 0.
    ctx = store.context_key("aa:bb:cc:dd:ee:ff")
    with_self = store.context_action_stats(ctx)
    without = store.context_action_stats(ctx, exclude_bssid="aa:bb:cc:dd:ee:ff")
    assert with_self[GOOD.id]["trials"] == 1.0
    assert without == {}


def test_similar_ap_still_transfers(tmp_path):
    store = LearningStore(path=tmp_path / "s.json", decay=1.0)
    store.ensure_ap("aa:bb:cc:dd:ee:ff", security="WPA2", band="5GHz", vendor="001122")
    for _ in range(5):
        store.record("aa:bb:cc:dd:ee:ff", GOOD, success=True)
        store.record("aa:bb:cc:dd:ee:ff", BAD, success=False)
    store.ensure_ap("11:22:33:44:55:66", security="WPA2", band="5GHz", vendor="001122")

    p = ActionPolicy(store, exploration=0.0, min_observations=0, transfer=1.0, seed=1)
    decision = p.choose("11:22:33:44:55:66", [GOOD, BAD])
    assert decision.action == GOOD
    assert decision.exploration is False


# --------------------------------------------------------------------------- #
# NIM parser no longer accepts hcxdumptool as a deauth engine
# --------------------------------------------------------------------------- #
def test_nim_parse_rejects_hcxdumptool_as_deauth_tool():
    sug = NimClient._parse('{"deauth_tool": "hcxdumptool"}')
    assert sug.deauth_tool is None
    assert any("hcxdumptool" in r for r in sug.rejected)


def test_nim_parse_accepts_scapy():
    sug = NimClient._parse('{"deauth_tool": "scapy", "burst_size": 8}')
    assert sug.deauth_tool == "scapy"
    assert sug.burst_size == 8


# --------------------------------------------------------------------------- #
# Config validation: transfer in [0, 1]
# --------------------------------------------------------------------------- #
def test_config_rejects_bad_transfer(tmp_path):
    from handshaker.config import load_config
    from handshaker.exceptions import ConfigError
    import pytest

    p = tmp_path / "c.yaml"
    p.write_text("learning:\n  transfer: 2.0\n")
    with pytest.raises(ConfigError):
        load_config(p)


# --------------------------------------------------------------------------- #
# Version is consistent
# --------------------------------------------------------------------------- #
def test_version_matches_pyproject():
    from handshaker import __version__
    import pathlib
    text = pathlib.Path("pyproject.toml").read_text()
    assert f'version = "{__version__}"' in text


# --------------------------------------------------------------------------- #
# Process helper: timeout uses graceful stop, not an undefined Timer
# --------------------------------------------------------------------------- #
def test_run_timeout_graceful(tmp_path):
    from handshaker.utils.proc import run
    res = run(["sleep", "5"], timeout=0.2, check=False)
    assert res.timed_out is True
    assert res.ok is False


def test_find_tool_rejects_missing_absolute(tmp_path):
    from handshaker.exceptions import ToolNotFoundError
    from handshaker.utils.proc import find_tool
    import pytest
    with pytest.raises(ToolNotFoundError):
        find_tool("nope", override=str(tmp_path / "not-a-binary"))
