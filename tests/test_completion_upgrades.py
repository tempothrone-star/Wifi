"""Tests for the completion upgrades: enterprise classification, frequency
precision, learned engine choice, and result export. Pure logic — no hardware."""

from __future__ import annotations

from handshaker.core.scanner import AccessPoint, channel_to_frequency


# --------------------------------------------------------------------------- #
# Enterprise (802.1X/MGT) classification
# --------------------------------------------------------------------------- #
def test_enterprise_detected_via_mgt():
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", privacy="WPA2", auth="MGT")
    assert ap.is_enterprise is True
    assert ap.security_label == "WPA2-Enterprise"


def test_enterprise_detected_via_8021x():
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", privacy="WPA2", auth="PSK",
                     cipher="CCMP 802.1X")
    assert ap.is_enterprise is True


def test_psk_not_enterprise():
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", privacy="WPA2", auth="PSK")
    assert ap.is_enterprise is False


def test_wpa3_enterprise_label():
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", privacy="WPA3", auth="MGT")
    assert ap.security_label == "WPA3-Enterprise"


def test_strategist_skips_enterprise():
    from handshaker.core.scanner import ScanResult
    from handshaker.core.strategist import Strategist
    from handshaker.learning.state import LearningStore
    from handshaker.tools.registry import ToolRegistry

    ent = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", privacy="WPA2", auth="MGT",
                      channel=6, power=-40, essid="Corp")
    psk = AccessPoint(bssid="11:22:33:44:55:66", privacy="WPA2", auth="PSK",
                      channel=6, power=-40, essid="Home")
    scan = ScanResult(aps={"aa:bb:cc:dd:ee:ff": ent, "11:22:33:44:55:66": psk},
                      clients={})
    cfg = {"targets": {"bssid": [], "exclude": [], "max_targets": 0},
           "capture": {"wpa_only": True}, "scan": {"min_signal": -90},
           "deauth": {"tools": []}, "pmkid": {"enabled": True},
           "learning": {"exploration": 0.25, "decay": 0.95, "min_observations": 2}}
    strat = Strategist(ToolRegistry(), LearningStore(path=None), cfg)
    targets = strat.prioritize(scan)
    # Enterprise AP excluded; only the PSK AP remains a target.
    assert [t.bssid for t in targets] == ["11:22:33:44:55:66"]


# --------------------------------------------------------------------------- #
# Frequency precision
# --------------------------------------------------------------------------- #
def test_channel_to_frequency_2g():
    assert channel_to_frequency(1) == 2412
    assert channel_to_frequency(6) == 2437
    assert channel_to_frequency(11) == 2462
    assert channel_to_frequency(14) == 2484


def test_channel_to_frequency_5g():
    assert channel_to_frequency(36) == 5180
    assert channel_to_frequency(149) == 5745
    assert channel_to_frequency(165) == 5825


def test_channel_to_frequency_unknown():
    assert channel_to_frequency(0) is None
    assert channel_to_frequency(200) is None  # 6 GHz (ambiguous from channel alone)


def test_ap_frequency_property():
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    assert ap.frequency == 2437
    ap5 = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=36)
    assert ap5.frequency == 5180


# --------------------------------------------------------------------------- #
# Learned engine choice
# --------------------------------------------------------------------------- #
def test_prefer_engine_default_none(tmp_path):
    from handshaker.config import load_config
    from handshaker.core.engine import Engine
    from handshaker.core.scanner import AccessPoint

    e = Engine(load_config())
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    assert e._prefer_engine(ap) is None  # no learning -> default


def test_prefer_engine_hcx_consistently_fails(tmp_path):
    from handshaker.config import load_config
    from handshaker.core.engine import Engine
    from handshaker.core.scanner import AccessPoint

    e = Engine(load_config())
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    for _ in range(3):
        e.store.record_capture_engine(ap.bssid, "hcxdumptool", False)
    # hcxdumptool failed 3x -> prefer airodump.
    assert e._prefer_engine(ap) == "airodump"


def test_prefer_engine_learns_better_engine(tmp_path):
    from handshaker.config import load_config
    from handshaker.core.engine import Engine
    from handshaker.core.scanner import AccessPoint

    e = Engine(load_config())
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    for _ in range(3):
        e.store.record_capture_engine(ap.bssid, "hcxdumptool", False)
        e.store.record_capture_engine(ap.bssid, "airodump", True)
    # airodump clearly better -> preferred.
    assert e._prefer_engine(ap) == "airodump"


# --------------------------------------------------------------------------- #
# Result export bundle
# --------------------------------------------------------------------------- #
def test_bundle_results(tmp_path):
    from handshaker import constants
    import handshaker.core.report as report_mod
    from handshaker.db import ResultsDB
    from handshaker.learning.state import LearningStore

    orig_hs, orig_pm, orig_ls = (
        constants.HANDSHAKES_DIR, constants.PMKID_DIR, constants.LEARNING_DIR,
    )
    import pathlib
    constants.HANDSHAKES_DIR = pathlib.Path(tmp_path / "hs")
    constants.PMKID_DIR = pathlib.Path(tmp_path / "pm")
    constants.LEARNING_DIR = pathlib.Path(tmp_path / "learning")
    constants.HANDSHAKES_DIR.mkdir(parents=True, exist_ok=True)
    constants.PMKID_DIR.mkdir(parents=True, exist_ok=True)
    constants.LEARNING_DIR.mkdir(parents=True, exist_ok=True)
    (constants.HANDSHAKES_DIR / "net1.pcapng").write_bytes(b"\x00" * 8)
    (constants.PMKID_DIR / "net1.22000").write_text("WPA*01*...\n")
    try:
        store = LearningStore(path=constants.LEARNING_DIR / "state.json", decay=1.0)
        db = ResultsDB(path=constants.LEARNING_DIR / "results.db")
        out = tmp_path / "out"
        bundle = report_mod.bundle_results(store, db, out_dir=out,
                                           wps_path=constants.LEARNING_DIR / "wps.json")
        assert bundle.exists()
        assert (bundle / "handshakes" / "net1.pcapng").exists()
        assert (bundle / "pmkid" / "net1.22000").exists()
        assert (bundle / "report.json").exists()
        import json
        rep = json.loads((bundle / "report.json").read_text())
        assert "handshakes" in rep
    finally:
        constants.HANDSHAKES_DIR = orig_hs
        constants.PMKID_DIR = orig_pm
        constants.LEARNING_DIR = orig_ls
