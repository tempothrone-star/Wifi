"""Tests for WPS assessment parsing and verdict logic."""

from __future__ import annotations

from handshaker.core.wps import (
    VULNERABLE_DEFAULT,
    VULNERABLE_PIXIE,
    WpsAp,
    WpsHistory,
    WpsStrategist,
    WpsVerdict,
    parse_wash,
    parse_wps_pin,
)
from handshaker.utils.proc import ProcResult

WASH_SAMPLE = """BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
E0:3F:49:6A:57:78    6  -73  1.0  No   Unknown   ASUS
C8:3A:35:2B:11:09   11  -55  2.0  Yes  Broadcom  HomeWiFi
00:11:22:33:44:55    1  -40  1.0  No   Ralink    My Network Name
"""


def _proc(stdout="", stderr="", rc=0):
    return ProcResult(args=["x"], returncode=rc, stdout=stdout, stderr=stderr)


def test_parse_wash_extracts_aps():
    aps = parse_wash(_proc(WASH_SAMPLE))
    assert len(aps) == 3
    first = aps[0]
    assert first.bssid == "e0:3f:49:6a:57:78"
    assert first.channel == 6
    assert first.wps_version == "1.0"
    assert first.locked is False
    assert first.essid == "ASUS"


def test_parse_wash_locked_and_multiword_essid():
    aps = parse_wash(_proc(WASH_SAMPLE))
    second = aps[1]
    assert second.locked is True
    assert second.wps_version == "2.0"
    third = aps[2]
    assert third.essid == "My Network Name"  # multi-word ESSID preserved


def test_parse_wash_empty_output():
    assert parse_wash(_proc("")) == []
    assert parse_wash(_proc("garbage line\n")) == []


def test_parse_wps_pin_bracket_form():
    out = "[+] WPS PIN: '12345670'\n[+] WPA PSK: 'secret'\n[+] AP SSID: 'Home'\n"
    assert parse_wps_pin(_proc(out)) == "12345670"


def test_parse_wps_pin_alt_form():
    out = "[Pixie-Dust]   [+] WPS pin: 9178"
    assert parse_wps_pin(_proc(out)) == "9178"


def test_parse_wps_pin_none_when_absent():
    assert parse_wps_pin(_proc("no pin here")) is None


def test_verdict_vulnerable_flag():
    v = WpsVerdict(bssid="aa:bb:cc:dd:ee:ff", essid="X",
                   status=VULNERABLE_PIXIE, wps_enabled=True, pin="12345670")
    assert v.vulnerable is True
    d = v.to_dict()
    assert d["status"] == VULNERABLE_PIXIE
    assert d["pin"] == "12345670"


def test_verdict_default_pin_vulnerable():
    v = WpsVerdict(bssid="aa:bb:cc:dd:ee:ff", essid="X",
                   status=VULNERABLE_DEFAULT, wps_enabled=True, pin="12345670")
    assert v.vulnerable is True


def test_wps_ap_enabled_detection():
    ap = WpsAp(bssid="aa:bb:cc:dd:ee:ff", wps_version="1.0")
    assert ap.wps_enabled is True
    ap_off = WpsAp(bssid="aa:bb:cc:dd:ee:ff", wps_version="")
    assert ap_off.wps_enabled is False


def test_assess_one_pixie_dust_success(monkeypatch):
    """Assess runs pixie dust and marks VULNERABLE_PIXIE on recovered PIN."""
    from handshaker.core.wps import WpsAssessor

    reg = _FakeRegistry({})
    assessor = WpsAssessor(reg, {"wps": {"pixie_dust": True, "default_pin": False}})

    def fake_pixie(interface, ap):
        return _proc(" [+] WPS PIN: '99999999'\n")

    monkeypatch.setattr(assessor, "pixie_dust", fake_pixie)
    monkeypatch.setattr(assessor, "_run",
                        lambda fn, iface, ap, label, *a: fn(iface, ap) if not a else fn(iface, ap, *a))

    ap = WpsAp(bssid="aa:bb:cc:dd:ee:ff", wps_version="1.0", channel=6)
    verdict = assessor.assess_one("wlan0", ap)
    assert verdict.status == VULNERABLE_PIXIE
    assert verdict.pin == "99999999"
    assert verdict.vulnerable is True


def test_assess_one_no_pin_not_vulnerable(monkeypatch):
    from handshaker.core.wps import NOT_VULNERABLE, WpsAssessor

    reg = _FakeRegistry({})
    assessor = WpsAssessor(reg, {"wps": {"pixie_dust": True, "default_pin": False}})

    def fake_pixie(interface, ap):
        return _proc("no pin recovered")

    monkeypatch.setattr(assessor, "pixie_dust", fake_pixie)
    monkeypatch.setattr(assessor, "_run",
                        lambda fn, iface, ap, label, *a: fn(iface, ap) if not a else fn(iface, ap, *a))

    ap = WpsAp(bssid="aa:bb:cc:dd:ee:ff", wps_version="1.0", channel=6)
    verdict = assessor.assess_one("wlan0", ap)
    assert verdict.status == NOT_VULNERABLE
    assert verdict.vulnerable is False


def test_assess_default_pin_vulnerable(monkeypatch):
    from handshaker.core.wps import WpsAssessor

    reg = _FakeRegistry({})
    assessor = WpsAssessor(reg, {"wps": {"pixie_dust": False, "default_pin": True}})

    calls = []

    def fake_default(interface, ap, vendor):
        calls.append(vendor)
        return _proc("[+] WPS PIN: '12345670'")

    monkeypatch.setattr(assessor, "default_pin", fake_default)
    monkeypatch.setattr(assessor, "_run",
                        lambda fn, iface, ap, label, *a: fn(iface, ap, *a))

    ap = WpsAp(bssid="aa:bb:cc:dd:ee:ff", wps_version="1.0", channel=6)
    verdict = assessor.assess_one("wlan0", ap)
    assert verdict.status == VULNERABLE_DEFAULT
    assert verdict.pin == "12345670"
    assert calls == [1]  # Belkin first


class _FakeRegistry:
    def __init__(self, present):
        self._present = set(present)

    def has(self, name):
        return name in self._present


# --------------------------------------------------------------------------- #
# WPS strategist: vendor-aware, lock-aware, learning-driven ordering
# --------------------------------------------------------------------------- #
ALL_ON = {
    "pixie_dust": True, "pixie_force": True, "default_pin": True,
    "pixie_loop": True, "push_button": True,
}


def _strat():
    return WpsStrategist(WpsHistory(path=None))


def test_strategist_pixie_vendor_first():
    ap = WpsAp(bssid="aa:bb:cc:dd:ee:ff", vendor="Broadcom")
    plan = _strat().plan(ap, ALL_ON)
    assert plan[0] == "pixie_dust"


def test_strategist_default_pin_vendor_first():
    ap = WpsAp(bssid="aa:bb:cc:dd:ee:ff", vendor="D-Link")
    plan = _strat().plan(ap, ALL_ON)
    assert plan[0] == "default_pin"


def test_strategist_locked_offline_only():
    ap = WpsAp(bssid="aa:bb:cc:dd:ee:ff", vendor="Broadcom", locked=True)
    plan = _strat().plan(ap, ALL_ON)
    assert plan, "plan should not be empty"
    assert all(m in {"pixie_dust", "pixie_force", "pixie_loop"} for m in plan)
    assert "default_pin" not in plan
    assert "push_button" not in plan


def test_strategist_learning_boosts_prior_success():
    hist = WpsHistory(path=None)
    strat = WpsStrategist(hist)
    # Previously, default_pin succeeded for this exact BSSID.
    hist.record("aa:bb:cc:dd:ee:ff", "default_pin", True)
    ap = WpsAp(bssid="aa:bb:cc:dd:ee:ff", vendor="Unknown")
    plan = strat.plan(ap, ALL_ON)
    assert plan[0] == "default_pin"


def test_strategist_vendor_learning_boost():
    hist = WpsHistory(path=None)
    strat = WpsStrategist(hist, transfer=1.0)
    # pixie_force succeeded repeatedly for OTHER Ralink 1.0 APs -> the new AP
    # inherits that prior via cross-AP transfer (context = vendor|version).
    for _ in range(5):
        hist.record("ralink|1.0", "pixie_force", True)
    ap = WpsAp(bssid="11:22:33:44:55:66", vendor="Ralink", wps_version="1.0")
    plan = strat.plan(ap, ALL_ON)
    # pixie_dust is vendor-first for Ralink, but the learned pixie_force should
    # now beat the canonical order (default_pin/pixie_loop/push_button).
    assert plan[0] == "pixie_dust"
    assert plan[1] == "pixie_force"


def test_strategist_transfer_off_starts_cold():
    hist = WpsHistory(path=None)
    strat = WpsStrategist(hist, transfer=0.0)
    for _ in range(5):
        hist.record("ralink|1.0", "default_pin", True)
    ap = WpsAp(bssid="11:22:33:44:55:66", vendor="Ralink", wps_version="1.0")
    plan = strat.plan(ap, ALL_ON)
    # With transfer off, the learned context prior is NOT inherited; the order
    # reverts to vendor-first + canonical (pixie_dust, pixie_force, default_pin).
    assert plan[0] == "pixie_dust"
    assert plan[1] == "pixie_force"


def test_strategist_respects_disabled_methods():
    ap = WpsAp(bssid="aa:bb:cc:dd:ee:ff", vendor="Broadcom")
    cfg = dict(ALL_ON); cfg["pixie_dust"] = False
    plan = _strat().plan(ap, cfg)
    assert "pixie_dust" not in plan
    assert plan[0] != "pixie_dust"


def test_strategist_no_methods_enabled():
    ap = WpsAp(bssid="aa:bb:cc:dd:ee:ff", vendor="Broadcom")
    plan = _strat().plan(ap, {"pixie_dust": False, "default_pin": False})
    assert plan == []
