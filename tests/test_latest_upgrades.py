"""Tests for the latest-tech upgrades: hcxdumptool v6.3+ flag adaptation,
WPA3 transition-mode detection, and PMF fallback. Pure logic — no hardware."""

from __future__ import annotations

from handshaker.core.scanner import AccessPoint
from handshaker.tools.hcx import Hcxdumptool


# --------------------------------------------------------------------------- #
# WPA3 transition-mode detection
# --------------------------------------------------------------------------- #
def test_pure_wpa3():
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", privacy="WPA3", auth="SAE")
    assert ap.is_pure_wpa3 is True
    assert ap.is_transition_mode is False
    assert ap.security_label == "WPA3"


def test_transition_mode_detected():
    # airodump reports transition mode as privacy "WPA2 WPA3" / auth "PSK SAE".
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", privacy="WPA2 WPA3", auth="PSK SAE")
    assert ap.is_transition_mode is True
    assert ap.is_pure_wpa3 is False
    assert ap.security_label == "WPA2/WPA3"


def test_transition_mode_auth_only():
    # Some builds report auth "PSK SAE" without the privacy column.
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", privacy="WPA2", auth="PSK SAE")
    assert ap.is_transition_mode is True


def test_plain_wpa2_not_transition():
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", privacy="WPA2", auth="PSK")
    assert ap.is_transition_mode is False
    assert ap.is_pure_wpa3 is False
    assert ap.security_label == "WPA2"


def test_strategist_treats_transition_as_capturable():
    from handshaker.core.scanner import ScanResult
    from handshaker.core.strategist import Strategist
    from handshaker.learning.state import LearningStore
    from handshaker.tools.registry import ToolRegistry

    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", privacy="WPA2 WPA3", auth="PSK SAE",
                     channel=6, power=-40, essid="Net")
    scan = ScanResult(aps={"aa:bb:cc:dd:ee:ff": ap}, clients={})  # no clients
    cfg = {"pmkid": {"enabled": True}, "deauth": {"tools": []},
           "targets": {"bssid": [], "max_targets": 0},
           "capture": {"wpa_only": True}, "scan": {"min_signal": -90},
           "learning": {"exploration": 0.25, "decay": 0.95, "min_observations": 2}}
    strat = Strategist(ToolRegistry(), LearningStore(path=None), cfg)
    s = strat.strategy_for(ap, scan)
    # Transition mode + no clients -> PMKID is a valid clientless option
    # (unlike pure WPA3 which excludes PMKID).
    assert s.prefer_pmkid is True
    assert any("transition" in r for r in s.reasons)


# --------------------------------------------------------------------------- #
# hcxdumptool version-adaptive flags
# --------------------------------------------------------------------------- #
class _FakeHcx(Hcxdumptool):
    def __init__(self, help_text):
        super().__init__(override="/usr/bin/hcxdumptool")
        self._path = "/usr/bin/hcxdumptool"  # skip PATH lookup in tests
        self._help = help_text
        self._caps = None


def test_capture_args_new_63_flags(monkeypatch):
    new_help = "usage: hcxdumptool\n -i : interface\n -w : write pcapng\n -c : channel\n --rds= : display\n --attemptclientmax= : max\n --attemptapmax= : max\n --disable_deauthentication : disable deauth\n"
    tool = _FakeHcx(new_help)
    monkeypatch.setattr(tool, "capabilities", lambda: {
        "new_output_w": True, "rds": True, "attemptclientmax": True,
        "attemptapmax": True, "enable_status": False,
        "disable_client_attacks": False, "disable_deauth": True,
        "filtermode": False, "filterlist_ap": False,
    })
    args = tool.capture_args("wlan0", "out.pcapng", channel="6", bssid="aa:bb:cc:dd:ee:ff",
                             disable_deauth=True, ap_only=True, status=1)
    assert "-w" in args and "out.pcapng" in args       # new output flag
    assert "-o" not in args
    assert "--rds=1" in args                            # new status flag
    assert "--attemptclientmax=0" in args               # new ap-only flag
    assert "--disable_client_attacks" not in args       # old flag not used
    assert "--filtermode" not in args                   # filtering removed in 6.3+


def test_capture_args_old_63_flags(monkeypatch):
    old_help = "usage: hcxdumptool\n -o : output\n --enable_status= : status\n --disable_client_attacks : x\n --filtermode= : m\n --filterlist_ap= : f\n --disable_deauthentication : d\n"
    tool = _FakeHcx(old_help)
    monkeypatch.setattr(tool, "capabilities", lambda: {
        "new_output_w": False, "rds": False, "attemptclientmax": False,
        "attemptapmax": False, "enable_status": True,
        "disable_client_attacks": True, "disable_deauth": True,
        "filtermode": True, "filterlist_ap": True,
    })
    args = tool.capture_args("wlan0", "out.pcapng", channel="6", bssid="aa:bb:cc:dd:ee:ff",
                             disable_deauth=True, ap_only=True, status=1)
    assert "-o" in args and "out.pcapng" in args        # old output flag
    assert "--enable_status=1" in args                  # old status flag
    assert "--disable_client_attacks" in args           # old ap-only flag
    assert "--filtermode=2" in args                     # old filtering
    assert "--filterlist_ap=aabbccddeeff" in args


def test_capture_args_full_attack_disables_nothing(monkeypatch):
    tool = _FakeHcx("")
    monkeypatch.setattr(tool, "capabilities", lambda: {
        "new_output_w": True, "rds": True, "attemptclientmax": True,
        "attemptapmax": True, "enable_status": False,
        "disable_client_attacks": False, "disable_deauth": True,
        "filtermode": False, "filterlist_ap": False,
    })
    # full_attack = disable_deauth=False, ap_only=False -> hcxdumptool runs its
    # own attack vectors (MFP-aware); no disable flags emitted.
    args = tool.capture_args("wlan0", "out.pcapng", channel="6",
                             disable_deauth=False, ap_only=False, status=1)
    assert "--disable_deauthentication" not in args
    assert "--attemptclientmax=0" not in args


# --------------------------------------------------------------------------- #
# PMF fallback (engine)
# --------------------------------------------------------------------------- #
def test_pmf_fallback_config_default_enabled():
    from handshaker.config import load_config
    cfg = load_config()
    assert cfg["capture"].get("pmf_fallback", True) is True


def test_pmf_fallback_method_verifies_and_stores(monkeypatch, tmp_path):
    """The PMF fallback capture path verifies output and stores a handshake."""
    from handshaker.core import engine as engine_mod
    from handshaker.core.engine import Engine, RunStats
    from handshaker.core.scanner import AccessPoint

    monkeypatch.setattr(engine_mod, "HANDSHAKES_DIR", tmp_path / "hs")
    monkeypatch.setattr(engine_mod, "QUARANTINE_DIR", tmp_path / "q")

    from handshaker.config import load_config
    e = Engine(load_config())

    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6, privacy="WPA2",
                     auth="PSK", power=-40, essid="Net")

    # A fake capture session whose output is a real file that passes verify.
    class FakeSession:
        out_prefix = str(tmp_path / "cap")

        def stop(self):
            pass

    fake_file = tmp_path / "cap.pcapng"
    fake_file.write_bytes(b"\x00" * 64)

    # Stub the capturer start/output_files so no real binary runs.
    monkeypatch.setattr(e.capturer, "start",
                        lambda *a, **kw: FakeSession())
    monkeypatch.setattr(e.capturer, "output_files",
                        staticmethod(lambda s: [fake_file]))

    # Force the verifier to PASS (simulate a genuine handshake).
    monkeypatch.setattr(e, "enforce_verification",
                        lambda f: (_FakePassReport(), False))

    stats = RunStats()
    ok = e._pmf_fallback_capture("wlan0mon", ap, stats, 1)
    assert ok is True
    assert stats.handshakes_captured == 1


class _FakePassReport:
    passed = True
    reason = "valid"


def test_capturer_full_attack_passes_through(monkeypatch):
    """capturer.start(full_attack=True) calls _start_hcx with full_attack=True."""
    from handshaker.core.capturer import Capturer, CaptureSession

    class R:
        def has(self, n):
            return n in ("hcxdumptool",)

        def hcxdumptool(self):
            class T:
                path = "/usr/bin/hcxdumptool"

                def capture_args(self, *a, **kw):
                    return ["hcxdumptool", "-i", a[0], "-w", a[1],
                            "--attemptclientmax=0"]  # ap_only when full_attack False
            return T()

    c = Capturer(R(), {"capture": {}})
    captured = {}

    def fake_start_hcx(interface, bssid, channel, prefix, *, full_attack=False):
        captured["full_attack"] = full_attack
        return CaptureSession(interface, bssid, prefix, None, "hcxdumptool", 0.0)

    monkeypatch.setattr(c, "_start_hcx", fake_start_hcx)
    c.start("wlan0", "aa:bb:cc:dd:ee:ff", 6, full_attack=True)
    assert captured["full_attack"] is True
