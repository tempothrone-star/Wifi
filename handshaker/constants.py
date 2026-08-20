"""Shared constants for the Wifi Auto Handshaker PMKID tool.

Centralising magic strings (paths, names, exit codes, EAPOL definitions)
keeps the codebase deterministic and auditable — a deliberate anti-hallucination
measure: every "fact" used downstream is defined here or measured at runtime.
"""

from __future__ import annotations

from pathlib import Path

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
PKG_ROOT: Path = Path(__file__).resolve().parent


def _default_project_root() -> Path:
    """Checkout root when developing; otherwise the process working directory.

    After ``pip install .`` this package lives under site-packages, so
    ``PKG_ROOT.parent / "data"`` would write into the install tree. Prefer a
    source checkout (``pyproject.toml`` / ``config/config.yaml`` next to the
    parent) and fall back to ``cwd`` for installed deployments.
    """
    src = PKG_ROOT.parent
    if (src / "pyproject.toml").exists() or (src / "config" / "config.yaml").exists():
        return src
    return Path.cwd()


PROJECT_ROOT: Path = _default_project_root()
CONFIG_DIR: Path = PROJECT_ROOT / "config"
DATA_DIR: Path = PROJECT_ROOT / "data"

CAPTURES_DIR: Path = DATA_DIR / "captures"      # raw .cap / .pcapng captures
HANDSHAKES_DIR: Path = DATA_DIR / "handshakes"  # verified 4-way handshakes only
PMKID_DIR: Path = DATA_DIR / "pmkid"            # converted PMKID hashes (22000)
QUARANTINE_DIR: Path = DATA_DIR / "quarantine"  # fails verification -> retained (or deleted)
LEARNING_DIR: Path = DATA_DIR / "learning"      # adaptive strategy state

DEFAULT_CONFIG: Path = CONFIG_DIR / "config.yaml"


def rebind_data_dirs(output_root: str | Path | None) -> None:
    """Honour ``general.output_root`` (and installed-package cwd defaults).

    Mutates the module-level directory constants so later lookups via
    ``handshaker.constants.HANDSHAKES_DIR`` (attribute access) see the new
    location. Call this from ``load_config`` *before* constructing Engine.
    """
    global DATA_DIR, CAPTURES_DIR, HANDSHAKES_DIR, PMKID_DIR, QUARANTINE_DIR, LEARNING_DIR
    base = Path(output_root).expanduser().resolve() if output_root else (PROJECT_ROOT / "data")
    DATA_DIR = base
    CAPTURES_DIR = base / "captures"
    HANDSHAKES_DIR = base / "handshakes"
    PMKID_DIR = base / "pmkid"
    QUARANTINE_DIR = base / "quarantine"
    LEARNING_DIR = base / "learning"
    for d in (CAPTURES_DIR, HANDSHAKES_DIR, PMKID_DIR, QUARANTINE_DIR, LEARNING_DIR):
        d.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------- #
# Exit codes
# --------------------------------------------------------------------------- #
EXIT_OK = 0
EXIT_NOT_ROOT = 1
EXIT_NO_ADAPTER = 2
EXIT_TOOL_MISSING = 3
EXIT_AUTH_DENIED = 4
EXIT_CAPTURE_FAILED = 5
EXIT_VERIFY_FAILED = 6

# --------------------------------------------------------------------------- #
# 802.11 / EAPOL constants (IEEE 802.11-2020, 802.1X-2020)
# --------------------------------------------------------------------------- #
# NOTE: We deliberately do NOT hard-code the EAPOL key_info bitfield here.
# Wireshark (tshark) already decodes the individual flags and exposes them as
# boolean fields (wlan_rsna_eapol.keydes.key_info.key_ack / .install / etc.),
# so the verifier consumes Wireshark's own decoding rather than re-implementing
# bit arithmetic that could drift out of sync. See tools/tshark.py.

# --------------------------------------------------------------------------- #
# WPA security suites (as reported by airodump-ng)
# --------------------------------------------------------------------------- #
SECURITY_WPA = "WPA"
SECURITY_WPA2 = "WPA2"
SECURITY_WPA3 = "WPA3"
SECURITY_WEP = "WEP"
SECURITY_OPEN = "OPN"
# Enterprise (802.1X/EAP) suffixes — capturable but NOT PSK-recoverable.
SECURITY_ENTERPRISE_SUFFIX = "-Enterprise"

# Suites that are in-scope for 4-way handshake / PMKID capture.
WPA_SUITES = {SECURITY_WPA, SECURITY_WPA2, SECURITY_WPA3}

# --------------------------------------------------------------------------- #
# Channels / bands
# --------------------------------------------------------------------------- #
BAND_2G = "2.4GHz"
BAND_5G = "5GHz"
BAND_6G = "6GHz"

# --------------------------------------------------------------------------- #
# Tool names (invoked via subprocess; detected at runtime)
# --------------------------------------------------------------------------- #
TOOL_AIRMON_NG = "airmon-ng"
TOOL_AIRODUMP_NG = "airodump-ng"
TOOL_AIREPLAY_NG = "aireplay-ng"
TOOL_AIRCRACK_NG = "aircrack-ng"
TOOL_HCXDUMPTOOL = "hcxdumptool"
TOOL_HCXPCAPNGTOOL = "hcxpcapngtool"
TOOL_HCXLABTOOL = "hcxlabtool"
TOOL_HCXPSCKTOOL = "hcxpsktool"
TOOL_TSHARK = "tshark"
TOOL_WIRESHARK = "wireshark"
TOOL_CAPINFOS = "capinfos"
TOOL_BETTERCAP = "bettercap"
TOOL_MDK4 = "mdk4"
TOOL_WIFITE = "wifite"
TOOL_WIFITE2 = "wifite2"
TOOL_COWPATTY = "cowpatty"
TOOL_PYRIT = "pyrit"
TOOL_KISMET = "kismet"
TOOL_WASH = "wash"
TOOL_REAVER = "reaver"
TOOL_BULLY = "bully"
TOOL_PIXIEWPS = "pixiewps"
TOOL_ONESHOT = "oneshot"
TOOL_IW = "iw"
TOOL_IWCONFIG = "iwconfig"
TOOL_RFKILL = "rfkill"
TOOL_IP = "ip"
