"""Configuration loading with validation.

Validation is strict on purpose: unknown keys or out-of-range values are
rejected so the runtime never operates on a guessed or silently-broken config.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

from .constants import DEFAULT_CONFIG, rebind_data_dirs
from .exceptions import ConfigError

# Allowed top-level keys. Adding a feature requires adding its key here —
# there is no silent pass-through.
_ALLOWED_TOP_KEYS = {
    "general",
    "adapter",
    "scan",
    "capture",
    "verify",
    "deauth",
    "pmkid",
    "learning",
    "nim",
    "targets",
    "tools",
    "wps",
}

_DEFAULTS: dict[str, Any] = {
    "general": {
        "interface": None,          # auto-detect when None
        "require_root": True,
        "consent_required": True,
        "output_root": None,        # defaults to data/ under the project
        "log_level": "INFO",
    },
    "adapter": {
        "auto_monitor": True,
        "reset_on_exit": True,
        "check_injection": True,
        "stop_conflicting_services": True,  # airmon-ng check kill (disruptive)
    },
    "scan": {
        "dwell": 12,                # seconds per channel
        "bands": ["2.4GHz", "5GHz"],
        "min_signal": -90,          # dBm threshold
        "adaptive": False,          # two-pass scan (quick survey + focused dwell)
        "quick_dwell": 5,           # quick-pass seconds (adaptive mode)
    },
    "capture": {
        "max_rounds": 3,            # capture+deauth+verify rounds per target
        "pmkid_duration": 45,       # seconds for a PMKID attempt
        "pmf_fallback": True,       # last-resort hcxdumptool attack (handles PMF/802.11w)
        "write_interval": 2,        # force-flush interval (seconds)
        "wpa_only": True,           # ignore WEP / OPN targets
    },
    "verify": {
        # Strict: require ALL 4 EAPOL messages (M1..M4) of the handshake.
        "require_full_handshake": True,
        # If strict is off, at minimum require a crackable M2(+SNonce,MIC)+M3 pair.
        "min_packets": 4,           # minimum EAPOL frames in the capture
        # Packet-level structural validation (direction, nonce/MIC, replay counter).
        "structural_checks": True,
        # Independent verifiers to consult (intersection of what is present).
        "tools": ["tshark", "aircrack-ng", "hcxpcapngtool", "cowpatty", "pyrit", "capinfos"],
        "delete_on_fail": True,     # reject & delete anything that isn't a 4-way HS
        "quarantine_before_delete": True,
    },
    "deauth": {
        "enabled": True,
        "max_bursts": 8,
        "burst_size": 15,           # deauth packets per burst
        "cooldown": 4,              # seconds between bursts
        "reason_codes": [1, 4, 7],  # 1=unspec, 4=disassoc, 7=class3-failure
        # Engine order. "scapy" = raw-frame injection (honours reason codes);
        # detected at runtime via import, silently skipped if not installed.
        "tools": ["scapy", "aireplay-ng", "mdk4", "bettercap"],
    },
    "pmkid": {
        "enabled": True,
    },
    "learning": {
        "enabled": True,
        "exploration": 0.25,        # exploration probability (per strategy)
        "strategy": "thompson",     # "thompson" | "ucb" | "epsilon"
        "transfer": 0.5,            # cross-AP shrinkage weight (0 = per-AP only)
        "decay": 0.95,              # per-minute decay for stale outcomes
        "min_observations": 2,      # min weighted trials before trusting policy
    },
    "nim": {
        "enabled": False,           # fully optional; tool is independent without it
        "api_key": None,            # NIM_API_KEY env var preferred
        "base_url": "https://integrate.api.nvidia.com/v1",
        "model": None,              # explicit model override (else smart selection)
        "prefer_tier": "fast",      # "fast" (cheap/latency) or "large" (capable)
        "discover_models": False,   # query /v1/models to expand the registry
        "rate_per_minute": 20,      # token-bucket rate limit
        "burst": 5,
        "max_suggestions": 8,
        "timeout": 20,
        # Privacy boundary: by default, BSSID/ESSID are NOT sent to the remote
        # NIM endpoint (they are pseudonymized). Set True only with consent, as
        # a scan can contain identifying info about nearby networks.
        "send_sensitive_context": False,
    },
    "targets": {
        "bssid": [],                # optional explicit targets
        "essid": [],
        "channel": [],
        "max_targets": 0,           # 0 = unlimited
        "exclude": [],              # BSSIDs to never touch
    },
    "tools": {
        # Per-tool explicit overrides; None means "auto-detect".
        "overrides": {},
    },
    "wps": {
        "enabled": True,        # include WPS assessment alongside handshake capture
        "timeout": 120,         # seconds per attack method
        "force_timeout": 180,   # seconds for pixie-force (full-range offline)
        "pixie_dust": True,     # offline pixie-dust test (reaver -K 1 / bully -d)
        "pixie_force": False,   # full-range offline brute (pixiewps -f); slower
        "pixie_loop": False,    # reaver -P: hash collection (avoids lockout)
        "default_pin": True,    # test vendor default PINs (Belkin + D-Link)
        "push_button": False,   # oneshot --pbc: requires physical WPS button press
        "show_all": False,      # wash -a: list APs even without WPS
        "ignore_fcs": True,     # wash -C: ignore frame checksum errors
        "transfer": 0.5,        # cross-AP WPS learning shrinkage (0 = per-AP only)
        "exploration": 0.0,     # shuffle the learned WPS order with this prob
    },
}


def _merge(default: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge an override dict onto a defaults dict (no new keys allowed)."""
    out = copy.deepcopy(default)
    for key, value in override.items():
        if key not in out:
            raise ConfigError(f"Unknown config key: {key!r}")
        if isinstance(value, dict) and isinstance(out[key], dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: Path | str | None = None) -> dict[str, Any]:
    """Load config from ``path`` (or the default location) and validate it."""
    explicit = path is not None
    if path:
        cfg_path = Path(path)
        if not cfg_path.exists():
            raise ConfigError(f"Config file not found: {cfg_path}")
    else:
        cwd_cfg = Path.cwd() / "config" / "config.yaml"
        cfg_path = cwd_cfg if cwd_cfg.exists() else DEFAULT_CONFIG
    raw: dict[str, Any] = {}
    if cfg_path.exists():
        try:
            loaded = yaml.safe_load(cfg_path.read_text()) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"Failed to parse config {cfg_path}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ConfigError(f"Config {cfg_path} must be a YAML mapping.")
        raw = loaded
    elif explicit:
        raise ConfigError(f"Config file not found: {cfg_path}")

    unknown = set(raw) - _ALLOWED_TOP_KEYS
    if unknown:
        raise ConfigError(f"Unknown top-level config section(s): {sorted(unknown)}")

    cfg = _merge(_DEFAULTS, raw)

    # Structural type checks first — range checks assume mappings/lists/ints.
    for section in _ALLOWED_TOP_KEYS:
        if not isinstance(cfg.get(section), dict):
            raise ConfigError(
                f"{section} must be a mapping, got {type(cfg.get(section)).__name__}"
            )

    ov = cfg["tools"].get("overrides", {})
    if ov is None:
        cfg["tools"]["overrides"] = {}
    elif not isinstance(ov, dict):
        raise ConfigError("tools.overrides must be a mapping of tool-name -> path")

    targets_pre = cfg["targets"]
    for key in ("bssid", "essid", "channel", "exclude"):
        val = targets_pre.get(key, [])
        if val is None:
            targets_pre[key] = []
        elif not isinstance(val, list):
            raise ConfigError(f"targets.{key} must be a list, got {type(val).__name__}")

    bands_val = cfg["scan"].get("bands", [])
    if not isinstance(bands_val, list):
        raise ConfigError("scan.bands must be a list")

    # --- Range / sanity validation (fail fast, no silent clamping) --- #
    verify = cfg["verify"]
    if not isinstance(verify["require_full_handshake"], bool):
        raise ConfigError("verify.require_full_handshake must be a boolean.")
    if verify["min_packets"] < 1:
        raise ConfigError("verify.min_packets must be >= 1.")

    learn = cfg["learning"]
    if not (0.0 <= float(learn["exploration"]) <= 1.0):
        raise ConfigError("learning.exploration must be in [0, 1].")
    if not (0.0 <= float(learn["decay"]) <= 1.0):
        raise ConfigError("learning.decay must be in [0, 1].")
    if not (0.0 <= float(learn.get("transfer", 0.5)) <= 1.0):
        raise ConfigError("learning.transfer must be in [0, 1].")

    def _pos_int(section: str, key: str, minimum: int = 1) -> None:
        val = cfg[section][key]
        if not isinstance(val, int) or isinstance(val, bool) or val < minimum:
            raise ConfigError(f"{section}.{key} must be an integer >= {minimum}, got {val!r}")

    def _nonneg_num(section: str, key: str) -> None:
        val = cfg[section][key]
        try:
            n = float(val)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{section}.{key} must be a number, got {val!r}") from exc
        if n < 0:
            raise ConfigError(f"{section}.{key} must be >= 0, got {val!r}")

    _pos_int("scan", "dwell")
    _pos_int("scan", "quick_dwell")
    _pos_int("capture", "max_rounds")
    _pos_int("capture", "pmkid_duration")
    _pos_int("capture", "write_interval")
    _nonneg_num("deauth", "cooldown")
    _pos_int("learning", "min_observations")
    _pos_int("nim", "timeout")
    _pos_int("nim", "burst")
    _nonneg_num("nim", "rate_per_minute")
    _pos_int("wps", "timeout")
    _pos_int("wps", "force_timeout")
    _pos_int("deauth", "burst_size")
    if int(cfg["targets"].get("max_targets", 0) or 0) < 0:
        raise ConfigError("targets.max_targets must be >= 0")

    deauth = cfg["deauth"]
    if not isinstance(deauth["max_bursts"], int) or isinstance(deauth["max_bursts"], bool) or deauth["max_bursts"] < 0:
        raise ConfigError("deauth.max_bursts must be an integer >= 0.")

    # Reason codes must be ints in the valid 802.11 range.
    for rc in deauth.get("reason_codes", []):
        if not isinstance(rc, int) or not (0 <= rc <= 65535):
            raise ConfigError(f"deauth.reason_codes contains invalid reason code {rc!r}")

    # Bands must be a known set.
    allowed_bands = {"2.4GHz", "5GHz", "6GHz"}
    for band in cfg["scan"].get("bands", []):
        if band not in allowed_bands:
            raise ConfigError(f"scan.bands contains unknown band {band!r} (allowed: {sorted(allowed_bands)})")
    # airodump-ng has no 6 GHz band flag. 6GHz-only would silently become 2.4/5.
    supported_bands = [b for b in cfg["scan"].get("bands", []) if b in {"2.4GHz", "5GHz"}]
    if "6GHz" in cfg["scan"].get("bands", []) and not supported_bands:
        raise ConfigError(
            "scan.bands: 6GHz-only scanning is not supported by airodump-ng; "
            "include 2.4GHz and/or 5GHz"
        )

    # Learning strategy enum.
    allowed_strategies = {"thompson", "ucb", "epsilon"}
    strategy = learn.get("strategy", "thompson")
    if strategy not in allowed_strategies:
        raise ConfigError(f"learning.strategy must be one of {sorted(allowed_strategies)}, got {strategy!r}")

    # NIM prefer_tier enum.
    nim = cfg["nim"]
    if nim.get("prefer_tier") not in (None, "fast", "large"):
        raise ConfigError("nim.prefer_tier must be 'fast' or 'large'")
    wps = cfg["wps"]
    if not (0.0 <= float(wps.get("transfer", 0.5)) <= 1.0):
        raise ConfigError("wps.transfer must be in [0, 1].")

    # Target MACs must parse as MAC addresses.
    from .utils.validation import parse_mac
    targets = cfg["targets"]
    for mac in targets.get("bssid", []) + targets.get("exclude", []):
        if parse_mac(mac) is None:
            raise ConfigError(f"targets contains invalid MAC address {mac!r}")

    nim_url = str(nim.get("base_url") or "")
    if cfg["nim"].get("enabled") and nim_url and not nim_url.lower().startswith("https://"):
        raise ConfigError("nim.base_url must use https:// when NIM is enabled")

    # Honour output_root / installed-package data location.
    rebind_data_dirs(cfg["general"].get("output_root"))
    return cfg
