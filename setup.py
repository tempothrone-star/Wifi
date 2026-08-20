#!/usr/bin/env python3
"""Setup / doctor for Wifi Auto Handshaker PMKID.

A single script that prepares the runtime and *verifies* it, checking:

  * Operating system (Kali/Debian support, package manager, root)
  * Python version + virtualenv
  * Required Python packages (optional install into a venv)
  * Every Kali wireless tool (PATH detection + apt install hint)
  * NVIDIA NIM API key (format + live validation + expiration/revocation check)

Usage:
    python3 setup.py                 # full check + report (safe, no changes)
    python3 setup.py doctor          # same as above
    python3 setup.py --venv          # create .venv and install requirements
    python3 setup.py --install-tools # attempt apt install of missing tools
    python3 setup.py --check-api-key # live-validate NIM_API_KEY / nim.api_key
    python3 setup.py --json          # machine-readable JSON report

Self-contained (stdlib only) so it runs even before dependencies are installed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

# stdlib-only helpers are imported from the package (no heavy deps).
try:
    from handshaker.utils.apikey import (
        NOT_PRESENT,
        UNKNOWN,
        format_check,
        load_nim_key,
        validate_nim_key,
    )
    from handshaker.utils.system import detect_os, detect_root, python_info
except ImportError:  # pragma: no cover - extremely defensive
    detect_os = detect_root = python_info = None  # type: ignore
    validate_nim_key = load_nim_key = format_check = None  # type: ignore

REQUIRED_PYTHON = (3, 11)

# Every Kali tool this project uses -> its Debian package.
TOOL_PACKAGES = {
    "airmon-ng": "aircrack-ng", "airodump-ng": "aircrack-ng",
    "aireplay-ng": "aircrack-ng", "aircrack-ng": "aircrack-ng",
    "hcxdumptool": "hcxdumptool", "hcxpcapngtool": "hcxtools",
    "tshark": "tshark", "wireshark": "wireshark-qt", "capinfos": "tshark",
    "bettercap": "bettercap", "mdk4": "mdk4", "wifite": "wifite",
    "wifite2": "wifite", "cowpatty": "cowpatty", "pyrit": "pyrit",
    "kismet": "kismet", "wash": "reaver", "reaver": "reaver",
    "bully": "bully", "pixiewps": "pixiewps", "oneshot": "oneshot",
    "iw": "iw", "iwconfig": "wireless-tools", "rfkill": "rfkill",
}
CORE_TOOLS = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
              "hcxdumptool", "hcxpcapngtool", "tshark"]

PY_PACKAGES = ["PyYAML>=6.0", "rich>=13.0"]


# --------------------------------------------------------------------------- #
# Checks (each returns a small dict of measured facts)
# --------------------------------------------------------------------------- #
def check_os() -> dict:
    osi = detect_os() if detect_os else None
    if not osi:
        return {"error": "os detection unavailable"}
    return {
        "system": osi.system, "release": osi.release, "distro": osi.distro,
        "kali": osi.is_kali, "debian_based": osi.is_debian_based,
        "package_manager": osi.package_manager, "supported": osi.supported,
    }


def check_python() -> dict:
    info = python_info() if python_info else {"version": platform_py(), "in_venv": False}
    v = sys.version_info[:2]
    ok = v >= REQUIRED_PYTHON
    info["ok"] = ok
    info["required"] = f"{REQUIRED_PYTHON[0]}.{REQUIRED_PYTHON[1]}+"
    return info


def platform_py() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def check_tools() -> dict:
    available, missing = {}, []
    for tool in TOOL_PACKAGES:
        path = shutil.which(tool)
        if path:
            available[tool] = path
        else:
            missing.append(tool)
    core_ready = all(t in available for t in CORE_TOOLS)
    return {"available": available, "missing": missing, "core_ready": core_ready}


def check_api_key(config: dict | None = None, base_url: str | None = None,
                  live: bool = False) -> dict:
    if validate_nim_key is None:
        return {"status": UNKNOWN, "reason": "apikey module unavailable"}
    key = load_nim_key(config)
    if not key:
        return {"status": NOT_PRESENT, "reason": "no NIM_API_KEY env var or nim.api_key"}
    if not live:
        if format_check is not None:
            static = format_check(key)
            if static is not None:
                return static.to_dict()
        return {"status": "PRESENT",
                "reason": "not validated (--check-api-key not requested)"}
    url = base_url or "https://integrate.api.nvidia.com/v1"
    return validate_nim_key(key, base_url=url).to_dict()


def missing_packages(missing_tools: list[str]) -> list[str]:
    pkgs = {TOOL_PACKAGES[t] for t in missing_tools if t in TOOL_PACKAGES}
    return sorted(pkgs)


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #
def create_venv() -> dict:
    """Create .venv and install Python requirements (no tools touched)."""
    out = {"venv": None, "pip": []}
    if not os.path.isdir(".venv"):
        r = subprocess.run([sys.executable, "-m", "venv", ".venv"])
        out["venv"] = "created" if r.returncode == 0 else f"failed rc={r.returncode}"
        if r.returncode != 0:
            return out
    else:
        out["venv"] = "exists"
    pip = os.path.join(".venv", "bin", "pip")
    for pkg in PY_PACKAGES:
        r = subprocess.run([pip, "install", "--quiet", pkg])
        out["pip"].append({"pkg": pkg, "ok": r.returncode == 0})
    return out


def install_tools(missing: list[str], package_manager: str | None) -> dict:
    if package_manager not in ("apt", "apt-get"):
        return {"installed": [], "error": f"no apt package manager (found {package_manager})"}
    if detect_root() is not True:
        return {"installed": [], "error": "root required to install packages (re-run with sudo)"}
    pkgs = missing_packages(missing)
    r = subprocess.run([package_manager, "install", "-y", *pkgs])
    return {"installed": pkgs, "ok": r.returncode == 0}


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def build_report(args: argparse.Namespace) -> dict:
    rep: dict = {"os": check_os(), "python": check_python(),
                 "root": bool(detect_root()) if detect_root else False,
                 "tools": check_tools(), "nim": check_api_key()}

    if args.check_api_key:
        rep["nim"] = check_api_key(base_url=args.base_url, live=True)

    if args.venv:
        rep["venv"] = create_venv()

    if args.install_tools:
        rep["tools_install"] = install_tools(
            rep["tools"]["missing"], rep["os"].get("package_manager"))
        rep["tools"] = check_tools()  # re-check after install

    return rep


def print_report(rep: dict, json_out: bool) -> None:
    if json_out:
        print(json.dumps(rep, indent=2))
        return

    print("=" * 66)
    print("  Wifi Auto Handshaker PMKID — setup / doctor")
    print("=" * 66)

    osi = rep["os"]
    print("\n[OS]")
    print(f"  system          : {osi.get('system')} {osi.get('release')}")
    print(f"  distribution    : {osi.get('distro') or '(unknown)'} "
          f"{osi.get('distro_version', '')}")
    print(f"  kali            : {'yes' if osi.get('kali') else 'no'}")
    print(f"  debian-based    : {'yes' if osi.get('debian_based') else 'no'}")
    print(f"  package manager : {osi.get('package_manager') or '(none)'}")
    print(f"  supported       : {'yes' if osi.get('supported') else 'no'}")

    py = rep["python"]
    print("\n[Python]")
    print(f"  version         : {py.get('version')} (need {py.get('required')}) "
          f"{'✓' if py.get('ok') else '✗ TOO OLD'}")
    print(f"  virtualenv      : {'yes' if py.get('in_venv') else 'no'}")
    print(f"  root            : {'yes' if rep.get('root') else 'no'}")

    tools = rep["tools"]
    print("\n[Kali tools]")
    print(f"  available       : {len(tools['available'])}/{len(TOOL_PACKAGES)}")
    print(f"  core toolchain  : {'READY ✓' if tools['core_ready'] else 'INCOMPLETE ✗'}")
    if tools["missing"]:
        print(f"  missing         : {', '.join(sorted(tools['missing']))}")
        pkgs = missing_packages(tools["missing"])
        if pkgs:
            print(f"  install hint    : sudo apt install {' '.join(pkgs)}")

    if "venv" in rep:
        print("\n[venv]")
        print(f"  {rep['venv']}")

    if "tools_install" in rep:
        ti = rep["tools_install"]
        print("\n[tool install]")
        print(f"  {'ok' if ti.get('ok') else 'error'}: {ti}")

    nim = rep["nim"]
    print("\n[NVIDIA NIM API key]")
    print(f"  status          : {nim.get('status')}")
    print(f"  detail          : {nim.get('reason')}")
    if nim.get("http_code"):
        print(f"  http            : {nim.get('http_code')}")
    if nim.get("models_visible") is not None:
        print(f"  models visible  : {nim.get('models_visible')}")

    print("\n" + "=" * 66)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Setup/doctor for Wifi Auto Handshaker PMKID")
    p.add_argument("doctor", nargs="?", default=None, help="run the self-check")
    p.add_argument("--venv", action="store_true", help="create .venv + install deps")
    p.add_argument("--install-tools", action="store_true",
                   help="apt-install missing Kali tools (needs root)")
    p.add_argument("--check-api-key", action="store_true", help="live-validate NIM API key")
    p.add_argument("--base-url", default=None, help="NIM base URL override")
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = p.parse_args(argv)

    rep = build_report(args)
    print_report(rep, args.json)
    return 0 if rep["tools"]["core_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
