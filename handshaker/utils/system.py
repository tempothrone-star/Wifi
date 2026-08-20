"""OS / environment detection helpers.

Purely observational — every field is read from the live system, never guessed.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import dataclass


@dataclass
class OSInfo:
    """Measured facts about the host operating system."""

    system: str
    release: str
    machine: str
    distro: str = ""            # e.g. "Kali", "Ubuntu", "Debian"
    distro_version: str = ""
    is_debian_based: bool = False
    is_kali: bool = False
    package_manager: str | None = None   # "apt", "dnf", "pacman", "brew", None

    @property
    def is_linux(self) -> bool:
        return self.system.lower() == "linux"

    @property
    def supported(self) -> bool:
        """The wireless toolchain realistically runs on Linux (Kali/Debian)."""
        return self.is_linux


def detect_os() -> OSInfo:
    """Detect the host OS and, on Linux, its distribution."""
    info = OSInfo(
        system=platform.system(),
        release=platform.release(),
        machine=platform.machine(),
    )
    if not info.is_linux:
        return info

    distro = ""
    version = ""
    if os.path.exists("/etc/os-release"):
        vals: dict[str, str] = {}
        for line in open("/etc/os-release", errors="replace"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                vals[k] = v.strip().strip('"')
        distro = vals.get("NAME", "")
        version = vals.get("VERSION_ID", vals.get("VERSION", ""))
        id_like = vals.get("ID_LIKE", "") + " " + vals.get("ID", "")

        info.is_debian_based = "debian" in id_like.lower()
        info.is_kali = "kali" in distro.lower()

    info.distro = distro
    info.distro_version = version

    # Package manager detection (measured, not assumed).
    for pm in ("apt", "apt-get", "dnf", "yum", "pacman", "zypper"):
        if shutil.which(pm):
            info.package_manager = pm
            break
    return info


def python_info() -> dict:
    """Measured Python facts."""
    return {
        "version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "executable": sys.executable,
        "in_venv": hasattr(sys, "base_prefix") and sys.prefix != sys.base_prefix,
    }


def detect_root() -> bool:
    """Whether we are running with root (uid 0)."""
    try:
        return os.geteuid() == 0
    except AttributeError:  # Windows
        return False
