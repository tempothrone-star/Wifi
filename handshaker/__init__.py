"""Wifi Auto Handshaker PMKID.

An autonomous, adaptive WiFi security-auditing tool that captures 4-way
handshakes and PMKIDs using the Kali Linux WiFi pentesting toolchain, and
strongly verifies that *only* genuine 4-way handshakes are retained.

**Capture only.** This tool does NOT perform password hashing or cracking.

For authorized security testing only. See README.md for legal and ethical
requirements before use.
"""

from __future__ import annotations

__version__ = "1.6.1"
__all__ = ["__version__"]
