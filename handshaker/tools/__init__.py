"""Thin, auditable wrappers around the Kali Linux WiFi toolchain.

Each wrapper does exactly one thing: build the correct argv for a Kali tool
and run it via :mod:`handshaker.utils.proc`. No wrapper invents output — the
raw text from the tool is returned and parsed downstream by explicit parsers.
"""
