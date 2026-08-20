"""Tests for the main launcher: menu flattening and argv builders."""

from __future__ import annotations

from handshaker.launcher import (
    _cmd_scan,
    _cmd_selftest,
    _cmd_wps,
    _flatten,
)


def test_flatten_has_all_commands():
    items = _flatten()
    descs = [d for d, _f in items]
    # Every group's commands are present and order is stable.
    assert any("Doctor" in d for d in descs)
    assert any("Scan nearby" in d for d in descs)
    assert any("Autonomous capture" in d for d in descs)
    assert any("Export bundle" in d for d in descs)
    # 14 total commands.
    assert len(items) == 14


def test_scan_builder_accepts_duration(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *a: "15")
    assert _cmd_scan() == ["scan", "--duration", "15"]


def test_selftest_builder_yes_enables_capture(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    assert _cmd_selftest() == ["selftest", "--capture"]


def test_selftest_builder_no_is_plain(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *a: "n")
    assert _cmd_selftest() == ["selftest"]


def test_wps_builder_detect_only(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    assert _cmd_wps() == ["wps", "--detect-only"]
