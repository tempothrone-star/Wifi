"""Tests for setup/doctor supporting modules: API key validation, OS detection,
and the doctor report (pure logic — no live network or hardware)."""

from __future__ import annotations

from handshaker.utils.apikey import (
    INVALID,
    NOT_PRESENT,
    ApiKeyStatus,
    format_check,
)
from handshaker.utils.system import detect_os, python_info


# --------------------------------------------------------------------------- #
# API key static validation
# --------------------------------------------------------------------------- #
def test_format_check_missing():
    assert format_check(None).status == NOT_PRESENT
    assert format_check("").status == NOT_PRESENT


def test_format_check_too_short():
    st = format_check("nvapi-short")
    assert st.status == INVALID


def test_format_check_plausible_key_passes_static():
    # A plausible (long) key passes the static format check (live probe decides).
    assert format_check("nvapi-" + "a" * 60) is None
    assert format_check("sk-" + "b" * 60) is None


def test_status_ok_flag():
    assert ApiKeyStatus(VALID, "ok").ok is True
    assert ApiKeyStatus(INVALID, "bad").ok is False


VALID = "VALID"


# --------------------------------------------------------------------------- #
# OS detection (works everywhere)
# --------------------------------------------------------------------------- #
def test_detect_os_returns_info():
    osi = detect_os()
    assert osi.system  # non-empty
    assert isinstance(osi.is_linux, bool)
    assert isinstance(osi.supported, bool)


def test_python_info_keys():
    info = python_info()
    assert "version" in info
    assert "in_venv" in info
    assert "executable" in info


# --------------------------------------------------------------------------- #
# Doctor report (no hardware needed)
# --------------------------------------------------------------------------- #
def test_doctor_runs_without_tools():
    from handshaker.doctor import Doctor

    rep = Doctor().run(check_api_key=False)
    d = rep.to_dict()
    assert "os" in d and "python" in d and "tools_available" in d and "nim" in d
    assert isinstance(d["core_ready"], bool)
    # On a machine with no Kali tools, core_ready must be False (honest).
    if not d["tools_available"]:
        assert d["core_ready"] is False


def test_doctor_apt_hint():
    from handshaker.doctor import apt_install_hint
    hint = apt_install_hint(["airmon-ng", "tshark", "nonexistent-tool"])
    assert hint is not None
    assert "aircrack-ng" in hint and "tshark" in hint
    assert "nonexistent-tool" not in hint


# --------------------------------------------------------------------------- #
# TUI: rich is available, but the UI must still construct (and degrade safely)
# --------------------------------------------------------------------------- #
def test_ui_constructs_and_table_renders(capsys):
    from handshaker.tui import UI

    ui = UI()
    ui.banner()
    ui.table(["A", "B"], [[1, 2]])
    out = capsys.readouterr().out
    # Either rich or plain text produced something non-empty.
    assert out.strip()


def test_ui_json_output(capsys):
    from handshaker.tui import UI
    ui = UI()
    ui.json({"a": 1})
    out = capsys.readouterr().out
    assert "a" in out and "1" in out
