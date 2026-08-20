"""Tests for the newly-wired independent verifiers (pyrit / cowpatty / capinfos)
and their output parsers. Pure logic — no tools or hardware required."""

from __future__ import annotations

from handshaker.core.verifier import (
    parse_capinfos_packets,
    parse_cowpatty,
    parse_pyrit,
)
from handshaker.utils.proc import ProcResult

PYRIT_OUTPUT = """Pyrit 0.5.1 (C) 2008-2011 Lukas Lueg - 2015 John Mora
Parsing file 'wpa2.eapol.cap' (1/1)...
Parsed 5 packets (5 802.11-packets), got 1 AP(s)

#1: AccessPoint 00:14:6c:7e:40:80 ('Harkonen'):
  #1: Station 00:13:46:fe:32:0c, 1 handshake(s):
    #1: HMAC_SHA1_AES, good, spread 1
"""

PYRIT_NO_HANDSHAKE = """Parsing file 'x.cap' (1/1)...
#1: AccessPoint 00:14:6c:7e:40:80 ('Harkonen'):
No valid EAOPL-handshake + ESSID detected.
"""


def _proc(stdout="", stderr="", rc=0):
    return ProcResult(args=["x"], returncode=rc, stdout=stdout, stderr=stderr)


def test_parse_pyrit_finds_good_handshake():
    assert parse_pyrit(_proc(PYRIT_OUTPUT)) == {"00:14:6c:7e:40:80"}


def test_parse_pyrit_workable_counts():
    out = "#1: AccessPoint 11:22:33:44:55:66 ('X'):\n  #1: HMAC_SHA1_AES, workable, spread 1\n"
    assert parse_pyrit(_proc(out)) == {"11:22:33:44:55:66"}


def test_parse_pyrit_no_handshake_is_empty():
    assert parse_pyrit(_proc(PYRIT_NO_HANDSHAKE)) == set()


def test_parse_pyrit_multiple_aps():
    out = (
        "#1: AccessPoint 00:00:00:00:00:01 ('A'):\n  #1: good\n"
        "#2: AccessPoint 00:00:00:00:00:02 ('B'):\n  #1: bad\n"
    )
    # Only AP #1 has a good handshake.
    assert parse_pyrit(_proc(out)) == {"00:00:00:00:00:01"}


def test_parse_cowpatty_success():
    out = "Collected all necessary data to mount crack against WPA2/PSK passphrase.\n"
    assert parse_cowpatty(_proc(out)) is True


def test_parse_cowpatty_failure():
    assert parse_cowpatty(_proc("Unable to identify a valid handshake.\n")) is False
    assert parse_cowpatty(_proc("No valid handshake found.\n")) is False


def test_parse_cowpatty_ambiguous_is_unknown():
    # Empty / unparseable output is "unknown", NOT "no handshake" (honest).
    assert parse_cowpatty(_proc("")) is None
    assert parse_cowpatty(_proc("some unrelated text")) is None


def test_parse_capinfos_packets():
    out = "Number of packets:   1,194\nCapture duration:    342.14 seconds\n"
    assert parse_capinfos_packets(_proc(out)) == 1194


def test_parse_capinfos_no_match():
    assert parse_capinfos_packets(_proc("garbage")) is None
