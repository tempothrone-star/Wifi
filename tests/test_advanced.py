"""Tests for the advanced components: structural verification, model registry,
rate limiter, and NIM output parsing. Pure-logic, no hardware required."""

from __future__ import annotations

from handshaker.core.verifier import (
    EapolFrame,
    HandshakeEvidence,
    _classify_message,
    _structural_problem,
)
from handshaker.nim.client import NimClient
from handshaker.nim.models import ModelRegistry
from handshaker.nim.ratelimit import BackoffPolicy, TokenBucket

BSSID = "aa:bb:cc:dd:ee:ff"
AP = BSSID
STA = "00:11:22:33:44:55"
NONCE64 = "a" * 64


def _frame(src, *, ack=False, install=False, mic=False, nonce="", msg=0, rc=None, num=1):
    f = EapolFrame(frame_number=num, bssid=BSSID, src=src, dst=STA if src == AP else AP,
                   key_info="0x0", has_ack=ack, has_install=install, has_mic=mic,
                   mic=("c" * 32) if mic else "", nonce=nonce, msgnr=msg,
                   replay_counter=rc)
    f.message = _classify_message(f)
    return f


def _full_handshake_evidence() -> HandshakeEvidence:
    ev = HandshakeEvidence(bssid=BSSID)
    ev.frames = [
        _frame(AP, ack=True, mic=False, nonce=NONCE64, num=1, rc=1),   # M1
        _frame(STA, mic=True, nonce=NONCE64, num=2, rc=1),             # M2
        _frame(AP, ack=True, install=True, mic=True, nonce=NONCE64, num=3, rc=2),  # M3
        _frame(STA, mic=True, nonce="", num=4, rc=2),                  # M4
    ]
    ev.messages = {f.message for f in ev.frames}
    return ev


# --------------------------------------------------------------------------- #
# Structural validation
# --------------------------------------------------------------------------- #
def test_full_handshake_passes_structural_checks():
    ev = _full_handshake_evidence()
    assert ev.has_full_handshake
    assert _structural_problem(ev) is None


def test_wrong_direction_rejected():
    ev = _full_handshake_evidence()
    # M2 must come from the STA; forge it from the AP.
    ev.frames[1] = _frame(AP, mic=True, nonce=NONCE64, num=2, rc=1)
    problem = _structural_problem(ev)
    assert problem is not None and "message 2" in problem


def test_malformed_mic_length_rejected():
    ev = _full_handshake_evidence()
    # M3 with a wrong-length MIC (not 16 bytes).
    f = _frame(AP, ack=True, install=True, mic=True, nonce=NONCE64, num=3, rc=2)
    f.mic = "deadbeef"  # 8 hex chars, not 32
    ev.frames[2] = f
    problem = _structural_problem(ev)
    assert problem is not None and "MIC" in problem


def test_malformed_nonce_rejected():
    ev = _full_handshake_evidence()
    ev.frames[0] = _frame(AP, ack=True, mic=False, nonce="short", num=1, rc=1)
    problem = _structural_problem(ev)
    assert problem is not None and "nonce" in problem


def test_replay_counter_monotonicity():
    ev = _full_handshake_evidence()
    # Replay counter decreasing should be flagged.
    ev.frames[3] = _frame(STA, mic=True, nonce="", num=4, rc=0)
    problem = _structural_problem(ev)
    assert problem is not None and "replay" in problem


# --------------------------------------------------------------------------- #
# Model registry
# --------------------------------------------------------------------------- #
def test_registry_explicit_override_first():
    reg = ModelRegistry(explicit="meta/llama-3.1-8b-instruct")
    assert reg.ordered()[0] == "meta/llama-3.1-8b-instruct"


def test_registry_fast_tier_first_by_default():
    reg = ModelRegistry()
    ordered = reg.ordered()
    assert ordered  # non-empty
    assert any(m["tier"] == "fast" for m in reg._catalog)


def test_registry_degrades_model_on_failure():
    reg = ModelRegistry()
    reg.mark_failure("meta/llama-3.1-8b-instruct", cooldown=30)
    ordered = reg.ordered()
    # The degraded fast model should be demoted to the end of the list.
    assert ordered[-1] == "meta/llama-3.1-8b-instruct"


def test_registry_recovers_after_success():
    reg = ModelRegistry()
    reg.mark_failure("meta/llama-3.1-8b-instruct", cooldown=30)
    reg.mark_success("meta/llama-3.1-8b-instruct")
    assert "meta/llama-3.1-8b-instruct" in reg.ordered()


def test_registry_merge_discovered():
    reg = ModelRegistry()
    reg.merge_discovered(["some/new-model", "meta/llama-3.1-8b-instruct"])
    assert "some/new-model" in reg.all_ids()
    # No duplicates.
    assert reg.all_ids().count("meta/llama-3.1-8b-instruct") == 1


# --------------------------------------------------------------------------- #
# Rate limiter & backoff
# --------------------------------------------------------------------------- #
def test_token_bucket_allows_then_blocks():
    b = TokenBucket(rate=0.1, burst=2)  # 0.1 token/s, capacity 2
    assert b.acquire(timeout=0.01)
    assert b.acquire(timeout=0.01)
    assert not b.acquire(timeout=0.05)  # drained


def test_backoff_grows_and_recovers():
    bp = BackoffPolicy(base_delay=1.0, factor=2.0, jitter=0.0)
    bp.on_failure()
    d1 = bp.current
    bp.on_failure()
    d2 = bp.current
    assert d2 > d1
    bp.on_success()
    assert bp.current == 0.0


def test_backoff_honors_retry_after():
    bp = BackoffPolicy()
    bp.on_failure(retry_after=42.0)
    assert 42.0 <= bp.current <= 42.0 * 1.1


# --------------------------------------------------------------------------- #
# NIM output parsing
# --------------------------------------------------------------------------- #
def test_nim_parse_valid_json():
    sug = NimClient._parse('{"deauth_tool": "mdk4", "burst_size": 40}')
    assert sug.deauth_tool == "mdk4"
    assert sug.burst_size == 40


def test_nim_parse_fenced_code_block():
    sug = NimClient._parse('```json\n{"prefer_pmkid": true}\n```')
    assert sug.prefer_pmkid is True


def test_nim_parse_rejects_bad_fields():
    sug = NimClient._parse('{"deauth_tool": "rm -rf /", "burst_size": 99999}')
    assert sug.deauth_tool is None
    assert sug.burst_size is None
    assert len(sug.rejected) == 2


def test_nim_parse_garbage_returns_empty():
    sug = NimClient._parse("I'm sorry, I can't do that.")
    assert sug.is_empty


def test_nim_parse_empty_object():
    sug = NimClient._parse("{}")
    assert sug.is_empty


# --------------------------------------------------------------------------- #
# WPA3/SAE classification (scanner)
# --------------------------------------------------------------------------- #
def test_security_label_recognizes_sae_as_wpa3():
    from handshaker.core.scanner import AccessPoint
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", privacy="WPA3", auth="SAE")
    assert ap.security_label == "WPA3"
    ap_mgt = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", privacy="WPA3", auth="MGT")
    assert ap_mgt.security_label == "WPA3-Enterprise"
    assert ap_mgt.is_enterprise is True
    ap_psk = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", privacy="WPA2", auth="PSK")
    assert ap_psk.security_label == "WPA2"
    assert ap_psk.is_enterprise is False
