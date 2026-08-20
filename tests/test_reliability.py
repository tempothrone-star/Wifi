"""Reliability contracts: JSON schema, secrets, process state, key precedence."""

from __future__ import annotations

import json

from handshaker.utils.proc import run
from handshaker.utils.secrets import parse_retry_after, redact


def test_redact_strips_bearer_and_nvapi():
    assert "nvapi-***" in redact("key nvapi-abcdefghijklmnopqrstuv")
    hidden = redact("Authorization: Bearer hunter2token")
    assert "hunter2token" not in hidden
    assert "Bearer ***" in hidden
    assert "secretvalue" not in redact("NIM_API_KEY=secretvalue")


def test_retry_after_seconds_and_http_date():
    assert parse_retry_after("12") == 12.0
    assert parse_retry_after("0") == 0.0
    # HTTP-date in the past → 0; far future → positive.
    assert parse_retry_after("not-a-date") is None
    delta = parse_retry_after("Thu, 01 Jan 2099 00:00:00 GMT")
    assert delta is not None and delta > 0


def test_proc_state_timeout():
    res = run(["sleep", "5"], timeout=0.15, check=False)
    assert res.timed_out is True
    assert res.state == "TIMED_OUT"
    ok = run(["true"], timeout=5, check=False)
    assert ok.state == "EXITED_OK"


def test_json_stdout_is_only_json_and_has_schema(capsys):
    from handshaker.tui import UI
    UI().json({"count": 0, "aps": []})
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["schema_version"] == 1
    assert "handshaker_version" in payload
    assert payload["count"] == 0


def test_nim_env_overrides_config(monkeypatch):
    from handshaker.utils.apikey import load_nim_key
    monkeypatch.setenv("NIM_API_KEY", "nvapi-" + "e" * 40)
    cfg = {"nim": {"api_key": "from-yaml-should-lose"}}
    assert load_nim_key(cfg).startswith("nvapi-")
    monkeypatch.delenv("NIM_API_KEY")
    assert load_nim_key(cfg) == "from-yaml-should-lose"


def test_learning_save_writes_schema_and_bak(tmp_path):
    from handshaker.learning.state import ActionKey, LearningStore
    p = tmp_path / "state.json"
    store = LearningStore(path=p, decay=1.0)
    store.record("aa:bb:cc:dd:ee:ff", ActionKey("mdk4", 10, 7), True)
    store.save()
    data = json.loads(p.read_text())
    assert data["schema_version"] == 2
    store.record("aa:bb:cc:dd:ee:ff", ActionKey("mdk4", 10, 7), False)
    store.save()
    assert list(tmp_path.glob("*.bak"))


def test_db_schema_version(tmp_path):
    from handshaker.db import ResultsDB
    db = ResultsDB(path=tmp_path / "r.db")
    conn = db._connect()
    row = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
    assert row[0] == "2"
    conn.close()


def test_policy_empty_candidates_is_explicit(tmp_path):
    from handshaker.learning.model import ActionPolicy
    from handshaker.learning.state import LearningStore
    import pytest
    p = ActionPolicy(LearningStore(path=tmp_path / "s.json"), min_observations=0)
    with pytest.raises(ValueError, match="at least one"):
        p.choose("aa:bb:cc:dd:ee:ff", [])


def test_graded_reward_zero_observations_stable():
    from handshaker.learning.model import graded_reward
    assert graded_reward(quality=0.0, rounds_taken=0, deauth_frames=0, success=False) == 0.0
    assert 0.0 <= graded_reward(quality=1.0, rounds_taken=1, deauth_frames=0, success=True) <= 1.0


def test_sanitize_unicode_essid():
    from handshaker.utils.validation import sanitize_filename
    assert "/" not in sanitize_filename("café/net")
    assert sanitize_filename("📡home") == "target" or "home" in sanitize_filename("home📡")


def test_package_classifiers_linux():
    text = open("pyproject.toml").read()
    assert "POSIX :: Linux" in text
    assert 'version = "1.6.3"' in text
