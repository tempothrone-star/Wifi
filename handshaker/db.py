"""SQLite results store — durable, cross-run operational history.

Every capture/verification outcome is recorded as a *measured fact* so the
engine and strategist can learn across sessions (not just within one run).

Schema (append-only, no derived scores persisted):

* ``sessions``   — one row per autonomous run.
* ``targets``    — one row per AP the engine engaged.
* ``actions``    — one row per deauth action attempted, with the verified result.
* ``captures``   — one row per capture file, with the verification verdict.

The SQLite stdlib module is used (no external dependency). Writes are safe for
concurrent use via a connection-per-operation pattern.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from . import constants

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    ended_at REAL,
    status TEXT,
    interface TEXT,
    env TEXT                       -- JSON: tool versions, config hash, kernel
);
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    bssid TEXT NOT NULL,
    essid TEXT,
    channel INTEGER,
    security TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    bssid TEXT NOT NULL,
    tool TEXT NOT NULL,
    burst INTEGER NOT NULL,
    reason INTEGER NOT NULL,
    success INTEGER NOT NULL,       -- 0/1, backed by verification only
    ts REAL NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
CREATE TABLE IF NOT EXISTS captures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    bssid TEXT NOT NULL,
    file TEXT NOT NULL,
    passed INTEGER NOT NULL,        -- 0/1 verification verdict
    reason TEXT,
    ts REAL NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
CREATE INDEX IF NOT EXISTS idx_actions_bssid ON actions(bssid);
CREATE INDEX IF NOT EXISTS idx_captures_bssid ON captures(bssid);
"""


class ResultsDB:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else (constants.LEARNING_DIR / "results.db")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            self._migrate(conn)

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Add columns that were introduced after the initial schema.

        ``CREATE TABLE IF NOT EXISTS`` does not add columns to an existing
        table, so additive schema changes are applied here with a guard, making
        the store robust to upgrades (not just fresh installs).
        """
        cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)")}
        if "ended_at" not in cols:
            conn.execute("ALTER TABLE sessions ADD COLUMN ended_at REAL")
        if "status" not in cols:
            conn.execute("ALTER TABLE sessions ADD COLUMN status TEXT")
        if "env" not in cols:
            conn.execute("ALTER TABLE sessions ADD COLUMN env TEXT")

    # ------------------------------------------------------------------ #
    def start_session(self, interface: str, env: str | None = None) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO sessions (started_at, interface, env) VALUES (?, ?, ?)",
                (time.time(), interface, env),
            )
            return int(cur.lastrowid)

    def finish_session(self, session_id: int, status: str) -> None:
        """Mark a session completed (status: 'ok' | 'interrupted' | 'error')."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE sessions SET ended_at = ?, status = ? WHERE id = ?",
                (time.time(), status, session_id),
            )

    def record_target(self, session_id: int, bssid: str, essid: str,
                      channel: int, security: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO targets (session_id, bssid, essid, channel, security) "
                "VALUES (?, ?, ?, ?, ?)",
                (session_id, bssid, essid, channel, security),
            )

    def record_action(self, session_id: int, bssid: str, tool: str,
                      burst: int, reason: int, success: bool) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO actions (session_id, bssid, tool, burst, reason, success, ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (session_id, bssid, tool, burst, reason, int(success), time.time()),
            )

    def record_capture(self, session_id: int, bssid: str, file: str,
                       passed: bool, reason: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO captures (session_id, bssid, file, passed, reason, ts) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, bssid, file, int(passed), reason, time.time()),
            )

    # ------------------------------------------------------------------ #
    def count(self, table: str, where: str = "", args: tuple = ()) -> int:
        """``SELECT COUNT(*)`` helper that always closes the connection."""
        if table not in {"sessions", "targets", "actions", "captures"}:
            raise ValueError(f"unknown table {table!r}")
        q = f"SELECT COUNT(*) FROM {table}" + (f" WHERE {where}" if where else "")
        with self._connect() as conn:
            return int(conn.execute(q, args).fetchone()[0])

    def handshake_count(self, bssid: str | None = None) -> int:
        """Verified handshakes on record (optionally per BSSID)."""
        q = "SELECT COUNT(*) FROM captures WHERE passed = 1"
        args: tuple = ()
        if bssid:
            q += " AND bssid = ?"
            args = (bssid,)
        with self._connect() as conn:
            return int(conn.execute(q, args).fetchone()[0])

    def recent_actions(self, limit: int = 200) -> list[dict]:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM actions ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
