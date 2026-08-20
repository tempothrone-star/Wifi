"""Report & export — surfaces the measured state of the whole project.

Completes the "learn and report" loop: after captures, the operator can inspect
what was stored, what the learning engine has measured, and the session history
— all derived from *real* artifacts and records, never fabricated.

Contents:
  * verified handshakes on disk (data/handshakes)
  * PMKID conversions (data/pmkid)
  * WPS assessment history (data/learning/wps.json)
  * deauth-action learning state (data/learning/state.json)
  * session/capture/action history (data/learning/results.db)
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..constants import HANDSHAKES_DIR, LEARNING_DIR, PMKID_DIR
from ..db import ResultsDB
from ..learning.state import LearningStore


@dataclass
class ProjectReport:
    """A measured snapshot of the project's artifacts and learning state."""

    handshakes: list[str] = field(default_factory=list)
    pmkids: list[str] = field(default_factory=list)
    sessions: int = 0
    captures_recorded: int = 0
    verified_captures: int = 0
    learned_aps: list[dict] = field(default_factory=list)
    wps_records: int = 0

    def to_dict(self) -> dict:
        return {
            "handshakes": self.handshakes,
            "pmkids": self.pmkids,
            "sessions": self.sessions,
            "captures_recorded": self.captures_recorded,
            "verified_captures": self.verified_captures,
            "learned_aps": self.learned_aps,
            "wps_records": self.wps_records,
        }


def build_report(store: LearningStore, db: ResultsDB,
                 wps_path: Path | None = None) -> ProjectReport:
    """Collect the measured state into a :class:`ProjectReport`."""
    rep = ProjectReport()

    # Verified handshakes on disk.
    if HANDSHAKES_DIR.exists():
        rep.handshakes = sorted(
            p.name for p in HANDSHAKES_DIR.iterdir() if p.is_file() and not p.name.startswith(".")
        )

    # PMKID conversions on disk.
    if PMKID_DIR.exists():
        rep.pmkids = sorted(
            p.name for p in PMKID_DIR.iterdir()
            if p.is_file() and p.suffix in (".22000", ".pcapng") and not p.name.startswith(".")
        )

    # Session / capture history from the SQLite DB.
    try:
        rep.sessions = db.count("sessions")
        rep.captures_recorded = db.count("captures")
        rep.verified_captures = db.count("captures", "passed = 1")
    except Exception:  # noqa: BLE001 - DB may not exist yet
        pass

    # Learned AP profiles (deauth actions) with recomputed stats.
    for bssid in store.all_bssids():
        profile = store.profile(bssid) or {}
        actions = len(profile.get("actions", []))
        pmkid = store.pmkid_stats(bssid)
        if actions or pmkid["trials"] > 0:
            rep.learned_aps.append({
                "bssid": bssid,
                "essid": profile.get("essid", ""),
                "security": profile.get("security", ""),
                "band": profile.get("band", ""),
                "vendor": profile.get("vendor", ""),
                "handshake_actions": actions,
                "pmkid_rate": round(pmkid["rate"], 3),
            })

    # WPS assessment records.
    if wps_path and wps_path.exists():
        try:
            data = json.loads(wps_path.read_text())
            rep.wps_records = len(data.get("records", []))
        except (json.JSONDecodeError, OSError):
            rep.wps_records = 0

    return rep


def bundle_results(store: LearningStore, db: ResultsDB,
                   out_dir: Path | str | None = None,
                   wps_path: Path | None = None) -> Path:
    """Export a portable bundle of the project's artifacts + report.

    Creates a timestamped directory containing:
      * verified handshakes (copied from data/handshakes)
      * PMKID conversions (copied from data/pmkid)
      * the full project report (report.json)
      * the learning state (state.json) and WPS history (wps.json)

    Returns the created directory path. This completes the capture → learn →
    report → export loop, so results can be archived or moved off-box.
    """
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = Path(out_dir) if out_dir else Path(".")
    bundle = out / f"handshaker-export-{stamp}"
    (bundle / "handshakes").mkdir(parents=True, exist_ok=True)
    (bundle / "pmkid").mkdir(parents=True, exist_ok=True)

    # Copy verified handshakes.
    if HANDSHAKES_DIR.exists():
        for p in HANDSHAKES_DIR.iterdir():
            if p.is_file() and not p.name.startswith("."):
                shutil.copy2(p, bundle / "handshakes" / p.name)

    # Copy PMKID conversions.
    if PMKID_DIR.exists():
        for p in PMKID_DIR.iterdir():
            if p.is_file() and not p.name.startswith("."):
                shutil.copy2(p, bundle / "pmkid" / p.name)

    # Full report.
    rep = build_report(store, db, wps_path=wps_path)
    (bundle / "report.json").write_text(json.dumps(rep.to_dict(), indent=2))

    # Learning state (handshake bandit) and WPS history.
    state = LEARNING_DIR / "state.json"
    if state.exists():
        shutil.copy2(state, bundle / "state.json")
    if wps_path and wps_path.exists():
        shutil.copy2(wps_path, bundle / "wps.json")

    return bundle
