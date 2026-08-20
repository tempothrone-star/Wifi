"""Autonomous capture engine — orchestrates scan -> target -> deauth -> capture
-> verify -> learn in a closed loop.

The engine is deterministic at every step and keeps a hard separation between:

* **facts** (measured by tools) and
* **decisions** (made by the strategist from those facts).

It also enforces the authorization gate: capture/deauth will not start unless
the operator has explicitly acknowledged authorized use.
"""

from __future__ import annotations

import logging
import os
import shutil
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path

from .. import __version__
from .. import constants
from ..constants import (
    EXIT_AUTH_DENIED,
    EXIT_CAPTURE_FAILED,
    EXIT_NOT_ROOT,
    EXIT_NO_ADAPTER,
    EXIT_OK,
    EXIT_VERIFY_FAILED,
)
from ..db import ResultsDB
from ..exceptions import (
    AdapterError,
    AuthorizationDeniedError,
    NoAdapterError,
    NotRootError,
)
from ..learning.model import graded_reward
from ..learning.state import ActionKey, LearningStore
from ..nim.client import NimClient
from ..tools.registry import ToolRegistry
from .adapter import AdapterManager
from .analyzer import Analyzer
from .capturer import Capturer
from .deauth import Deauther
from .pmkid import PmidCapture
from .scanner import AccessPoint, Scanner
from .strategist import Strategist
from .verifier import HandshakeVerifier, handshake_quality
from .wps import WpsAssessor, WpsHistory

log = logging.getLogger("handshaker.engine")


@dataclass
class RunStats:
    """Truthful summary of one autonomous run."""

    targets_scanned: int = 0
    targets_attacked: int = 0
    handshakes_captured: int = 0
    handshakes_rejected: int = 0
    pmkids_captured: int = 0
    wps_assessed: int = 0
    wps_vulnerable: int = 0
    failures: list[str] = field(default_factory=list)
    verified_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "targets_scanned": self.targets_scanned,
            "targets_attacked": self.targets_attacked,
            "handshakes_captured": self.handshakes_captured,
            "handshakes_rejected": self.handshakes_rejected,
            "pmkids_captured": self.pmkids_captured,
            "wps_assessed": self.wps_assessed,
            "wps_vulnerable": self.wps_vulnerable,
            "failures": self.failures,
            "verified_files": self.verified_files,
        }


class Engine:
    def __init__(self, config: dict) -> None:
        self.config = config
        overrides = config["tools"].get("overrides", {})
        self.registry = ToolRegistry(overrides)
        self.adapter = AdapterManager(self.registry)
        self.scanner = Scanner(self.registry, config)
        self.capturer = Capturer(self.registry, config)
        self.verifier = HandshakeVerifier(self.registry, config)
        self.deauther = Deauther(self.registry, config)
        self.analyzer = Analyzer(self.registry)
        self.pmkid = PmidCapture(self.registry, config)
        self.wps = WpsAssessor(
            self.registry, config,
            history=WpsHistory(path=constants.LEARNING_DIR / "wps.json"),
        )
        self.store = LearningStore(
            path=constants.LEARNING_DIR / "state.json",
            decay=float(config["learning"]["decay"]),
            enabled=bool(config["learning"].get("enabled", True)),
        )
        self.strategist = Strategist(self.registry, self.store, config)
        self.nim = NimClient(config)
        self.db = ResultsDB()
        self._active_mon_iface: str | None = None
        self._active_session = None  # CaptureSession currently running, if any
        self._injection_ok = True  # default; set honestly during run_auto
        self._dwell_override: float | None = None

        for d in (constants.HANDSHAKES_DIR, constants.QUARANTINE_DIR):
            d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Safety gates
    # ------------------------------------------------------------------ #
    def check_root(self) -> None:
        if self.config["general"]["require_root"] and os.geteuid() != 0:
            raise NotRootError(
                "Capture, monitor mode, and deauth require root privileges. "
                "Re-run with `sudo`."
            )

    def require_authorization(self) -> None:
        """Interactive operator-acknowledgement gate. Fails closed unless the
        operator explicitly confirms authorized use.

        This is a per-run *acknowledgement*, not a security boundary — it is not
        persisted, so every autonomous run re-prompts. (It never claims to be an
        enforcement mechanism; real authorization is legal/scope, not this UX.)
        """
        if not self.config["general"]["consent_required"]:
            return
        print("=" * 72)
        print(" AUTHORIZATION REQUIRED")
        print("=" * 72)
        print(
            " This tool captures WiFi 4-way handshakes and PMKIDs and performs\n"
            " deauthentication attacks. These actions are ILLEGAL against\n"
            " networks you do not own or lack explicit written permission to test.\n\n"
            " You may only use this tool on networks you own or are explicitly\n"
            " authorized to audit. You are solely responsible for lawful use.\n"
        )
        try:
            answer = input(
                "Type YES to confirm you have authorization to test the target\n"
                "network(s), or anything else to abort: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            raise AuthorizationDeniedError("No authorization confirmation given.")
        if answer != "YES":
            raise AuthorizationDeniedError("Authorization denied by operator.")
        print("Authorization acknowledged. Proceeding.\n")

    def tool_report(self) -> dict[str, object]:
        """Report which Kali tools are present/missing (honest environment view)."""
        return {
            "available": sorted(self.registry.paths),
            "missing": self.registry.missing(),
        }

    # ------------------------------------------------------------------ #
    # One-shot operations (used by CLI subcommands)
    # ------------------------------------------------------------------ #
    def scan(self, interface: str, duration: int | None = None):
        return self.scanner.scan(interface, duration)

    def verify(self, capture_file: str):
        return self.verifier.verify_file(capture_file)

    def wps_assess(self, interface: str, channel: str | None = None):
        """Detect WPS APs and test each for the pixie-dust vulnerability."""
        return self.wps.assess(interface, channel=channel)

    def enforce_verification(self, capture_file: str):
        """Verify a file and, if it is NOT a genuine 4-way handshake, reject it.

        Rejected captures are moved to quarantine (NOT deleted) when
        ``quarantine_before_delete`` is set, so the evidence needed to reproduce
        a false rejection is preserved. ``delete_on_fail`` hard-deletes only when
        quarantine is off.
        """
        report = self.verifier.verify_file(capture_file)
        if report.passed:
            return report, False
        if self.config["verify"]["delete_on_fail"]:
            if self.config["verify"]["quarantine_before_delete"]:
                dst = constants.QUARANTINE_DIR / Path(capture_file).name
                shutil.move(capture_file, dst)
                log.info("quarantined non-handshake capture -> %s (retained)", dst)
            else:
                Path(capture_file).unlink(missing_ok=True)
                log.warning("DELETED %s: %s", Path(capture_file).name, report.reason)
        return report, True

    # ------------------------------------------------------------------ #
    # Full autonomous loop
    # ------------------------------------------------------------------ #
    def run_auto(self, interface: str, scan_duration: int | None = None) -> RunStats:
        self.check_root()
        self.require_authorization()
        self.adapter.unblock_rfkill()

        stats = RunStats()
        mon_iface = interface

        # Graceful shutdown on SIGINT: stop the current capture and reset the
        # adapter, then propagate so the caller can print a partial summary.
        interrupted = {"flag": False}
        prev_handler = signal.getsignal(signal.SIGINT)

        def _on_int(signum, frame):
            interrupted["flag"] = True
            sess = self._active_session
            if sess is not None:
                try:
                    sess.stop()
                except Exception:  # noqa: BLE001
                    pass
            log.warning("SIGINT received — stopping capture and cleaning up")

        signal.signal(signal.SIGINT, _on_int)

        try:
            return self._run_auto(mon_iface, scan_duration, stats, interrupted)
        finally:
            # Exception-safe cleanup: always attempt to restore the adapter,
            # regardless of where an unexpected exception escaped from.
            sess = self._active_session
            if sess is not None:
                try:
                    sess.stop()
                except Exception:  # noqa: BLE001
                    pass
                self._active_session = None
            self._cleanup_adapter_guarded()
            signal.signal(signal.SIGINT, prev_handler)

    def _run_auto(self, mon_iface, scan_duration, stats, interrupted) -> RunStats:
        interface = mon_iface

        # 1) Prepare adapter (monitor mode + injection check).
        if self.config["adapter"].get("auto_monitor", True):
            try:
                mon_iface = self.adapter.enable_monitor(
                    interface,
                    stop_services=bool(self.config["adapter"].get("stop_conflicting_services", True)),
                )
            except AdapterError as exc:
                stats.failures.append(str(exc))
                return stats
        else:
            log.info("auto_monitor disabled; assuming %s is already in monitor mode", interface)
        self._active_mon_iface = mon_iface

        # Injection gate: if the test fails, active deauth is disabled (passive
        # capture only) rather than pretending injection works.
        if self.config["adapter"]["check_injection"]:
            self._injection_ok = self.adapter.check_injection(mon_iface)
            if not self._injection_ok:
                log.warning("injection test FAILED — active deauth disabled for this run")

        # 2) Scan (adaptive two-pass when configured, else single pass).
        if self.config["scan"].get("adaptive", False) and scan_duration is None:
            scan = self.scanner.scan_adaptive(mon_iface)
        else:
            scan = self.scanner.scan(mon_iface, scan_duration)
        stats.targets_scanned = len(scan.aps)
        if not scan.aps:
            log.warning("No APs found during scan.")
            return stats

        targets = self.strategist.prioritize(scan)
        log.info("Prioritized %d target(s): %s",
                 len(targets), [t.essid or t.bssid for t in targets])

        # Optional NIM hint (validated, never authoritative).
        nim_hint = self.nim.suggest_strategy(self._context(scan)) if self.nim.available else None

        # WPS assessment (optional, runs before deauth so it never contends for
        # the channel with handshake capture).
        if self.config.get("wps", {}).get("enabled", False):
            self._assess_wps(mon_iface, targets, stats)

        candidates = self.strategist.candidate_actions()
        if not candidates:
            # PMKID / passive capture does not need a deauth engine. Aborting
            # the whole run here used to skip clientless captures entirely.
            if not self.config["pmkid"]["enabled"]:
                log.error("No deauth tools installed (need aireplay-ng/mdk4/bettercap/scapy).")
                return stats
            log.warning("No deauth tools installed; continuing with PMKID/passive capture only.")

        session_id = self.db.start_session(interface, env=self._env_fingerprint())

        # 3) Per-target loop (analysis- and strategy-driven).
        for ap in targets:
            if interrupted["flag"]:
                log.warning("Interrupted — stopping before next target")
                break
            self._process_target(mon_iface, ap, scan, candidates, nim_hint, stats, session_id)

        self.store.save()
        status = "interrupted" if interrupted["flag"] else "ok"
        self.db.finish_session(session_id, status)
        return stats

    def _env_fingerprint(self) -> str:
        """A compact JSON snapshot of the environment that influences action
        success (tool versions + config hash). Stored with the session so that
        historical learning can be judged against the environment it came from —
        not treated as comparable across driver/tool/kernel upgrades."""
        import hashlib
        import json
        import platform

        tools = {}
        for name, path in sorted(self.registry.paths.items()):
            # Record the tool's version (best-effort; empty if it can't report).
            try:
                from ..utils.proc import run as _run
                res = _run([path, "--version"], timeout=10, check=False)
                ver = (res.stdout or res.stderr or "").strip().splitlines()[0][:120]
            except Exception:  # noqa: BLE001
                ver = ""
            tools[name] = ver

        cfg_hash = hashlib.sha256(
            json.dumps(self.config, sort_keys=True, default=str).encode()).hexdigest()[:16]
        return json.dumps({
            "handshaker": __version__,
            "kernel": platform.release(),
            "config_hash": cfg_hash,
            "tools": tools,
        })

    def _assess_wps(self, mon_iface: str, targets, stats: RunStats) -> None:
        """Run WPS assessment for each target (only WPS-enabled APs)."""
        try:
            aps = self.wps.detect(mon_iface)
        except Exception as exc:  # noqa: BLE001
            stats.failures.append(f"wps detect: {exc}")
            return
        if not aps:
            log.info("WPS: no WPS-enabled APs detected")
            return
        for ap in aps:
            stats.wps_assessed += 1
            verdict = self.wps.assess_one(mon_iface, ap)
            if verdict.vulnerable:
                stats.wps_vulnerable += 1
                log.info("WPS: %s VULNERABLE (%s)", ap.essid or ap.bssid, verdict.status)
            else:
                log.info("WPS: %s not vulnerable (%s)", ap.essid or ap.bssid, verdict.status)

    # ------------------------------------------------------------------ #
    def _process_target(self, mon_iface, ap, scan, candidates, nim_hint, stats, session_id) -> None:
        stats.targets_attacked += 1
        self.store.ensure_ap(ap.bssid, essid=ap.essid, channel=ap.channel,
                             security=ap.security_label,
                             vendor=self.strategist._vendor_oui(ap.bssid),
                             band=ap.band)
        self.db.record_target(session_id, ap.bssid, ap.essid, ap.channel, ap.security_label)

        strategy = self.strategist.strategy_for(ap, scan)
        log.info("Target %s: %s (%s)", ap.essid or ap.bssid, strategy.summary,
                 "; ".join(strategy.reasons) or "client-deauth handshake")

        # Choose a deauth action (learning-driven, or NIM-hinted burst).
        # Empty candidates (no deauth engine) must not call choose_action —
        # that raises ValueError and used to abort PMKID-only runs.
        if candidates:
            decision = self.strategist.choose_action(ap.bssid, candidates, ap=ap)
            action = decision.action
            if nim_hint and nim_hint.burst_size:
                action = ActionKey(action.tool, nim_hint.burst_size, action.reason)
            # NIM deauth_tool is only honoured if it is a REAL, available deauth
            # engine (hcxdumptool is not a deauth engine and must be ignored).
            valid_deauth = set(self.strategist.available_deauth_tools())
            if nim_hint and nim_hint.deauth_tool and nim_hint.deauth_tool in valid_deauth:
                action = ActionKey(nim_hint.deauth_tool, action.burst, action.reason)
            log.info("  action: %s (%s)", action.id, decision.reason)
        else:
            action = ActionKey("none", 1, 7)
            log.info("  action: none (no deauth engine available; passive/PMKID only)")

        # NIM prefer_pmkid is an untrusted hint: honour True only, never force
        # handshake-only when the strategist chose PMKID from measured facts.
        if nim_hint and nim_hint.prefer_pmkid is True:
            strategy.prefer_pmkid = True
        if nim_hint and nim_hint.dwell_seconds:
            self._dwell_override = float(nim_hint.dwell_seconds)
        else:
            self._dwell_override = None

        # --- PMKID-first path (clientless targets). ---------------------- #
        if strategy.prefer_pmkid and self.config["pmkid"]["enabled"]:
            # Record PMKID outcome on the SEPARATE pmkid track (a PMKID capture
            # is not a handshake and must not be rewarded as the deauth action).
            got = self._try_pmkid(mon_iface, ap, stats)
            self.store.record_pmkid(ap.bssid, got)
            # Still attempt a handshake capture passively afterward; that path
            # records the deauth action's handshake outcome exactly once.
            self._capture_handshake(mon_iface, ap, action, None, stats, session_id)
            return

        # --- Handshake path: capture + strategic, client-targeted deauth. #
        self._capture_handshake(mon_iface, ap, action, scan, stats, session_id)

    def _round_budget(self, ap: AccessPoint) -> int:
        """Per-target capture-round budget, learned from measured history.

        APs that historically failed (and never succeeded) get fewer rounds —
        further airtime is unlikely to help — while APs with any prior success
        keep the full budget. Cold APs get the configured default.
        """
        max_rounds = int(self.config["capture"].get("max_rounds", 3))
        actions = self.store.actions_for(ap.bssid)
        if not actions:
            return max_rounds
        any_success = any(a.get("success") for a in actions)
        if any_success:
            return max_rounds
        # Proven-hard AP: give it at most 1 round (don't waste the campaign).
        return min(max_rounds, 1)

    def _prefer_engine(self, ap: AccessPoint) -> str | None:
        """Choose the capture engine that has *proven* to work for this AP.

        Consults the learned per-AP engine success rates; prefers the engine
        with a clearly higher rate once it has enough trials, otherwise falls
        back to the default (hcxdumptool → airodump). Returns None to use the
        capturer's own default.
        """
        hcx = self.store.engine_success(ap.bssid, "hcxdumptool")
        airo = self.store.engine_success(ap.bssid, "airodump")
        min_trials = 2
        if hcx["trials"] >= min_trials and airo["trials"] >= min_trials:
            # Both proven: prefer the clearly better one.
            if hcx["rate"] > airo["rate"] + 0.2:
                return "hcxdumptool"
            if airo["rate"] > hcx["rate"] + 0.2:
                return "airodump"
        elif hcx["trials"] >= min_trials and hcx["rate"] < 0.3:
            # hcxdumptool consistently failed → try airodump.
            return "airodump"
        elif airo["trials"] >= min_trials and airo["rate"] < 0.3:
            return "hcxdumptool"
        return None

    def _adaptive_wait(self, ap: AccessPoint, default: float = 2.0) -> float:
        """Post-deauth verify-wait adapted to the AP's measured reconnect latency.

        Uses the learned mean latency (+ margin) so we don't give up before a
        slow client re-authenticates, nor over-wait for a fast one. Bounded to
        [default, 15s] so a single bad reading can't stall the campaign.
        """
        override = getattr(self, "_dwell_override", None)
        if override is not None:
            return max(default, min(60.0, float(override)))
        learned = self.store.latency_seconds(ap.bssid)
        if learned is None:
            return default
        return max(default, min(15.0, learned * 1.5 + 1.0))

    def _capture_handshake(self, mon_iface, ap, action, scan, stats, session_id) -> None:
        """Capture + analysis-guided deauth + verification, in rounds.

        Runs up to a learned per-target round budget, stopping early as soon as
        a genuine 4-way handshake is verified. Uses adaptive post-deauth waits
        and computes a graded reward for the learner.
        """
        max_rounds = self._round_budget(ap)
        log.info("budget %d round(s) for %s", max_rounds, ap.essid or ap.bssid)

        # Aim deauth at the most active client (Wireshark-driven targeting).
        client = None
        if scan is not None:
            clients = scan.clients_of(ap.bssid)
            if clients:
                client = clients[0].station_mac

        success = False
        best_quality = 0.0
        deauth_frames = 0
        rounds_taken = 0
        for round_i in range(1, max_rounds + 1):
            rounds_taken = round_i
            log.info("round %d/%d for %s", round_i, max_rounds, ap.essid or ap.bssid)

            # Learned engine preference (falls back to hcxdumptool → airodump).
            preferred = self._prefer_engine(ap)
            try:
                session = self.capturer.start(mon_iface, ap.bssid, ap.channel,
                                              essid=ap.essid, engine=preferred)
            except Exception as exc:  # noqa: BLE001
                stats.failures.append(f"capture start {ap.bssid}: {exc}")
                break
            self._active_session = session

            # Crash detection: a capture process that died immediately (nonzero
            # exit) is a *different* signal from "ran but no handshake". Brief
            # wait so a process that fails on startup is actually observed.
            time.sleep(0.2)
            capture_started_at = time.monotonic()
            if session.crashed:
                stats.failures.append(
                    f"capture process crashed for {ap.bssid} (exit {session.exit_code})")
                self.store.record_capture_engine(ap.bssid, session.engine, False)
                self._active_session = None
                break

            # Deauth gate: only run active deauth when it's enabled AND injection
            # was confirmed AND we actually have a deauth engine. Otherwise
            # capture is passive only.
            deauth_done_at = None
            can_deauth = (self.config["deauth"].get("enabled", True)
                          and self._injection_ok
                          and action.tool != "none")
            if can_deauth:
                try:
                    results = self.deauther.campaign(
                        mon_iface, ap.bssid, action,
                        client=client, channel=ap.channel,
                        fallback_tools=self.strategist.available_deauth_tools(),
                    )
                    deauth_done_at = time.monotonic()
                    # Count only *successful* deauth bursts (campaign returns
                    # successful results only), for the stealth bonus.
                    deauth_frames += len(results) * action.burst
                except Exception as exc:  # noqa: BLE001
                    stats.failures.append(f"deauth {ap.bssid}: {exc}")
            else:
                log.info("active deauth skipped (enabled=%s, injection_ok=%s, tool=%s)",
                         self.config["deauth"].get("enabled", True), self._injection_ok,
                         action.tool)

            # Adaptive verify-wait (learned reconnection latency).
            time.sleep(self._adaptive_wait(ap))
            session.stop()
            self._active_session = None

            # Measure deauth → first-EAPOL latency (NOT capture-start → EAPOL).
            # ``first_eapol_time`` is relative to capture start; we subtract the
            # measured deauth offset from capture start to get the *reconnection*
            # latency the adaptive-wait actually wants.
            files = self.capturer.output_files(session)
            if files and deauth_done_at is not None:
                lat_rel = self.analyzer.first_eapol_time(str(files[0]))
                if lat_rel is not None:
                    deauth_offset = deauth_done_at - capture_started_at
                    reconn = max(0.0, lat_rel - deauth_offset)
                    self.store.record_latency(ap.bssid, reconn)

            # Refine client targeting from the just-captured traffic. The
            # refined deauth runs inside a *fresh* capture session so the new
            # handshake is actually captured (previously it ran after stop()).
            refined = self._refine_client(session, ap.bssid, client)
            if refined and refined != client and can_deauth:
                log.info("analyzer: re-targeting deauth at most active client %s", refined)
                client = refined
                try:
                    session2 = self.capturer.start(mon_iface, ap.bssid, ap.channel,
                                                   essid=ap.essid, engine=preferred)
                    self._active_session = session2
                    self.deauther.campaign(
                        mon_iface, ap.bssid, action, client=client, channel=ap.channel,
                        max_bursts=max(1, int(self.config["deauth"]["max_bursts"]) // 2),
                    )
                    time.sleep(self._adaptive_wait(ap))
                    session2.stop()
                    files.extend(self.capturer.output_files(session2))
                except Exception as exc:  # noqa: BLE001
                    stats.failures.append(f"refined deauth {ap.bssid}: {exc}")
                finally:
                    self._active_session = None

            # Verify and enforce.
            if not files:
                stats.failures.append(f"no capture output for {ap.bssid} (round {round_i})")
                self.store.record_capture_engine(ap.bssid, session.engine, False)
                continue
            for f in files:
                report, _deleted = self.enforce_verification(str(f))
                self.db.record_capture(session_id, ap.bssid, str(f), report.passed, report.reason)
                q = max((handshake_quality(e) for e in report.evidence), default=0.0)
                best_quality = max(best_quality, q)
                if report.passed:
                    stats.handshakes_captured += 1
                    stats.verified_files.append(str(f))
                    shutil.move(str(f), constants.HANDSHAKES_DIR / f.name)
                    success = True
                else:
                    stats.handshakes_rejected += 1
            # Learn engine-choice outcome using the ACTUAL engine the session
            # used (not the requested one — Capturer may silently fall back).
            self.store.record_capture_engine(ap.bssid, session.engine, success)
            if success:
                break

        # PMF / 802.11w fallback: if classic deauth failed every round, try
        # hcxdumptool's OWN attack vectors (which work on MFP networks where
        # old-school deauthentication fails). Config-gated.
        if not success and self.config["capture"].get("pmf_fallback", True):
            if self.registry.has("hcxdumptool"):
                log.info("PMF fallback: hcxdumptool full-attack for %s", ap.essid or ap.bssid)
                success = self._pmf_fallback_capture(mon_iface, ap, stats, session_id)

        # Graded reward (measured quality + speed + stealth), learned once.
        reward = graded_reward(quality=best_quality, rounds_taken=rounds_taken,
                               deauth_frames=deauth_frames, success=success)
        self.store.record(ap.bssid, action, success=success, reward=reward)
        self.db.record_action(session_id, ap.bssid, action.tool, action.burst,
                              action.reason, success)
        if success:
            log.info("✓ Handshake verified & stored for %s (quality %.2f)",
                     ap.essid or ap.bssid, best_quality)
        else:
            log.info("✗ No verified handshake for %s after %d round(s) (reward %.2f)",
                     ap.essid or ap.bssid, max_rounds, reward)

    def _pmf_fallback_capture(self, mon_iface, ap, stats, session_id) -> bool:
        """Last-resort capture using hcxdumptool's own (MFP-aware) attack mode.

        Returns True only if a genuine 4-way handshake is verified.
        """
        try:
            session = self.capturer.start(mon_iface, ap.bssid, ap.channel,
                                          essid=ap.essid, full_attack=True)
        except Exception as exc:  # noqa: BLE001
            stats.failures.append(f"pmf fallback capture {ap.bssid}: {exc}")
            return False
        self._active_session = session
        try:
            time.sleep(3)
            session.stop()
        finally:
            self._active_session = None

        files = self.capturer.output_files(session)
        if not files:
            stats.failures.append(f"no pmf-fallback output for {ap.bssid}")
            return False
        success = False
        for f in files:
            report, _deleted = self.enforce_verification(str(f))
            self.db.record_capture(session_id, ap.bssid, str(f), report.passed, report.reason)
            if report.passed:
                stats.handshakes_captured += 1
                stats.verified_files.append(str(f))
                shutil.move(str(f), constants.HANDSHAKES_DIR / f.name)
                success = True
            else:
                stats.handshakes_rejected += 1
        return success

    def _refine_client(self, session, bssid: str, current: str | None) -> str | None:
        """Use tshark analysis on the captured traffic to pick a better deauth
        target than the scan-time guess (best active client)."""
        files = self.capturer.output_files(session)
        if not files:
            return current
        try:
            analysis = self.analyzer.analyze(str(files[0]), bssid)
        except Exception:  # noqa: BLE001
            return current
        if not analysis.ok:
            return current
        best = analysis.best_client()
        if best and best.mac != current:
            return best.mac
        return current

    def _try_pmkid(self, mon_iface: str, ap: AccessPoint, stats: RunStats) -> bool:
        """Attempt a PMKID capture; only count it when a real ``WPA*01*`` line
        is present in the converted 22000 output (never a handshake line)."""
        duration = int(self.config["capture"].get("pmkid_duration", 45))
        try:
            cap = self.pmkid.capture(mon_iface, ap.bssid, ap.channel, duration=duration)
            if cap:
                converted = self.pmkid.convert(str(cap))
                if converted:
                    n_pmkid, _n_eapol = self.pmkid.count_22000_types(str(converted))
                    if n_pmkid > 0:
                        stats.pmkids_captured += 1
                        log.info("PMKID captured for %s -> %s (%d PMKID line(s))",
                                 ap.essid or ap.bssid, converted, n_pmkid)
                        return True
                    log.info("No PMKID for %s (conversion had no WPA*01* lines)",
                             ap.essid or ap.bssid)
        except Exception as exc:  # noqa: BLE001
            stats.failures.append(f"pmkid {ap.bssid}: {exc}")
        return False

    def _context(self, scan) -> dict:
        """Build the measured context handed to NIM.

        Privacy boundary: unless ``nim.send_sensitive_context`` is explicitly
        enabled, BSSID and ESSID are pseudonymized (deterministic hash) before
        leaving the machine — a scan can contain identifying information about
        nearby networks, and it must never be sent to a remote endpoint by
        default. The pseudonymization is deterministic so the same AP maps to
        the same id within a run, without revealing its identity.
        """
        import hashlib
        sensitive = bool(self.config["nim"].get("send_sensitive_context", False))
        aps = []
        for a in list(scan.aps.values())[:20]:
            if sensitive:
                bssid, essid = a.bssid, a.essid
            else:
                bssid = hashlib.sha256(a.bssid.encode()).hexdigest()[:16]
                essid = (hashlib.sha256(a.essid.encode()).hexdigest()[:12]
                         if a.essid else "")
            aps.append({
                "bssid": bssid, "essid": essid, "channel": a.channel,
                "security": a.security_label, "signal": a.power,
                "clients": len(scan.clients_of(a.bssid)),
            })
        return {"aps": aps, "tools": sorted(self.registry.paths)}

    def _cleanup_adapter_guarded(self) -> None:
        """Restore the adapter exactly once, guarding against every exception.

        Called from ``run_auto``'s finally block so adapter state is restored
        even when an unexpected exception escapes mid-campaign.
        """
        if not self.config["adapter"].get("reset_on_exit", True):
            return
        if not self._active_mon_iface:
            return
        try:
            self.adapter.reset(self._active_mon_iface)
        except Exception as exc:  # noqa: BLE001
            log.warning("Adapter reset failed: %s", exc)
        finally:
            self._active_mon_iface = None


def exit_code_for(stats: RunStats | None, exception: Exception | None) -> int:
    if exception is not None:
        if isinstance(exception, NotRootError):
            return EXIT_NOT_ROOT
        if isinstance(exception, AuthorizationDeniedError):
            return EXIT_AUTH_DENIED
        if isinstance(exception, NoAdapterError):
            return EXIT_NO_ADAPTER
        return EXIT_CAPTURE_FAILED
    if stats is None:
        return EXIT_CAPTURE_FAILED
    if stats.handshakes_captured > 0 or stats.pmkids_captured > 0:
        return EXIT_OK
    return EXIT_VERIFY_FAILED
