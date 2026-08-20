"""Command-line interface.

Subcommands:

    adapter   manage monitor mode / injection test / reset
    scan      discover nearby APs
    capture   autonomous handshake+PMKID capture (scan -> deauth -> verify -> learn)
    pmkid     capture/convert PMKIDs
    verify    strongly verify a capture is a genuine 4-way handshake
    tools     report which Kali tools are installed / missing
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .config import load_config
from .constants import (
    EXIT_AUTH_DENIED,
    EXIT_CAPTURE_FAILED,
    EXIT_NOT_ROOT,
    EXIT_OK,
    EXIT_TOOL_MISSING,
    EXIT_VERIFY_FAILED,
)
from .core.engine import Engine, exit_code_for
from .exceptions import (
    AuthorizationDeniedError,
    ConfigError,
    HandshakerError,
    NotRootError,
    ToolNotFoundError,
)
from .utils.logging import configure_logging


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="handshaker",
        description="Autonomous WiFi 4-way handshake & PMKID capturer "
                    "(authorized security testing only; capture only — no cracking).",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-c", "--config", help="path to config.yaml")
    p.add_argument("-i", "--interface", help="wireless interface (default: auto-detect)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")

    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("adapter", help="manage monitor mode / injection test / reset")

    scan = sub.add_parser("scan", help="discover nearby APs")
    scan.add_argument("--duration", type=int, default=None, help="scan seconds")
    scan.add_argument("--json", action="store_true", help="machine-readable output")

    cap = sub.add_parser("capture", help="autonomous capture (scan+deauth+verify+learn)")
    cap.add_argument("--scan-duration", type=int, default=None)
    cap.add_argument("--json", action="store_true", help="machine-readable output")
    cap.add_argument("--loop", action="store_true",
                     help="repeat scan+capture until interrupted (long-run mode)")
    cap.add_argument("--loop-interval", type=int, default=30,
                     help="seconds between loop iterations (default 30)")

    pmkid = sub.add_parser("pmkid", help="capture or convert PMKIDs")
    pmkid.add_argument("--bssid", help="target BSSID")
    pmkid.add_argument("--channel", type=int, help="target channel")
    pmkid.add_argument("--convert", metavar="FILE", help="convert existing capture to 22000")

    verify = sub.add_parser("verify", help="verify a capture is a 4-way handshake")
    verify.add_argument("file", nargs="?", help="capture file (.pcap/.pcapng)")
    verify.add_argument("--dir", metavar="DIR",
                        help="verify every .cap/.pcap/.pcapng in a directory")
    verify.add_argument("--json", action="store_true", help="machine-readable output")

    analyze = sub.add_parser("analyze", help="deep-analyze a capture (capinfos + tshark + client activity)")
    analyze.add_argument("file", help="capture file (.pcap/.pcapng)")
    analyze.add_argument("--bssid", help="target BSSID to analyze")
    analyze.add_argument("--gui", action="store_true", help="also open in Wireshark GUI")
    analyze.add_argument("--json", action="store_true", help="machine-readable output")

    wps = sub.add_parser("wps", help="assess WPS vulnerability (detect + attack tests)")
    wps.add_argument("--channel", help="restrict to a single channel")
    wps.add_argument("--detect-only", action="store_true",
                     help="only list WPS-enabled APs (skip attack tests)")
    wps.add_argument("--pixie-force", action="store_true",
                     help="also run pixie-force (full-range offline brute)")
    wps.add_argument("--pixie-loop", action="store_true",
                     help="also run pixie-loop (hash collection)")
    wps.add_argument("--push-button", action="store_true",
                     help="also run push-button connect (PBC) test")
    wps.add_argument("--json", action="store_true", help="machine-readable output")

    sub.add_parser("tools", help="report installed/missing Kali tools")

    doctor = sub.add_parser("doctor", help="system self-check (OS/tools/python/API key)")
    doctor.add_argument("--check-api-key", action="store_true",
                        help="live-validate the NIM API key")
    doctor.add_argument("--check-injection", action="store_true",
                        help="run an injection test (needs root + adapter)")
    doctor.add_argument("--json", action="store_true",
                        help="machine-readable JSON output")

    selftest = sub.add_parser("selftest", help="guided hardware validation (root/tools/adapter/scan/capture)")
    selftest.add_argument("--capture", action="store_true",
                          help="also capture + verify the strongest AP (your own network)")
    selftest.add_argument("--wps", action="store_true",
                          help="also run WPS detection (wash)")
    selftest.add_argument("--json", action="store_true",
                          help="machine-readable JSON output")

    report = sub.add_parser("report", help="show captured artifacts + learning state")
    report.add_argument("--json", action="store_true", help="machine-readable JSON output")

    export = sub.add_parser("export", help="bundle handshakes + PMKIDs + report into an archive dir")
    export.add_argument("--out", help="output directory (default: current dir)")

    sub.add_parser("menu", help="interactive TUI launcher over all commands")
    return p


def _report_tools(engine: Engine) -> int:
    rep = engine.tool_report()
    print("Available tools:")
    for t in rep["available"]:
        print(f"  [x] {t}")
    print("\nMissing tools:")
    for t in rep["missing"]:
        print(f"  [ ] {t}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CAPTURE_FAILED
    configure_logging("DEBUG" if args.verbose else config["general"]["log_level"])

    try:
        engine = Engine(config)

        if args.command == "tools":
            return _report_tools(engine)

        if args.command == "doctor":
            return _cmd_doctor(engine, args)

        if args.command == "selftest":
            return _cmd_selftest(engine, args)

        if args.command == "report":
            return _cmd_report(engine, args)

        if args.command == "export":
            return _cmd_export(engine, args)

        if args.command == "adapter":
            return _cmd_adapter(engine, args)

        if args.command == "scan":
            return _cmd_scan(engine, args)

        if args.command == "capture":
            return _cmd_capture(engine, args)

        if args.command == "pmkid":
            return _cmd_pmkid(engine, args)

        if args.command == "verify":
            return _cmd_verify(engine, args)

        if args.command == "analyze":
            return _cmd_analyze(engine, args)

        if args.command == "wps":
            return _cmd_wps(engine, args)

        if args.command == "menu":
            return _cmd_menu(args)

    except HandshakerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if isinstance(exc, NotRootError):
            return EXIT_NOT_ROOT
        if isinstance(exc, AuthorizationDeniedError):
            return EXIT_AUTH_DENIED
        if isinstance(exc, ToolNotFoundError):
            return EXIT_TOOL_MISSING
        return EXIT_CAPTURE_FAILED
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130

    return EXIT_OK


def _requested_iface(engine: Engine, args) -> str | None:
    """CLI ``-i`` wins; otherwise honour ``general.interface`` from config."""
    cli = getattr(args, "interface", None)
    if cli:
        return cli
    return engine.config["general"].get("interface")


def _with_monitor(engine: Engine, requested: str | None, fn):
    """Enable monitor mode, run ``fn(mon_iface)``, optionally restore after.

    Scan / WPS / PMKID all require monitor mode; previously those CLI commands
    ran airodump/wash/hcxdumptool on a managed interface and failed.
    """
    engine.check_root()
    iface = engine.adapter.select_interface(requested)
    stop = bool(engine.config["adapter"].get("stop_conflicting_services", True))
    if engine.config["adapter"].get("auto_monitor", True):
        mon = engine.adapter.enable_monitor(iface, stop_services=stop)
    else:
        mon = iface
    try:
        return fn(mon)
    finally:
        if engine.config["adapter"].get("reset_on_exit", True):
            try:
                engine.adapter.reset(mon)
            except Exception:  # noqa: BLE001
                pass


def _cmd_adapter(engine: Engine, args) -> int:
    engine.check_root()
    iface = engine.adapter.select_interface(_requested_iface(engine, args))
    print(f"Interface: {iface}")
    print(f"Monitor mode: {engine.adapter.is_monitor(iface)}")
    mon = iface
    if not engine.adapter.is_monitor(iface):
        mon = engine.adapter.enable_monitor(iface)
        print(f"Enabled monitor mode: {mon}")
    if engine.config["adapter"]["check_injection"]:
        print(f"Injection working: {engine.adapter.check_injection(mon)}")
    return EXIT_OK


def _cmd_scan(engine: Engine, args) -> int:
    from .tui import UI, render_scan

    result = _with_monitor(engine, _requested_iface(engine, args),
                           lambda mon: engine.scan(mon, args.duration))
    ui = UI()
    if args.json:
        ui.json({
            "count": len(result.aps),
            "aps": [
                {"bssid": a.bssid, "channel": a.channel, "signal": a.power,
                 "security": a.security_label, "essid": a.essid,
                 "clients": len(result.clients_of(a.bssid))}
                for a in sorted(result.aps.values(), key=lambda x: x.power, reverse=True)
            ],
        })
    else:
        render_scan(ui, result)
    return EXIT_OK


def _cmd_capture(engine: Engine, args) -> int:
    from .tui import UI, render_run_summary

    iface = engine.adapter.select_interface(_requested_iface(engine, args))
    ui = UI()
    stats = None
    exc = None

    if not args.loop:
        try:
            stats = engine.run_auto(iface, args.scan_duration)
        except HandshakerError as e:
            exc = e
            print(f"error: {e}", file=sys.stderr)
    else:
        # Long-run mode: repeat scan+capture until interrupted, accumulating
        # learning across iterations (state persists in data/learning/).
        import time as _time
        iteration = 0
        if not args.json:
            ui.info(f"Long-run mode: scanning every {args.loop_interval}s (Ctrl-C to stop)")
        try:
            while True:
                iteration += 1
                if not args.json:
                    ui.info(f"--- iteration {iteration} ---")
                stats = engine.run_auto(iface, args.scan_duration)
                if stats is not None and not args.json:
                    render_run_summary(ui, stats)
                _time.sleep(args.loop_interval)
        except KeyboardInterrupt:
            if not args.json:
                ui.info(f"\nStopped after {iteration} iteration(s).")
            else:
                print(f"Stopped after {iteration} iteration(s).", file=sys.stderr)

    if stats is not None:
        if args.json:
            ui.json(stats.to_dict())
        elif not args.loop:
            render_run_summary(ui, stats)
    return exit_code_for(stats, exc)


def _cmd_pmkid(engine: Engine, args) -> int:
    if args.convert:
        # Conversion is a file operation; it does not need root or monitor mode.
        out = engine.pmkid.convert(args.convert)
        print(f"Converted -> {out}" if out else "No 22000 lines produced.")
        return EXIT_OK
    if not args.bssid or not args.channel:
        print("error: --bssid and --channel are required for PMKID capture.", file=sys.stderr)
        return EXIT_CAPTURE_FAILED
    out = _with_monitor(
        engine, _requested_iface(engine, args),
        lambda mon: engine.pmkid.capture(mon, args.bssid, args.channel),
    )
    print(f"PMKID capture -> {out}" if out else "No PMKID captured.")
    return EXIT_OK


def _cmd_verify(engine: Engine, args) -> int:
    from pathlib import Path
    from .tui import UI, render_verify

    ui = UI()
    if args.dir:
        root = Path(args.dir)
        if not root.is_dir():
            print(f"error: not a directory: {root}", file=sys.stderr)
            return EXIT_CAPTURE_FAILED
        files = sorted(
            p for p in root.iterdir()
            if p.is_file() and p.suffix.lower() in {".cap", ".pcap", ".pcapng"}
        )
        reports = [engine.verify(str(p)) for p in files]
        if args.json:
            ui.json({
                "dir": str(root),
                "count": len(reports),
                "passed": sum(1 for r in reports if r.passed),
                "reports": [r.to_dict() for r in reports],
            })
        else:
            ui.title(f"Batch verify — {len(files)} file(s)")
            for r in reports:
                render_verify(ui, r)
        return EXIT_OK if reports and all(r.passed for r in reports) else EXIT_VERIFY_FAILED
    if not args.file:
        print("error: provide a capture file or --dir", file=sys.stderr)
        return EXIT_CAPTURE_FAILED
    report = engine.verify(args.file)
    if args.json:
        ui.json(report.to_dict())
    else:
        render_verify(ui, report)
    return EXIT_OK if report.passed else EXIT_VERIFY_FAILED


def _cmd_analyze(engine: Engine, args) -> int:
    """Deep-analyze a capture: capinfos metadata + tshark EAPOL + client activity.

    Wires capinfos, the analyzer, and (optionally) the Wireshark GUI into a real
    workflow — previously these wrappers existed but were never invoked.
    """
    from .tui import UI

    ui = UI()
    result: dict = {"file": args.file}

    # 1) capinfos metadata (packet count, duration).
    if engine.registry.has("capinfos"):
        res = engine.registry.capinfos().info(args.file)
        from .core.verifier import parse_capinfos_packets
        packets = parse_capinfos_packets(res)
        result["packets"] = packets
        if packets is not None and not args.json:
            ui.info(f"capinfos: {packets} packet(s)")

    # 2) tshark EAPOL + client activity analysis.
    bssid = args.bssid
    if not bssid:
        # Default to the first BSSID with EAPOL traffic, if any.
        report = engine.verify(args.file)
        if report.evidence:
            bssid = report.evidence[0].bssid
    if bssid:
        analysis = engine.analyzer.analyze(args.file, bssid)
        result["bssid"] = bssid
        result["analysis"] = {
            "eapol_frames": analysis.eapol_count,
            "beacons": analysis.beacon_count,
            "probe_requests": analysis.probe_req_count,
            "data_frames": analysis.data_count,
            "clients": [c.mac for c in analysis.clients],
        }
        if not args.json:
            ui.table(
                ["BSSID", "EAPOL", "Beacons", "Probes", "Data", "Clients"],
                [[bssid, analysis.eapol_count, analysis.beacon_count,
                  analysis.probe_req_count, analysis.data_count, len(analysis.clients)]],
                title="Capture analysis",
            )

    # 3) optional Wireshark GUI (skipped in --json so scripted output stays clean).
    if args.gui and engine.registry.has("wireshark") and not args.json:
        ui.info(f"Opening Wireshark on {args.file} …")
        engine.registry.wireshark().open(args.file)

    if args.json:
        ui.json(result)
    return EXIT_OK


def _cmd_doctor(engine: Engine, args) -> int:
    from .doctor import Doctor
    from .tui import UI, render_doctor

    doc = Doctor(engine.config)
    report = doc.run(check_api_key=args.check_api_key,
                     check_injection=args.check_injection)
    ui = UI()
    if args.json:
        ui.json(report.to_dict())
    else:
        render_doctor(ui, report)
    return EXIT_OK if report.core_ready else EXIT_TOOL_MISSING


def _cmd_selftest(engine: Engine, args) -> int:
    from .core.selftest import SelfTester
    from .tui import UI

    ui = UI()
    tester = SelfTester(engine)
    rep = tester.run(do_capture=args.capture, do_wps=args.wps)

    if args.json:
        ui.json(rep.to_dict())
    else:
        ui.title("Hardware self-test (run on networks you own)")
        rows = [[s.name, s.status, s.detail] for s in rep.steps]
        ui.table(["Step", "Result", "Detail"], rows)
        if rep.passed:
            ui.status("Overall", True, "all steps passed")
        else:
            ui.error("Overall: some steps failed — see above")

    return EXIT_OK if rep.passed else EXIT_CAPTURE_FAILED


def _cmd_report(engine: Engine, args) -> int:
    from . import constants
    from .core.report import build_report
    from .tui import UI

    ui = UI()
    rep = build_report(engine.store, engine.db, wps_path=constants.LEARNING_DIR / "wps.json")

    if args.json:
        ui.json(rep.to_dict())
    else:
        ui.title("Project report")
        ui.table(["Metric", "Value"], [
            ["Verified handshakes", len(rep.handshakes)],
            ["PMKID conversions", len(rep.pmkids)],
            ["Sessions", rep.sessions],
            ["Captures recorded", rep.captures_recorded],
            ["Captures verified", rep.verified_captures],
            ["WPS records", rep.wps_records],
        ])
        if rep.handshakes:
            ui.info("Stored handshakes:")
            for h in rep.handshakes:
                ui.info(f"  - {h}")
        if rep.learned_aps:
            ui.table(["BSSID", "ESSID", "Security", "Band", "Handshake acts", "PMKID rate"],
                     [[a["bssid"], a["essid"], a["security"], a["band"],
                       a["handshake_actions"], a["pmkid_rate"]] for a in rep.learned_aps],
                     title="Learned access points")
    return EXIT_OK


def _cmd_export(engine: Engine, args) -> int:
    from . import constants
    from .core.report import bundle_results
    from .tui import UI

    ui = UI()
    bundle = bundle_results(engine.store, engine.db,
                            out_dir=args.out, wps_path=constants.LEARNING_DIR / "wps.json")
    ui.status("Exported bundle", True, str(bundle))
    return EXIT_OK


def _cmd_menu(args) -> int:
    """Launch the interactive TUI menu (dispatches to launcher.main)."""
    from .launcher import Launcher
    return Launcher(interface=args.interface, config=args.config).run()


def _cmd_wps(engine: Engine, args) -> int:
    from .core.wps import WpsAssessor
    from .tui import UI, render_wps

    assessor = WpsAssessor(engine.registry, engine.config)

    # Optional per-run toggles override config.
    if args.pixie_force:
        assessor.config["pixie_force"] = True
    if args.pixie_loop:
        assessor.config["pixie_loop"] = True
    if args.push_button:
        assessor.config["push_button"] = True

    ui = UI()

    def _run(mon: str):
        aps = assessor.detect(mon, channel=args.channel)
        if not aps:
            return [], []
        if args.detect_only:
            return aps, []
        return aps, [assessor.assess_one(mon, ap) for ap in aps]

    aps, verdicts = _with_monitor(engine, _requested_iface(engine, args), _run)
    if not aps:
        if args.json:
            ui.json({"verdicts": [], "aps": []})
        else:
            ui.info("No WPS-enabled access points detected.")
        return EXIT_OK

    if args.detect_only:
        if args.json:
            ui.json({"aps": [ap.summary() for ap in aps]})
        else:
            for ap in aps:
                ui.info(f"  {ap.summary()}")
        return EXIT_OK

    if args.json:
        ui.json({"verdicts": [v.to_dict() for v in verdicts]})
    else:
        render_wps(ui, verdicts)
        for v in verdicts:
            ui.info(f"  {v.bssid}: {v.reason}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
