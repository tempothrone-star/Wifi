"""Main launcher — an interactive TUI menu over every handshaker command.

Run with::

    python -m handshaker launcher      # or `handshaker menu`

It presents a grouped, numbered menu (rich when available, plain text
otherwise), lets the operator pick a command, prompts for the inputs that
command needs, runs it via :func:`handshaker.cli.main`, and returns to the menu
afterward. This is a thin, safe front-end — it does not bypass the
authorization gate or any safety checks, it only dispatches to the same CLI
functions.

For authorized WiFi security testing only.
"""

from __future__ import annotations

from typing import Callable

from . import __version__

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    _RICH = True
except ImportError:  # pragma: no cover
    _RICH = False

# --------------------------------------------------------------------------- #
# Command catalogue. Each entry: (key, title, description, argv_builder).
# argv_builder prompts (if needed) and returns the list of CLI args to run.
# --------------------------------------------------------------------------- #


def _ask(prompt: str, default: str = "") -> str:
    """Prompt for a value; empty input returns the default."""
    try:
        raw = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        raise KeyboardInterrupt
    return raw if raw else default


def _cmd_doctor() -> list[str]:
    return ["doctor"]


def _cmd_doctor_key() -> list[str]:
    return ["doctor", "--check-api-key"]


def _cmd_selftest() -> list[str]:
    ans = _ask("  Run full capture validation too? [y/N] ", "n").lower()
    return ["selftest", "--capture"] if ans in ("y", "yes") else ["selftest"]


def _cmd_scan() -> list[str]:
    d = _ask("  Scan duration in seconds [10]: ", "10")
    return ["scan", "--duration", d]


def _cmd_capture() -> list[str]:
    return ["capture"]


def _cmd_capture_loop() -> list[str]:
    iv = _ask("  Interval between iterations in seconds [30]: ", "30")
    return ["capture", "--loop", "--loop-interval", iv]


def _cmd_wps() -> list[str]:
    ans = _ask("  Detect only (skip attack tests)? [y/N] ", "n").lower()
    return ["wps", "--detect-only"] if ans in ("y", "yes") else ["wps"]


def _cmd_pmkid() -> list[str]:
    bssid = _ask("  Target BSSID [AA:BB:CC:DD:EE:FF]: ", "")
    if not bssid:
        print("  (skipped — no BSSID given)")
        return []
    channel = _ask("  Channel [6]: ", "6")
    return ["pmkid", "--bssid", bssid, "--channel", channel]


def _cmd_verify() -> list[str]:
    f = _ask("  Capture file path (.pcap/.pcapng): ", "")
    return ["verify", f] if f else []


def _cmd_analyze() -> list[str]:
    f = _ask("  Capture file path (.pcap/.pcapng): ", "")
    if not f:
        return []
    ans = _ask("  Open in Wireshark GUI too? [y/N] ", "n").lower()
    return ["analyze", f, "--gui"] if ans in ("y", "yes") else ["analyze", f]


def _cmd_report() -> list[str]:
    return ["report"]


def _cmd_export() -> list[str]:
    return ["export"]


def _cmd_adapter() -> list[str]:
    return ["adapter"]


def _cmd_tools() -> list[str]:
    return ["tools"]


# Ordered groups of commands. Each entry is (description, argv_builder).
GROUPS: list[tuple[str, list[tuple[str, Callable[[], list[str]]]]]] = [
    ("Setup & diagnostics", [
        ("Doctor (system self-check)", _cmd_doctor),
        ("Doctor + API-key validation", _cmd_doctor_key),
        ("Hardware self-test", _cmd_selftest),
        ("List Kali tools", _cmd_tools),
        ("Adapter (monitor mode / injection)", _cmd_adapter),
    ]),
    ("Reconnaissance", [
        ("Scan nearby APs", _cmd_scan),
        ("WPS assessment", _cmd_wps),
    ]),
    ("Capture", [
        ("Autonomous capture (scan+deauth+verify+learn)", _cmd_capture),
        ("Capture long-run mode (loop)", _cmd_capture_loop),
        ("PMKID capture", _cmd_pmkid),
    ]),
    ("Analysis & reporting", [
        ("Verify a capture is a 4-way handshake", _cmd_verify),
        ("Deep-analyze a capture", _cmd_analyze),
        ("Project report", _cmd_report),
        ("Export bundle (handshakes + PMKIDs + report)", _cmd_export),
    ]),
]


def _flatten() -> list[tuple[str, Callable[[], list[str]]]]:
    out: list[tuple[str, Callable[[], list[str]]]] = []
    for _title, entries in GROUPS:
        out.extend(entries)
    return out


class Launcher:
    def __init__(self, interface: str | None = None, config: str | None = None) -> None:
        self.interface = interface
        self.config = config
        self._console = Console() if _RICH else None

    # ------------------------------------------------------------------ #
    def _print(self, text: str, **kw) -> None:
        if self._console:
            self._console.print(text, **kw)
        else:
            print(text)

    def _banner(self) -> None:
        from .tui import BANNER
        if self._console:
            self._console.print(Panel(Text(BANNER, style="bold cyan"),
                                      title=f"v{__version__}", style="cyan"))
        else:
            print(BANNER)

    def _menu(self, items: list[tuple[str, Callable[[], list[str]]]]) -> None:
        if self._console:
            t = Table(box=None, show_header=False, padding=(0, 1))
            t.add_column(style="bold cyan", justify="right")
            t.add_column()
            for i, (desc, _f) in enumerate(items, 1):
                t.add_row(f"{i}.", desc)
            self._console.print(t)
        else:
            for i, (desc, _f) in enumerate(items, 1):
                print(f"  {i:>2}. {desc}")

    def run(self) -> int:
        """Show the menu loop until the operator quits."""
        items = _flatten()
        self._banner()

        if self.interface:
            self._print(f"\n  Interface: [bold]{self.interface}[/bold]" if self._console
                        else f"\n  Interface: {self.interface}")

        while True:
            self._print("\n" + ("─" * 60))
            self._print("[bold]Main menu[/bold]" if self._console else "Main menu")
            self._menu(items)
            self._print("[dim]Enter a number, or q to quit[/dim]" if self._console
                        else "Enter a number, or q to quit:")

            choice = _ask("  > ", "")
            if choice.lower() in ("q", "quit", "exit", ""):
                self._print("Bye.")
                return 0
            if not choice.isdigit() or not (1 <= int(choice) <= len(items)):
                self._print("[yellow]Invalid choice[/yellow]" if self._console
                            else "Invalid choice.")
                continue

            _desc, builder = items[int(choice) - 1]
            try:
                argv = builder()
            except KeyboardInterrupt:
                return 130
            if not argv:
                self._print("[yellow]Skipped (no input)[/yellow]" if self._console
                            else "Skipped (no input).")
                continue

            self._run_command(argv)

    # ------------------------------------------------------------------ #
    def _run_command(self, argv: list[str]) -> None:
        """Run a CLI command in-process, catching errors so the menu survives."""
        from .cli import main as cli_main

        # Prepend global flags (interface/config) if set.
        full = []
        if self.config:
            full += ["-c", self.config]
        if self.interface:
            full += ["-i", self.interface]
        full += argv

        self._print(f"\n  Running: [bold]handshaker {' '.join(argv)}[/bold]" if self._console
                    else f"\n  Running: handshaker {' '.join(argv)}")
        self._print("")
        try:
            cli_main(full)
        except SystemExit:
            pass  # the CLI signals exit codes via SystemExit; swallow for the menu
        except KeyboardInterrupt:
            self._print("[yellow]Interrupted.[/yellow]" if self._console else "Interrupted.")
        except Exception as exc:  # noqa: BLE001 - keep the menu alive
            self._print(f"[red]error: {exc}[/red]" if self._console else f"error: {exc}")


def main(argv: list[str] | None = None) -> int:
    """Entry point: parse a couple of optional flags, then run the menu."""
    import argparse
    p = argparse.ArgumentParser(prog="handshaker-menu",
                                description="Interactive TUI launcher for the handshaker.")
    p.add_argument("-i", "--interface", help="wireless interface (default: auto-detect)")
    p.add_argument("-c", "--config", help="path to config.yaml")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    launcher = Launcher(interface=args.interface, config=args.config)
    return launcher.run()


if __name__ == "__main__":
    raise SystemExit(main())
