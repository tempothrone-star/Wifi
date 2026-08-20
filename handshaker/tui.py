"""Terminal UI (rich) with a plain-text fallback.

Every renderer checks for ``rich`` at import time; if it is missing, the same
content degrades to plain text so the tool never depends on a UI library.
"""

from __future__ import annotations

from typing import Any

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
    _RICH = True
except ImportError:  # pragma: no cover - plain fallback
    _RICH = False

BANNER = r"""
 _    _ _  __ _        _   _                _     _
| |  | (_)/ _(_)      | | | |              | |   | |
| |__| |_| |_ _  __ _ | |_| |__   ___  ___ | | __| | ___ _ __
|  __  | |  _| |/ _` || __| '_ \ / _ \/ __|| |/ _` |/ _ \ '__|
| |  | | | | | | (_| || |_| | | |  __/\__ \| | (_| |  __/ |
|_|  |_|_|_| |_|\__, | \__|_| |_|\___||___/|_|\__,_|\___|_|
                 __/ |   autonomous 4-way handshake + PMKID + WPS
                |___/    capture-only · authorized testing only
"""


class UI:
    """A thin console facade: rich when available, plain text otherwise."""

    def __init__(self) -> None:
        self.rich = _RICH
        self._console = Console() if _RICH else None

    # ------------------------------------------------------------------ #
    def banner(self) -> None:
        if self.rich:
            text = Text(BANNER, style="bold cyan")
            self._console.print(text)
        else:
            print(BANNER)

    def title(self, text: str) -> None:
        if self.rich:
            self._console.print(Panel(Text(text, style="bold white"),
                                      box=box.ROUNDED, style="cyan"))
        else:
            print(f"\n=== {text} ===\n")

    def table(self, headers: list[str], rows: list[list[Any]], title: str | None = None) -> None:
        if self.rich:
            t = Table(title=title, box=box.SIMPLE_HEAD, header_style="bold magenta",
                      title_style="bold cyan")
            for h in headers:
                t.add_column(h)
            for r in rows:
                t.add_row(*[str(c) for c in r])
            self._console.print(t)
        else:
            if title:
                print(f"--- {title} ---")
            print("  " + " | ".join(headers))
            for r in rows:
                print("  " + " | ".join(str(c) for c in r))

    def status(self, label: str, ok: bool, detail: str = "") -> None:
        mark = ("✓" if ok else "✗") if self.rich else ("[ok]" if ok else "[!!]")
        color = "green" if ok else "red"
        if self.rich:
            self._console.print(f"  {mark} {label}" + (f"  {detail}" if detail else ""),
                                style=color)
        else:
            print(f"  {mark} {label}  {detail}")

    def warn(self, text: str) -> None:
        if self.rich:
            self._console.print(f"[yellow]![/] {text}")
        else:
            print(f"[!] {text}")

    def error(self, text: str) -> None:
        if self.rich:
            self._console.print(f"[red]✗[/] {text}")
        else:
            print(f"[✗] {text}")

    def info(self, text: str) -> None:
        if self.rich:
            self._console.print(text)
        else:
            print(text)

    def json(self, data: dict) -> None:
        if self.rich:
            self._console.print_json(data=data)
        else:
            import json
            print(json.dumps(data, indent=2))


# --------------------------------------------------------------------------- #
# Domain renderers
# --------------------------------------------------------------------------- #
def render_doctor(ui: UI, report) -> None:
    ui.banner()
    ui.title("System self-check")

    # OS
    osi = report.os
    ui.table(
        ["Field", "Value"],
        [
            ["System", f"{osi['system']} {osi['release']}"],
            ["Distribution", osi.get("distro") or "(unknown)"],
            ["Kali", "yes" if osi.get("kali") else "no"],
            ["Debian-based", "yes" if osi.get("debian_based") else "no"],
            ["Package manager", osi.get("package_manager") or "(none found)"],
            ["Supported", "yes" if osi.get("supported") else "no"],
        ],
        title="Operating system",
    )

    # Python
    py = report.python
    ui.table(
        ["Field", "Value"],
        [
            ["Version", py["version"]],
            ["Implementation", py["implementation"]],
            ["Virtualenv", "yes" if py.get("in_venv") else "no"],
            ["Executable", py["executable"]],
        ],
        title="Python",
    )
    ui.status("Root privileges", report.root, "required for capture/deauth")

    # Tools
    rows = []
    for t in sorted(report.tools):
        rows.append([t, report.tools[t], "✓"])
    for t in sorted(report.missing):
        rows.append([t, "(missing)", "✗"])
    ui.table(["Tool", "Path", "Status"], rows, title="Kali tools")

    # hcxdumptool flags
    if report.hcxdumptool_flags:
        rows = [[k, "yes" if v else "no"] for k, v in report.hcxdumptool_flags.items()]
        ui.table(["hcxdumptool flag", "supported"], rows, title="hcxdumptool capabilities")

    # Adapter
    if report.adapter.get("interfaces"):
        ui.info("  Interfaces: " + ", ".join(report.adapter["interfaces"]))
    else:
        ui.warn("No wireless adapter detected (needed for live capture).")

    # NIM
    nim = report.nim
    ui.table(["Field", "Value"],
             [["API key", nim.get("status")], ["Detail", nim.get("reason", "")]],
             title="NVIDIA NIM API key")

    if report.core_ready:
        ui.status("Core capture toolchain", True, "aircrack-ng + hcxtools + tshark present")
    else:
        ui.error("Core toolchain incomplete — some required tools are missing.")


def render_scan(ui: UI, result) -> None:
    rows = []
    for ap in sorted(result.aps.values(), key=lambda a: a.power, reverse=True):
        clients = len(result.clients_of(ap.bssid))
        rows.append([ap.bssid, ap.channel, f"{ap.power} dBm",
                     ap.security_label, clients, ap.essid or "(hidden)"])
    ui.table(["BSSID", "Ch", "Signal", "Security", "Clients", "ESSID"],
             rows, title=f"Scan — {len(result.aps)} access point(s)")


def render_wps(ui: UI, verdicts: list) -> None:
    rows = []
    for v in verdicts:
        mark = "VULNERABLE" if v.vulnerable else "ok"
        pin = v.pin or ""
        rows.append([v.bssid, v.essid, v.status, mark, pin])
    ui.table(["BSSID", "ESSID", "Status", "Result", "PIN"], rows,
             title="WPS assessment")


def render_verify(ui: UI, report) -> None:
    if report.passed:
        ui.status("Verified 4-way handshake", True, report.reason)
    else:
        ui.status("Rejected (not a handshake)", False, report.reason)
    if report.evidence:
        rows = [[e.bssid, ",".join(str(m) for m in sorted(e.messages)),
                 e.hcx_pairs, e.aircrack_confirmed] for e in report.evidence]
        ui.table(["BSSID", "Messages", "EAPOL pairs", "aircrack"], rows,
                 title="Evidence")


def render_run_summary(ui: UI, stats) -> None:
    ui.title("Run summary")
    rows = [
        ["Targets scanned", stats.targets_scanned],
        ["Targets attacked", stats.targets_attacked],
        ["Handshakes verified", stats.handshakes_captured],
        ["Handshakes rejected", stats.handshakes_rejected],
        ["PMKIDs captured", stats.pmkids_captured],
    ]
    ui.table(["Metric", "Value"], rows)
    if stats.verified_files:
        ui.info("Stored handshakes:")
        for f in stats.verified_files:
            ui.info(f"  - {f}")
    if stats.failures:
        ui.warn("Failures (recorded truthfully):")
        for f in stats.failures:
            ui.warn(f"  - {f}")
