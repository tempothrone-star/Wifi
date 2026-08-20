"""Subprocess helpers: timeouts, streaming, and truthful result capture."""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
from dataclasses import dataclass
from typing import Iterable, Sequence

from ..exceptions import ToolNotFoundError


@dataclass
class ProcResult:
    """The truthful outcome of a subprocess run (never fabricated)."""

    args: Sequence[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def output(self) -> str:
        """Combined stdout+stderr; used by most CLI tools that mix streams."""
        return (self.stdout + "\n" + self.stderr).strip()


def find_tool(name: str, override: str | None = None) -> str:
    """Resolve a tool binary path.

    Prefers an explicit override, then PATH. Raises ToolNotFoundError with a
    clear, actionable message when the tool is absent. Absolute override
    paths are verified to exist and be executable — a missing binary is
    never silently accepted.
    """
    if override:
        if os.path.isfile(override) and os.access(override, os.X_OK):
            return override
        resolved = shutil.which(override)
        if resolved is not None:
            return resolved
        raise ToolNotFoundError(name)
    resolved = shutil.which(name)
    if resolved is None:
        raise ToolNotFoundError(name)
    return resolved


def run(
    args: Sequence[str],
    timeout: float | None = None,
    check: bool = False,
    input_bytes: bytes | None = None,
    env: dict[str, str] | None = None,
) -> ProcResult:
    """Run a command and capture its output.

    ``timeout`` bounds the *whole* command. ``check=True`` raises
    ToolExecutionError on a non-zero exit so callers never proceed on a
    silently-failed tool run.
    """
    cmd = list(args)
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
    except FileNotFoundError as exc:
        raise ToolNotFoundError(cmd[0] if cmd else "?") from exc

    timed_out = False
    out = err = b""
    try:
        out, err = proc.communicate(input=input_bytes, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Graceful shutdown: SIGINT first so tools like airodump-ng / wash /
        # hcxdumptool can flush capture files. A direct SIGKILL skips that
        # flush and is why scans used to return empty CSVs.
        timed_out = True
        out, err = _stop_process(proc)

    result = ProcResult(
        args=cmd,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=out.decode("utf-8", "replace") if out else "",
        stderr=err.decode("utf-8", "replace") if err else "",
        timed_out=timed_out,
    )

    if check and not result.ok:
        from ..exceptions import ToolExecutionError

        raise ToolExecutionError(
            f"Command failed (rc={result.returncode}): {' '.join(shlex.quote(a) for a in cmd)}\n{result.output}"
        )
    return result


def _stop_process(proc: subprocess.Popen) -> tuple[bytes, bytes]:
    """SIGINT → SIGTERM → SIGKILL, reaping stdout/stderr at each stage.

    Capture tools (airodump-ng, hcxdumptool, wash) only flush their output
    files on SIGINT. A direct SIGKILL was leaving empty CSVs / pcapngs.
    """
    out = err = b""
    try:
        proc.send_signal(signal.SIGINT)
        out, err = proc.communicate(timeout=5)
        return out or b"", err or b""
    except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
        pass
    try:
        proc.terminate()
        out, err = proc.communicate(timeout=3)
        return out or b"", err or b""
    except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
        pass
    try:
        proc.kill()
        out, err = proc.communicate(timeout=3)
    except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
        try:
            out, err = proc.communicate(timeout=1)
        except Exception:  # noqa: BLE001
            out, err = b"", b""
    return out or b"", err or b""


def stream(args: Sequence[str], timeout: float | None = None) -> ProcResult:
    """Run a command streaming output to the terminal (for interactive tools)."""
    cmd = list(args)
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL)
    except FileNotFoundError as exc:
        raise ToolNotFoundError(cmd[0] if cmd else "?") from exc
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        return ProcResult(args=cmd, returncode=proc.returncode, timed_out=True)
    return ProcResult(args=cmd, returncode=rc)


def discover_tools(names: Iterable[str], overrides: dict[str, str] | None = None) -> dict[str, str]:
    """Return a mapping of {tool_name: path} for every tool that is present.

    Missing tools are simply omitted — this is how the strategist knows which
    Kali tools are *actually* available instead of assuming they all are.
    """
    overrides = overrides or {}
    found: dict[str, str] = {}
    for name in names:
        try:
            found[name] = find_tool(name, overrides.get(name))
        except ToolNotFoundError:
            continue
    return found
