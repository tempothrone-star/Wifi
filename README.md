# Wifi Auto Handshaker PMKID

An **autonomous, adaptive** WiFi security-auditing tool for Kali Linux that:

1. **Scans** nearby WiFi networks,
2. **Captures 4-way handshakes** (EAPOL) and **PMKIDs** using the full Kali toolchain,
3. **Strongly verifies** that *only* genuine 4-way handshakes are stored — anything
   else is rejected and deleted (with packet-level structural validation),
4. Performs **strategic, analysis-driven deauthentication** (client targeting,
   reason-code rotation, multi-tool fallback) using almost every Kali deauth engine,
5. **Learns and adapts** from measured success/failure — deterministically, across
   sessions (bandit + SQLite history), with explicit anti-hallucination guarantees,
6. Optionally uses the **NVIDIA NIM API** for strategy *suggestions* only, with
   smart model selection and rate limiting — the tool is fully independent without it.

> **Capture only — no password hashing or cracking.** This tool captures and
> verifies handshakes/PMKIDs. It never runs a dictionary/brute-force attack and
> never computes password hashes.

---

## ⚠️ Legal & ethical notice — read first

Capturing WiFi handshakes/PMKIDs and performing deauthentication attacks against
networks you do **not** own or lack **explicit written permission** to test is
**illegal** in most jurisdictions (e.g. wiretap and computer-fraud statutes).

* You may use this tool **only** on networks you own, or that you are explicitly
  authorized to audit (penetration-testing engagement, bug-bounty scope, lab).
* You are solely responsible for lawful use. The authors provide this software
  for authorized security research and education only.

The tool enforces an interactive **authorization gate** on every autonomous run
and refuses to operate without it.

---

## Requirements

* **Python 3.12+** (the tool is written for 3.12; it also runs on 3.11).
* **Kali Linux** (or another Linux with the wireless toolchain installed).
* Root privileges (`sudo`).
* A wireless adapter that supports **monitor mode** and **packet injection**.

System tools (detected at runtime, none are "abandoned"):

| Purpose | Tools |
|---|---|
| Adapter / monitor mode | `airmon-ng`, `iw`, `iwconfig`, `rfkill` |
| Scanning | `airodump-ng`, `kismet`, `wash` |
| Handshake capture | `airodump-ng`, `hcxdumptool`, `wifite`/`wifite2` |
| Deauthentication | `aireplay-ng`, `mdk4`, `bettercap`, `hcxdumptool` (own attack mode) |
| **Verification** | `tshark` (Wireshark), `aircrack-ng`, `hcxpcapngtool`, `cowpatty`, `pyrit`, `capinfos` |
| PMKID | `hcxdumptool`, `hcxpcapngtool`, `hcxlabtool`, `hcxpsktool` |
| WPS assessment | `wash`, `reaver`, `bully`, `pixiewps`, `oneshot` |
| Analysis | `wireshark` (GUI), `tshark`, `capinfos` |

### Modern-toolchain compatibility (hcxdumptool v6.3+)

hcxdumptool's CLI **changed in v6.3.0 (May 2023)** — `-o`→`-w`,
`--enable_status`→`--rds`, `--disable_client_attacks`→`--attemptclientmax=0`,
and `--filtermode/--filterlist_ap` were removed (replaced by BPF). The wrapper
**probes `--help` at runtime** and selects the correct flag family, so it works
on both pre- and post-6.3 builds. On 6.3+, single-AP targeting degrades
honestly to one-channel-per-target (BPF compilation is left to the operator).

### WPA3 transition-mode & PMF (802.11w) awareness

* **WPA3 transition mode** (`WPA2/WPA3`) is *detected* distinctly. A transition-
  mode AP accepts WPA2 clients, so a WPA2-compatible client may still permit a
  WPA2 handshake capture. (This is detection + honest labelling; the tool does
  **not** implement an active WPA3→WPA2 downgrade/rogue-AP attack.)
* **PMF / 802.11w fallback** — when classic deauth fails every round, the engine
  makes one last-resort capture using hcxdumptool's *own* attack vectors, which
  work on MFP networks where old-school deauthentication fails
  (`capture.pmf_fallback`).

Install the core suite on Kali/Debian:

```bash
sudo apt update
sudo apt install -y aircrack-ng hcxdumptool hcxtools tshark mdk4 bettercap \
                    python3-pip python3-venv
```

Install Python dependencies:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
# optional: .venv/bin/pip install scapy   (independent parser fallback)
```

---

## Setup & environment self-check

`setup.py` is a self-contained (stdlib-only) script that prepares and *verifies*
the runtime — it runs even before Python dependencies are installed:

* **OS check** — Kali/Debian detection, package manager, root privileges.
* **Python check** — version (3.11+), virtualenv status.
* **venv creation** — `setup.py --venv` builds `.venv` and installs the deps.
* **Tool check** — detects all 24 Kali tools, maps them to apt packages, and
  prints an exact `apt install` line (or installs them with `--install-tools`).
* **API key check** — validates `NIM_API_KEY` / `nim.api_key`:
  * format (prefix, length),
  * **live probe** against `GET /v1/models` (the authoritative check — NVIDIA
    does not expose key expiry client-side, so a 401/403 means the key is
    expired/revoked/wrong, 429 means rate-limited, network error means
    "cannot verify").

The same checks are available inside the tool as `handshaker doctor` (with a
rich TUI).

## Terminal UI

All commands render through a **rich** TUI (banner, tables, panels, status
icons) and gracefully degrade to plain text when `rich` is absent. `--json`
flags on `scan`, `capture`, `verify`, `analyze`, `wps`, and `doctor` emit machine-readable
output for scripting.

## Quick start

```bash
# 0) Setup + environment self-check (OS / python / venv / tools / API key)
python3 setup.py
python3 setup.py --json            # machine-readable
python3 setup.py --venv            # create .venv and install Python deps
sudo python3 setup.py --install-tools   # apt-install missing Kali tools

# The easiest way in: the interactive launcher (TUI menu over every command)
sudo .venv/bin/python -m handshaker menu
# (or, after `pip install .`:  handshaker-menu)

# 1) Rich system self-check (doctor)
sudo .venv/bin/python -m handshaker doctor
sudo .venv/bin/python -m handshaker doctor --check-api-key
sudo .venv/bin/python -m handshaker doctor --json

# 2) Guided hardware validation (root/tools/adapter/scan/capture) — run first on
#    your own network to prove the toolchain works end-to-end.
sudo .venv/bin/python -m handshaker selftest --capture

# 3) See which tools are installed / missing
sudo .venv/bin/python -m handshaker tools

# 4) Fully autonomous run: scan -> prioritize -> deauth -> capture -> verify -> learn
sudo .venv/bin/python -m handshaker -i wlan0 capture

# 5) Just scan for nearby APs
sudo .venv/bin/python -m handshaker -i wlan0 scan --duration 15

# 6) Manually verify an existing capture is a genuine 4-way handshake
.venv/bin/python -m handshaker verify data/captures/some.pcapng
.venv/bin/python -m handshaker analyze data/captures/some.pcapng --bssid AA:BB:CC:DD:EE:FF
.venv/bin/python -m handshaker analyze data/captures/some.pcapng --gui   # open in Wireshark

# 7) Adapter management (monitor mode / injection test / reset)
sudo .venv/bin/python -m handshaker -i wlan0 adapter

# 8) PMKID capture / conversion
sudo .venv/bin/python -m handshaker pmkid --bssid AA:BB:CC:DD:EE:FF --channel 6
.venv/bin/python -m handshaker pmkid --convert data/captures/some.pcapng

# 9) WPS vulnerability assessment (detect + pixie-dust test)
sudo .venv/bin/python -m handshaker -i wlan0 wps
sudo .venv/bin/python -m handshaker -i wlan0 wps --detect-only

# 10) Show captured artifacts + learning state
.venv/bin/python -m handshaker report
.venv/bin/python -m handshaker report --json
```

After an install (`pip install .`), the `handshaker` console script is also
available.

---

## How verification works (the integrity core)

The centerpiece is `handshaker/core/verifier.py`. It answers one question with
high confidence: *"Does this capture contain a structurally consistent, complete
4-way EAPOL exchange?"* (It establishes structural consistency, not cryptographic
proof of every semantic property — that requires the PSK, which this capture-only
tool deliberately does not handle.)

Verification is **deterministic and multi-tool**, and its design makes
hallucination structurally impossible:

1. **tshark (Wireshark) is the ground truth.** Every EAPOL-Key frame is read and
   classified M1–M4 from the fields Wireshark itself decoded — the `key_ack` /
   `install` flags and the MIC / nonce contents — **not** from any re-implemented
   bit arithmetic that could drift out of sync.
2. **aircrack-ng** independently reports `WPA handshake: <bssid>`.
3. **hcxpcapngtool** independently counts EAPOL pairs.
4. **pyrit** (`analyze`) independently rates each BSSID's handshake as
   good/workable — a real contradiction signal if it finds none.
5. **cowpatty** (`-c -s <ESSID>`) independently checks for a complete 4-way
   frame set, run **per BSSID** against its own extracted ESSID.
6. **capinfos** reports the capture's packet count as a metadata sanity check.

Verification is **primary structural verification + contradiction checks**:
the tshark EAPOL analysis is the authoritative structural signal; the other
tools are *contradiction checks*. A tool that runs and explicitly finds *no*
handshake rejects the capture; an *unavailable* tool degrades to "not run"
(never silently assumed to pass). This is graceful degradation, not a strict
all-tools intersection.

Classification of the 4-way handshake (IEEE 802.11-2020 §12.7.6.2):

| Msg | Direction | Key ACK | Install | Key MIC | Nonce |
|-----|-----------|:-------:|:-------:|:-------:|:-----:|
| M1  | AP → STA  |   ✓     |         |         | ANonce |
| M2  | STA → AP  |         |         |   ✓     | SNonce |
| M3  | AP → STA  |   ✓     |   ✓     |   ✓     | ANonce |
| M4  | STA → AP  |         |         |   ✓     |  —    |

**Advanced, packet-level validation** (all derived from dissected fields, no
inference):

* **Completeness** — M1–M4 all present (strict mode).
* **Direction** — M1/M3 must originate from the AP; M2/M4 from the STA.
* **Nonce presence & length** — M1 (ANonce) and M2 (SNonce) must be present and
  32 bytes (64 hex chars); MIC must be 16 bytes (32 hex chars).
* **Replay-counter monotonicity, per direction** — the AP and STA keep
  independent replay counters, so monotonicity is checked per transmitter
  (a global check would falsely reject valid handshakes). The hex counter from
  Wireshark is parsed correctly.
* **Retransmission de-duplication** — repeated identical frames are collapsed so
  a duplicated M2 cannot fake completeness.

**Retention policy (default `verify.require_full_handshake: true`):**

* A capture **passes** only if **all four messages** (M1, M2, M3, M4) are present,
  MICs and nonces are present, and **no** configured, available tool contradicts it.
* If `require_full_handshake: false`, a crackable **M2 + M3** pair is the minimum.
* Everything else is **rejected** and moved to quarantine (or deleted if
  `quarantine_before_delete` is off), with a truthful reason recorded.

The verdict is **primary structural verification + contradiction checks** (see
above), not a strict all-tools intersection. A tool that is *unavailable* is
reported truthfully and degrades gracefully — it is never silently assumed to
pass.

---

## How the learning / adaptation works (no hallucinations)

`handshaker/learning/` implements an **advanced multi-armed bandit** over deauth
actions (tool × burst size × reason code), backed by a **SQLite results
database** (`handshaker/db.py`) and a JSON state store for cross-run history:

* **Three principled exploration strategies** (configurable via
  `learning.strategy`):
  * `thompson` (default) — Bayesian Thompson sampling: each action has a Beta
    posterior, and exploration is *uncertainty-driven* (untried actions have
    wide posteriors and get tried naturally).
  * `ucb` — Upper Confidence Bound (UCB1): picks the action with the best
    `mean + confidence bound`.
  * `epsilon` — classic epsilon-greedy.
* **Cross-AP transfer learning** (`learning.transfer`) — hierarchical shrinkage:
  an action's posterior blends the AP's own measured outcomes with the
  aggregated outcomes of *structurally similar* APs (same security × band ×
  vendor/OUI). A new AP inherits a prior from similar APs instead of starting
  cold, but its own evidence dominates as it accumulates. Set `transfer: 0` for
  per-AP independence.
* **PMKID is a separate learning track.** A PMKID capture is *not* a handshake,
  so it is recorded on its own track (`store.record_pmkid`) and never rewards
  the deauth action. The strategist uses PMKID history to prioritize targets it
  can actually capture (PMKID or handshake), and learns PMKID-vs-handshake
  preference per AP and per context.
* **Only measured outcomes are recorded.** An "action" is only ever stored after
  the verifier decides whether a handshake was actually captured. There is no
  score stored — posteriors are recomputed from raw, **time-decayed**
  observations on every call.
* **Honest uncertainty.** Until `learning.min_observations` weighted trials
  exist, the policy explores near-uniformly rather than trusting a single lucky
  run.
* **No invented actions.** The policy only ever selects from actions that (a)
  have been tried, or (b) are the principled exploration pick — and only among
  actions the *installed* toolset can actually perform (`tools` registry, never
  assumed).

## How strategic deauth works (Wireshark-driven)

Deauth is **aimed, timed, and rotated** — not sprayed:

1. The **analyzer** (`handshaker/core/analyzer.py`) measures, via tshark, which
   clients are actually exchanging data/EAPOL with the target BSSID.
2. Deauth is **aimed at the most active client** so its reconnection re-runs the
   4-way handshake in front of the sniffer.
3. **Reason codes are rotated** (7 → 4 → 1) because clients/APs ignore specific
   codes. When **scapy** is installed, reason codes are honoured for real on the
   wire via raw 802.11 frame injection; otherwise each tool's native reason is
   used.
4. **Exactly one engine runs per campaign** — the first usable engine in the
   chain (`scapy` → `aireplay-ng` → `mdk4` → `bettercap`). A missing engine
   triggers fallback to the next; engines are never run concurrently or
   sequentially against the same target (which would over-deauth).
5. The channel is pinned via `iw`/`iwconfig` before deauth so mdk4/bettercap
   don't hop away.
6. The analyzer is re-run on the just-captured traffic to **re-target** the best
   client mid-campaign.

## WPS vulnerability assessment

`handshaker/core/wps.py` tests whether access points are vulnerable to WPS
attacks, using the Kali WPS toolchain — every step measured, nothing guessed.

**Strategic attack ordering** — the `WpsStrategist` orders attacks from
measured facts and learned outcomes, not a hardcoded list:

1. **Vendor-driven** — a pixie-dust-vulnerable chipset (Broadcom/Ralink/Realtek/
   MediaTek/Atheros/Marvell) tries *pixie dust* first; a Belkin/D-Link AP tries
   the *default-PIN* attack first.
2. **Learning with cross-AP transfer** — every remaining method gets a Beta
   posterior over its success probability, blended from the AP's own outcomes
   and the aggregated outcomes of *structurally similar* APs (same vendor × WPS
   version) via hierarchical shrinkage (`wps.transfer`). Methods are ranked by
   posterior mean, so a new AP inherits a prior instead of starting cold, while
   its own evidence dominates as it accumulates. `wps.exploration` enables
   epsilon-style shuffling of the learned order.
3. **Lock-aware** — a locked AP only runs *offline* methods (no online PIN
   exchange that wastes time or worsens lockout).
4. **Fallback** — the canonical order fills in the remainder.

**Attack methods (the full WPS surface):**

| Method | Tool(s) | Notes |
|---|---|---|
| Detection | `wash -i IFACE` | BSSID, channel, WPS version, lock state, vendor |
| Pixie dust | `reaver -K 1` / `bully -d` / `oneshot -K` | offline, exploits weak entropy; safe (no lockout) |
| Pixie force | `oneshot -F` / `pixiewps -f` | full-range offline brute (mode 3) |
| Pixie loop | `reaver -P` | collect PixieHashes without M4 (avoids lockout) |
| Default PIN | `reaver -W 1\|2` / `bully -g 1\|2` | Belkin / D-Link vendor-computed PINs |
| Known PIN | `reaver -p <pin>` | test a specific candidate PIN |
| Push-button (PBC) | `oneshot --pbc` | physical WPS-button exposure test |
| Online brute force | `reaver -b` / `oneshot -B` | **not auto-run** (hours + lockout risk) |

Verdicts (deterministic):

| Status | Meaning |
|---|---|
| `WPS_DISABLED` | No WPS — safe from WPS attacks |
| `WPS_ENABLED` | WPS present; not (yet) confirmed exploitable |
| `VULNERABLE_PIXIE` | Pixie dust/force recovered a PIN offline — confirmed flaw |
| `VULNERABLE_DEFAULT` | A vendor default PIN was accepted — confirmed flaw |
| `NOT_VULNERABLE` | WPS present but no tested method recovered a PIN |

The online PIN brute force is deliberately **not** run automatically (hours +
lockout risk); it is exposed via wrappers for manual, authorized use.

## Optional NVIDIA NIM integration (smart, rate-limited, independent)

`handshaker/nim/` provides advanced, *optional* NIM strategy suggestions:

* **Smart model selection** (`models.py`) — a curated registry of real NIM model
  IDs, preference-ordered (fast/cheap tier first, large/capable fallback), plus
  optional dynamic discovery from the `/v1/models` endpoint.
* **Degraded-model tracking** — a model that returns 429/5xx is deprioritized for
  a cooldown and the next model is tried automatically (measured HTTP outcomes
  only).
* **Rate limiting & backoff** (`ratelimit.py`) — a token bucket bounds request
  rate; exponential backoff honours the `Retry-After` header.
* NIM is **optional and off by default** — the tool is fully independent.
* NIM only *suggests* strategy parameters (tool, burst, dwell, prefer_pmkid). Its
  output is schema-validated and clamped to what the installed tools can do.
* NIM is **never** consulted for verification, and it is given only measured scan
  facts. Any suggestion is an untrusted hint.

Anti-hallucination principles baked into the code:

1. **Facts vs. decisions are separated.** BSSIDs, channels, clients, signals come
   from the live scan; decisions are made from those facts.
2. **"I don't know" is a valid answer.** Parsers return `None` on garbage instead
   of guessing (`utils/validation.py`).
3. **Verification is independent of strategy/AI** and always deterministic.
4. **Failures are recorded truthfully**, never masked or retconned.

---

## Project layout

```
handshaker/
├── cli.py                 # subcommands: adapter, scan, capture, pmkid, verify, analyze, wps, tools, doctor, selftest, report
├── config.py              # strict, validated YAML config loading
├── constants.py           # single source of truth for names/paths/codes
├── db.py                  # SQLite results store (cross-run learning history)
├── doctor.py              # system self-check (OS/tools/python/API key/injection)
├── tui.py                 # rich terminal UI with plain-text fallback
├── core/
│   ├── adapter.py         # monitor mode on/off/reset, injection test
│   ├── scanner.py         # airodump-ng scan + strict CSV parsing (WPA3/SAE aware)
│   ├── capturer.py        # background capture sessions (airodump / hcxdumptool)
│   ├── verifier.py        # ★ strong 4-way handshake verification (structural)
│   ├── deauth.py          # strategic deauth (client targeting, reason rotation)
│   ├── pmkid.py           # PMKID capture & 22000 conversion
│   ├── wps.py             # WPS assessment (strategic ordering + full attack surface)
│   ├── analyzer.py        # tshark-based client-activity analysis
│   ├── strategist.py      # weighted scoring + per-target strategy (PMKID vs deauth)
│   ├── selftest.py        # guided hardware validation workflow
│   ├── report.py          # captured artifacts + learning state report
│   └── engine.py          # autonomous loop + auth gate + signal handling + DB
├── tools/                 # thin wrappers for every Kali tool (modern flags)
├── learning/              # advanced bandit (Thompson/UCB) + persistent state
├── nim/                   # optional NIM client (model registry + rate limiting)
└── utils/                 # proc, logging, validation, apikey, system detection
config/config.yaml         # configuration
setup.py                   # setup/doctor installer (stdlib-only)
Makefile                   # venv/install/test/lint/compile/doctor/selftest/report
requirements.txt           # runtime deps
requirements-dev.txt       # dev/test deps
CHANGELOG.md               # release history
data/
├── captures/              # raw captures (gitignored)
├── handshakes/            # ★ verified 4-way handshakes only
├── pmkid/                 # PMKID / 22000 output
├── quarantine/            # rejected captures (transient)
└── learning/              # adaptive state + results.db + wps.json
```

---

## Configuration

Edit `config/config.yaml`. Highlights:

* `verify.require_full_handshake` — strict M1–M4 requirement (default `true`).
* `verify.structural_checks` — direction / nonce+MIC length / per-direction replay-counter checks.
* `verify.min_packets` — minimum EAPOL frames required.
* `verify.delete_on_fail` — delete anything that isn't a 4-way handshake.
* `capture.max_rounds` — capture+deauth+verify rounds per target (default `3`).
* `capture.pmkid_duration` — seconds per PMKID attempt.
* `deauth.tools` — deauth engine order (`scapy`, `aireplay-ng`, `mdk4`, `bettercap`).
* `pmkid.enabled` — whether to also capture PMKIDs.
* `wps.*` — WPS assessment: `enabled`, `pixie_dust`, `timeout`, `show_all`,
  `ignore_fcs`.
* `learning.*` — exploration rate, decay, minimum observations.
* `nim.*` — optional NIM strategy hints: `enabled`, `model`, `prefer_tier`,
  `discover_models`, `rate_per_minute`, `burst` (default `false`).
* `targets.*` — explicit BSSID/ESSID/channel allow-lists and exclusions.

Unknown config keys and out-of-range values are rejected at load time (fail fast,
no silent clamping).

---

## Tests

```bash
.venv/bin/python -m pytest -q
```

The test suite proves the anti-hallucination properties of the verifier (including
the packet-level structural checks), the policy layer, the model registry, the
rate limiter, and the NIM output parser — without requiring Kali tools or root.

---

## Disclaimer

This software is provided for authorized security testing and education only.
The authors disclaim all responsibility for unlawful use.
