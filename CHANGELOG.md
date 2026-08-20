# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/) and the
project uses [Semantic Versioning](https://semver.org/).

> **This tool is for authorized WiFi security testing only.** It performs
> capture only — it never hashes or cracks passwords.

## [1.6.1] — 2026-08

### ChatGPT review follow-up
- **M4 classification** — an all-zero 32-byte nonce (the real EAPOL-Key M4
  on the wire) is no longer classified as M2. Wireshark `msgnr` is preferred
  when present.
- **`general.output_root` is wired** — data dirs rebind at config load;
  installed packages write under cwd, not site-packages.
- **`general.interface`** is honoured when CLI `-i` is omitted.
- **Refined deauth** uses `max(1, max_bursts // 2)` so `max_bursts: 1` still
  fires one burst.
- **Self-test adapter cleanup** is in a `finally` after monitor mode.
- **Replay-counter check is per handshake** (shared ANonce / paired M2-M4),
  so a later re-auth that resets the counter no longer rejects the capture.
- **Dedup** includes MIC + replay counter.
- **Config validation** covers dwell, rounds, timeouts, NIM rate, WPS
  timeouts, and requires `https://` for an enabled NIM endpoint.
- **Analyzer** distinguishes tshark failure from a true zero-frame capture.
- **NIM** `prefer_pmkid` / `dwell_seconds` are applied; prompts mark ESSID as
  opaque data; cache key includes the model list.
- **6 GHz / unknown channels** are no longer labelled `5GHz`.
- **PMKID convert** writes under `constants.PMKID_DIR` at call time (was a
  `NameError` on the unbound name `PMKID_DIR`, so `pmkid --convert` and the
  engine conversion path never produced a 22000 file).

### Bug fixes (third-pass review)
- **Graceful tool shutdown** — subprocess timeout now sends SIGINT (then
  SIGTERM, then SIGKILL) so airodump-ng / hcxdumptool / wash can flush
  capture files. A direct SIGKILL was producing empty scan CSVs.
- **Scan write-interval + duration** — airodump is invoked with
  `--write-interval 1`, and scan duration is measured from start, not from
  CSV parse time.
- **Monitor mode on CLI scan / WPS / PMKID** — those commands now enable
  monitor mode (and honour `reset_on_exit`). They previously ran on a
  managed interface and failed.
- **PMKID-only runs without deauth tools** — missing aireplay/mdk4/bettercap
  no longer aborts the whole autonomous loop; passive/PMKID capture continues.
- **ESSID filename sanitisation** — capture prefixes no longer embed raw
  ESSIDs (`/`, `..`, spaces) which could write outside `data/captures/`.
- **`parse_mac` matches its docs** — bare `aabbccddeeff` and Cisco
  `aabb.ccdd.eeff` forms are accepted.
- **`LearningStore(path=None)` is in-memory** — same contract as
  `WpsHistory`; the engine now passes `data/learning/state.json` explicitly.
- **Transfer learning no longer double-counts** the current AP in the
  context prior (`exclude_bssid`).
- **SIGINT stops the live capture** — the handler now `stop()`s the active
  `CaptureSession` instead of waiting for the current target to finish.
- **Injection test uses the monitor iface** — `handshaker adapter` no longer
  tests injection on the pre-airmon name.
- **`iw set type` downs the iface first** — required by iw; previously the
  raw-iw monitor fallback silently failed.
- **`wlan1mon` / `wlp3s0mon` recognised as monitor names** (not just
  `wlan0mon` / `mon*`).
- **`--json` on `analyze` and `wps --detect-only`** no longer mixes human
  tables into machine-readable output.
- **Invalid config is a clean error** instead of a traceback.
- **`pmkid --convert` no longer requires root**.
- **hcxdumptool apt package** is `hcxdumptool`, not `hcxtools`.
- **setup.py does not live-probe the NIM key** unless `--check-api-key`.
- **hcxpcapngtool temp 22000 files are cleaned up**.
- **tshark field separator is tab** (`occurrence=f`) to avoid comma-collision
  when a field has multiple values.
- **WPS pixie-loop / PBC parse recovered PINs**; oneshot `--pbc` is targeted
  with `-b BSSID`.
- **Scapy deauth is bidirectional** (AP→STA and STA→AP).
- **NIM deauth_tool** no longer accepts `hcxdumptool` (not a deauth engine);
  `scapy` is allowed.
- **Version** synced to 1.6.1 (`__version__`, pyproject, session fingerprint).
- **SQLite counts** go through a connection-closing helper (no leaked
  connections in `report`).
- **`learning.transfer` / `wps.transfer`** validated in `[0, 1]`.

## [1.6.0] — 2026-08

### Main launcher (TUI)
- **`handshaker menu` / `handshaker-menu`** — an interactive TUI launcher over
  every command. A grouped, numbered menu (rich when available, plain text
  otherwise) lets the operator pick a command, prompts for the inputs it needs
  (scan duration, BSSID/channel, file path, detect-only, capture validation,
  loop interval, Wireshark GUI, …), and dispatches to the same CLI functions.
  It does not bypass the authorization gate or any safety checks.

## [1.5.0] — 2026-08

### Second-pass review fixes (state/event contracts)
- **Multi-BSSID verifier granularity** — a capture is accepted when *at least
  one* BSSID holds a genuine handshake; an unrelated incomplete AP in the same
  capture no longer rejects the valid one (channel-level hcxdumptool filtering
  captures multiple APs).
- **Per-BSSID `min_packets`** — the minimum is now evaluated per candidate
  handshake, not as a global file total.
- **False engine attribution fixed** — capture-engine learning now records the
  `CaptureSession.engine` (what actually ran) rather than the requested engine,
  so a silent airodump fallback is no longer credited to hcxdumptool.
- **Correct deauth→EAPOL latency** — the measured first-EAPOL time is now
  offset by the deauth timestamp, so `latency_seconds` reflects *reconnection*
  latency, not capture-start→EAPOL (which fed the adaptive wait the wrong value).
- **Quarantine retains evidence** — rejected captures are moved to quarantine
  and *kept* (not move-then-delete), so false-rejection evidence is preserved.
- **Capture crash detection** — a capture process that exits nonzero is a
  distinct learning signal from "ran but no handshake".
- **`Popen` errors normalized** — OSError at capture start becomes a domain
  `CaptureError`, not a leaked exception.
- **Explicit targets are authoritative** — an operator-specified BSSID now
  bypasses automatic signal/enterprise/WPA filters.
- **NIM privacy boundary** — BSSID/ESSID are pseudonymized before leaving the
  machine unless `nim.send_sensitive_context` is explicitly enabled.
- **Session lifecycle** — `finish_session()` records `ended_at` + `status`
  (`ok`/`interrupted`); environment fingerprint (tool versions + config hash)
  stored with each session.
- **DB schema migration** — additive columns are applied with a guard, so an
  existing `results.db` upgrades cleanly instead of erroring.
- **Adapter side-effects made explicit** — `airmon-ng check kill` is now
  `adapter.stop_conflicting_services` (default true); the raw-iw fallback no
  longer changes TX power.

## [1.4.0] — 2026-08

### Independent-review fixes (correctness & control-plane)
Addressed a detailed independent code review; the following are now fixed:

- **Deauth failure-based fallback** — an engine that *runs but fails* (non-zero
  exit / timeout) is now abandoned and the next engine is tried, not just
  availability fallback. Only successful bursts are returned.
- **Subprocess results are authoritative** — the deauth campaign inspects
  `ProcResult.ok` and only counts successful bursts (previously failures were
  appended as successes).
- **Capability-aware action space** — `reason` is only varied/learned for scapy
  (the one engine that honours arbitrary reason codes); other tools use a single
  canonical reason, so the bandit no longer learns non-causal parameters.
- **Injection gate** — a failed injection test now disables active deauth
  (passive capture only) instead of being ignored.
- **Dead configs wired** — `deauth.enabled`, `learning.enabled`,
  `adapter.auto_monitor`, and `capture.write_interval` are now honoured.
- **Exception-safe adapter cleanup** — adapter reset moved to a `finally` block
  so it runs even on unexpected exceptions.
- **Capture/retarget lifecycle** — refined-client deauth now runs inside a
  *fresh* capture session (previously it ran after `session.stop()`, so the
  retargeted handshake was never captured).
- **Transfer weight scales the evidence gate** — borrowed (similar-AP) evidence
  now counts toward `min_observations` scaled by the transfer weight λ.
- **NIM deauth_tool restricted** to real deauth engines (hcxdumptool ignored).
- **Config validation** — reason codes, bands, strategy enum, prefer_tier, and
  target MACs are now validated (fail fast, no silent clamping).
- **Public `available_deauth_tools()`** replaces direct `_deauth_chain` coupling.
- **Authorization is per-run** — the persistent consent marker was removed; each
  autonomous run re-prompts (it is an acknowledgement, not an enforcement boundary).
- **Analyzer EAPOL detection** — uses the explicit `eapol.type` field instead of
  a fragile substring match.
- **Documentation corrected** — verifier is described as "primary structural
  verification + contradiction checks" (not a strict intersection); "certainty"
  softened to "structural consistency"; "Bayesian posterior" → "Beta-style
  weighted posterior"; transition-mode claims no longer imply an active
  downgrade attack.

## [1.3.0] — 2026-08

### Scope & precision completion
- **WPA-Enterprise (802.1X/MGT) detection** — enterprise APs are now labelled
  distinctly (`WPA2-Enterprise` / `WPA3-Enterprise`) and explicitly *excluded*
  from capture targets (their handshakes are capturable but not PSK-recoverable,
  so attacking them wastes airtime).
- **Frequency precision** — APs expose a `frequency` (center MHz) derived from
  the channel for 2.4/5 GHz, distinguishing same-channel APs across bands.
- **Learned capture-engine choice** — hcxdumptool vs airodump success is now
  *wired back into the decision*: the engine prefers the proven engine per AP
  once enough trials accumulate (previously it was measured but not used).
- **`handshaker export`** — bundle verified handshakes + PMKIDs + the full
  report + learning state into a timestamped directory (capture → learn →
  report → export loop complete).
- **`handshaker capture --loop`** — long-run mode: repeat scan+capture until
  interrupted, accumulating learning across iterations.

## [1.2.0] — 2026-08

### Precision, timing, strategy & learning upgrades
- **Handshake-quality score** — the verifier now emits a 0..1 quality score
  (completeness × distinct-message ratio × nonce consistency) instead of a bare
  pass/fail, giving the learner and operator a graded signal.
- **Reconnection-latency measurement** — the analyzer measures deauth → first
  EAPOL latency; the store tracks a decayed per-AP mean, and the engine uses an
  *adaptive* post-deauth verify-wait instead of a hardcoded `sleep(2)`.
- **Graded reward** — the bandit now learns from a graded reward (quality +
  speed + stealth bonus; partial credit for a crackable M2+M3 pair), not a flat
  0/1. Fractional rewards feed the Thompson/UCB posterior directly.
- **Per-target round budget** — APs that historically failed get fewer rounds
  (proven-hard), cold APs get the default, prior-success APs keep the full budget.
- **Capture-engine choice learning** — hcxdumptool vs airodump success is
  tracked per AP so the capturer can prefer the engine that actually works.
- **Adaptive scan dwell** — optional two-pass scan: quick survey to find active
  channels, then a focused longer dwell on only those channels (`scan.adaptive`).

## [1.1.0] — 2026-08

### Modern-toolchain & security-model upgrades
- **hcxdumptool v6.3+ compatibility** — the wrapper now probes `--help` at
  runtime and selects the correct flag family (`-w` vs `-o`, `--rds` vs
  `--enable_status`, `--attemptclientmax=0` vs `--disable_client_attacks`),
  since hcxdumptool's CLI changed in v6.3.0 (May 2023). The background capturer
  now uses the same version-adaptive argv (previously it hardcoded pre-6.3
  flags).
- **WPA3 transition-mode detection** — `WPA2/WPA3` APs are now labelled
  distinctly and treated as capturable via WPA2 downgrade (Dragonblood), instead
  of being collapsed into pure `WPA3` (which would wrongly exclude PMKID).
- **PMF (802.11w) fallback** — when classic deauth fails every round, the engine
  makes a last-resort capture using hcxdumptool's own MFP-aware attack vectors
  (`capture.pmf_fallback`).

## [1.0.0] — 2026-08

### Core
- Autonomous 4-way handshake capture (EAPOL) via `airodump-ng` / `hcxdumptool`.
- PMKID capture via `hcxdumptool` (AP-only attack) with hashcat 22000 conversion.
- **Strong multi-tool verification** — tshark (ground truth) cross-checked with
  `aircrack-ng`, `hcxpcapngtool`, `pyrit`, `cowpatty`, `capinfos`; only genuine
  4-way handshakes are retained, everything else is rejected and deleted.
- Packet-level structural validation: direction, nonce/MIC presence + length,
  per-direction replay-counter monotonicity, retransmission de-duplication.
- Strategic deauth (`scapy` raw-frame / `aireplay-ng` / `mdk4` / `bettercap`)
  with client targeting, reason-code rotation, single-engine fallback, and
  Wireshark-driven mid-campaign re-targeting.

### WPS assessment
- Full WPS attack surface: pixie dust, pixie force, pixie loop, vendor default
  PIN, known PIN, push-button connect (PBC).
- Strategic attack ordering: vendor-aware, lock-aware, and learning-driven.

### Learning / adaptation
- Advanced multi-armed bandit (Thompson sampling / UCB1 / epsilon) over deauth
  actions, with **cross-AP transfer learning** (hierarchical shrinkage).
- Separate PMKID learning track (never pollutes the deauth bandit).
- WPS method ordering with Beta posteriors + cross-AP transfer.
- Persistent state (JSON) + SQLite results history.

### Optional NVIDIA NIM integration
- Strategy *suggestions* only (never verification): smart model selection,
  token-bucket rate limiting, exponential backoff honoring `Retry-After`,
  degraded-model cooldown, strict schema validation.

### Tooling
- `setup.py` — environment doctor: OS, Python, venv, 24-tool detection with apt
  mapping, API-key format + live validation (expired/revoked/invalid detection).
- Rich TUI with plain-text fallback; `--json` on all commands.
- `handshaker selftest` — guided hardware validation.
- `handshaker report` — captured artifacts + learning state.
- `handshaker doctor` — system self-check.
- 112 unit + integration tests.

### Ethics & scope
- Interactive authorization gate on every autonomous run.
- Capture only — no password hashing, no cracking, no brute force.
