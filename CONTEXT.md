# CONTEXT.md — FlockBack

> Internal context file for future Claude Code sessions working in this repo. Human docs live in `README.md` (user-facing) and `docs/*.md` (RF/protocol theory). This file is the engineering map + audit trail.

Last audited: 2026-08-17, by Claude Code. Environment: this machine has a real `hci0` Bluetooth adapter and a real `wlo1` WiFi adapter (this is the user's actual laptop, not a disposable sandbox — see "Environment" section before running anything that touches `wlo1`).

---

## 1. What This App Is

**FlockBack** is a Python CLI tool for passively detecting **Flock Safety AI license-plate-reader (LPR) cameras** (and related hardware: Raven, Penguin, PigVision) while wardriving. It listens for two independent radio signatures these devices leak:

- **BLE advertisements** — older/some camera firmware still broadcasts a GAP `local_name` (e.g. `"FS Ext Battery"`, `"Flock"`, `"Penguin"`) in plaintext, no connection required.
- **WiFi probe requests / beacons** — newer firmware stopped BLE advertising and instead the camera's WiFi radio sends wildcard probe requests (hidden-SSID scanning behavior) whose transmitter MAC matches known Flock-hardware OUIs.

Detection is entirely passive/receive-only — no packet injection, no active probing, no connection attempts. (`-test` mode / `Inject_Test` is misleadingly named: it also just *listens* for probe requests to verify an adapter is in working monitor mode, it does not inject anything.)

This is a defensive-privacy / civil-liberties tool: it exists to let someone find and document surveillance cameras in their environment, not to attack the cameras. The `docs/` folder is deliberately educational (RF jamming theory, LTE band theory) but the tool itself does not jam or attack.

### Real-world deployment
FlockBack is the **detection engine** inside a separate project, **Dooku** (`github.com/nsm-barii/dooku`) — a Raspberry Pi 5 based hardened wardriving rig with multiple monitor-mode adapters that runs headless, creates its own AP, and auto-launches FlockBack on boot with `-w -k -p`. This repo is a library/CLI consumed by that hardware project; treat "how does this actually get used" as "inside Dooku, in wardriver+kismet+packet mode."

---

## 2. Architecture

```
src/
  main.py            CLI entrypoint / arg parsing / boot sequence (Main_UI)
  vars.py             Global mutable state (Variables class — shared across all threads)
  flock_finder.py      Core detection engine: PDU_Inspector (signature matcher),
                       BLE_Sniffer (bleak-based), WiFi_Sniffer (tshark subprocess-based),
                       Main_Thread (orchestrator), Inject_Test (probe-request listen mode)
  wardriver.py         Wardriver mode (-w): auto-detects monitor adapters, splits
                       2.4/5GHz channels across them
  kismet_watcher.py    Kismet mode (-k): polls Kismet's REST API every 2s instead of
                       running tshark directly; also exports WiGLE-format CSV
  database.py          DataBase (vendor/manufacturer lookups, BLE service UUID tables,
                       flocks.json/packets.json writers) + Utilities (banner, timestamps,
                       monitor-mode helper) + Background_Threads (channel hopper)
  signatures.py        FLOCK_SIGNATURES dict — the actual detection fingerprints
                       (MAC OUI prefixes, SSID strings, BLE names, Raven BLE service UUIDs)
  server.py            Stdlib http.server exposing /api/cameras (JSON) + serving gui/ statically
  mode.py              Standalone CLI script to flip an iface between managed/monitor — BROKEN, see audit
  deappreciated.py     Dead code graveyard, not imported anywhere — see audit

gui/                  Static dashboard (vanilla HTML/CSS/JS), polls /api/cameras every 2s
database/              Signature data + vendor DBs + runtime output (flocks.json etc.)
docs/                  RF/protocol theory write-ups (BLE, WiFi, LTE, jamming, references)
setup/                 Plain-text setup notes (GPS on Arch/Debian, BLE troubleshooting, etc.)
proof/                 Screenshot evidence of real-world detections
```

### Execution flow (`main.py` → `Main_UI.main_menu`)
1. Parse args, populate `Variables` (the global state god-object — everything reads/writes this one class, guarded by `Variables.LOCK` for the pieces that matter).
2. If `-w`: `Wardriver.main()` — detects all non-AP monitor-capable adapters, splits channel bands across them, populates `Variables.ifaces` (dict of iface → channel list), and starts a channel-hopper thread per iface (skipped if `-k` also set, since Kismet owns channel hopping then).
3. If `-i <iface>` given without `-w`: puts that single iface into monitor mode.
4. Print banner + constants panel.
5. Always calls, in order: `Kismet_Watcher.main()`, `Inject_Test.main()`, `Main_Thread.main()`. Each of these is a no-op early-return unless its corresponding flag (`-k`, `-test`) is set — so in practice only one of the three ever actually does anything, and whichever one does becomes the permanent blocking call (each contains an infinite loop / `serve_forever()`).
6. Two independent sniffer threads run: `BLE_Sniffer` (asyncio + `bleak`, unless `-nb`) and `WiFi_Sniffer` (subprocess wrapping `tshark`, only if an iface is active). Both funnel hits through `PDU_Inspector.controller()`.
7. On a hit: printed to console, appended to `Variables.ai_cameras_all`/`ble_ai_cameras`/`wifi_ai_cameras` (in-memory, read by the `/api/cameras` endpoint), and appended as a line of JSON to `database/flocks.json` (first-seen) or `database/packets.json` (repeat hits, only if `-p`).
8. If not in wardriver multi-iface mode, `Main_Thread` starts `Web_Server` (blocking `serve_forever()` on port 8000) serving the dashboard + API. **This means the GUI dashboard never starts in `-w` (wardriver) mode** — see audit #3, this is the flagship Dooku deployment mode.

### Detection logic (`PDU_Inspector` in `flock_finder.py`)
Four independent checks, ORed together — a hit on *any* one of these triggers a "Found AI Camera":
- `_check_ssid` — exact string match against `FLOCK_SIGNATURES["wifi_ssid_patterns"]`
- `_check_mac` — MAC prefix match (case-insensitive `startswith`) against `FLOCK_SIGNATURES["mac_prefixes"]`
- `_check_ble_name` — exact match against `FLOCK_SIGNATURES["ble_name_patterns"]`
- `_check_uuid` — BLE service UUID match against `FLOCK_SIGNATURES["raven_service_uuids"]`

All signature data lives in one place: `src/signatures.py`. This is the single most valuable file to keep updated — it's the entire fingerprint database, and the README explicitly solicits community contributions of new OUIs/SSIDs/UUIDs.

### WiFi capture path
`WiFi_Sniffer._wifi_scanner` shells out to `tshark` with display filter `wlan.fc.type_subtype == 0x04 || wlan.fc.type_subtype == 0x08` (probe requests **and** beacons) and parses fixed-position tab-separated fields from stdout line-by-line, streaming (not a pcap read). Vendor lookup uses two chained local OUI databases (`database/manuf_old.txt` from Wireshark's manuf, `database/manuf_ring_mast4r.txt` as fallback).

### BLE capture path
`BLE_Sniffer.ble_scan` runs `bleak.BleakScanner` in a loop: `start()` → sleep `ble_scan_duration` (default 5s, `-bs`) → `stop()` → read `discovered_devices_and_advertisement_data`. This is a **cumulative snapshot poll**, not an event stream — devices are only reported once per scan window and de-duped for the process lifetime via `cls.macs`.

### Kismet path (`-k`)
Alternative to running `tshark` directly — polls Kismet's REST API (`/devices/summary/devices.json`) every `POLL_INTERVAL = 2` seconds, matches against a *subset* of the same signature dict (MAC prefix + SSID-in-name + SSID-in-vendor — notably **does not** check BLE names or Raven UUIDs, since Kismet mode is WiFi-only), and separately logs every device seen (matched or not) to `database/wigle.csv` in WiGLE-upload format. When `-k` is active, BLE sniffing still runs as its own thread if not `-nb`.

---

## 3. CLI Reference (flags, `main.py`)

| Flag | Effect |
|---|---|
| `-i <iface>` | Single monitor-mode WiFi iface |
| `-b <adapter>` | Bluetooth adapter (default `hci0`) |
| `-w` | Wardriver mode — multi-adapter, auto band-split |
| `-k` | Kismet mode — poll Kismet instead of driving tshark directly |
| `-nb` | Disable BLE scanner |
| `-p` | Packet mode — keep logging repeat hits to `packets.json` |
| `-v` | Verbose — print non-matching devices too |
| `-g [host:port]` | Enable GPS tagging of hits via gpsd (default `127.0.0.1:2947`). Requires gpsd running with a source configured — see `setup/*_gps_setup.txt` (`android_gps_setup.txt` covers using a phone instead of a dongle). Wired up 2026-08-17, see §8. |
| `-bs <sec>` | BLE scan window (default 5) |
| `-delay <sec>` | Channel hop dwell (default 0.125) |
| `-hops <ch...>` | Custom channel list |
| `-preset {2.4,5,all}` | Channel preset |
| `-test` | Listen-only probe-request verification mode (requires `-i`) |
| `-h` | Help |

---

## 4. Environment / How To Run (verified 2026-08-17)

This machine already has: Python 3.12.3, `bluez`/`bluetoothctl`/`hciconfig` installed, Bluetooth service active with a real `hci0` adapter, and a real WiFi interface `wlo1` (currently your primary connected network — **do not** put it into monitor mode without asking first, it will drop your internet connection).

**`tshark` 4.2.2 is now installed** (was missing at first audit, installed by the user 2026-08-17). `dumpcap` is capability-restricted (`cap_net_admin,cap_net_raw`, group-owned by `wireshark`); the current user is **not** in the `wireshark` group, so unprivileged capture fails with `Permission denied` — confirmed by testing `tshark -i wlo1 -c 1` as the plain user. This matches the README's `sudo venv/bin/python main.py` instruction: **run flock-back with `sudo`, or add your user to the `wireshark` group** (`sudo usermod -aG wireshark $USER`, then log out/in) if you want to run it unprivileged.

I validated the exact filter expressions and field names both `WiFi_Sniffer._wifi_scanner` and `Inject_Test.main()` use — `wlan.fc.type_subtype == 0x04 || 0x08`, `wlan_radio.channel`, `wlan_radio.frequency`, `radiotap.dbm_antsignal`, `frame.interface_name`, etc. — against tshark 4.2.2 by running them over an empty pcap (`tshark -r empty.pcap -Y "..." -T fields -e ...`, exit 0, no "field doesn't exist"/filter-syntax errors on either command). This confirms the capture commands are syntactically valid on the tshark version installed here; it does **not** confirm real packets parse correctly, since that needs actual monitor-mode 802.11 traffic.

**Live WiFi capture (`-i`, `-w`, `-test`) was intentionally not tested end-to-end.** This machine has exactly one WiFi adapter (`wlo1`/`phy0`, currently associated to the user's network) and no secondary monitor-mode-capable adapter — putting `wlo1` into monitor mode would drop the machine off its network. Given the choice, the user opted to skip live capture testing rather than disrupt connectivity. If a second adapter becomes available, the untested paths are: real probe-request/beacon parsing (`WiFi_Sniffer._line_parser`), wardriver mode's multi-adapter band-splitting (`Wardriver._get_adapters`/`_split_channels`), and `-test` mode's live listen loop.

**What I set up and verified:**
```bash
cd src
python3 -m venv venv
source venv/bin/activate
pip install -r ../requirements.txt   # rich, pyfiglet, requests, scapy, bleak, pathlib, gps3, manuf — all installed clean
```

**Verified working (no hardware/tshark needed for these):**
- All `.py` files parse cleanly (`ast.parse`) except one `SyntaxWarning` (see audit #7).
- `python3 main.py -h` — banner + arg parsing works end-to-end.
- `python3 main.py -bs 3` (BLE-only, no `-i`) — ran clean for 12s: banner, BLE_Sniffer thread started, Web_Server started, no exceptions.
- `/api/cameras` endpoint returns valid JSON (`{"wifi": [], "ble": []}`), `gui/index.html` serves 200 over the built-in web server.
- Signature-matching unit checks against `PDU_Inspector` (MAC/SSID/BLE-name/UUID) all returned expected True/False.
- Vendor DB lookup (`DataBase.WiFi.get_vendor_main`) resolves a real OUI correctly.
- `database/bluetooth_sig/assigned_numbers/company_identifiers/company_ids.json` already exists (294KB, pre-generated from the vendored `company_identifiers.yaml` via `database/converter.py` — you don't need to regenerate it).

**Not verified (needs a second monitor-mode adapter and/or `sudo`, deliberately skipped to avoid dropping this machine's only WiFi connection):**
- Real WiFi probe-request/beacon capture (`-i`) and wardriver mode (`-w`) end-to-end — filter/field syntax is confirmed valid for tshark 4.2.2 (see above), but no live 802.11 frames were parsed.
- Kismet mode (`-k`) — needs a running Kismet instance, not set up here.
- Actual over-the-air Flock camera detection (no camera in range to test against).
- Running as `sudo` in general — BLE scanning worked fine without root here (BlueZ D-Bus API), but confirmed `tshark`/`dumpcap` capture does need elevated privileges on this machine (permission denied as plain user; user is not in the `wireshark` group) — so `-i`/`-w`/`-k`/`-test` all require either `sudo` or that group membership.

**No automated test suite exists in this repo** (confirmed — no `test_*.py`, no `pytest`/`unittest` anywhere, no CI config). Everything above was manual/exploratory verification. If you want durable regression coverage, the signature-matching logic in `PDU_Inspector` (pure functions, no I/O) is the highest-value, lowest-effort thing to actually unit test.

---

## 5. What It Doesn't Do / Known Gaps

- ~~No GPS/location tagging in the main detection path~~ — fixed 2026-08-17 (see §8): `-g` now starts a background gpsd client that tags every hit with `lat`/`lon`. Kismet mode's `geopoint` field and the WiGLE CSV export remain the location path for `-k` runs, unaffected by this change.
- **No pcap/packet storage** — tshark output is parsed line-by-line and discarded; there's no raw capture artifact to go back and re-analyze later.
- **No encryption detection for the primary WiFi path** — `encryption` is hardcoded to `"unknown"` in every `flocks.json`/`packets.json` WiFi record (see audit #6).
- **No persistence/dedup across runs** — `cls.macs` (BLE) and `cls.macs`/`cls.flock_macs` (WiFi) are in-process sets, reset every run. Re-running the tool re-alerts on cameras already logged in a previous session's `flocks.json`.
- **No GUI in the primary deployment mode** — the dashboard only serves when a single-iface/no-iface path is taken; wardriver mode (the Dooku use case) never starts the web server (audit #3).
- **Signature set is small and manually curated** — 20 MAC prefixes, a handful of SSID/BLE-name strings, 8 Raven UUIDs. No fuzzy/heuristic matching, no ML — pure exact-match/prefix-match. Anything with a MAC prefix not in the list is invisible to this tool regardless of behavior.
- **No rate limiting / signal validation** — a single probe request with a matching MAC is enough to declare a hit; no correlation across multiple observations, no RSSI-based proximity gating.

---

## 6. Audit Findings

Ranked roughly by severity/impact.

### 1. `src/mode.py` is completely broken — crashes on import-time argparse setup
```python
parser.add_argument("a", required=False, action="store_true", ...)
```
`required=` is not a valid kwarg for a positional argument; argparse raises `TypeError` from inside `add_argument()` itself, before any user input is even read. **Verified**: `python3 mode.py -i wlan0` crashes immediately with `TypeError: 'required' is an invalid argument for positionals`. This script (a standalone "quickly flip iface mode" utility) cannot run at all in its current state. Either fix the arg definition (drop `required=`, and `a` probably should've been a `-a` flag, not positional) or remove the file if `Utilities.get_monitor_mode` fully superseded it.

### 2. Sensitive real-world capture data committed to git
`database/bari.json` is tracked in the repo and contains a real wardriving detection (timestamp, MAC, RSSI, SSID, vendor) — someone's actual capture output got committed instead of gitignored. More importantly, **none of the runtime output files are gitignored**: `.gitignore` (root) only excludes `venv/`, `*.pyc`, `.claude/` — it does not exclude `database/flocks.json`, `database/packets.json`, or `database/wigle.csv`. The WiGLE CSV in particular carries lat/lon coordinates. Anyone running this tool and doing a naive `git add .` / `git commit` will leak their own location/device-tracking history into version control. Recommend adding these to `.gitignore` and considering whether `bari.json` should be purged from history.

**Partially fixed 2026-08-17**: `.gitignore` now excludes `database/flocks.json`, `database/packets.json`, `database/wigle.csv`. `bari.json` has not been purged from history — still there if that's ever wanted.

### 3. Web dashboard never starts in wardriver mode (the primary/documented deployment path)
`Main_Thread.main()` and `Kismet_Watcher.main()` both gate `Web_Server.start()` behind `if not Variables.ifaces` (i.e., only when *not* in multi-adapter wardriver mode). But Dooku — the actual hardware product this tool ships inside — runs `-w -k -p`, which populates `Variables.ifaces`. So in the intended real-world deployment, `/api/cameras` and `gui/index.html` are never served. The dashboard's `dashboard.js` also fetches `/api/cameras` — it has no fallback to read `flocks.json` directly, so there's currently no way to view live results in a browser while wardriving with the recommended flags.

### 4. `gui/README.md` is stale and describes a different architecture than what exists
It documents editing `dashboard.js` line 5 to point at a file path `../../../.data/flock-back/war_drives/live.json` and references a hardcoded macOS path from the original author's machine (`/Users/jabarilucien/Documents/nsm_tools/flock-back/gui`). The actual `dashboard.js` fetches `/api/cameras` (an HTTP endpoint, not a file) and has no `DATA_PATH` file-editing story anymore. This README predates the `server.py` API rewrite and will actively mislead anyone trying to reconfigure the dashboard.

### 5. Half-finished WiFi encryption detection
`DataBase.WiFi.get_encryption_tshark()` and `update_encryption()` are fully implemented (parse `protected`/`rsn`/`akm`/`wep` tshark fields into WEP/WPA/WPA2/WPA3) but **never called**. `WiFi_Sniffer._wifi_scanner`'s tshark field list doesn't even request `wlan.rsn.*`/`wlan.fixed.capabilities.privacy`/etc., and `_line_parser` just hardcodes `encryption = "unknown"` with a comment `# THIS WILL BE TO COMPLICATED TO GET WITH TSHARK`. So there's a full, unused implementation sitting next to a stub that contradicts it — pick one: wire it up (add the missing `-e` fields) or delete the dead methods.

### 6. Dead/unreachable code with a live bug inside it
`DataBase.Bluetooth._get_uuids_main` (in `database.py`) is never called from anywhere in the codebase (the actual UUID matching path is the separate, working `PDU_Inspector._check_uuid`). Its `else` branch does `for service in service:` — iterating over the string/scalar loop variable name from a completely different (and only conditionally-executed) prior loop, which would raise `UnboundLocalError`/`NameError` if this branch ever executed. Harmless today only because nothing calls it. Same file also has two other unused stubs: `_get_service_uuids` (literally `pass`) and `_get_etc` (implemented, unused). Recommend deleting all three — they're not "in progress," they're orphaned.

### 7. `src/deappreciated.py` (typo for "deprecated") is dead weight and doesn't even run
Not imported by any other module (confirmed via grep). Contains `Settings`, `WiFi_Sniffer_old`, `Recon_Pusher` — references undefined names (`BASE_DIR`, `Dot11`, `LOCK`, `Main_Thread.BACKGROUND`, `Main_Thread.ai_cameras_all`) that don't exist in the current codebase (state moved to `Variables` long ago). It would fail immediately if anything tried to import/run it. Safe to delete outright rather than keep "in case."

### 8. Cosmetic: `SyntaxWarning` on every startup
`src/database.py:567`, inside `Utilities.help_menu()`'s ASCII art string, has `\_` sequences in a non-raw string, producing `SyntaxWarning: invalid escape sequence '\_'` on every single run (visible in the `-h` output captured during testing today). Trivial fix: make it a raw string (`r"""..."""`).

### 9. Minor doc/config drift
- README's options table says `-k` "polls Kismet REST API every 10s"; the actual constant is `POLL_INTERVAL = 2` (2 seconds) in `kismet_watcher.py`, and the in-program log message *also* says "checking every 10s" — three-way mismatch between README, log string, and real value. Pick the true number and fix all three.
- `docs/wifi.md` states "Flock cameras do not beacon... you will not see them in a standard WiFi scan as an AP" and frames probe requests (`0x04`) as the sole detection vector, but the actual tshark filter in `flock_finder.py` also captures beacon frames (`0x04 || 0x08`). Not wrong, just under-documented — worth a one-line note on why beacons are also captured (likely to catch the FS Ext Battery / other non-camera Flock-adjacent hardware that *does* act as an AP).

### 10. `Kismet_Watcher._match` is a strictly weaker signature check than the main path
It only checks MAC-prefix and SSID-substring-in-name/vendor — no BLE names (expected, Kismet mode is WiFi-only) but also no Raven UUID matching equivalent, and it's a **substring** match (`pattern.lower() in vendor`) rather than the exact-match logic used elsewhere, which is inconsistent (slightly more permissive) versus `PDU_Inspector._check_ssid`'s exact-equality check. Worth deciding intentionally whether Kismet-path matching should be as strict as the direct-tshark path, and documenting the difference if not.

---

## 8. Session log — 2026-08-17 (follow-up, pre-trial pass)

User was preparing a real trial run (single-adapter, plain `-i` mode, offline, possibly a long parked scan) and asked for anything urgent affecting that specific scenario. Findings and fixes, beyond what's in §6:

- **BLE and WiFi sniffer threads died silently and permanently on any exception** (`flock_finder.py`, `BLE_Sniffer.ble_scan` and `WiFi_Sniffer._wifi_scanner`) — one transient `bleak` D-Bus timeout or `tshark` hiccup would kill that entire data stream for the rest of the run with no restart and no obvious indicator beyond a scrolled-past console line. This is the reliability gap most likely to bite an unattended parked-car session. **Fixed**: both now retry with a short backoff (BLE: per-scan-cycle try/except with 2s sleep; WiFi: outer `while Variables.BACKGROUND` loop around the tshark subprocess, 2s sleep between restarts) instead of the thread just ending.
- **`Background_Threads.channel_hopper`'s actual per-channel `iw dev ... set channel` call had no `sudo`**, inconsistent with the sibling `set_channel` branch and `Utilities.get_monitor_mode` right next to it (`database.py`). Masked entirely if the whole process runs as `sudo venv/bin/python main.py` (recommended path — child processes inherit root), but would silently fail every hop under the "add user to `wireshark` group" alternative, leaving the interface stuck on one channel with zero error output. **Fixed**: `sudo` added for consistency.
- **`.gitignore` didn't cover the runtime output files** — see updated §6 item 2 above. **Fixed.**
- **GPS was fully dead** (`-g` parsed, stored, never used; `Utilities._get_gps_cords` was a one-shot print loop, not something callers could read a value from; the flag's own help text described a serial-port path when the actual gps3/gpsd client only ever takes a `host:port`). **Fixed and rewired end-to-end**:
  - `Utilities._get_gps_cords` deleted, replaced by `Background_Threads.gps_tracker(host, port, verbose)` (`database.py`) — a resilient background thread (same retry-on-error pattern as the sniffer fixes above) that keeps `Variables.gps_fix = {"lat", "lon", "alt", "time"}` updated from gpsd's JSON protocol via `gps3`.
  - `Variables.gps_fix` added (`vars.py`), read (lock-free — dict reassignment is atomic under the GIL, consistent with how the rest of `Variables` is accessed) by both `BLE_Sniffer.ble_scan` and `WiFi_Sniffer._line_parser` in `flock_finder.py`, so every hit written to `flocks.json`/`packets.json` now carries `"lat"`/`"lon"` (`null` until a fix is available).
  - `-g` flag semantics changed in `main.py`: now `nargs="?", const="127.0.0.1:2947"` — bare `-g` enables GPS tagging against the default local gpsd, `-g host:port` points at a non-default one. `main.py` starts `Background_Threads.gps_tracker` right after monitor-mode setup when `Variables.gps` is truthy.
  - This still requires gpsd itself to be running with some GPS source — flock-back only ever talks to gpsd's JSON protocol, never a device directly, so this was and is source-agnostic.
  - User has no GPS dongle. Added `setup/android_gps_setup.txt`, documenting bridging an Android phone's GPS into gpsd via **Android-GPSd-Forwarder** (open source, forwards NMEA over UDP — `gpsd -N -n udp://*:29998` consumes it) over **USB tethering** specifically (not WiFi — the adapter will be in monitor mode and can't hold a managed link simultaneously; not Bluetooth — untested whether concurrent BLE scanning and a Bluetooth SPP GPS bridge on the same `hci0` radio contend with each other). Not verified end-to-end in this session (no phone/gpsd available here) — code side was smoke-tested against a refused connection (no gpsd running) and confirmed to retry cleanly rather than crash; the actual phone→gpsd→flock-back fix pipeline still needs a real run to confirm.
  - `README.md` and this file's §3 CLI table updated to match.

All changes smoke-tested via `timeout N python3 -u main.py -bs 2 [-g]` (BLE-only, no hardware needed) — clean startup, no exceptions, GPS retry loop confirmed non-fatal against a refused connection. Live WiFi capture, real gpsd/phone GPS fix, and long-duration/unattended behavior remain unverified in this environment for the same reasons as §4 (single WiFi adapter currently on the network, no GPS hardware here).

---

## 7. Suggested Priorities (if picking up work here)

1. **Fix or delete `mode.py`** — quick, unblocks a currently-broken standalone utility.
2. **Gitignore the runtime output files and scrub `bari.json`** — privacy/security hygiene, low effort, real risk (this tool's whole purpose is capturing device+location data; the repo currently sets a bad precedent for its own users).
3. **Decide the dashboard's fate in wardriver mode** — either start `Web_Server` regardless of `Variables.ifaces`, or explicitly document that the GUI is BLE/single-iface-only and Dooku users should read `flocks.json`/`wigle.csv` directly.
4. **Rewrite `gui/README.md`** to match the current `/api/cameras` architecture.
5. **Delete dead code**: `deappreciated.py`, `_get_uuids_main`/`_get_service_uuids`/`_get_etc` in `database.py`, unused encryption-detection methods (or wire them up instead — pick one).
6. **Add a minimal test suite** for `PDU_Inspector`'s four `_check_*` methods — pure functions, zero I/O, highest ROI for regression safety as the signature list grows via community contributions.
7. Once `tshark` is installed, do a full live smoke test of `-i`, `-w`, and `-test` modes to confirm the WiFi capture path still works end-to-end on current tshark/Wireshark versions.
