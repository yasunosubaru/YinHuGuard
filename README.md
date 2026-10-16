# YinHuGuard

A **read-only** Windows triage tool for the Silver Fox (ValleyRAT) trojan — surfaces hidden processes, persistence mechanisms, and kernel-level implants that traditional antivirus often misses.

Built for incident responders who need to answer one question quickly: *"Is this machine compromised, and if so, where?"*

---

## What it does

YinHuGuard scans **seven surfaces** in a single pass and presents results through a desktop GUI, CLI, and machine-readable reports. It is **strictly read-only** — no cleanup, no remediation, no system modification. Detection and reporting only.

The first three surfaces originate from a widely-circulated batch script by [@SYSTEM-RAMOS-ZDY](https://space.bilibili.com/493998035); the remaining four are deep-scan surfaces added by this project, each backed by vendor threat intelligence.

| # | Surface | What it finds |
|---|---------|---------------|
| 1 | **Hidden Processes** | Executables with `hidden` or `system` file attributes |
| 2 | **Hidden Run Keys** | Run/RunOnce registry entries pointing to hidden files |
| 3 | **Suspicious Services** | Services launched via command interpreters, or binaries outside system directories |
| 4 | **Registry Payloads** | `HKCU\Console\` hex-named values, `IpDates_sun`, `Magisk`, `FaCai2024` markers — *not* startup items, but deleting them is required for full remediation |
| 5 | **Driver Services** | Known BYOVD driver names; `ImagePath` outside `System32\drivers`. Silver Fox uses these to kill protected processes from kernel mode — all carry valid signatures, so name-matching is the only reliable method |
| 6 | **File Drops** | Known full paths; arbitrary `.sys` in `ProgramData`; 6-character alphanumeric random subdirectories under IE paths |
| 7 | **Scheduled Tasks** | Known task names; actions targeting non-standard directories |

All seven surfaces run sequentially — you cannot skip any. Deep-scan surfaces (4–7) increase total scan time from seconds to minutes, with scheduled tasks being the slowest.

---

## Key Features

- **Self-check panel with four mutually-exclusive states** — enumeration failure → permission gap → coverage complete → elevated-normal — so "no findings" never silently means "clean"
- **Uncovered item triage** — automatically classifies unreadable entries against a known-component list (Windows system components / identified third-party / needs review), reducing a 38-item list to a 1-item action list
- **Multi-channel output** — desktop GUI, CLI, JSON report, CSV report, and structured log — all from the same data source
- **Automatic redaction** — usernames and machine names replaced with `<USER>` / `<MACHINE>` in all output; file paths preserved for remote analysis
- **Zero network activity** — no uploads, no crash reporting, no telemetry, no auto-update
- **Portable** — single-folder deployment, no installation, no dependencies beyond the bundled DLLs

---

## Self-Check Panel

The most important UI element. It exists to prevent the fatal misreading: *"no findings" sounds like "the machine is clean."*

| State | Display | Meaning | Action |
|-------|---------|---------|--------|
| **Incomplete** | Red | Items exist that couldn't be checked due to permissions — elevation resolves this | Click "Full Scan (Elevate)" → UAC "Yes" |
| **Elevated: Everything Checkable Was Checked** | Blue | Elevated, no permission gaps; a few items remain unreadable (protected processes, race conditions) — listed as "uncovered," normal | No action needed; results are conclusive |
| **Coverage Complete** | Blue | Elevated, zero permission gaps, zero uncovered items in the findings list (rare on real machines) | Results are conclusive |
| **Enumeration Failure** | Blue | Process/service enumeration returned zero — engine malfunction, results unusable | Re-scan; if persistent, re-extract a fresh copy |

The panel shows raw counts: elevated status, process total, path-resolved count, Session 0 visible count, service total, ImagePath-resolved count.

---

## Uncovered Item Triage

After elevation, dozens of items may remain unreadable. Rather than asking the user to manually verify each one, YinHuGuard cross-references every uncovered entry against a built-in known-component list:

| Marker | Meaning | What to do |
|--------|---------|------------|
| **Known System Component** | Name matches a Windows built-in process or driver | Ignore |
| **Known Third-Party** | Name matches an identified vendor component (e.g., Intel PresentMon) | Ignore |
| **Needs Review** | Name not in the list | Open Task Manager and identify it |

A summary line appears in the self-check panel: e.g., *"Uncovered 38: 37 matched known components, 1 needs review."*

**Two critical limitations:**
1. **Name-only matching** — uncovered items are precisely those whose paths cannot be read, so no path, signature, or hash is available. Names can be spoofed. "Matched" means "the name is familiar," **not** "it is safe."
2. **Not a verdict** — matched items remain visible, remain marked "uncovered," and are never folded away. The tool's principle: *what cannot be read must not be hidden.*

This classification only appears in the **elevated** view. Without elevation, unreadable items are explained by the permission gap, not by identity.

---

## Quick Start

1. Extract the entire zip to a folder (do **not** run from inside the archive)
2. Double-click `YinHuGuard.exe`
3. Click **Start Scan**

The program does **not** auto-scan on launch — a security tool that enumerates processes and services before the user clicks anything is indistinguishable from malware.

On completion, logs and reports are written to `reports/` beside the executable. If that location is not writable (e.g., installed under `Program Files`), output falls back to `Documents\YinHuGuard`.

### SmartScreen

This tool is **not code-signed**. Individual code-signing certificates cost ~$200/year, so SmartScreen will flag it as unknown publisher. This is expected.

To proceed:
1. See the blue "Windows protected your computer" dialog
2. Click **"More info"**
3. Click **"Run anyway"**

If that dialog makes you uncomfortable, that is reasonable — a trojan-scanning tool deserves suspicion. You can use CLI mode first, which produces the same report without a GUI.

---

## CLI Usage

```powershell
YinHuGuard.exe --scan                      # Scan and print summary
YinHuGuard.exe --json D:\report.json       # Scan and write JSON report to specified path
```

Exit codes: `0` no findings, `10` findings present, `1` argument error, `2` engine error, `3` config/engine not found.

---

## Building from Source

### Prerequisites

- [Flutter SDK](https://docs.flutter.dev/) (stable channel)
- [CMake](https://cmake.org/) ≥ 3.20
- Visual Studio 2022 or later with C++ workload
- Windows SDK 10.0.22000.0+

### Build

```powershell
# Configure and build the C++ engine
cmake -S engine -B engine/build -G "Visual Studio 17 2022" -A x64
cmake --build engine/build --config Release

# Build the Flutter app
cd app
flutter build windows --release

# Package for distribution
cd ..
powershell -File package/build_package.ps1
```

### Project Structure

```
YinHuGuard/
├── engine/                  # C++ scanning engine (DLL)
│   ├── include/             #   Public headers
│   ├── src/                 #   Implementation (7 scan surfaces)
│   └── tests/               #   CTest unit tests
├── app/                     # Flutter GUI application
│   ├── lib/
│   │   ├── ui/              #   Dashboard, self-check panel, findings table
│   │   ├── headless.dart    #   CLI entry point
│   │   └── elevate.dart     #   UAC elevation logic
│   └── test/                #   Widget tests
├── lib/                     # Core library (pure Dart)
│   └── src/
│       ├── model/           #   Finding, Observation, SelfCheck
│       ├── criteria/        #   Evaluator, redaction
│       ├── triage/          #   Known-component matcher
│       ├── report/          #   JSON/CSV/log writers
│       └── scan/            #   Orchestrator
├── fixtures/                # Test data (synthetic machine states)
├── rules/rules.json         # Scan configuration (pure data, user-editable)
├── package/                 # Packaging script and distribution README
└── docs/                    # Design specs and implementation plans
```

---

## Design Principles

1. **Read-only** — the tool never deletes, modifies, stops, or cleans anything. It reads and reports. Full stop.

2. **Never hide what cannot be read** — upstream batch scripts silently drop items they cannot access. YinHuGuard surfaces every unreadable item with an explicit reason, so "no findings" never becomes a false all-clear.

3. **One computation, four channels** — findings are evaluated once in the core library, then consumed identically by the GUI, log writer, CLI, and JSON report. No channel-specific logic.

4. **Judgment follows elevation state** — an `ACCESS_DENIED` before elevation means "run as admin." The same error after elevation means "protected by the kernel." The wording, color, and flags all change accordingly.

5. **No permanent red** — a warning that is always on becomes invisible after two weeks. Residual items (race conditions, protected processes) are gray, not red. Only genuinely actionable gaps are red.

6. **Rules are pure data** — `rules.json` is the only user-editable configuration. It is never code, never executed, and malformed values cause startup rejection with a specific error.

---

## What It Does Not Do

| Not included | Why |
|-------------|-----|
| Cleanup / remediation | Risk of damaging the system; the upstream script's destructive operations include deleting the volume shadow copy service |
| Process code signature verification | Silver Fox injects into `svchost`/`winlogon`/`explorer`; signature checking is the only reliable defense against name-legitimate processes, but implementation is ongoing |
| Network IOC matching | Out of scope for a local triage tool |
| COM / TypeLib hijacking, DLL side-loading | No public evidence of Silver Fox using these; adding them would be noise |
| Winlogon hijacking (`Shell`/`Userinit`), IFEO, WMI event subscriptions | Same as above |

---

## Known Limitations

- **Heuristic detection** — false positives are expected. Normal software sometimes hides its files; vendor drivers and security tools often live outside `System32`. Findings require human confirmation before acting on them.
- **Name-only triage** — the known-component list matches by name only. A spoofed name will be classified as "known." This is a triage aid, not a verdict.
- **Coverage is partial** — the tool covers known Silver Fox techniques. New variants, changed IOCs, and novel techniques will not be detected. "No findings" does not mean "not compromised."

If you suspect an active compromise:
1. Run this tool (elevated) to identify obvious traces
2. Run a full scan with a reputable antivirus (Huorong, 360, etc.)
3. If the antivirus itself cannot open, the compromise is deep — consider reimaging

---

## License

[MIT](LICENSE)

---

## Credits

Tool interface and implementation: this project. Scan methodology and the first three surfaces: [@SYSTEM-RAMOS-ZDY](https://space.bilibili.com/493998035).
