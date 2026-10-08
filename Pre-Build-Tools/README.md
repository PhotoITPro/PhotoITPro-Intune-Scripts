# Rob's Toolkit

A Windows PowerShell 5.1 toolkit with a GUI (and a command-line mode) for technicians. It has two parts:

- **Diagnostics** (read-only): 15 checks that grade findings RED / AMBER / GREEN against stated thresholds and produce a self-contained `report.html`, plus `summary.json`, `metrics.csv` and raw CSV/TXT exports. Covers system, performance sampling, memory/pool, CPU throttling, disk, OneDrive, Windows Search and Defender, startup load, drivers and updates, event logs, stability history (blue screens, dumps, failing apps), boot and shutdown timings, system file integrity, network, and security products.
- **Tasks** (these change the PC): install the Windows 11 25H2 update, remove HP Wolf Security, collect the Autopilot hardware ID, and upgrade Windows Home to Pro. They need administrator rights, ask for confirmation, and are logged.

It supersedes [`Diagnostics/Get-SlowPCReport.ps1`](../Diagnostics/Get-SlowPCReport.ps1), which is the original single-purpose "slow PC" report.

## Run it

| How | Command |
|---|---|
| GUI | Double-click `Run-RobsToolkit.bat`, or run `.\RobsToolkit.ps1` with no parameters |
| Diagnostics from the command line | `.\RobsToolkit.ps1 -Preset Performance -Label WhenSlow` |
| Quick run | `.\RobsToolkit.ps1 -Preset Stability -Quick` |
| List checks and tasks | `.\RobsToolkit.ps1 -ListChecks` |
| Tasks (changes the PC) | `.\RobsToolkit.ps1 -RunTask hwid,25h2 -Ticket INC1234 -ConfirmTasks` |
| Version | `.\RobsToolkit.ps1 -Version` |

Presets: `General` (default), `Performance`, `Stability`, `Network`, `Security`, `Update`. Use `-Include` / `-Exclude` with check ids for a custom selection. Run it as administrator for full results (SMART/NVMe data, minifilters, Defender exclusions, integrity scans, minidumps, boot timings).

Reports go to `C:\RobsToolkit\<COMPUTERNAME>_<timestamp>[_<Label>]\`. Run it twice with different `-Label` values (for example `AfterReboot` and `WhenSlow`) and compare the two `metrics.csv` files; the report explains how.

## Notes

- Diagnostics never change settings, delete anything or restart services. Tasks do change the PC; `-RunTask` only lists what it would do unless you add `-ConfirmTasks`.
- The 25H2 task looks for `Files\25H2 installer.msu` next to the script (or use `-MsuPath`). It is skipped on PCs already on 25H2 or later (build 26200+). The installer itself is not included in this repository.
- Windows PowerShell 5.1 only, no external modules. Performance counters are looked up by their English names.
- Versioning is Major.Minor.Patch plus a running build number. See [CHANGELOG.md](CHANGELOG.md).

## Disclaimer

Provided as is, with no warranty. Test on a non-production device first, especially the Tasks.
