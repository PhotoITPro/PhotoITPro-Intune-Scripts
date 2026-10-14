# Rob's Toolkit

A Windows PowerShell 5.1 toolkit with a GUI (and a command-line mode) for technicians. It has two parts:

- **Diagnostics** (read-only): 19 checks that grade findings RED / AMBER / GREEN against stated thresholds and produce a self-contained `report.html`, plus `summary.json`, `metrics.csv` and raw CSV/TXT exports. Covers system, performance sampling, memory/pool, CPU throttling, disk, OneDrive, Windows Search and Defender, startup load, drivers and updates, event logs, stability history (blue screens, dumps, failing apps), boot and shutdown timings, system file integrity, network (including Wi-Fi drops and Microsoft 365 reachability), security products, **crash/hang/restart analysis with an incident timeline**, **management and security agent health** (RMM, ScreenConnect, CrowdStrike, Intune, Entra join state), **user profile health** and **hardware/battery**.
- **Tasks** (these change the PC or write files): install the Windows 11 25H2 update, remove HP Wolf Security, collect the Autopilot hardware ID, upgrade Windows Home to Pro, collect crash dump files, collect power and Wi-Fi reports, configure a kernel memory dump, repair the Windows image (DISM + sfc), reset OneDrive, reset the network stack, and run/restore a Modern Standby isolation test. They need administrator rights, ask for confirmation, and are logged.

It supersedes [`Diagnostics/Get-SlowPCReport.ps1`](../Diagnostics/Get-SlowPCReport.ps1), which is the original single-purpose "slow PC" report.

## Run it

| How | Command |
|---|---|
| GUI | Double-click `Run-RobsToolkit.bat`, or run `.\RobsToolkit.ps1` with no parameters |
| Full runbook run | `.\RobsToolkit.ps1 -Preset Troubleshoot -IncidentTime "2026-10-14 09:30" -Symptom "Screen goes black then restarts" -Label WhenFaulty` |
| Diagnostics from the command line | `.\RobsToolkit.ps1 -Preset Performance -Label WhenSlow` |
| Quick run | `.\RobsToolkit.ps1 -Preset Stability -Quick` |
| List checks and tasks | `.\RobsToolkit.ps1 -ListChecks` |
| Tasks (changes the PC) | `.\RobsToolkit.ps1 -RunTask hwid,25h2 -Ticket INC1234 -ConfirmTasks` |
| Collect evidence after an incident | `.\RobsToolkit.ps1 -RunTask dumps,powerdata -DumpFolder D:\Evidence -ConfirmTasks` (add `-IncludeFullDump` for MEMORY.DMP; `-DumpSource` reads an offline Windows folder) |
| Prepare for a hang | `.\RobsToolkit.ps1 -RunTask kerneldump -ConfirmTasks` |
| Version | `.\RobsToolkit.ps1 -Version` |

Task ids: `25h2`, `wolf`, `hwid`, `pro`, `dumps`, `powerdata`, `kerneldump`, `repair`, `onedrivereset`, `netreset`, `standbyiso`, `standbyrestore`.

Presets: `General` (default), `Performance`, `Stability`, `Network`, `Security`, `Update`, `Troubleshoot` (every check). Use `-Include` / `-Exclude` with check ids for a custom selection. Run it as administrator for full results (SMART/NVMe data, minifilters, Defender exclusions, integrity scans, minidumps, boot timings).

Reports go to `C:\RobsToolkit\<COMPUTERNAME>_<timestamp>[_<Label>]\`. Run it twice with different `-Label` values (for example `AfterReboot` and `WhenSlow`) and compare the two `metrics.csv` files; the report explains how.

## Windows 11 troubleshooting runbook

How the toolkit maps to the standard troubleshooting process:

| Runbook step | In the toolkit |
|---|---|
| Record the symptom and the time of the last occurrence | **Time of last occurrence** and **User-reported symptom** fields (`-IncidentTime`, `-Symptom`), shown in the report header and `summary.json` |
| Baseline data (system, event logs, reliability, hotfixes) | System overview, Event logs, Stability, Drivers and updates (last 10 installed updates) |
| Agents healthy (RMM, CrowdStrike, Intune) | **Management and security agents** check |
| Quick wins: restart, updates, free disk (under 15%), DISM + sfc | **Restart PC...** button, pending-update and pending-reboot checks, disk check (AMBER under 15% free), **Repair Windows image** task |
| Slowness: memory, pool, OneDrive, SearchIndexer, disk, startup | Performance, Memory, OneDrive, Search/Defender, Disk and Startup checks; **Reset OneDrive client** task |
| Crash, hang, restart: classify event 41 / 1001 / 6008, sleep flags | **Crash, hang and restart analysis** check: classification table, Modern Standby flags, dump configuration, incident timeline (30 min before to 10 min after) and ranked contributors |
| Dumps and kernel dump setting | **Collect crash dump files** and **Configure kernel memory dump** tasks |
| Sleep study, power and battery reports, wake sources | **Collect power and Wi-Fi reports** task |
| Isolate Modern Standby for 2 to 3 weeks | **Modern Standby isolation** and **Restore power settings** tasks |
| Network and Wi-Fi: WLAN events, NIC power management, M365 reachability, `ipconfig /all`, stack reset | Network check (adds these) and **Reset network stack** task |
| Profile problems: `.bak` ProfileList keys, temporary profile | **User profile health** check (profile reset itself stays with `Reset-UserProfile.ps1 -WhatIf`) |
| Hardware: battery wear and cycles, memory diagnostic results, OEM tools | **Hardware and battery** check |

Still manual by design: the ConnectWise ticket, M365 service health and Intune/RMM change history, Hudu lookups, WinDbg analysis of dumps (`!analyze -v`, `!stacks 2`), rebuilding the Search index, BitLocker recovery keys and WinRE steps, running the OEM diagnostic, and the profile reset.

## Restart button

Every tab has a **Restart PC...** button in the footer. It asks for confirmation, then schedules a restart in 15 seconds and offers **Cancel restart**.

## Notes

- Diagnostics never change settings, delete anything or restart services. Tasks do change the PC or write files; `-RunTask` only lists what it would do unless you add `-ConfirmTasks`.
- The 25H2 task looks for `Files\25H2 installer.msu` next to the script (or use `-MsuPath`). It is skipped on PCs already on 25H2 or later (build 26200+). The installer itself is not included in this repository.
- Crash dumps can contain sensitive data from memory. Share the evidence folders only with people who need them.
- Windows PowerShell 5.1 only, no external modules. Performance counters are looked up by their English names.
- Versioning is Major.Minor.Patch plus a running build number. See [CHANGELOG.md](CHANGELOG.md).

## Disclaimer

Provided as is, with no warranty. Test on a non-production device first, especially the Tasks.
