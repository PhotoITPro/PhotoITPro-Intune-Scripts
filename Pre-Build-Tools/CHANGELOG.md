# Rob's Toolkit - Changelog

Versioning: **Major.Minor.Patch** plus a running **build number** that increases with every build and never resets.
- Major: redesign or breaking change (parameters, output layout)
- Minor: new features or checks
- Patch: fixes only

The version lives in the "Version info" block near the top of `RobsToolkit.ps1`
(`$script:AppVersion`, `$script:AppBuild`, `$script:AppBuildDate`). Update it and add an entry here for every change.
`RobsToolkit.ps1 -Version` prints it; it is also shown in the GUI header and written to each report and `summary.json`.

## 2.4.0 (build 9) - 2026-10-14
- Added a **Restart PC...** button in the footer of every tab: confirmation, then a restart in 15 seconds with **Cancel restart**.
  The "restart needed" prompt after tasks uses the same cancellable restart.
- Added the **Collect crash dump files** task (`dumps`, Tasks tab > Troubleshooting): copies minidumps (optionally MEMORY.DMP) to
  `CrashDumps_<host>_<time>` with `manifest.csv`, `dump-info.txt` (dump settings, recent bugcheck codes) and a zip. Nothing is deleted.
  New parameters: `-DumpFolder`, `-DumpSource` (another folder or an offline Windows folder), `-IncludeFullDump`.
- Merged with 2.3.0 (build 8) from GitHub (Stability and Boot checks), which was published from a different copy while this work
  was in progress. Both sets of changes are included; 2.3.0 build 8 as described below is unchanged.
## 2.3.0 (build 8) - 2026-10-08
- New check **stability**: Reliability Monitor stability index, most repeatedly failing application, bugchecks (blue screens) with decoded codes over 30 days, minidump count, Kernel-Power 41 trend.
- New check **boot**: boot time and the apps, services and drivers that slowed boot (Diagnostics-Performance events), plus slow shutdowns. Both new checks need administrator for full results; without it the boot check says so instead of reporting a false GREEN.
- Added to the General, Performance and Stability presets (stability also in Security). Now 15 checks.

## 2.2.3 (build 7) - 2026-10-08
- Added author/licence header and #Requires -Version 5.1; published to the PhotoITPro-Intune-Scripts repository (Diagnostics/RobsToolkit).

## 2.2.2 (build 6) - 2026-10-08
- Tasks: the Install 25H2 option is disabled (and skipped by -RunTask 25h2) when the PC is already on build 26200 or later.

## 2.2.1 (build 5) - 2026-10-08
- GUI header now shows the Windows edition, feature version (e.g. 24H2) and build next to the computer name.

## 2.2.0 (build 4) - 2026-10-07
- Added a **Tasks** tab and `-RunTask` command-line option, ported from the standalone `RobToolkit.ps1`:
  Install Windows 11 25H2 update, Remove HP Wolf Security, Collect Autopilot Hardware ID, Upgrade Windows Home to Pro.
- Tasks CHANGE the PC (diagnostics stay read-only): administrator required, confirmation prompt in the GUI,
  `-ConfirmTasks` required on the command line, every run logged to `<OutputPath>\TaskLogs`.
- New parameters: `-Tab`, `-RunTask`, `-ConfirmTasks`, `-Ticket`, `-HwidFolder`, `-MsuPath`. `-ListChecks` also lists tasks.
- Fixes versus the original script: works under strict mode (uninstall entries without a DisplayName), reads process exit codes reliably.
## 2.1.0 (build 3) - 2026-10-07
- Renamed to Rob's Toolkit (`RobsToolkit.ps1`, `Run-RobsToolkit.bat`); default output folder is now `C:\RobsToolkit`.
- Added version and build numbering, `-Version` switch, version shown in the GUI, reports and `summary.json`.

## 2.0.0 (build 2) - 2026-10-07
- Refactored into a check registry with presets (General, Performance, Stability, Network, Security, Update), `-Include`, `-Exclude`, `-ListChecks`, `-Quick`.
- Added the WPF GUI (default when run with no parameters): setup, live progress with cancel, results with scorecard and findings grid.
- Reports grouped by category with a scorecard; added `summary.json`.

## 1.0.0 (build 1) - 2026-09-29
- Initial release as `Get-SlowPCReport.ps1`: 13 read-only checks and an HTML report for a slow Surface/Windows laptop.




