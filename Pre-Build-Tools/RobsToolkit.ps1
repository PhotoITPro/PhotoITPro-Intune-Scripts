# Written by Rob Young | PhotoITPro
# Website:    https://photoitpro.co.uk
# Repository: https://github.com/PhotoITPro/PhotoITPro-Intune-Scripts
# Licence:    MIT
#Requires -Version 5.1
<#
.SYNOPSIS
    Rob's Toolkit: a read-only Windows diagnostic tool with a GUI (default) and a command-line mode. Produces a self-contained HTML report.

.DESCRIPTION
    Run with no parameters to open the GUI: pick a preset, tick the checks you want, and click Run.
    Any parameter (or -NoGui) runs the command-line mode instead, which is also what the GUI uses behind the scenes.

    Checks (use -ListChecks to see them): system overview, performance sampling, memory/pool, CPU throttling,
    disk, OneDrive, Windows Search/Defender, startup load, drivers/updates, event logs, system-file integrity,
    network, security products/kernel drivers.

    Output goes to  <OutputPath>\<COMPUTERNAME>_<yyyyMMdd_HHmmss>[_<Label>]\  and contains report.html, summary.json,
    metrics.csv, findings.csv and raw CSV/TXT exports.

    The tool NEVER changes settings, deletes anything or restarts services. The only "active" work is:
      * sampling performance counters,
      * enumerating folders (OneDrive) with a time limit,
      * a Windows Update *search* (query only) and a DNS lookup,
      * optionally (-RunIntegrityChecks) sfc /verifyonly and DISM /CheckHealth, which are read-only scans.

    Requires Windows PowerShell 5.1 and no external modules. Counter names are looked up in English; on a
    non-English OS some performance-counter based sections will report an error and be skipped.

.PARAMETER Preset
    Which set of checks to run: General (default), Performance, Stability, Network, Security, Update.

.PARAMETER Include
    Explicit list of check ids to run (overrides -Preset). Comma separated. See -ListChecks.

.PARAMETER Exclude
    Check ids to leave out of the selected preset.

.PARAMETER Version
    Show the tool name, version and build number, then exit.

.PARAMETER Tab
    GUI only: which tab to open first (Diagnostics or Tasks).

.PARAMETER RunTask
    Run maintenance/deployment tasks instead of diagnostics. Ids: 25h2, wolf, hwid, pro. These CHANGE the PC, need
    administrator rights, and only run with -ConfirmTasks (otherwise the selection is just listed). Always run in the
    order 25h2, wolf, hwid, pro. Logged to <OutputPath>\TaskLogs. A needed restart is reported but never done automatically.
      25h2 = install the Windows 11 25H2 enablement package (wusa)      wolf = uninstall HP Wolf Security
      hwid = save the Autopilot hardware hash as a CSV                  pro  = switch Home to Pro with the generic key
      dumps = copy crash dump files (minidumps) to a folder and zip them, with the recent bugcheck codes

.PARAMETER ConfirmTasks
    Required with -RunTask to actually run the tasks.

.PARAMETER Ticket
    Ticket/tag added to the Autopilot CSV file name (hwid task).

.PARAMETER HwidFolder
    Folder for the Autopilot CSV (hwid task). Default in CLI mode: <OutputPath>\HWID. The GUI asks.

.PARAMETER MsuPath
    Path to the 25H2 installer .msu. Default: Files\25H2 installer.msu next to this script.

.PARAMETER DumpFolder
    Folder where the crash dump task (dumps) creates its CrashDumps_<COMPUTERNAME>_<timestamp> folder and zip.
    Default in CLI mode: <OutputPath>\Dumps. The GUI asks.

.PARAMETER DumpSource
    dumps task: collect from this folder instead of this PC's own dump locations. Either a folder of .dmp files or a
    Windows folder containing Minidump (and MEMORY.DMP), for example D:\Windows from an offline disk.

.PARAMETER IncludeFullDump
    dumps task: also copy the full memory dump (MEMORY.DMP), which can be several GB. Minidumps are always collected.

.PARAMETER ListChecks
    List the available checks and presets, then exit.

.PARAMETER Quick
    Shorter run: sampling capped at 15 s, OneDrive file count capped at 30 s, no Windows Update search, no sfc/DISM scans.

.PARAMETER Gui
    Force the GUI even when other parameters are supplied.

.PARAMETER NoGui
    Never show the GUI (command-line mode).

.PARAMETER OutputPath
    Parent folder for the report folder. Default: C:\RobsToolkit

.PARAMETER SampleSeconds
    How long to sample performance counters (10-600). Default 60. Run it WHILE the problem is happening.

.PARAMETER Label
    Free-text tag (letters, digits, _ and -) added to the report and folder name, e.g. "AfterReboot" or "WhenSlow".
    Run twice with different labels and compare metrics.csv from both folders (see "How to compare" in the report).

.PARAMETER RunIntegrityChecks
    Also run "sfc /verifyonly" and "DISM /Online /Cleanup-Image /CheckHealth" (read-only, but sfc can take 10+ minutes).

.PARAMETER FileCountTimeLimitSeconds
    Total time budget for counting files under the OneDrive folders (10-1800). Default 180.

.PARAMETER StatusFile
    Internal: the GUI passes a file path here so it can follow progress. Cancel is requested by creating <StatusFile>.cancel.

.EXAMPLE
    .\RobsToolkit.ps1 -RunTask hwid,25h2 -Ticket INC1234 -ConfirmTasks
    Elevated command prompt: collects the Autopilot hash and installs 25H2.

.EXAMPLE
    .\RobsToolkit.ps1
    Opens the GUI.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\RobsToolkit.ps1 -Preset Performance -Label WhenSlow

.EXAMPLE
    .\RobsToolkit.ps1 -Include sys,events,integrity -Quick
#>
[CmdletBinding()]
param(
    [ValidateSet('General', 'Performance', 'Stability', 'Network', 'Security', 'Update')][string]$Preset = 'General',
    [string[]]$Include = @(),
    [string[]]$Exclude = @(),
    [switch]$Version,
    [ValidateSet('Diagnostics', 'Tasks')][string]$Tab = 'Diagnostics',
    [string[]]$RunTask = @(),
    [switch]$ConfirmTasks,
    [string]$Ticket = '',
    [string]$HwidFolder = '',
    [string]$MsuPath = '',
    [string]$DumpFolder = '',
    [string]$DumpSource = '',
    [switch]$IncludeFullDump,
    [switch]$ListChecks,
    [switch]$Quick,
    [switch]$Gui,
    [switch]$NoGui,
    [string]$OutputPath = 'C:\RobsToolkit',
    [ValidateRange(10, 600)][int]$SampleSeconds = 60,
    [ValidatePattern('^[A-Za-z0-9_\-]{0,40}$')][string]$Label = '',
    [switch]$RunIntegrityChecks,
    [ValidateRange(10, 1800)][int]$FileCountTimeLimitSeconds = 180,
    [string]$StatusFile = ''
)

# Decide the mode before anything else: GUI when run with no parameters (or -Gui), CLI otherwise.
$script:UseGui = ((-not $NoGui) -and ($Gui -or $PSBoundParameters.Count -eq 0)) -and (-not $ListChecks)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

#region Script-wide state ---------------------------------------------------------------------------------------------
# ---- Version info. Bump on every change and record it in CHANGELOG.md ----
#   Version = Major.Minor.Patch (Major: redesign/breaking, Minor: new features, Patch: fixes)
#   Build   = running build number, increments with every build and never resets
$script:AppName      = "Rob's Toolkit"
$script:AppVersion   = '2.4.0'
$script:AppBuild     = 9
$script:AppBuildDate = '2026-10-14'
$script:AppVersionText = 'v{0} (build {1}, {2})' -f $script:AppVersion, $script:AppBuild, $script:AppBuildDate
$script:StatusFile    = $StatusFile           # GUI progress channel (empty in plain CLI use)
$script:Cancelled     = $false
$script:SkipUpdateSearch = $false
$script:SelectedChecks = @()
$script:PresetName    = $Preset
$script:StartTime     = Get-Date
$script:Computer      = $env:COMPUTERNAME
$script:Findings      = New-Object System.Collections.Generic.List[object]
$script:Sections      = New-Object System.Collections.Generic.List[object]
$script:Metrics       = New-Object System.Collections.Generic.List[object]
$script:MetricKeys    = @{}
$script:Ctx           = $null                 # the section currently being built
$script:ProcStats     = @{}                   # ProcId -> averaged process stats from the sampling window
$script:Perf          = $null                 # sampled counter rows + stats
$script:EventCache    = @{}
$script:Classified    = $null
$script:EventStart    = (Get-Date).AddDays(-7)
$script:CompanyCache  = @{}
$script:Flt           = $null
$script:TotalRam      = $null
$script:IsAdmin       = $false
$script:OutDir        = $null

$script:CauseInfo = [ordered]@{
    onedrive  = 'OneDrive sync load (file count, process resource use, Files On-Demand state)'
    memory    = 'Memory pressure or a kernel/driver memory leak (non-paged pool, commit charge, resource exhaustion)'
    faststart = 'Fast Startup plus long uptime: "Shut down" never fully resets the kernel session'
    throttle  = 'CPU throttling (thermal limits, power plan/mode, battery)'
    disk      = 'Storage bottleneck, disk health or low free space'
    scan      = 'Real-time scanning / indexing overhead (Defender, Windows Search, third-party AV and filter drivers)'
    startup   = 'Startup and background software load'
    drivers   = 'Outdated drivers/firmware or pending updates'
    stability = 'Hardware or OS instability (WHEA, unexpected shutdowns, crashes, corruption)'
    network   = 'Network constraints affecting cloud sync'
    boot      = 'Slow boot or shutdown (slow startup apps, services and drivers)'
}

# Check registry: one entry per check. Admin = results are reduced without elevation. Est = rough runtime in seconds.
$script:CheckRegistry = @(
    @{ Id = 'sys';       Title = 'System overview';                  Category = 'System';              Function = 'Check-SystemOverview'; Admin = $false; Est = 8 }
    @{ Id = 'perf';      Title = 'Performance snapshot';             Category = 'Performance';         Function = 'Check-Performance';    Admin = $false; Est = 75 }
    @{ Id = 'mem';       Title = 'Memory leak indicators';           Category = 'Performance';         Function = 'Check-Memory';         Admin = $false; Est = 10 }
    @{ Id = 'cpu';       Title = 'CPU throttling';                   Category = 'Performance';         Function = 'Check-CpuThrottling';  Admin = $false; Est = 8 }
    @{ Id = 'disk';      Title = 'Disk health and space';            Category = 'Storage';             Function = 'Check-Disk';           Admin = $true;  Est = 10 }
    @{ Id = 'onedrive';  Title = 'OneDrive';                         Category = 'Cloud & Sync';        Function = 'Check-OneDrive';       Admin = $false; Est = 190 }
    @{ Id = 'search';    Title = 'Windows Search and Defender';      Category = 'Security & Scanning'; Function = 'Check-SearchDefender'; Admin = $true;  Est = 15 }
    @{ Id = 'security';  Title = 'Security products and kernel drivers'; Category = 'Security & Scanning'; Function = 'Check-Security'; Admin = $true;  Est = 15 }
    @{ Id = 'startup';   Title = 'Startup and background load';      Category = 'Software & Startup';  Function = 'Check-Startup';        Admin = $false; Est = 20 }
    @{ Id = 'drivers';   Title = 'Drivers, firmware and updates';    Category = 'Updates & Drivers';   Function = 'Check-Drivers';        Admin = $false; Est = 45 }
    @{ Id = 'events';    Title = 'Event logs (last 7 days)';         Category = 'Reliability';         Function = 'Check-EventLogs';      Admin = $false; Est = 15 }
    @{ Id = 'integrity'; Title = 'System file integrity';            Category = 'Reliability';         Function = 'Check-Integrity';      Admin = $true;  Est = 5 }
    @{ Id = 'stability'; Title = 'Stability history (blue screens, crashes)'; Category = 'Reliability'; Function = 'Check-Stability';   Admin = $true;  Est = 20 }
    @{ Id = 'boot';      Title = 'Boot and shutdown performance'; Category = 'Performance';       Function = 'Check-BootPerformance'; Admin = $true;  Est = 10 }
    @{ Id = 'network';   Title = 'Network';                          Category = 'Network';             Function = 'Check-Network';        Admin = $false; Est = 10 }
)
$script:CategoryOrder = @('System', 'Performance', 'Storage', 'Cloud & Sync', 'Security & Scanning', 'Software & Startup', 'Updates & Drivers', 'Reliability', 'Network')
$script:PresetMap = [ordered]@{
    General     = @('sys', 'perf', 'mem', 'cpu', 'disk', 'search', 'security', 'startup', 'drivers', 'events', 'stability', 'boot', 'integrity', 'network')
    Performance = @('sys', 'perf', 'mem', 'cpu', 'disk', 'onedrive', 'search', 'security', 'startup', 'drivers', 'events', 'stability', 'boot', 'integrity', 'network')
    Stability   = @('sys', 'mem', 'disk', 'security', 'drivers', 'events', 'stability', 'boot', 'integrity')
    Network     = @('sys', 'network', 'onedrive', 'security')
    Security    = @('sys', 'search', 'security', 'drivers', 'events', 'stability', 'integrity')
    Update      = @('sys', 'disk', 'drivers', 'events', 'integrity')
}
#endregion

#region Generic helpers -----------------------------------------------------------------------------------------------
function Write-Status {
    param([string]$Message, [string]$Level = 'INFO')
    $colour = switch ($Level) { 'WARN' { 'Yellow' } 'ERROR' { 'Red' } 'OK' { 'Green' } default { 'Cyan' } }
    Write-Host ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor $colour
    Send-Status 'LOG' @($Level, $Message)
}

# One-line event for the GUI to follow (TYPE|field|field...). No-op unless -StatusFile was given.
function Send-Status {
    param([string]$Type, [string[]]$Fields = @())
    if (-not $script:StatusFile) { return }
    try {
        $clean = @($Fields | ForEach-Object { ([string]$_) -replace '[\r\n|]+', ' ' })
        [System.IO.File]::AppendAllText($script:StatusFile, ($Type + '|' + ($clean -join '|') + "`n"))
    } catch { }
}

# The GUI asks for a graceful stop by creating <StatusFile>.cancel
function Test-Cancelled {
    if ($script:Cancelled) { return $true }
    if ($script:StatusFile -and [System.IO.File]::Exists($script:StatusFile + '.cancel')) { $script:Cancelled = $true }
    return $script:Cancelled
}

# Work out which checks to run from -Preset / -Include / -Exclude.
function Resolve-CheckSelection {
    param([string]$Preset, [string[]]$Include, [string[]]$Exclude)
    $inc = @($Include | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
    $exc = @($Exclude | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
    $ids = @($script:PresetMap[$Preset])
    if ($inc.Count -gt 0) { $ids = $inc }
    $known = @($script:CheckRegistry | ForEach-Object { $_.Id })
    foreach ($i in (@($ids) + @($exc))) { if ($known -notcontains $i) { Write-Warning "Unknown check id '$i' (use -ListChecks to see valid ids)." } }
    return @($script:CheckRegistry | Where-Object { $ids -contains $_.Id -and $exc -notcontains $_.Id })
}

# Safe property read: returns $Default if the object or property does not exist (StrictMode friendly).
function Get-P {
    param($Obj, [string]$Name, $Default = $null)
    if ($null -eq $Obj) { return $Default }
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p) { return $Default }
    return $p.Value
}

# Evaluate a scriptblock and swallow any error (returns $null).
function Get-SafeValue {
    param([scriptblock]$Block)
    try { return (& $Block) } catch { return $null }
}

# @() on a generic List can throw in Windows PowerShell 5.1, so lists are converted with ToArray() first.
function ConvertTo-PlainArray { param($Data) if ($Data -is [System.Collections.Generic.List[object]]) { return ,$Data.ToArray() } return ,@($Data) }

function Get-First { param($Items) $a = ConvertTo-PlainArray $Items; if ($a.Count -gt 0) { return $a[0] } return $null }

function Esc { param($Value) if ($null -eq $Value) { return '' } return [System.Net.WebUtility]::HtmlEncode([string]$Value) }

function Get-Badge {
    param([string]$Severity)
    if (-not $Severity) { return '' }
    return "<span class='badge $($Severity.ToLower())'>$Severity</span>"
}

function Format-Cell {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm') }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) { return ([math]::Round([double]$Value, 2)).ToString() }
    if ($Value -is [array]) { return (@($Value) -join '; ') }
    return [string]$Value
}

function Get-Stats {
    param($Values)
    $v = @($Values | Where-Object { $null -ne $_ } | ForEach-Object { [double]$_ } | Sort-Object)
    if ($v.Count -eq 0) { return $null }
    $idx = [math]::Min($v.Count - 1, [int][math]::Ceiling(0.95 * $v.Count) - 1)
    [pscustomobject]@{
        N   = $v.Count
        Min = $v[0]
        Avg = ($v | Measure-Object -Average).Average
        P95 = $v[$idx]
        Max = $v[$v.Count - 1]
    }
}

function Get-TotalRamBytes {
    if ($null -eq $script:TotalRam) {
        $cs = Get-SafeValue { Get-CimInstance Win32_ComputerSystem }
        $script:TotalRam = [double](Get-P $cs 'TotalPhysicalMemory' 0)
    }
    return $script:TotalRam
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
#endregion

#region Report-building helpers (operate on the current section context) ----------------------------------------------
function Add-CheckError { param([string]$Message) $script:Ctx.Errors.Add($Message) }

# Run a block; on failure record the error in the report section and return nothing.
function Invoke-Safe {
    param([string]$Label, [scriptblock]$Block)
    $ErrorActionPreference = 'Stop'
    try { return (& $Block) }
    catch { Add-CheckError ('{0}: {1}' -f $Label, $_.Exception.Message); return }
}

function Add-Html { param([string]$Html) [void]$script:Ctx.Html.Append($Html).Append("`n") }
function Add-Note { param([string]$Text, [string]$Class = 'note') Add-Html "<p class='$Class'>$(Esc $Text)</p>" }
function Add-SubHeading { param([string]$Text) Add-Html "<h3>$(Esc $Text)</h3>" }
function Add-Pre {
    param([string]$Text, [int]$MaxChars = 6000)
    if ($Text.Length -gt $MaxChars) { $Text = $Text.Substring(0, $MaxChars) + "`n...[truncated]" }
    Add-Html "<pre>$(Esc $Text)</pre>"
}

function Add-Metric {
    param([string]$Key, $Value)
    $k = $Key; $n = 1
    while ($script:MetricKeys.ContainsKey($k)) { $n++; $k = "$Key #$n" }
    $script:MetricKeys[$k] = $true
    $script:Metrics.Add([pscustomobject]@{ Key = $k; Value = (Format-Cell $Value) })
}

function Save-Csv {
    param($Data, [string]$Name)
    try {
        $d = ConvertTo-PlainArray $Data
        if ($d.Count -gt 0 -and $null -ne $d[0]) {
            $d | Export-Csv -LiteralPath (Join-Path $script:OutDir $Name) -NoTypeInformation -Encoding UTF8
        }
    } catch { Add-CheckError "CSV export $Name failed: $($_.Exception.Message)" }
}

function New-HtmlTable {
    param($Data, [string[]]$Columns, [int]$Max = 200, [switch]$NoSort)
    $rows = ConvertTo-PlainArray $Data
    if ($rows.Count -eq 0 -or $null -eq $rows[0]) { return "<p class='muted'>No data.</p>" }
    if (-not $Columns) { $Columns = @($rows[0].PSObject.Properties.Name) }
    $cls = if ($NoSort) { 'grid' } else { 'grid sortable' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<div class='tw'><table class='$cls'><thead><tr>")
    foreach ($c in $Columns) { [void]$sb.Append("<th>$(Esc $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    $n = 0
    foreach ($r in $rows) {
        $n++
        if ($n -gt $Max) { break }
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            $v = Get-P $r $c
            if (($c -eq 'Flag' -or $c -eq 'Severity') -and $v) { [void]$sb.Append("<td>$(Get-Badge ([string]$v))</td>") }
            else { [void]$sb.Append("<td>$(Esc (Format-Cell $v))</td>") }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($rows.Count -gt $Max) { [void]$sb.Append("<p class='muted'>Showing first $Max of $($rows.Count) rows (full data in the CSV export).</p>") }
    return $sb.ToString()
}

function Add-Table {
    param($Data, [string]$Title = '', [string]$CsvName = '', [string[]]$Columns, [int]$Max = 200, [switch]$NoSort)
    if ($Title) { Add-SubHeading $Title }
    Add-Html (New-HtmlTable -Data $Data -Columns $Columns -Max $Max -NoSort:$NoSort)
    if ($CsvName) { Save-Csv $Data $CsvName }
}

function Add-KV {
    param([System.Collections.IDictionary]$Pairs, [string]$Title = '')
    $rows = foreach ($k in $Pairs.Keys) { [pscustomobject]@{ Item = $k; Value = $Pairs[$k] } }
    Add-Table -Data $rows -Title $Title -Columns 'Item', 'Value' -NoSort
}

# Record a judgement. Value = raw value used, Threshold = the rule applied, Action = manual step (never performed by this script).
function Add-Finding {
    param(
        [ValidateSet('RED', 'AMBER', 'GREEN', 'INFO')][string]$Severity,
        [string]$Title,
        [string]$Value = '',
        [string]$Threshold = '',
        [string]$Action = '',
        [string]$Cause = ''
    )
    $script:Findings.Add([pscustomobject]@{
            Severity = $Severity; SectionId = $script:Ctx.Id; Category = $script:Ctx.Category; Area = $script:Ctx.Title
            Title = $Title; Value = $Value; Threshold = $Threshold; Action = $Action; Cause = $Cause
        })
    Add-Metric ('{0}: {1}' -f $script:Ctx.Title, $Title) $Value
}

# Run one check function inside try/catch and store its section.
function Invoke-Check {
    param($Check, [int]$Index, [int]$Total)
    $Id = $Check.Id; $Title = $Check.Title; $Function = $Check.Function
    Write-Progress -Id 1 -Activity $script:AppName -Status "[$Index/$Total] $Title" -PercentComplete ([int](100 * ($Index - 1) / $Total))
    Write-Status "Check $Index/${Total}: $Title"
    Send-Status 'CHECKSTART' @($Id, $Index, $Total)
    $ctx = [pscustomobject]@{
        Id = $Id; Title = $Title; Category = $Check.Category
        Html = (New-Object System.Text.StringBuilder)
        Errors = (New-Object System.Collections.Generic.List[string])
    }
    $script:Ctx = $ctx
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { & $Function | Out-Null }
    catch {
        $ctx.Errors.Add(('Check aborted: {0} (line {1})' -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber))
        Write-Status "Check '$Title' failed: $($_.Exception.Message)" 'ERROR'
    }
    $sw.Stop()
    $script:Sections.Add([pscustomobject]@{
            Id = $Id; Title = $Title; Category = $Check.Category; Html = $ctx.Html.ToString(); Errors = @($ctx.Errors)
            Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        })
    $rankW = @{ RED = 4; AMBER = 3; GREEN = 2; INFO = 1 }
    $worstSev = ''; $wr = 0
    foreach ($f in @($script:Findings | Where-Object { $_.SectionId -eq $Id })) { if ($rankW[$f.Severity] -gt $wr) { $wr = $rankW[$f.Severity]; $worstSev = $f.Severity } }
    Send-Status 'CHECKDONE' @($Id, [math]::Round($sw.Elapsed.TotalSeconds, 1), $worstSev, $ctx.Errors.Count)
}
#endregion

#region Shared data helpers -------------------------------------------------------------------------------------------
# Process stats (averaged during the sampling window when available; falls back to a one-off Get-Process).
function Get-ProcStatsList {
    if ($script:ProcStats.Count -eq 0) {
        foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
            $script:ProcStats[[int]$p.Id] = [pscustomobject]@{
                ProcId = [int]$p.Id; Name = $p.ProcessName; CpuAvg = 0.0
                WSMB = [math]::Round($p.WorkingSet64 / 1MB, 1); PBMB = [math]::Round($p.PrivateMemorySize64 / 1MB, 1)
                Handles = $p.HandleCount; Threads = @($p.Threads).Count; IoKBs = 0.0
            }
        }
    }
    return @($script:ProcStats.Values)
}

# Live process rows for named processes, enriched with sampled CPU where available.
function Get-ProcRows {
    param([string[]]$Names)
    $null = Get-ProcStatsList
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($p in @(Get-Process -Name $Names -ErrorAction SilentlyContinue)) {
        $st = $script:ProcStats[[int]$p.Id]
        $out.Add([pscustomobject]@{
                Name = $p.ProcessName; ProcId = $p.Id
                CpuPct = $(if ($st) { [math]::Round($st.CpuAvg, 1) } else { $null })
                WorkingSetMB = [math]::Round($p.WorkingSet64 / 1MB, 1)
                PrivateMB = [math]::Round($p.PrivateMemorySize64 / 1MB, 1)
                Handles = $p.HandleCount; Threads = @($p.Threads).Count
                IoKBs = $(if ($st) { [math]::Round($st.IoKBs, 1) } else { $null })
                Started = (Get-SafeValue { $p.StartTime })
                Path = (Get-SafeValue { $p.Path })
            })
    }
    return $out.ToArray()
}

# Event log cache: Error/Warning/Critical events for the last 7 days.
function Get-CachedEvents {
    param([string]$Log)
    if ($script:EventCache.ContainsKey($Log)) { return $script:EventCache[$Log] }
    $ev = @()
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $Log; StartTime = $script:EventStart; Level = 1, 2, 3 } -MaxEvents 20000 -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') { $script:EventCache[$Log] = @(); throw }
    }
    $script:EventCache[$Log] = $ev
    return $ev
}

# Event classification rules (first match wins).
function Get-ClassifiedEvents {
    if ($null -ne $script:Classified) { return $script:Classified }
    $rules = @(
        @{ Cat = 'Resource exhaustion (2004)'; Log = 'System'; Prov = @('Microsoft-Windows-Resource-Exhaustion-Detector'); Ids = @(2004) }
        @{ Cat = 'Kernel-Power 41 (unexpected reboot)'; Log = 'System'; Prov = @('Microsoft-Windows-Kernel-Power'); Ids = @(41) }
        @{ Cat = 'Unexpected shutdown (6008)'; Log = 'System'; Prov = @('EventLog'); Ids = @(6008) }
        @{ Cat = 'Bugcheck (BSOD)'; Log = 'System'; Prov = @('Microsoft-Windows-WER-SystemErrorReporting'); Ids = @(1001) }
        @{ Cat = 'WHEA hardware error'; Log = 'System'; Prov = @('Microsoft-Windows-WHEA-Logger'); Ids = $null }
        @{ Cat = 'Disk / NTFS'; Log = 'System'; Prov = @('disk', 'Ntfs', 'Microsoft-Windows-Ntfs', 'stornvme', 'storahci', 'iaStorA', 'iaStorAVC', 'iaStorAC', 'volmgr', 'Microsoft-Windows-StorPort', 'partmgr', 'volsnap'); Ids = $null }
        @{ Cat = 'Driver failure'; Log = 'System'; Prov = @('Microsoft-Windows-Kernel-PnP'); Ids = @(219, 411) }
        @{ Cat = 'Service/driver start failure'; Log = 'System'; Prov = @('Service Control Manager'); Ids = @(7000, 7001, 7026) }
        @{ Cat = 'Display driver reset (TDR)'; Log = 'System'; Prov = @('Display'); Ids = @(4101) }
        @{ Cat = 'Application crash/hang'; Log = 'Application'; Prov = @('Application Error', 'Application Hang'); Ids = @(1000, 1002) }
    )
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($log in 'System', 'Application') {
        $events = @()
        try { $events = @(Get-CachedEvents $log) } catch { Add-CheckError "Read $log log: $($_.Exception.Message)" }
        foreach ($e in $events) {
            foreach ($r in $rules) {
                if ($r.Log -ne $log) { continue }
                if ($r.Prov -notcontains $e.ProviderName) { continue }
                if ($null -ne $r.Ids -and $r.Ids -notcontains $e.Id) { continue }
                $out.Add([pscustomobject]@{ Cat = $r.Cat; Log = $log; Provider = $e.ProviderName; Id = $e.Id; Time = $e.TimeCreated; Ev = $e })
                break
            }
        }
    }
    $script:Classified = $out.ToArray()
    return $script:Classified
}

function Get-EventSummary {
    param($Items)
    $rows = New-Object System.Collections.Generic.List[object]
    $groups = @($Items | Group-Object { '{0}|{1}|{2}' -f $_.Cat, $_.Provider, $_.Id })
    foreach ($g in $groups) {
        $latest = @($g.Group | Sort-Object Time -Descending)[0]
        $msg = ''
        try { $msg = [string]$latest.Ev.Message } catch { }
        $msg = ($msg -replace '\s+', ' ')
        if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) + '...' }
        $rows.Add([pscustomobject]@{
                Category = $latest.Cat; Log = $latest.Log; Provider = $latest.Provider; EventId = $latest.Id
                Count = $g.Count; LastSeen = $latest.Time; LatestMessage = $msg
            })
    }
    return @($rows | Sort-Object Count -Descending)
}

# Executable path from a command line / service PathName / driver path.
function Resolve-ExePath {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    $c = $c -replace '^\\\?\?\\', ''
    $c = $c -replace '^\\SystemRoot', $env:windir
    if ($c -match '^"([^"]+)"') { return $Matches[1] }
    if ($c -match '^(.+?\.(exe|bat|cmd|com|msc|lnk|vbs|ps1|sys))(\s|$)') { return $Matches[1] }
    return ($c -split '\s+')[0]
}

function Get-Company {
    param([string]$Path)
    if (-not $Path) { return '' }
    if ($script:CompanyCache.ContainsKey($Path)) { return $script:CompanyCache[$Path] }
    $co = ''
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) { $co = [string](Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo.CompanyName }
    } catch { }
    $script:CompanyCache[$Path] = $co
    return $co
}

function Get-FltmcFilters {
    if ($null -ne $script:Flt) { return $script:Flt }
    $res = New-Object System.Collections.Generic.List[object]
    if ($script:IsAdmin) {
        $lines = @(& fltmc.exe filters 2>$null)
        $started = $false
        foreach ($l in $lines) {
            if ($l -match '^-{5,}') { $started = $true; continue }
            if ($started -and $l.Trim()) {
                $parts = @($l.Trim() -split '\s{2,}')
                if ($parts.Count -ge 3) {
                    $res.Add([pscustomobject]@{ Name = $parts[0]; Instances = $parts[1]; Altitude = $parts[2]; Frame = $(if ($parts.Count -ge 4) { $parts[3] } else { '' }) })
                }
            }
        }
    }
    $script:Flt = $res.ToArray()
    return $script:Flt
}

# Timed, iterative folder walk. Never follows reparse points. Samples file attributes to spot OneDrive placeholders.
function Measure-FolderFiles {
    param([string]$Root, [datetime]$Deadline)
    $files = [int64]0; $dirs = [int64]0; $errs = 0; $skipped = 0; $timedOut = $false
    $sampled = 0; $placeholders = 0
    $ph = [int]([System.IO.FileAttributes]::Offline) -bor 0x40000 -bor 0x400000   # Offline | RecallOnOpen | RecallOnDataAccess
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($Root)
    $tick = 0
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($stack.Count -gt 0) {
        $tick++
        if ($tick % 200 -eq 0) {
            if ((Get-Date) -gt $Deadline -or (Test-Cancelled)) { $timedOut = $true; break }
            if ($tick % 1000 -eq 0) {
                Send-Status 'PROG' @('onedrive', ('Counting files: {0:N0} so far' -f $files))
                Write-Progress -Id 3 -ParentId 1 -Activity 'Counting OneDrive files' -Status ("{0:N0} files, {1:N0} folders in {2}" -f $files, $dirs, $Root)
            }
        }
        $d = $stack.Pop(); $dirs++
        try {
            $f = [System.IO.Directory]::GetFiles($d)
            $files += $f.Length
            if ($sampled -lt 500) {
                foreach ($x in $f) {
                    if ($sampled -ge 500) { break }
                    $sampled++
                    try { if (([int][System.IO.File]::GetAttributes($x) -band $ph) -ne 0) { $placeholders++ } } catch { }
                }
            }
        } catch { $errs++ }
        try {
            foreach ($sd in [System.IO.Directory]::GetDirectories($d)) {
                $isRp = $false
                try { $isRp = (([int][System.IO.File]::GetAttributes($sd)) -band 0x400) -ne 0 } catch { }
                if ($isRp) { $skipped++ } else { $stack.Push($sd) }
            }
        } catch { $errs++ }
    }
    Write-Progress -Id 3 -Activity 'Counting OneDrive files' -Completed
    [pscustomobject]@{
        Root = $Root; Files = $files; Folders = $dirs; Errors = $errs; SkippedReparse = $skipped
        TimedOut = $timedOut; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        SampledFiles = $sampled; SampledPlaceholders = $placeholders
    }
}

function Get-ProcSample {
    $ncpu = [Environment]::ProcessorCount
    $raw = @(Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction Stop | Where-Object { $_.Name -ne '_Total' -and $_.Name -ne 'Idle' })
    foreach ($p in $raw) {
        [pscustomobject]@{
            ProcId = [int]$p.IDProcess; Name = ($p.Name -replace '#\d+$', '')
            Cpu = ([double]$p.PercentProcessorTime / $ncpu)     # % of total CPU capacity
            WS = [double]$p.WorkingSet; PB = [double]$p.PrivateBytes
            Handles = [int]$p.HandleCount; Threads = [int]$p.ThreadCount; Io = [double]$p.IODataBytesPersec
        }
    }
}

# Try a counter path; return CounterSamples or an empty array without recording errors (optional counters).
function Get-OptionalCounter {
    param([string[]]$Path)
    try { return @((Get-Counter -Counter $Path -MaxSamples 1 -ErrorAction Stop).CounterSamples) } catch { return @() }
}
#endregion

#region CHECK 1: System overview --------------------------------------------------------------------------------------
function Check-SystemOverview {
    $cs   = Invoke-Safe 'Win32_ComputerSystem' { Get-CimInstance Win32_ComputerSystem }
    $bios = Invoke-Safe 'Win32_BIOS' { Get-CimInstance Win32_BIOS }
    $os   = Invoke-Safe 'Win32_OperatingSystem' { Get-CimInstance Win32_OperatingSystem }
    $cpu  = @(Invoke-Safe 'Win32_Processor' { Get-CimInstance Win32_Processor })
    $dimm = @(Invoke-Safe 'Win32_PhysicalMemory' { Get-CimInstance Win32_PhysicalMemory })
    $cv   = Invoke-Safe 'CurrentVersion registry' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' }
    $fast = Get-P (Invoke-Safe 'Session Manager\Power key' { Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction Stop }) 'HiberbootEnabled'
    $hib  = Get-P (Invoke-Safe 'Control\Power key' { Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -ErrorAction Stop }) 'HibernateEnabled'
    $hiberFile = [System.IO.File]::Exists("$env:SystemDrive\hiberfile.sys")
    $dg   = Invoke-Safe 'Win32_DeviceGuard (VBS)' { Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard }

    # Uptime: WMI boot time and the kernel "System Up Time" counter (Fast Startup can make these differ). Use the longer.
    $lastBoot = Get-P $os 'LastBootUpTime'
    $upWmi = $null; if ($lastBoot) { $upWmi = (Get-Date) - $lastBoot }
    $upSec = Invoke-Safe 'System Up Time counter' { (Get-Counter '\System\System Up Time' -ErrorAction Stop).CounterSamples[0].CookedValue }
    $upCtr = $null; if ($upSec) { $upCtr = [TimeSpan]::FromSeconds([double]$upSec) }
    $uptime = $upWmi
    if ($upCtr -and ((-not $uptime) -or $upCtr -gt $uptime)) { $uptime = $upCtr }

    $ramBytes = [double](Get-P $cs 'TotalPhysicalMemory' 0)
    if ($ramBytes -gt 0) { $script:TotalRam = $ramBytes }
    $ramGB = [math]::Round($ramBytes / 1GB, 1)
    $cpu0 = Get-First $cpu

    $vbsText = 'Unknown'
    if ($dg) {
        $vbsMap = @{ 0 = 'Not enabled'; 1 = 'Enabled but not running'; 2 = 'Running' }
        $vs = [int](Get-P $dg 'VirtualizationBasedSecurityStatus' 0)
        $svcMap = @{ 1 = 'Credential Guard'; 2 = 'Memory integrity (HVCI)'; 3 = 'System Guard'; 4 = 'SMM protection' }
        $svc = @((Get-P $dg 'SecurityServicesRunning' @()) | ForEach-Object { if ($svcMap.ContainsKey([int]$_)) { $svcMap[[int]$_] } else { "svc$_" } })
        $vbsText = $vbsMap[$vs]; if ($svc.Count -gt 0) { $vbsText += ' (' + ($svc -join ', ') + ')' }
    }

    $hibText = 'Unknown'; if ($null -ne $hib) { $hibText = $(if ($hib) { 'Enabled' } else { 'Disabled' }) }
    $fastText = 'Not set (default)'; if ($null -ne $fast) { $fastText = $(if ($fast) { 'Enabled (HiberbootEnabled=1)' } else { 'Disabled (HiberbootEnabled=0)' }) }
    $build = '{0}.{1}' -f (Get-P $cv 'CurrentBuildNumber' '?'), (Get-P $cv 'UBR' '?')
    $modules = ($dimm | ForEach-Object { '{0} GB @ {1} MT/s' -f [math]::Round([double](Get-P $_ 'Capacity' 0) / 1GB, 0), (Get-P $_ 'Speed' '?') }) -join '; '

    $kv = [ordered]@{
        'Computer name'          = $script:Computer
        'Manufacturer / Model'   = ('{0} / {1}' -f (Get-P $cs 'Manufacturer' '?'), (Get-P $cs 'Model' '?'))
        'Serial number'          = Get-P $bios 'SerialNumber' '?'
        'BIOS/UEFI version'      = ('{0} (released {1})' -f (Get-P $bios 'SMBIOSBIOSVersion' '?'), (Format-Cell (Get-P $bios 'ReleaseDate')))
        'OS'                     = ('{0} {1}, build {2}' -f (Get-P $os 'Caption' '?'), (Get-P $cv 'DisplayVersion' ''), $build)
        'OS install date'        = Format-Cell (Get-P $os 'InstallDate')
        'Last boot (WMI)'        = Format-Cell $lastBoot
        'Uptime (WMI)'           = $(if ($upWmi) { '{0:N1} days' -f $upWmi.TotalDays } else { '?' })
        'Uptime (kernel counter)' = $(if ($upCtr) { '{0:N1} days' -f $upCtr.TotalDays } else { '?' })
        'Fast Startup'           = $fastText
        'Hibernate'              = ('{0}; hiberfile.sys present: {1}' -f $hibText, $hiberFile)
        'CPU'                    = ('{0} ({1} cores / {2} logical, base {3} MHz)' -f (Get-P $cpu0 'Name' '?'), (Get-P $cpu0 'NumberOfCores' '?'), (Get-P $cpu0 'NumberOfLogicalProcessors' '?'), (Get-P $cpu0 'MaxClockSpeed' '?'))
        'RAM'                    = ('{0} GB ({1})' -f $ramGB, $modules)
        'Virtualization-based security' = $vbsText
    }
    Add-KV $kv

    $isSurface = ((Get-P $cs 'Model' '') -match 'Surface') -or ((Get-P $cs 'Manufacturer' '') -match 'Microsoft')
    if (-not $isSurface) { Add-Note 'Model does not look like a Microsoft Surface; Surface-specific hints may not apply.' }

    if ($uptime) {
        $d = [math]::Round($uptime.TotalDays, 1)
        $sev = 'GREEN'; if ($d -ge 30) { $sev = 'RED' } elseif ($d -ge 14) { $sev = 'AMBER' }
        Add-Finding $sev 'Uptime' "$d days" 'AMBER >= 14 days, RED >= 30 days' 'Do a full restart (Start > Power > Restart, not Shut down), then re-run with -Label AfterReboot and compare against a run taken while slow.' 'faststart'
    }
    if ($null -ne $fast) {
        $days = 0; if ($uptime) { $days = $uptime.TotalDays }
        if ($fast -eq 1 -and $days -ge 3) {
            Add-Finding 'AMBER' 'Fast Startup enabled with multi-day uptime' "HiberbootEnabled=1, uptime $([math]::Round($days,1)) d" 'AMBER if enabled and uptime >= 3 days' 'Consider disabling Fast Startup (Control Panel > Power Options > Choose what the power buttons do, or powercfg /h off). A "Shut down" with Fast Startup only hibernates the kernel, so leaks survive; only Restart clears them.' 'faststart'
        } elseif ($fast -eq 1) {
            Add-Finding 'INFO' 'Fast Startup enabled' 'HiberbootEnabled=1' 'AMBER only if uptime >= 3 days' 'If the machine is normally shut down rather than restarted, remember Fast Startup preserves the kernel session.' 'faststart'
        } else {
            Add-Finding 'GREEN' 'Fast Startup disabled' 'HiberbootEnabled=0' 'n/a' '' ''
        }
    }
    if ($ramGB -gt 0) {
        $sev = 'GREEN'; if ($ramGB -le 4) { $sev = 'RED' } elseif ($ramGB -le 8) { $sev = 'AMBER' }
        Add-Finding $sev 'Installed RAM' "$ramGB GB" 'RED <= 4 GB, AMBER <= 8 GB' 'With a very large OneDrive sync, 8 GB or less leaves little file-cache headroom; consider reducing the synced set (selective sync / Files On-Demand) or more RAM.' 'memory'
    }
    if ($vbsText -match '^Running') {
        Add-Finding 'INFO' 'Virtualization-based security running' $vbsText 'Informational' 'VBS/HVCI can cost a few percent CPU on older Intel parts; review only if throttling and driver findings do not explain the slowdown.' ''
    }
}
#endregion

#region CHECK 2: Performance snapshot ---------------------------------------------------------------------------------
function Check-Performance {
    $defs = @(
        @{ K = 'CpuPct';         P = '\Processor(_Total)\% Processor Time' }
        @{ K = 'AvailMB';        P = '\Memory\Available MBytes' }
        @{ K = 'PagesSec';       P = '\Memory\Pages/sec' }
        @{ K = 'PageFaultsSec';  P = '\Memory\Page Faults/sec' }
        @{ K = 'DiskQueue';      P = '\PhysicalDisk(_Total)\Avg. Disk Queue Length' }
        @{ K = 'DiskReadSec';    P = '\PhysicalDisk(_Total)\Avg. Disk sec/Read' }
        @{ K = 'DiskWriteSec';   P = '\PhysicalDisk(_Total)\Avg. Disk sec/Write' }
        @{ K = 'NPPoolBytes';    P = '\Memory\Pool Nonpaged Bytes' }
        @{ K = 'PagedPoolBytes'; P = '\Memory\Pool Paged Bytes' }
        @{ K = 'CommittedBytes'; P = '\Memory\Committed Bytes' }
        @{ K = 'ProcPerfPct';    P = '\Processor Information(_Total)\% Processor Performance' }
        @{ K = 'ProcFreqMHz';    P = '\Processor Information(_Total)\Processor Frequency' }
    )
    $paths = @($defs | ForEach-Object { $_.P })
    $valid = $paths
    try { $null = Get-Counter -Counter $paths -MaxSamples 1 -ErrorAction Stop }
    catch {
        # One bad counter fails the whole call; find the usable ones.
        $valid = @()
        foreach ($p in $paths) {
            try { $null = Get-Counter -Counter $p -MaxSamples 1 -ErrorAction Stop; $valid += $p }
            catch { Add-CheckError "Counter unavailable: $p" }
        }
    }
    if (@($valid).Count -eq 0) { throw 'No performance counters could be read.' }

    $keyByPath = @{}
    foreach ($d in $defs) { $keyByPath[$d.P.ToLower()] = $d.K }

    Write-Status "Sampling performance counters for $SampleSeconds seconds (use the PC normally / reproduce the slowness)..."
    $rows = New-Object System.Collections.Generic.List[object]
    $acc = @{}
    $procTimes = @(($SampleSeconds * 0.3), ($SampleSeconds * 0.6), ($SampleSeconds * 0.9))
    $nextProc = 0
    $t0 = Get-Date
    while ((((Get-Date) - $t0).TotalSeconds) -lt $SampleSeconds) {
        $elapsed = ((Get-Date) - $t0).TotalSeconds
        if (Test-Cancelled) { Add-CheckError 'Sampling stopped early (cancelled).'; break }
        Send-Status 'PROG' @('perf', ('Sampling counters: {0:N0} / {1} s' -f $elapsed, $SampleSeconds))
        Write-Progress -Id 2 -ParentId 1 -Activity 'Sampling performance counters' -Status ('{0:N0} / {1} s' -f $elapsed, $SampleSeconds) -PercentComplete ([int][math]::Min(100, 100 * $elapsed / $SampleSeconds))
        $r = Get-Counter -Counter $valid -MaxSamples 1 -ErrorAction SilentlyContinue
        $row = [ordered]@{ Time = (Get-Date).ToString('HH:mm:ss') }
        foreach ($d in $defs) { $row[$d.K] = $null }
        if ($r) {
            foreach ($cs in $r.CounterSamples) {
                $suffix = ($cs.Path -replace '^\\\\[^\\]+', '').ToLower()
                if ($keyByPath.ContainsKey($suffix)) { $row[$keyByPath[$suffix]] = [double]$cs.CookedValue }
            }
        }
        $rows.Add([pscustomobject]$row)

        if ($nextProc -lt 3 -and $elapsed -ge $procTimes[$nextProc]) {
            $nextProc++
            try {
                foreach ($s in @(Get-ProcSample)) {
                    if (-not $acc.ContainsKey($s.ProcId)) { $acc[$s.ProcId] = [pscustomobject]@{ Sample = $s; CpuSum = 0.0; IoSum = 0.0; N = 0 } }
                    $a = $acc[$s.ProcId]; $a.Sample = $s; $a.CpuSum += $s.Cpu; $a.IoSum += $s.Io; $a.N++
                }
            } catch { Add-CheckError "Process sample failed: $($_.Exception.Message)" }
        }
    }
    Write-Progress -Id 2 -Activity 'Sampling performance counters' -Completed
    $rows = $rows.ToArray()

    # Averaged per-process stats (CPU is % of total CPU capacity; averaged across the samples taken).
    foreach ($a in $acc.Values) {
        $s = $a.Sample
        $script:ProcStats[$s.ProcId] = [pscustomobject]@{
            ProcId = $s.ProcId; Name = $s.Name; CpuAvg = ($a.CpuSum / [math]::Max(1, $a.N))
            WSMB = [math]::Round($s.WS / 1MB, 1); PBMB = [math]::Round($s.PB / 1MB, 1)
            Handles = $s.Handles; Threads = $s.Threads; IoKBs = ($a.IoSum / [math]::Max(1, $a.N) / 1KB)
        }
    }

    $stats = @{}
    foreach ($d in $defs) { $stats[$d.K] = Get-Stats ($rows | ForEach-Object { $_.($d.K) }) }
    $script:Perf = @{ Rows = $rows; Stats = $stats }
    Save-Csv $rows 'perf_samples.csv'

    # Display table (scaled units) with thresholds.
    $tbl = New-Object System.Collections.Generic.List[object]
    $addRow = {
        param($Key, $Label, $Unit, $Scale, $Threshold)
        $s = $stats[$Key]
        if ($s) {
            $tbl.Add([pscustomobject]@{
                    Counter = $Label; Unit = $Unit; Min = [math]::Round($s.Min * $Scale, 2); Avg = [math]::Round($s.Avg * $Scale, 2)
                    P95 = [math]::Round($s.P95 * $Scale, 2); Max = [math]::Round($s.Max * $Scale, 2); Threshold = $Threshold
                })
        }
    }
    & $addRow 'CpuPct' 'CPU % Processor Time' '%' 1 'AMBER avg >= 50, RED avg >= 80'
    & $addRow 'AvailMB' 'Available memory' 'MB' 1 'AMBER < 10% of RAM, RED < 5%'
    & $addRow 'PagesSec' 'Memory Pages/sec' 'pages/s' 1 'AMBER avg >= 100, RED avg >= 500'
    & $addRow 'PageFaultsSec' 'Page faults/sec (soft+hard)' 'faults/s' 1 'informational'
    & $addRow 'DiskQueue' 'Disk avg queue length' 'requests' 1 'AMBER avg >= 2, RED avg >= 5'
    & $addRow 'DiskReadSec' 'Disk read latency' 'ms' 1000 'AMBER avg >= 20 ms, RED avg >= 50 ms'
    & $addRow 'DiskWriteSec' 'Disk write latency' 'ms' 1000 'AMBER avg >= 20 ms, RED avg >= 50 ms'
    & $addRow 'NPPoolBytes' 'Non-paged pool' 'MB' (1 / 1MB) 'AMBER >= 512 MB, RED >= 1024 MB'
    & $addRow 'PagedPoolBytes' 'Paged pool' 'MB' (1 / 1MB) 'AMBER >= 2048 MB'
    & $addRow 'CommittedBytes' 'Committed bytes' 'GB' (1 / 1GB) 'see Memory section'
    & $addRow 'ProcPerfPct' '% Processor Performance' '%' 1 'see CPU throttling section'
    & $addRow 'ProcFreqMHz' 'Processor frequency' 'MHz' 1 'see CPU throttling section'
    Add-Table -Data $tbl -Title "Counter statistics ($(@($rows).Count) samples over ~$SampleSeconds s)" -NoSort

    # Findings
    $cpuS = $stats['CpuPct']
    if ($cpuS) {
        $sev = 'GREEN'; if ($cpuS.Avg -ge 80) { $sev = 'RED' } elseif ($cpuS.Avg -ge 50) { $sev = 'AMBER' }
        Add-Finding $sev 'Average CPU utilisation during sample' ('{0:N1}% (max {1:N0}%)' -f $cpuS.Avg, $cpuS.Max) 'AMBER >= 50%, RED >= 80%' 'Identify the top CPU process in the table below (and in OneDrive/Defender/Search sections); investigate that process first.' 'startup'
    }
    $am = $stats['AvailMB']; $ram = Get-TotalRamBytes
    if ($am -and $ram -gt 0) {
        $pct = 100 * ($am.Avg * 1MB) / $ram
        $sev = 'GREEN'; if ($pct -lt 5) { $sev = 'RED' } elseif ($pct -lt 10) { $sev = 'AMBER' }
        Add-Finding $sev 'Available memory' ('{0:N0} MB avg ({1:N1}% of RAM)' -f $am.Avg, $pct) 'AMBER < 10% free, RED < 5% free' 'Review top working-set processes; close/restart the heaviest, and check the Memory section for pool/commit growth.' 'memory'
    }
    $ps = $stats['PagesSec']
    if ($ps) {
        $sev = 'GREEN'; if ($ps.Avg -ge 500) { $sev = 'RED' } elseif ($ps.Avg -ge 100) { $sev = 'AMBER' }
        Add-Finding $sev 'Hard paging (Pages/sec)' ('{0:N0} avg, {1:N0} max' -f $ps.Avg, $ps.Max) 'AMBER avg >= 100, RED avg >= 500' 'Sustained paging means memory pressure or heavy file I/O; correlate with disk latency and the top processes.' 'memory'
    }
    $lat = @()
    foreach ($k in 'DiskReadSec', 'DiskWriteSec') { if ($stats[$k]) { $lat += ($stats[$k].Avg * 1000) } }
    if ($lat.Count -gt 0) {
        $worst = ($lat | Measure-Object -Maximum).Maximum
        $sev = 'GREEN'; if ($worst -ge 50) { $sev = 'RED' } elseif ($worst -ge 20) { $sev = 'AMBER' }
        Add-Finding $sev 'Disk latency (worst of read/write average)' ('{0:N1} ms' -f $worst) 'AMBER >= 20 ms, RED >= 50 ms' 'Check the Disk section for health/wear and OneDrive/Defender I/O; latency this high on an SSD points at saturation or a failing drive.' 'disk'
    }
    $dq = $stats['DiskQueue']
    if ($dq) {
        $sev = 'GREEN'; if ($dq.Avg -ge 5) { $sev = 'RED' } elseif ($dq.Avg -ge 2) { $sev = 'AMBER' }
        Add-Finding $sev 'Disk queue length' ('{0:N2} avg, {1:N1} max' -f $dq.Avg, $dq.Max) 'AMBER avg >= 2, RED avg >= 5' 'Identify the top I/O process (table below); pause OneDrive sync temporarily to test.' 'disk'
    }
    foreach ($m in 'CpuPct', 'PagesSec', 'DiskQueue') { if ($stats[$m]) { Add-Metric "Perf avg $m" $stats[$m].Avg } }

    # Top process tables
    $plist = @(Get-ProcStatsList | ForEach-Object {
            [pscustomobject]@{
                Name = $_.Name; ProcId = $_.ProcId; CpuPct = [math]::Round($_.CpuAvg, 1); WorkingSetMB = $_.WSMB
                PrivateMB = $_.PBMB; Handles = $_.Handles; Threads = $_.Threads; IoKBs = [math]::Round($_.IoKBs, 0)
            }
        })
    Save-Csv $plist 'processes_all.csv'
    Add-Note 'CPU % is the average of up to three samples taken during the window and is expressed as % of TOTAL CPU capacity (all logical cores). Memory/handle values are from the last sample.'
    Add-Table -Data @($plist | Sort-Object CpuPct -Descending | Select-Object -First 15) -Title 'Top 15 processes by CPU' -NoSort
    Add-Table -Data @($plist | Sort-Object WorkingSetMB -Descending | Select-Object -First 15) -Title 'Top 15 processes by working set' -NoSort
    Add-Table -Data @($plist | Sort-Object PrivateMB -Descending | Select-Object -First 15) -Title 'Top 15 processes by private bytes' -NoSort
    Add-Table -Data @($plist | Sort-Object Handles -Descending | Select-Object -First 15) -Title 'Top 15 processes by handle count' -NoSort
}
#endregion

#region CHECK 3: Memory leak indicators -------------------------------------------------------------------------------
function Check-Memory {
    $m = Invoke-Safe 'Win32_PerfFormattedData_PerfOS_Memory' { Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory }
    $pf = @(Invoke-Safe 'Win32_PageFileUsage' { Get-CimInstance Win32_PageFileUsage })
    $ram = Get-TotalRamBytes

    if ($m) {
        $commit = [double](Get-P $m 'CommittedBytes' 0); $limit = [double](Get-P $m 'CommitLimit' 0)
        $np = [double](Get-P $m 'PoolNonpagedBytes' 0); $pp = [double](Get-P $m 'PoolPagedBytes' 0)
        $avail = [double](Get-P $m 'AvailableBytes' 0)
        $cache = [double](Get-P $m 'CacheBytes' 0)
        $commitPct = 0; if ($limit -gt 0) { $commitPct = 100 * $commit / $limit }
        Add-KV ([ordered]@{
                'Committed bytes'      = ('{0:N2} GB' -f ($commit / 1GB))
                'Commit limit'         = ('{0:N2} GB' -f ($limit / 1GB))
                'Commit charge'        = ('{0:N1}%' -f $commitPct)
                'Non-paged pool'       = ('{0:N0} MB' -f ($np / 1MB))
                'Paged pool'           = ('{0:N0} MB' -f ($pp / 1MB))
                'System cache (bytes)' = ('{0:N0} MB' -f ($cache / 1MB))
                'Available memory'     = ('{0:N0} MB' -f ($avail / 1MB))
            }) 'Memory counters (point in time)'

        $sev = 'GREEN'; if ($commitPct -ge 90) { $sev = 'RED' } elseif ($commitPct -ge 80) { $sev = 'AMBER' }
        Add-Finding $sev 'Commit charge vs limit' ('{0:N1}% ({1:N1} of {2:N1} GB)' -f $commitPct, ($commit / 1GB), ($limit / 1GB)) 'AMBER >= 80%, RED >= 90%' 'Find the top private-bytes processes (Performance section). If commit is high with modest working sets, look for a leaking process or driver; restarting the offender confirms it.' 'memory'

        $npMB = $np / 1MB
        $sev = 'GREEN'; if ($npMB -ge 1024) { $sev = 'RED' } elseif ($npMB -ge 512) { $sev = 'AMBER' }
        Add-Finding $sev 'Non-paged pool size' ('{0:N0} MB' -f $npMB) 'AMBER >= 512 MB, RED > 1 GB' 'Manually run poolmon.exe (from the Windows Driver Kit), press B to sort by bytes, note the top tag, then find its driver: findstr /s /m /l <Tag> C:\Windows\System32\drivers\*.sys. Update or remove that driver/software.' 'memory'
        $sev = 'GREEN'; if (($pp / 1MB) -ge 2048) { $sev = 'AMBER' }
        Add-Finding $sev 'Paged pool size' ('{0:N0} MB' -f ($pp / 1MB)) 'AMBER >= 2048 MB' 'Same poolmon approach (Paged tag). Large paged pool often indicates a filter driver or registry/handle leak.' 'memory'

        # Unaccounted memory: used RAM minus the sum of process working sets (includes kernel, drivers, modified/locked pages).
        if ($ram -gt 0) {
            $procWs = [double](Get-Process -ErrorAction SilentlyContinue | Measure-Object -Property WorkingSet64 -Sum).Sum
            $used = $ram - $avail
            $gap = $used - $procWs
            $gapPct = 100 * $gap / $ram
            Add-KV ([ordered]@{
                    'Physical RAM'            = ('{0:N2} GB' -f ($ram / 1GB))
                    'In use (RAM - available)' = ('{0:N2} GB' -f ($used / 1GB))
                    'Sum of process working sets' = ('{0:N2} GB' -f ($procWs / 1GB))
                    'Not attributable to a process (kernel, drivers, modified/locked pages, cache)' = ('{0:N2} GB ({1:N1}% of RAM)' -f ($gap / 1GB), $gapPct)
                }) 'Memory attribution'
            $sev = 'GREEN'; if ($gap -gt 2GB -and $gapPct -ge 25) { $sev = 'AMBER' }
            Add-Finding $sev 'Memory not attributable to processes' ('{0:N1} GB ({1:N1}% of RAM)' -f ($gap / 1GB), $gapPct) 'AMBER > 2 GB and >= 25% of RAM (heuristic; shared pages inflate process working sets)' 'A large unattributed block plus a big non-paged pool suggests a driver leak; use poolmon (or RAMMap from Sysinternals) to see whether it is pool, driver-locked or modified memory.' 'memory'
        }
    }

    # Pool growth during the sampling window (needs Performance check to have run).
    if ($script:Perf) {
        $rows = @($script:Perf.Rows | Where-Object { $null -ne $_.NPPoolBytes })
        if ($rows.Count -ge 5) {
            $growth = ($rows[$rows.Count - 1].NPPoolBytes - $rows[0].NPPoolBytes) / 1MB
            $sev = 'GREEN'; if ($growth -ge 50) { $sev = 'AMBER' }
            Add-Finding $sev 'Non-paged pool growth during sample' ('{0:N1} MB over {1} s' -f $growth, $SampleSeconds) 'AMBER >= 50 MB growth within the sample window' 'If growing while idle, capture poolmon snapshots a few minutes apart to identify the tag that grows.' 'memory'
        }
    }

    foreach ($p in @($pf)) {
        Add-KV ([ordered]@{
                'Page file'     = Get-P $p 'Name'
                'Allocated'     = ('{0} MB' -f (Get-P $p 'AllocatedBaseSize'))
                'Current usage' = ('{0} MB' -f (Get-P $p 'CurrentUsage'))
                'Peak usage'    = ('{0} MB' -f (Get-P $p 'PeakUsage'))
            }) 'Page file'
        $alloc = [double](Get-P $p 'AllocatedBaseSize' 0); $peak = [double](Get-P $p 'PeakUsage' 0)
        if ($alloc -gt 0) {
            $sev = 'GREEN'; if (100 * $peak / $alloc -ge 90) { $sev = 'AMBER' }
            Add-Finding $sev 'Page file peak usage' ('{0} of {1} MB' -f $peak, $alloc) 'AMBER >= 90% of allocated' 'Ensure the page file is system-managed and the system drive has free space.' 'memory'
        }
    }

    # Handle / thread heavy processes
    $procs = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{
                Name = $_.ProcessName; ProcId = $_.Id; Handles = $_.HandleCount; Threads = @($_.Threads).Count
                PrivateMB = [math]::Round($_.PrivateMemorySize64 / 1MB, 1); WorkingSetMB = [math]::Round($_.WorkingSet64 / 1MB, 1)
            }
        })
    Add-Table -Data @($procs | Sort-Object Handles -Descending | Select-Object -First 15) -Title 'Top 15 processes by handle count' -NoSort
    Add-Table -Data @($procs | Sort-Object Threads -Descending | Select-Object -First 15) -Title 'Top 15 processes by thread count' -NoSort
    if ($procs.Count -gt 0) {
        $h = Get-First ($procs | Sort-Object Handles -Descending)
        $sev = 'GREEN'; if ($h.Handles -ge 100000) { $sev = 'RED' } elseif ($h.Handles -ge 50000) { $sev = 'AMBER' }
        Add-Finding $sev 'Highest process handle count' ('{0}: {1:N0}' -f $h.Name, $h.Handles) 'AMBER >= 50,000, RED >= 100,000' "Restart '$($h.Name)' and see whether handle count returns to normal; a steady climb indicates a handle leak in that process." 'memory'
        $t = Get-First ($procs | Sort-Object Threads -Descending)
        $sev = 'GREEN'; if ($t.Threads -ge 2000) { $sev = 'AMBER' }
        Add-Finding $sev 'Highest process thread count' ('{0}: {1:N0}' -f $t.Name, $t.Threads) 'AMBER >= 2,000' "Investigate '$($t.Name)' if it keeps growing between runs." 'memory'
        $pb = Get-First ($procs | Sort-Object PrivateMB -Descending)
        $sev = 'GREEN'; if ($pb.PrivateMB -ge 4096) { $sev = 'RED' } elseif ($pb.PrivateMB -ge 2048) { $sev = 'AMBER' }
        Add-Finding $sev 'Largest process private bytes' ('{0}: {1:N0} MB' -f $pb.Name, $pb.PrivateMB) 'AMBER >= 2 GB, RED >= 4 GB' "Check whether '$($pb.Name)' grows over uptime (compare WhenSlow vs AfterReboot reports)." 'memory'
    }

    Add-Note 'Driver pool growth cannot be attributed to a specific driver with built-in tools; the non-paged pool, unattributed memory and 2004 events above are the indicators. Poolmon/RAMMap are the manual follow-ups.'
}
#endregion

#region CHECK 4: CPU throttling ---------------------------------------------------------------------------------------
function Check-CpuThrottling {
    $cpu = Get-First (Invoke-Safe 'Win32_Processor' { Get-CimInstance Win32_Processor })
    $baseMHz = [double](Get-P $cpu 'MaxClockSpeed' 0)
    $curMHz = [double](Get-P $cpu 'CurrentClockSpeed' 0)

    $kv = [ordered]@{
        'CPU'                       = Get-P $cpu 'Name' '?'
        'Rated/base clock (MaxClockSpeed)' = "$baseMHz MHz"
        'Current clock (CurrentClockSpeed)' = "$curMHz MHz"
    }

    # Sustained clock analysis from the sampling window (only samples under load are meaningful).
    if ($script:Perf) {
        $rows = @($script:Perf.Rows)
        $loaded = @($rows | Where-Object { $null -ne $_.CpuPct -and $_.CpuPct -ge 30 -and $null -ne $_.ProcPerfPct })
        $all = Get-Stats ($rows | ForEach-Object { $_.ProcPerfPct })
        $fr = Get-Stats ($rows | ForEach-Object { $_.ProcFreqMHz })
        if ($all) { $kv['% Processor Performance (all samples)'] = ('avg {0:N0}% / min {1:N0}% / max {2:N0}%' -f $all.Avg, $all.Min, $all.Max) }
        if ($fr) { $kv['Processor frequency counter'] = ('avg {0:N0} / min {1:N0} / max {2:N0} MHz' -f $fr.Avg, $fr.Min, $fr.Max) }
        $kv['Samples with CPU >= 30% load'] = "$($loaded.Count) of $($rows.Count)"
        if ($loaded.Count -ge 5) {
            $lp = Get-Stats ($loaded | ForEach-Object { $_.ProcPerfPct })
            $eff = $baseMHz * $lp.Avg / 100
            $kv['% Processor Performance under load'] = ('avg {0:N0}% (~{1:N0} MHz effective)' -f $lp.Avg, $eff)
            $sev = 'GREEN'; if ($lp.Avg -lt 70) { $sev = 'RED' } elseif ($lp.Avg -lt 100) { $sev = 'AMBER' }
            Add-Finding $sev 'Sustained clock vs base speed under load' ('{0:N0}% of base (avg over {1} loaded samples)' -f $lp.Avg, $loaded.Count) 'AMBER < 100% of base while CPU >= 30%, RED < 70%' 'CPU is running below base clock under load: check thermals/dust, AC power, power mode slider (Settings > System > Power), and Surface firmware/DTT driver updates.' 'throttle'
        } else {
            Add-Finding 'INFO' 'Throttling verdict needs CPU load' ("only $($loaded.Count) samples with CPU >= 30%") 'Needs >= 5 samples with CPU >= 30%' 'Re-run while the PC is slow and busy (or lengthen -SampleSeconds) so clock behaviour under load can be judged.' 'throttle'
        }
    }
    Add-KV $kv 'Clock speed'

    # Power plan and overlay
    $plan = Invoke-Safe 'powercfg /getactivescheme' { & powercfg.exe /getactivescheme }
    $planText = (@($plan) -join ' ').Trim()
    Add-Pre $planText
    if ($planText) {
        $sev = 'GREEN'; if ($planText -match 'Power saver') { $sev = 'AMBER' }
        Add-Finding $sev 'Active power plan' $planText 'AMBER if Power saver' 'Switch to Balanced (or a performance mode) via Settings > System > Power & battery.' 'throttle'
    }
    $overlayMap = @{
        '00000000-0000-0000-0000-000000000000' = 'Balanced / default'
        '961cc777-2547-4f9d-8174-7d86181b8a7a' = 'Best power efficiency / Better battery (power-saving overlay)'
        '3af9b8d9-7c97-431d-ad78-34a8bfea439f' = 'Better battery'
        '381b4222-f694-41f0-9685-ff5bb260df2e' = 'Better performance'
        'ded574b5-45a0-4f42-8737-46345c09c238' = 'Best performance'
    }
    $ov = Invoke-Safe 'Power overlay registry' { Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes' -ErrorAction Stop }
    if ($ov) {
        $ac = [string](Get-P $ov 'ActiveOverlayAcPowerScheme' ''); $dc = [string](Get-P $ov 'ActiveOverlayDcPowerScheme' '')
        $acN = $overlayMap[$ac.ToLower()]; $dcN = $overlayMap[$dc.ToLower()]
        Add-KV ([ordered]@{ 'Power mode overlay (AC)' = "$ac  $acN"; 'Power mode overlay (battery)' = "$dc  $dcN" }) 'Power mode slider (overlay GUIDs; may be absent on some builds)'
        foreach ($pair in @(@('AC', $ac, $acN), @('battery', $dc, $dcN))) {
            if ($pair[1] -and $pair[2] -match 'efficiency|Better battery') {
                Add-Finding 'AMBER' "Power mode on $($pair[0]) is power-saving" "$($pair[1]) ($($pair[2]))" 'AMBER if the active overlay is a power-saving mode' 'Set the power mode to Balanced or Best performance (Settings > System > Power & battery > Power mode).' 'throttle'
            }
        }
    }
    # Maximum processor state
    $pmax = Invoke-Safe 'powercfg PROCTHROTTLEMAX' { & powercfg.exe /q SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX }
    if ($pmax) {
        $txt = @($pmax) -join "`n"
        $acM = [regex]::Match($txt, 'Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)')
        $dcM = [regex]::Match($txt, 'Current DC Power Setting Index:\s*0x([0-9a-fA-F]+)')
        if ($acM.Success) {
            $acV = [Convert]::ToInt32($acM.Groups[1].Value, 16)
            $dcV = $acV; if ($dcM.Success) { $dcV = [Convert]::ToInt32($dcM.Groups[1].Value, 16) }
            $sev = 'GREEN'; if ($acV -lt 100 -or $dcV -lt 100) { $sev = 'AMBER' }
            Add-Finding $sev 'Maximum processor state' "AC $acV%, battery $dcV%" 'AMBER if < 100%' 'Set Maximum processor state to 100% in Advanced power settings (or reset the plan to defaults with powercfg -restoredefaultschemes).' 'throttle'
        }
    }

    # Battery
    $bat = @(Invoke-Safe 'Win32_Battery' { Get-CimInstance Win32_Battery })
    if ($bat.Count -gt 0) {
        $b = $bat[0]
        $statusMap = @{ 1 = 'Discharging'; 2 = 'On AC'; 3 = 'Fully charged'; 4 = 'Low'; 5 = 'Critical'; 6 = 'Charging'; 7 = 'Charging (high)'; 8 = 'Charging (low)'; 9 = 'Charging (critical)'; 10 = 'Unknown'; 11 = 'Partially charged' }
        $bs = [int](Get-P $b 'BatteryStatus' 10)
        $bkv = [ordered]@{ 'Charge' = ('{0}%' -f (Get-P $b 'EstimatedChargeRemaining' '?')); 'Status' = $statusMap[$bs] }
        $full = Invoke-Safe 'BatteryFullChargedCapacity' { Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity }
        $stat = Invoke-Safe 'BatteryStaticData' { Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData }
        $fc = [double](Get-P (Get-First $full) 'FullChargedCapacity' 0); $dcap = [double](Get-P (Get-First $stat) 'DesignedCapacity' 0)
        if ($fc -gt 0 -and $dcap -gt 0) {
            $health = 100 * $fc / $dcap
            $bkv['Full-charge capacity vs design'] = ('{0:N0} of {1:N0} mWh ({2:N0}%)' -f $fc, $dcap, $health)
            $sev = 'GREEN'; if ($health -lt 50) { $sev = 'RED' } elseif ($health -lt 70) { $sev = 'AMBER' }
            Add-Finding $sev 'Battery health (capacity vs design)' ('{0:N0}%' -f $health) 'AMBER < 70%, RED < 50%' 'A worn battery can cause power limiting on Surface devices; consider a battery service/replacement.' 'throttle'
        }
        if ($bs -eq 1) {
            Add-Finding 'INFO' 'Running on battery' ('{0}% charge' -f (Get-P $b 'EstimatedChargeRemaining' '?')) 'Informational' 'Re-test on AC power with the genuine Surface charger; battery mode limits CPU power.' 'throttle'
        }
        Add-KV $bkv 'Battery'
    } else { Add-Note 'No battery reported by Win32_Battery.' }

    # Thermal
    $tz = Invoke-Safe 'MSAcpi_ThermalZoneTemperature' { Get-CimInstance -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop }
    $tzRows = @($tz | ForEach-Object { [pscustomobject]@{ Zone = (Get-P $_ 'InstanceName'); TempC = [math]::Round(([double](Get-P $_ 'CurrentTemperature' 0)) / 10 - 273.15, 1) } })
    if ($tzRows.Count -gt 0) {
        Add-Table -Data $tzRows -Title 'ACPI thermal zones (MSAcpi_ThermalZoneTemperature)' -NoSort
        $mx = ($tzRows | Measure-Object TempC -Maximum).Maximum
        $sev = 'GREEN'; if ($mx -ge 85) { $sev = 'RED' } elseif ($mx -ge 75) { $sev = 'AMBER' }
        Add-Finding $sev 'Hottest ACPI thermal zone' ('{0:N1} C' -f $mx) 'AMBER >= 75 C, RED >= 85 C' 'Clean vents, keep the device off soft surfaces, and check for a runaway process; re-test after cooling.' 'throttle'
    } else { Add-Note 'MSAcpi_ThermalZoneTemperature returned no data (common on Surface; firmware does not always expose it).' }

    # Thermal Zone Information / Performance Limit counters (Windows 10 1809+)
    $tzs = @(Get-OptionalCounter @('\Thermal Zone Information(*)\Temperature', '\Thermal Zone Information(*)\% Passive Limit'))
    if ($tzs.Count -gt 0) {
        $trows = @($tzs | ForEach-Object {
                $v = [double]$_.CookedValue
                $name = ($_.Path -replace '^\\\\[^\\]+\\', '')
                if ($name -match 'temperature') { $v = $v - 273.15 }
                [pscustomobject]@{ Counter = $name; Value = [math]::Round($v, 1) }
            })
        Add-Table -Data $trows -Title 'Thermal Zone Information counters (Temperature in C, Passive Limit in %)' -NoSort
        $pl = @($trows | Where-Object { $_.Counter -match 'passive limit' })
        if ($pl.Count -gt 0) {
            $minPl = ($pl | Measure-Object Value -Minimum).Minimum
            $sev = 'GREEN'; if ($minPl -lt 80) { $sev = 'RED' } elseif ($minPl -lt 100) { $sev = 'AMBER' }
            Add-Finding $sev 'Thermal passive limit (OS is throttling for heat)' ('{0:N0}% (100 = no limit)' -f $minPl) 'AMBER < 100%, RED < 80%' 'Thermal throttling is active: check vents/fan, ambient temperature, dock/charger heat and firmware updates.' 'throttle'
        }
    }
    $pls = @(Get-OptionalCounter @('\Processor Information(_Total)\% Performance Limit'))
    if ($pls.Count -gt 0) {
        $pv = [double]$pls[0].CookedValue
        $sev = 'GREEN'; if ($pv -lt 80) { $sev = 'AMBER' }
        Add-Finding $sev 'Processor % Performance Limit (instant)' ('{0:N0}%' -f $pv) 'AMBER < 80% (single instant sample)' 'If persistently below 100%, investigate power limit (PL1/PL2) via Surface power mode and thermals.' 'throttle'
    }
}
#endregion

#region CHECK 5: Disk health and space --------------------------------------------------------------------------------
function Check-Disk {
    $vols = @(Invoke-Safe 'Get-Volume' { Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } })
    $vrows = @($vols | ForEach-Object {
            $sz = [double](Get-P $_ 'Size' 0); $fr = [double](Get-P $_ 'SizeRemaining' 0)
            $pct = 0; if ($sz -gt 0) { $pct = 100 * $fr / $sz }
            $flag = 'GREEN'
            if ($pct -lt 10 -or ($fr / 1GB) -lt 10) { $flag = 'RED' } elseif ($pct -lt 20) { $flag = 'AMBER' }
            [pscustomobject]@{
                Drive = ('{0}:' -f $_.DriveLetter); Label = $_.FileSystemLabel; FileSystem = $_.FileSystem
                SizeGB = [math]::Round($sz / 1GB, 1); FreeGB = [math]::Round($fr / 1GB, 1); FreePct = [math]::Round($pct, 1)
                Health = [string](Get-P $_ 'HealthStatus'); Flag = $flag
            }
        })
    Add-Table -Data $vrows -Title 'Volumes (thresholds: AMBER < 20% free, RED < 10% free or < 10 GB free)' -CsvName 'volumes.csv' -NoSort
    foreach ($v in $vrows) {
        Add-Finding $v.Flag "Free space $($v.Drive)" ('{0} GB free ({1}%)' -f $v.FreeGB, $v.FreePct) 'AMBER < 20%, RED < 10% or < 10 GB' 'Free space (Storage Sense, remove large/unused data). If Files On-Demand is off, OneDrive needs local space for every synced file.' 'disk'
    }

    $pd = @(Invoke-Safe 'Get-PhysicalDisk' { Get-PhysicalDisk })
    if (-not $script:IsAdmin) { Add-Note 'Not elevated: Get-StorageReliabilityCounter (SMART/NVMe wear and temperature) needs Administrator and is skipped.' }
    $drows = New-Object System.Collections.Generic.List[object]
    foreach ($d in $pd) {
        $rel = $null
        if ($script:IsAdmin) { $rel = Invoke-Safe "Reliability counters ($($d.FriendlyName))" { $d | Get-StorageReliabilityCounter } }
        $wear = Get-P $rel 'Wear'; $temp = Get-P $rel 'Temperature'
        $flag = 'GREEN'
        $health = [string](Get-P $d 'HealthStatus')
        if ($health -and $health -ne 'Healthy') { $flag = 'RED' }
        if ($null -ne $wear -and $wear -ge 80) { $flag = 'RED' } elseif ($null -ne $wear -and $wear -ge 50 -and $flag -eq 'GREEN') { $flag = 'AMBER' }
        if ($null -ne $temp -and $temp -ge 80) { $flag = 'RED' } elseif ($null -ne $temp -and $temp -ge 70 -and $flag -eq 'GREEN') { $flag = 'AMBER' }
        $re = Get-P $rel 'ReadErrorsTotal'; $we = Get-P $rel 'WriteErrorsTotal'
        if (($re -and $re -gt 0) -or ($we -and $we -gt 0)) { if ($flag -eq 'GREEN') { $flag = 'AMBER' } }
        $drows.Add([pscustomobject]@{
                Disk = Get-P $d 'FriendlyName'; Media = [string](Get-P $d 'MediaType'); Bus = [string](Get-P $d 'BusType')
                SizeGB = [math]::Round([double](Get-P $d 'Size' 0) / 1GB, 0); Health = $health; Operational = (@(Get-P $d 'OperationalStatus') -join ',')
                TempC = $temp; WearPct = $wear; PowerOnHours = Get-P $rel 'PowerOnHours'
                ReadErrors = $re; WriteErrors = $we; ReadLatencyMax = Get-P $rel 'ReadLatencyMax'; WriteLatencyMax = Get-P $rel 'WriteLatencyMax'
                Flag = $flag
            })
    }
    Add-Table -Data $drows.ToArray() -Title 'Physical disks (thresholds: RED if not Healthy, wear >= 80%, temp >= 80 C; AMBER wear >= 50%, temp >= 70 C, any read/write errors)' -CsvName 'physical_disks.csv' -NoSort
    foreach ($r in $drows) {
        $val = 'Health={0}, Temp={1} C, Wear={2}%, Errors R/W={3}/{4}' -f $r.Health, $r.TempC, $r.WearPct, $r.ReadErrors, $r.WriteErrors
        Add-Finding $r.Flag "Physical disk: $($r.Disk)" $val 'see table header' 'If not green: back up data, update SSD/NVMe firmware and Surface drivers, and consider replacing the SSD if wear/errors are high.' 'disk'
    }

    # Disk-related events (7 days)
    $ev = @(Get-ClassifiedEvents | Where-Object { $_.Cat -eq 'Disk / NTFS' })
    if ($ev.Count -gt 0) {
        Add-Table -Data (Get-EventSummary $ev) -Title 'Disk / NTFS events in the last 7 days' -CsvName 'events_disk.csv' -NoSort
    } else { Add-Note 'No disk/NTFS errors or warnings in the last 7 days.' }
    $sev = 'GREEN'; if ($ev.Count -ge 10) { $sev = 'RED' } elseif ($ev.Count -ge 1) { $sev = 'AMBER' }
    Add-Finding $sev 'Disk/NTFS error events (7 d)' "$($ev.Count) events" 'AMBER >= 1, RED >= 10' 'Run chkdsk (read-only: chkdsk C:) and review the SSD vendor tool/firmware; correlate event times with slowdowns.' 'disk'
}
#endregion

#region CHECK 6: OneDrive ---------------------------------------------------------------------------------------------
function Check-OneDrive {
    $procs = @(Get-ProcRows -Names 'OneDrive', 'FileSyncHelper', 'FileCoAuth')
    if ($procs.Count -eq 0) {
        Add-Note 'OneDrive.exe / FileSyncHelper.exe are not running.'
    } else {
        Add-Table -Data $procs -Title 'OneDrive processes' -CsvName 'onedrive_processes.csv' -Columns 'Name', 'ProcId', 'CpuPct', 'WorkingSetMB', 'PrivateMB', 'Handles', 'Threads', 'IoKBs', 'Started', 'Path' -NoSort
    }
    # Version
    $exe = $null
    foreach ($p in $procs) { if ($p.Name -eq 'OneDrive' -and $p.Path) { $exe = $p.Path; break } }
    if (-not $exe) {
        foreach ($c in "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe", "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe", "${env:ProgramFiles(x86)}\Microsoft OneDrive\OneDrive.exe") {
            if (Test-Path -LiteralPath $c) { $exe = $c; break }
        }
    }
    $ver = 'not found'
    if ($exe) { $ver = [string](Get-SafeValue { (Get-Item -LiteralPath $exe).VersionInfo.FileVersion }) }

    foreach ($p in $procs) {
        if ($p.Name -ne 'OneDrive') { continue }
        $sev = 'GREEN'; if ($p.WorkingSetMB -ge 2048) { $sev = 'RED' } elseif ($p.WorkingSetMB -ge 1024) { $sev = 'AMBER' }
        Add-Finding $sev 'OneDrive.exe working set' ('{0:N0} MB' -f $p.WorkingSetMB) 'AMBER >= 1 GB, RED >= 2 GB' 'Compare against the post-reboot run; if it balloons over uptime, update OneDrive and consider unlinking/relinking as a manual test.' 'onedrive'
        $sev = 'GREEN'; if ($p.Handles -ge 50000) { $sev = 'AMBER' }
        Add-Finding $sev 'OneDrive.exe handle count' ('{0:N0}' -f $p.Handles) 'AMBER >= 50,000' 'High handle counts during a huge initial sync are expected; watch whether it decays after sync completes.' 'onedrive'
        if ($null -ne $p.CpuPct) {
            $sev = 'GREEN'; if ($p.CpuPct -ge 25) { $sev = 'RED' } elseif ($p.CpuPct -ge 10) { $sev = 'AMBER' }
            Add-Finding $sev 'OneDrive.exe CPU (avg over sample)' ('{0:N1}% of total CPU' -f $p.CpuPct) 'AMBER >= 10%, RED >= 25%' 'Pause syncing (OneDrive tray > Pause) as a manual test to confirm impact, or sync fewer libraries/folders.' 'onedrive'
        }
    }
    foreach ($p in $procs) {
        if ($p.Name -ne 'FileSyncHelper') { continue }
        if ($null -ne $p.CpuPct -and $p.CpuPct -ge 10) {
            Add-Finding 'AMBER' 'FileSyncHelper.exe CPU' ('{0:N1}%' -f $p.CpuPct) 'AMBER >= 10%' 'FileSyncHelper is busy processing sync work; pausing/finishing the sync will reduce it.' 'onedrive'
        }
    }

    # Sync roots
    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($v in 'OneDrive', 'OneDriveCommercial', 'OneDriveConsumer') {
        $p = [Environment]::GetEnvironmentVariable($v)
        if ($p -and (Test-Path -LiteralPath $p)) { $roots.Add($p) }
    }
    $accRows = New-Object System.Collections.Generic.List[object]
    $accKey = 'HKCU:\Software\Microsoft\OneDrive\Accounts'
    if (Test-Path $accKey) {
        foreach ($k in @(Invoke-Safe 'OneDrive accounts registry' { Get-ChildItem $accKey })) {
            $props = Get-ItemProperty -LiteralPath $k.PSPath
            $uf = [string](Get-P $props 'UserFolder' '')
            $accRows.Add([pscustomobject]@{ Account = $k.PSChildName; Name = (Get-P $props 'DisplayName'); UserFolder = $uf; Email = (Get-P $props 'UserEmail') })
            if ($uf -and (Test-Path -LiteralPath $uf)) { $roots.Add($uf) }
            $tk = "$($k.PSPath)\Tenants"
            if (Test-Path -LiteralPath $tk) {
                foreach ($t in @(Get-ChildItem -LiteralPath $tk)) {
                    foreach ($vn in @((Get-Item -LiteralPath $t.PSPath).GetValueNames())) {
                        if ($vn -and ($vn -match '^[A-Za-z]:\\') -and (Test-Path -LiteralPath $vn)) { $roots.Add($vn) }
                    }
                }
            }
        }
    }
    if ($accRows.Count -gt 0) { Add-Table -Data $accRows.ToArray() -Title 'OneDrive accounts (registry)' -NoSort }

    $uniq = @($roots | Sort-Object -Unique)
    $final = @($uniq | Where-Object {
            $r = $_.TrimEnd('\')
            -not ($uniq | Where-Object { $o = $_.TrimEnd('\'); $o -ne $r -and $r.StartsWith($o + '\', [StringComparison]::OrdinalIgnoreCase) })
        })

    # Files On-Demand / driver state
    $fodUser = Get-SafeValue { (Get-ItemProperty 'HKCU:\Software\Microsoft\OneDrive' -ErrorAction Stop).FilesOnDemandEnabled }
    $fodPol  = Get-SafeValue { (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' -ErrorAction Stop).FilesOnDemandEnabled }
    $drv = Invoke-Safe 'CldFlt driver' { Get-CimInstance Win32_SystemDriver -Filter "Name='CldFlt'" }
    $cldState = [string](Get-P $drv 'State' 'not installed')
    $flt = @(Get-FltmcFilters | Where-Object { $_.Name -ieq 'CldFlt' })
    $fltText = 'unknown (needs elevation)'; if ($script:IsAdmin) { $fltText = $(if ($flt.Count -gt 0) { 'attached (altitude ' + $flt[0].Altitude + ')' } else { 'NOT attached' }) }

    # Count files with a time limit
    $results = New-Object System.Collections.Generic.List[object]
    if ($final.Count -gt 0) {
        $deadline = (Get-Date).AddSeconds($FileCountTimeLimitSeconds)
        $remaining = $final.Count
        foreach ($root in $final) {
            $budget = [math]::Max(5, ($deadline - (Get-Date)).TotalSeconds / $remaining)
            Write-Status ("Counting files under {0} (budget {1:N0}s) ..." -f $root, $budget)
            $results.Add((Measure-FolderFiles -Root $root -Deadline (Get-Date).AddSeconds($budget)))
            $remaining--
        }
        Add-Table -Data $results.ToArray() -Title 'File counts (recursive, reparse points not followed, time-limited)' -CsvName 'onedrive_filecounts.csv' -NoSort
    } else { Add-Note 'No OneDrive sync folders were found for this user (registry / environment variables).' }

    $total = [int64]0; $timedOut = $false; $samp = 0; $sph = 0
    foreach ($r in $results) { $total += $r.Files; if ($r.TimedOut) { $timedOut = $true }; $samp += $r.SampledFiles; $sph += $r.SampledPlaceholders }
    $fodText = 'not explicitly set'
    if ($null -ne $fodUser) { $fodText = $(if ($fodUser -eq 1) { 'enabled' } else { 'disabled' }) }
    if ($null -ne $fodPol) { $fodText += $(if ($fodPol -eq 1) { '; policy: enabled' } else { '; policy: disabled' }) }
    Add-KV ([ordered]@{
            'OneDrive.exe path'        = $exe
            'OneDrive version'         = $ver
            'Sync folders found'       = ($final -join '; ')
            'Total files counted'      = ('{0:N0}{1}' -f $total, $(if ($timedOut) { ' (INCOMPLETE - time limit reached)' } else { '' }))
            'Files On-Demand (registry)' = $fodText
            'Placeholder files in sample' = ('{0} of {1} sampled files carry cloud placeholder attributes' -f $sph, $samp)
            'cldflt.sys service state'  = $cldState
            'cldflt minifilter'         = $fltText
        }) 'Summary'

    if ($final.Count -gt 0) {
        $sev = 'GREEN'; $note = ''
        if ($total -gt 300000) { $sev = 'RED' } elseif ($timedOut) { $sev = 'AMBER'; $note = ' (count incomplete; true total is higher)' }
        Add-Finding $sev 'Total files under OneDrive folders' ('{0:N0}{1}' -f $total, $note) 'RED > 300,000 files' 'A very large synced set drives CPU, handles, disk I/O and indexing. Use "Choose folders" (selective sync) or Files On-Demand to shrink what is kept locally; let the initial sync finish before judging performance.' 'onedrive'
        if ($samp -ge 50) {
            if ($sph -eq 0 -and $fodUser -ne 1) {
                Add-Finding 'AMBER' 'Files On-Demand appears OFF (no placeholder files sampled)' "$sph of $samp sampled" 'AMBER if no placeholders sampled and FoD not explicitly enabled' 'Enable Files On-Demand (OneDrive Settings > Sync and backup > Advanced settings) so files are not all downloaded locally.' 'onedrive'
            } else {
                Add-Finding 'GREEN' 'Files On-Demand in use' "$sph of $samp sampled are placeholders" 'n/a' '' ''
            }
        }
    }
    if ($cldState -ne 'Running' -and $cldState -ne 'not installed') {
        Add-Finding 'AMBER' 'cldflt (Cloud Files filter) driver not running' $cldState 'AMBER if not Running while OneDrive is in use' 'Files On-Demand depends on cldflt.sys; check Windows updates and the driver state (sc query cldflt).' 'onedrive'
    } elseif ($script:IsAdmin -and $flt.Count -eq 0 -and $procs.Count -gt 0) {
        Add-Finding 'AMBER' 'cldflt minifilter not attached' $fltText 'AMBER if OneDrive runs but cldflt is not attached' 'Investigate with fltmc filters and Windows updates.' 'onedrive'
    } else {
        Add-Finding 'GREEN' 'cldflt.sys loaded' "$cldState / $fltText" 'n/a' '' ''
    }

    # Event log
    $appEv = @(); try { $appEv = @(Get-CachedEvents 'Application') } catch { Add-CheckError "Application log: $($_.Exception.Message)" }
    $sysEv = @(); try { $sysEv = @(Get-CachedEvents 'System') } catch { Add-CheckError "System log: $($_.Exception.Message)" }
    $odEv = @($appEv | Where-Object { $_.ProviderName -match 'OneDrive|FileSyncHelper' }) + @($sysEv | Where-Object { $_.ProviderName -match 'cldflt|CloudFiles|CloudFilter' })
    if ($odEv.Count -gt 0) {
        $sum = Get-EventSummary @($odEv | ForEach-Object { [pscustomobject]@{ Cat = 'OneDrive / Cloud Files'; Log = 'Application/System'; Provider = $_.ProviderName; Id = $_.Id; Time = $_.TimeCreated; Ev = $_ } })
        Add-Table -Data $sum -Title 'OneDrive / Cloud Files errors and warnings (7 days)' -CsvName 'events_onedrive.csv' -NoSort
    }
    $sev = 'GREEN'; if ($odEv.Count -ge 20) { $sev = 'RED' } elseif ($odEv.Count -ge 1) { $sev = 'AMBER' }
    Add-Finding $sev 'OneDrive/Cloud Files error events (7 d)' "$($odEv.Count) events" 'AMBER >= 1, RED >= 20' 'Open OneDrive > Help & settings > View sync problems and resolve reported items (path length, invalid names, locked files).' 'onedrive'
}
#endregion

#region CHECK 7: Windows Search and Defender --------------------------------------------------------------------------
function Check-SearchDefender {
    # --- Windows Search ---
    $srch = @(Get-ProcRows -Names 'SearchIndexer', 'SearchProtocolHost', 'SearchFilterHost')
    if ($srch.Count -gt 0) { Add-Table -Data $srch -Title 'Windows Search processes' -Columns 'Name', 'ProcId', 'CpuPct', 'WorkingSetMB', 'PrivateMB', 'Handles', 'Threads', 'IoKBs' -NoSort }
    else { Add-Note 'SearchIndexer.exe is not running.' }
    $svc = Get-SafeValue { Get-Service WSearch }
    $edbInfo = @()
    foreach ($f in "$env:ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb", "$env:ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.db") {
        if ([System.IO.File]::Exists($f)) { $edbInfo += [pscustomobject]@{ File = $f; SizeGB = [math]::Round(([System.IO.FileInfo]$f).Length / 1GB, 2); Modified = ([System.IO.FileInfo]$f).LastWriteTime } }
    }
    if ($edbInfo.Count -gt 0) { Add-Table -Data $edbInfo -Title 'Search index database' -NoSort }
    Add-KV ([ordered]@{ 'WSearch service' = $(if ($svc) { "$($svc.Status) / $($svc.StartType)" } else { 'not found' }) })

    $idxProc = $srch | Where-Object { $_.Name -eq 'SearchIndexer' } | Select-Object -First 1
    if ($idxProc) {
        if ($null -ne $idxProc.CpuPct) {
            $sev = 'GREEN'; if ($idxProc.CpuPct -ge 25) { $sev = 'RED' } elseif ($idxProc.CpuPct -ge 10) { $sev = 'AMBER' }
            Add-Finding $sev 'SearchIndexer.exe CPU (avg)' ('{0:N1}% of total CPU' -f $idxProc.CpuPct) 'AMBER >= 10%, RED >= 25%' 'A large OneDrive sync gets indexed too. Review Indexing Options (control.exe srchadmin.dll) and exclude the OneDrive tree or reduce indexed locations as a test.' 'scan'
        }
        $sev = 'GREEN'; if ($idxProc.WorkingSetMB -ge 1024) { $sev = 'RED' } elseif ($idxProc.WorkingSetMB -ge 500) { $sev = 'AMBER' }
        Add-Finding $sev 'SearchIndexer.exe working set' ('{0:N0} MB' -f $idxProc.WorkingSetMB) 'AMBER >= 500 MB, RED >= 1 GB' 'If large and persistent, rebuild the index manually (Indexing Options > Advanced > Rebuild) after reducing indexed locations.' 'scan'
    }
    foreach ($e in $edbInfo) {
        $sev = 'GREEN'; if ($e.SizeGB -ge 10) { $sev = 'RED' } elseif ($e.SizeGB -ge 5) { $sev = 'AMBER' }
        Add-Finding $sev ('Search index size: ' + (Split-Path $e.File -Leaf)) ('{0} GB' -f $e.SizeGB) 'AMBER >= 5 GB, RED >= 10 GB' 'An oversized index suggests too many indexed items; reduce indexed locations and rebuild the index manually.' 'scan'
    }
    # Index item count via Search performance counters (names vary by build)
    $itemRows = Invoke-Safe 'Search index counters' {
        $out = @()
        foreach ($set in @(Get-Counter -ListSet 'Search*' -ErrorAction Stop)) {
            $paths = @($set.PathsWithInstances) + @($set.Paths) | Where-Object { $_ -match 'Item|Index|Catalog|Retr|Delayed|Queue' } | Select-Object -First 25
            foreach ($cs in Get-OptionalCounter @($paths)) {
                $out += [pscustomobject]@{ Counter = ($cs.Path -replace '^\\\\[^\\]+', ''); Value = [math]::Round([double]$cs.CookedValue, 1) }
            }
        }
        $out
    }
    if (@($itemRows).Count -gt 0) { Add-Table -Data @($itemRows | Select-Object -First 40) -Title 'Search indexer performance counters (index item counts where exposed)' -NoSort }
    else { Add-Note 'Search index item count is not exposed via performance counters on this build.' }

    # --- Defender ---
    $def = Invoke-Safe 'MsMpEng/Defender processes' { Get-ProcRows -Names 'MsMpEng', 'MpDefenderCoreService', 'NisSrv', 'MpCmdRun' }
    if (@($def).Count -gt 0) { Add-Table -Data @($def) -Title 'Defender processes' -Columns 'Name', 'ProcId', 'CpuPct', 'WorkingSetMB', 'PrivateMB', 'Handles', 'Threads', 'IoKBs' -NoSort }
    $ms = @($def | Where-Object { $_.Name -eq 'MsMpEng' }) | Select-Object -First 1
    if ($ms) {
        if ($null -ne $ms.CpuPct) {
            $sev = 'GREEN'; if ($ms.CpuPct -ge 25) { $sev = 'RED' } elseif ($ms.CpuPct -ge 10) { $sev = 'AMBER' }
            Add-Finding $sev 'MsMpEng.exe CPU (avg)' ('{0:N1}% of total CPU' -f $ms.CpuPct) 'AMBER >= 10%, RED >= 25%' 'Defender is scanning heavily (often due to OneDrive sync churn). Check scan status below; do not disable protection, but review scan schedules and exclusions.' 'scan'
        }
        $sev = 'GREEN'; if ($ms.WorkingSetMB -ge 2048) { $sev = 'RED' } elseif ($ms.WorkingSetMB -ge 1024) { $sev = 'AMBER' }
        Add-Finding $sev 'MsMpEng.exe working set' ('{0:N0} MB' -f $ms.WorkingSetMB) 'AMBER >= 1 GB, RED >= 2 GB' 'Compare with the post-reboot report; consider engine/platform updates.' 'scan'
    }
    if (@($def | Where-Object { $_.Name -eq 'MpCmdRun' }).Count -gt 0) {
        Add-Finding 'INFO' 'MpCmdRun.exe is running (a scan/update command is active)' 'process present' 'Informational' 'Let the running scan finish before judging performance.' 'scan'
    }

    $mp = Invoke-Safe 'Get-MpComputerStatus' { Get-MpComputerStatus }
    if ($mp) {
        $keys = 'AMRunningMode', 'AMServiceEnabled', 'AntivirusEnabled', 'RealTimeProtectionEnabled', 'OnAccessProtectionEnabled', 'BehaviorMonitorEnabled', 'IsTamperProtected',
        'AntivirusSignatureVersion', 'AntivirusSignatureLastUpdated', 'AntivirusSignatureAge', 'QuickScanEndTime', 'QuickScanAge', 'FullScanEndTime', 'FullScanAge', 'AMProductVersion', 'AMEngineVersion'
        $kv = [ordered]@{}
        foreach ($k in $keys) { $kv[$k] = Format-Cell (Get-P $mp $k) }
        Add-KV $kv 'Get-MpComputerStatus'
        $age = Get-P $mp 'AntivirusSignatureAge'
        if ($null -ne $age) {
            $sev = 'GREEN'; if ($age -gt 7) { $sev = 'AMBER' }
            Add-Finding $sev 'Defender signature age' "$age days" 'AMBER > 7 days' 'Check Windows Update / Defender update source connectivity.' 'scan'
        }
        $mode = [string](Get-P $mp 'AMRunningMode' '')
        if ($mode -match 'Passive|EDR') { Add-Finding 'INFO' 'Defender is not the primary AV' $mode 'Informational' 'A third-party AV is doing real-time scanning; see the Security section.' 'scan' }
    }
    $scanEv = Invoke-Safe 'Defender scan events' {
        try { @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1000, 1001, 1002, 1005 } -MaxEvents 8 -ErrorAction Stop) }
        catch { if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') { @() } else { throw } }
    }
    if (@($scanEv).Count -gt 0) {
        $names = @{ 1000 = 'Scan started'; 1001 = 'Scan finished'; 1002 = 'Scan stopped'; 1005 = 'Scan failed' }
        Add-Table -Data @($scanEv | ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated; Event = $names[[int]$_.Id]; Id = $_.Id } }) -Title 'Recent Defender scan events' -NoSort
    }

    $pref = Invoke-Safe 'Get-MpPreference' { Get-MpPreference }
    if ($pref) {
        $ex = [ordered]@{}
        foreach ($k in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension') {
            $v = @(Get-P $pref $k @())
            if ($v.Count -eq 1 -and ([string]$v[0]) -like 'N/A*') { $ex[$k] = '(hidden: requires Administrator)' }
            elseif ($v.Count -eq 0 -or ($v.Count -eq 1 -and -not $v[0])) { $ex[$k] = '(none)' }
            else { $ex[$k] = ($v -join '; ') }
        }
        Add-KV $ex 'Defender exclusions'
        $pathEx = @(Get-P $pref 'ExclusionPath' @()) | Where-Object { $_ -and ([string]$_) -notlike 'N/A*' }
        Add-Finding 'INFO' 'Defender path exclusions configured' "$(@($pathEx).Count) paths" 'Informational' 'Review exclusions for anything unexpected. Microsoft documents recommended (not blanket) OneDrive exclusions; do not exclude broadly.' 'scan'
    }
}
#endregion

#region CHECK 8: Startup and background load --------------------------------------------------------------------------
function Check-Startup {
    # Aggregate live process stats by image name so startup items can be scored.
    $byName = @{}
    foreach ($s in @(Get-ProcStatsList)) {
        $k = $s.Name.ToLower()
        if (-not $byName.ContainsKey($k)) { $byName[$k] = [pscustomobject]@{ Cpu = 0.0; WS = 0.0; Handles = 0 } }
        $byName[$k].Cpu += $s.CpuAvg; $byName[$k].WS += $s.WSMB; $byName[$k].Handles += $s.Handles
    }
    $items = New-Object System.Collections.Generic.List[object]
    $newItem = {
        param($Type, $Name, $Command, $Enabled, $Detail, $ProcId)
        $exe = Resolve-ExePath $Command
        $co = Get-Company $exe
        $cpu = 0.0; $ws = 0.0; $h = 0; $running = $false
        if ($ProcId -and $script:ProcStats.ContainsKey([int]$ProcId)) {
            $s = $script:ProcStats[[int]$ProcId]; $cpu = $s.CpuAvg; $ws = $s.WSMB; $h = $s.Handles; $running = $true
        } elseif ($exe) {
            $k = [IO.Path]::GetFileNameWithoutExtension($exe).ToLower()
            if ($byName.ContainsKey($k)) { $b = $byName[$k]; $cpu = $b.Cpu; $ws = $b.WS; $h = $b.Handles; $running = $true }
        }
        $impact = [math]::Round($cpu * 10 + $ws / 100 + $h / 500, 1)
        if (-not $Enabled) { $impact = 0 }
        [pscustomobject]@{ Type = $Type; Name = $Name; Publisher = $co; Enabled = $Enabled; Running = $running; Impact = $impact; CpuPct = [math]::Round($cpu, 1); WorkingSetMB = [math]::Round($ws, 0); Handles = $h; Detail = $Detail; Command = $Command }
    }

    # Registry Run keys
    $runKeys = @(
        @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; A = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'; L = 'HKLM Run' }
        @{ P = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; A = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'; L = 'HKLM Run (32-bit)' }
        @{ P = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; A = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'; L = 'HKCU Run' }
    )
    foreach ($rk in $runKeys) {
        $vals = Invoke-Safe "Read $($rk.L)" { Get-Item -LiteralPath $rk.P -ErrorAction Stop }
        if (-not $vals) { continue }
        $appr = Get-SafeValue { Get-Item -LiteralPath $rk.A -ErrorAction Stop }
        foreach ($n in $vals.GetValueNames()) {
            if (-not $n) { continue }
            $enabled = $true
            if ($appr) {
                $bytes = Get-SafeValue { $appr.GetValue($n) }
                if ($bytes -is [byte[]] -and $bytes.Length -gt 0 -and ($bytes[0] -band 1) -eq 1) { $enabled = $false }
            }
            $items.Add((& $newItem $rk.L $n ([string]$vals.GetValue($n)) $enabled '' $null))
        }
    }
    # Startup folders
    $shell = Get-SafeValue { New-Object -ComObject WScript.Shell }
    foreach ($fd in @(@("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", 'All-users Startup folder', 'HKLM'), @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", 'User Startup folder', 'HKCU'))) {
        if (-not (Test-Path -LiteralPath $fd[0])) { continue }
        $appr = Get-SafeValue { Get-Item -LiteralPath ($fd[2] + ':\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder') -ErrorAction Stop }
        foreach ($f in @(Get-ChildItem -LiteralPath $fd[0] -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $cmd = $f.FullName
            if ($shell -and $f.Extension -eq '.lnk') { $tgt = Get-SafeValue { $shell.CreateShortcut($f.FullName).TargetPath }; if ($tgt) { $cmd = $tgt } }
            $enabled = $true
            if ($appr) { $bytes = Get-SafeValue { $appr.GetValue($f.Name) }; if ($bytes -is [byte[]] -and $bytes.Length -gt 0 -and ($bytes[0] -band 1) -eq 1) { $enabled = $false } }
            $items.Add((& $newItem $fd[1] $f.Name $cmd $enabled $f.FullName $null))
        }
    }
    # Scheduled tasks at logon/boot (non-Microsoft)
    $tasks = @(Invoke-Safe 'Get-ScheduledTask' { Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } })
    foreach ($t in $tasks) {
        $trig = @(@($t.Triggers) | Where-Object { $_ } | ForEach-Object { [string](Get-P (Get-P $_ 'CimClass') 'CimClassName') })
        if (-not ($trig -contains 'MSFT_TaskLogonTrigger' -or $trig -contains 'MSFT_TaskBootTrigger')) { continue }
        if ($t.TaskPath -like '\Microsoft\Windows\*') { continue }
        $act = Get-First $t.Actions
        $cmd = [string](Get-P $act 'Execute' ''); $args1 = [string](Get-P $act 'Arguments' '')
        $co = Get-Company (Resolve-ExePath $cmd)
        if ($co -match '^Microsoft') { continue }
        $when = @($trig | ForEach-Object { $_ -replace '^MSFT_Task', '' -replace 'Trigger$', '' }) -join ','
        $items.Add((& $newItem 'Scheduled task' ($t.TaskPath + $t.TaskName) ($cmd + ' ' + $args1).Trim() $true "Trigger: $when; State: $($t.State)" $null))
    }
    # Auto-start non-Microsoft services
    $svcs = @(Invoke-Safe 'Win32_Service' { Get-CimInstance Win32_Service -Filter "StartMode='Auto'" })
    foreach ($s in $svcs) {
        $exe = Resolve-ExePath ([string](Get-P $s 'PathName' ''))
        $co = Get-Company $exe
        if ($co -match '^Microsoft') { continue }
        $items.Add((& $newItem 'Auto-start service' ([string]$s.Name) ([string](Get-P $s 'PathName' '')) $true ("$($s.DisplayName); State: $($s.State)") $(if ($s.State -eq 'Running') { $s.ProcessId } else { $null })))
    }

    $all = @($items | Sort-Object Impact -Descending)
    Save-Csv $all 'startup_items.csv'
    Add-Note 'Impact score = CPU% (avg, of total) x 10 + working set MB / 100 + handles / 500 for the matching running process. Items that are not running score 0. Disabled items (StartupApproved) are excluded from scoring.'
    Add-Table -Data @($all | Select-Object -First 20) -Title 'Top 20 startup/background items by impact (non-Microsoft; full list in startup_items.csv)' -Columns 'Impact', 'Type', 'Name', 'Publisher', 'Enabled', 'Running', 'CpuPct', 'WorkingSetMB', 'Handles', 'Command'

    $startupCnt = @($all | Where-Object { $_.Enabled -and ($_.Type -match 'Run|Startup folder') }).Count
    $sev = 'GREEN'; if ($startupCnt -ge 20) { $sev = 'RED' } elseif ($startupCnt -ge 10) { $sev = 'AMBER' }
    Add-Finding $sev 'Enabled startup entries (Run keys + Startup folders)' "$startupCnt" 'AMBER >= 10, RED >= 20' 'Disable non-essential entries via Task Manager > Startup apps (manual review).' 'startup'
    $svcCnt = @($all | Where-Object { $_.Type -eq 'Auto-start service' }).Count
    $sev = 'GREEN'; if ($svcCnt -ge 40) { $sev = 'RED' } elseif ($svcCnt -ge 25) { $sev = 'AMBER' }
    Add-Finding $sev 'Non-Microsoft auto-start services' "$svcCnt" 'AMBER >= 25, RED >= 40' 'Review with services.msc / msconfig (Hide all Microsoft services); set unneeded ones to Manual after testing.' 'startup'
    $taskCnt = @($all | Where-Object { $_.Type -eq 'Scheduled task' }).Count
    Add-Finding 'INFO' 'Non-Microsoft logon/boot scheduled tasks' "$taskCnt" 'Informational' 'Review in Task Scheduler for stale vendor updaters.' 'startup'
    $hot = Get-First ($all | Where-Object { $_.CpuPct -ge 10 -and $_.Publisher -notmatch '^Microsoft' } | Sort-Object CpuPct -Descending)
    if ($hot) { Add-Finding 'AMBER' 'Third-party startup item using CPU' ('{0}: {1}% CPU' -f $hot.Name, $hot.CpuPct) 'AMBER >= 10% CPU' "Investigate/update or remove '$($hot.Name)' (publisher: $($hot.Publisher))." 'startup' }
}
#endregion

#region CHECK 9: Drivers, firmware, updates ---------------------------------------------------------------------------
function Check-Drivers {
    $drv = @(Invoke-Safe 'Win32_PnPSignedDriver' { Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DriverDate } })
    $now = Get-Date
    $rows = @($drv | ForEach-Object {
            $age = [math]::Round(($now - $_.DriverDate).TotalDays / 365.25, 1)
            [pscustomobject]@{
                Device = $_.DeviceName; Class = $_.DeviceClass; Provider = $_.DriverProviderName; Manufacturer = $_.Manufacturer
                Version = $_.DriverVersion; DriverDate = $_.DriverDate.ToString('yyyy-MM-dd'); AgeYears = $age; Inf = $_.InfName
            }
        } | Sort-Object AgeYears -Descending)
    Save-Csv $rows 'drivers_all.csv'
    $keyRx = 'Surface|Management Engine|MEI|HECI|UHD Graphics|Iris|Xe Graphics|HD Graphics|Dynamic Platform|Thermal Framework|DPTF|Dynamic Tuning|Serial IO|Intel\(R\).*(Wi-?Fi|Wireless|Bluetooth)'
    $key = @($rows | Where-Object { ($_.Device -match $keyRx) -or ($_.Manufacturer -match 'Surface') })
    $keyOut = @($key | ForEach-Object {
            $f = 'GREEN'; if ($_.AgeYears -gt 3) { $f = 'AMBER' }
            [pscustomobject]@{ Flag = $f; Device = $_.Device; Provider = $_.Provider; Version = $_.Version; DriverDate = $_.DriverDate; AgeYears = $_.AgeYears }
        })
    Add-Table -Data $keyOut -Title 'Surface / Intel ME / Intel graphics / platform drivers (AMBER if older than 3 years)' -CsvName 'drivers_key.csv' -Max 100
    $oldKey = @($keyOut | Where-Object { $_.Flag -eq 'AMBER' }).Count
    $sev = 'GREEN'; if ($oldKey -gt 0) { $sev = 'AMBER' }
    Add-Finding $sev 'Key Surface/Intel drivers older than 3 years' "$oldKey of $($keyOut.Count)" 'AMBER if any > 3 years old' 'Install the latest Surface driver/firmware MSI for this model (manually, via Windows Update or the Surface driver download), then reboot.' 'drivers'

    $old = @($rows | Where-Object { $_.AgeYears -gt 3 -and $_.Provider -notmatch '^Microsoft' })
    Add-Table -Data @($old | Select-Object -First 60) -Title 'Third-party drivers older than 3 years (excluding Microsoft-provided; oldest first)' -Max 60
    $sev = 'GREEN'; if ($old.Count -ge 25) { $sev = 'AMBER' }
    Add-Finding $sev 'Third-party drivers older than 3 years' "$($old.Count) drivers" 'AMBER >= 25' 'Review the oldest entries in drivers_all.csv; update those tied to storage, graphics, network and security software.' 'drivers'

    # Pending updates (query only) and reboot flags
    if ($script:SkipUpdateSearch) { Add-Note 'Windows Update search skipped (Quick mode).' 'muted' }
    $upd = if ($script:SkipUpdateSearch) { $null } else { Invoke-Safe 'Windows Update search' {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $res = $searcher.Search("IsInstalled=0 and IsHidden=0")
        @($res.Updates | ForEach-Object { [pscustomobject]@{ Title = $_.Title; Severity = [string]$_.MsrcSeverity; RebootRequired = $_.RebootRequired; DownloadedLocally = $_.IsDownloaded } })
    } }
    if ($null -ne $upd) {
        Add-Table -Data @($upd) -Title 'Pending Windows Updates (query only)' -CsvName 'pending_updates.csv' -Columns 'Title', 'Severity', 'RebootRequired', 'DownloadedLocally'
        $n = @($upd).Count
        $sev = 'GREEN'; if ($n -ge 5) { $sev = 'AMBER' } elseif ($n -ge 1) { $sev = 'INFO' }
        Add-Finding $sev 'Pending Windows Updates' "$n" 'AMBER >= 5, INFO 1-4' 'Install pending updates (and firmware/driver updates) then restart; check Settings > Windows Update.' 'drivers'
    }
    $hist = Invoke-Safe 'Update history' {
        $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $codes = @{ 1 = 'InProgress'; 2 = 'Succeeded'; 3 = 'SucceededWithErrors'; 4 = 'Failed'; 5 = 'Aborted' }
        @($s.QueryHistory(0, 15) | ForEach-Object { [pscustomobject]@{ Date = $_.Date; Result = $codes[[int]$_.ResultCode]; Title = $_.Title } })
    }
    if (@($hist).Count -gt 0) {
        Add-Table -Data @($hist) -Title 'Recent update history' -NoSort
        $failed = @($hist | Where-Object { $_.Result -eq 'Failed' }).Count
        $sev = 'GREEN'; if ($failed -ge 1) { $sev = 'AMBER' }
        Add-Finding $sev 'Failed updates among last 15 history entries' "$failed" 'AMBER >= 1' 'Investigate failures (Windows Update log / Settings > Update history); repeated failed servicing can burn CPU in TiWorker.' 'drivers'
    }
    $pend = [ordered]@{}
    $pend['CBS RebootPending'] = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $pend['CBS PackagesPending'] = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending'
    $pend['Windows Update RebootRequired'] = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $pfr = Get-SafeValue { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop).PendingFileRenameOperations }
    $pend['PendingFileRenameOperations'] = [bool]$pfr
    Add-KV $pend 'Pending reboot indicators'
    $anyPend = @($pend.Values | Where-Object { $_ }).Count
    $sev = 'GREEN'; if ($anyPend -gt 0) { $sev = 'AMBER' }
    Add-Finding $sev 'Pending reboot indicators' "$anyPend of 4 set" 'AMBER if any set' 'Restart to complete pending servicing; a machine that is always awaiting a reboot can run servicing tasks in the background.' 'drivers'
    foreach ($n in 'TiWorker', 'TrustedInstaller', 'wuauserv') {
        $pr = @(Get-ProcRows -Names $n)
        foreach ($p in $pr) {
            if ($null -ne $p.CpuPct -and $p.CpuPct -ge 10) { Add-Finding 'AMBER' "$($p.Name) using CPU" ('{0:N1}%' -f $p.CpuPct) 'AMBER >= 10%' 'Windows servicing is active; let it finish and restart.' 'drivers' }
        }
    }
}
#endregion

#region CHECK 10: Event logs ------------------------------------------------------------------------------------------
function Check-EventLogs {
    $cls = @(Get-ClassifiedEvents)
    Add-Note ("Window: {0} to {1}. Only Critical/Error/Warning events are collected (up to 20,000 per log)." -f $script:EventStart.ToString('yyyy-MM-dd HH:mm'), (Get-Date).ToString('yyyy-MM-dd HH:mm'))
    $sum = Get-EventSummary $cls
    Add-Table -Data $sum -Title 'Summary by event ID (count and most recent example)' -CsvName 'events_summary.csv' -Max 150
    $fullRows = @($cls | ForEach-Object { [pscustomobject]@{ Time = $_.Time; Category = $_.Cat; Log = $_.Log; Provider = $_.Provider; EventId = $_.Id; Level = [string]$_.Ev.LevelDisplayName } })
    Save-Csv $fullRows 'events_all_classified.csv'

    $count = { param($Cat) @($cls | Where-Object { $_.Cat -eq $Cat }).Count }
    $c = & $count 'Resource exhaustion (2004)'
    $sev = 'GREEN'; if ($c -ge 1) { $sev = 'RED' }
    Add-Finding $sev 'Resource-Exhaustion-Detector events (ID 2004)' "$c" 'RED >= 1' 'Windows logged low virtual memory. Read the latest event text below: it names the processes consuming the most commit. Restart or update those.' 'memory'
    if ($c -ge 1) {
        $latest = Get-First ($cls | Where-Object { $_.Cat -eq 'Resource exhaustion (2004)' } | Sort-Object Time -Descending)
        Add-SubHeading 'Most recent 2004 event'
        Add-Pre ('{0}  {1}' -f $latest.Time, [string]$latest.Ev.Message) 3000
    }
    $k = (& $count 'Kernel-Power 41 (unexpected reboot)') + (& $count 'Unexpected shutdown (6008)')
    $sev = 'GREEN'; if ($k -ge 3) { $sev = 'RED' } elseif ($k -ge 1) { $sev = 'AMBER' }
    Add-Finding $sev 'Kernel-Power 41 / unexpected shutdowns' "$k" 'AMBER >= 1, RED >= 3' 'Unexpected power loss/crashes: check power adapter/battery, firmware, and BSOD dumps (C:\Windows\Minidump).' 'stability'
    $b = & $count 'Bugcheck (BSOD)'
    $sev = 'GREEN'; if ($b -ge 1) { $sev = 'RED' }
    Add-Finding $sev 'Bugchecks (BSOD)' "$b" 'RED >= 1' 'Analyse minidumps (WinDbg) or the bugcheck code in the event text.' 'stability'
    $w = & $count 'WHEA hardware error'
    $sev = 'GREEN'; if ($w -ge 1) { $sev = 'RED' }
    Add-Finding $sev 'WHEA-Logger events' "$w" 'RED >= 1' 'Hardware errors reported by the platform (CPU/cache/PCIe/memory). Update firmware; if persistent, escalate to hardware service.' 'stability'
    $d = & $count 'Disk / NTFS'
    $sev = 'GREEN'; if ($d -ge 10) { $sev = 'RED' } elseif ($d -ge 1) { $sev = 'AMBER' }
    Add-Finding $sev 'Disk / NTFS events' "$d" 'AMBER >= 1, RED >= 10' 'See the Disk section; run chkdsk (read-only) and check SSD firmware.' 'disk'
    $a = & $count 'Application crash/hang'
    $sev = 'GREEN'; if ($a -ge 50) { $sev = 'RED' } elseif ($a -ge 20) { $sev = 'AMBER' }
    Add-Finding $sev 'Application crashes and hangs (1000/1002)' "$a" 'AMBER >= 20, RED >= 50' 'Find the repeating faulting module in the summary and update or repair that application.' 'stability'
    $df = (& $count 'Driver failure') + (& $count 'Service/driver start failure') + (& $count 'Display driver reset (TDR)')
    $sev = 'GREEN'; if ($df -ge 20) { $sev = 'RED' } elseif ($df -ge 1) { $sev = 'AMBER' }
    Add-Finding $sev 'Driver / service failures (Kernel-PnP 219/411, SCM 7000/7001/7026, Display 4101)' "$df" 'AMBER >= 1, RED >= 20' 'Identify the failing driver/service from the event text and update or remove it.' 'drivers'
}
#endregion

#region CHECK 14: Stability history (Reliability Monitor, bugchecks, dumps, crashing apps) ----------------------------
# Name/value pairs from an event's XML payload (empty hashtable if it cannot be parsed).
function Get-EventDataMap {
    param($Ev)
    $map = @{}
    try {
        $x = [xml]$Ev.ToXml()
        foreach ($d in @($x.Event.EventData.Data)) {
            if ($null -ne $d -and $d.Name) { $map[[string]$d.Name] = [string]$d.'#text' }
        }
    } catch { }
    return $map
}

function Check-Stability {
    $since = $script:EventStart
    $dmtf = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($since)

    # Reliability Monitor stability index (10 = perfect)
    $idx = @(Invoke-Safe 'Reliability stability index' {
            Get-CimInstance Win32_ReliabilityStabilityMetrics -Filter "TimeGenerated >= '$dmtf'" -ErrorAction Stop |
                Sort-Object TimeGenerated
        })
    $idx = @($idx | Where-Object { $null -ne $_ })
    if ($idx.Count -gt 0) {
        $last = $idx[$idx.Count - 1]
        $val = [double]$last.SystemStabilityIndex
        $min = ($idx | ForEach-Object { [double]$_.SystemStabilityIndex } | Measure-Object -Minimum).Minimum
        $sev = 'GREEN'; if ($val -lt 5) { $sev = 'RED' } elseif ($val -lt 8) { $sev = 'AMBER' }
        Add-Finding $sev 'Reliability Monitor stability index (latest)' ('{0:N1} (lowest in window {1:N1})' -f $val, $min) 'AMBER < 8, RED < 5 (10 is perfect)' 'Open Reliability Monitor (perfmon /rel) and look at the days where the index dropped.' 'stability'
        Save-Csv ($idx | ForEach-Object { [pscustomobject]@{ Time = $_.TimeGenerated; StabilityIndex = $_.SystemStabilityIndex } }) 'stability_index.csv'
    } else {
        Add-Note 'No Reliability Monitor stability data was returned (the Reliability service may be disabled or the PC is new).'
    }

    # Failure records from Reliability Monitor
    $rec = @(Invoke-Safe 'Reliability records' {
            Get-CimInstance Win32_ReliabilityRecords -Filter "TimeGenerated >= '$dmtf'" -ErrorAction Stop
        })
    $rec = @($rec | Where-Object { $null -ne $_ })
    if ($rec.Count -gt 0) {
        $crash = @($rec | Where-Object { $_.SourceName -eq 'Application Error' })
        $hang = @($rec | Where-Object { $_.SourceName -eq 'Application Hanging' })
        $top = @($crash + $hang | Group-Object ProductName | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
                [pscustomobject]@{ Application = $_.Name; Failures = $_.Count; Latest = (($_.Group | Sort-Object TimeGenerated -Descending | Select-Object -First 1).TimeGenerated) }
            })
        if ($top.Count -gt 0) { Add-Table -Data $top -Title 'Applications failing most (Reliability Monitor, last 7 days)' -CsvName 'stability_top_apps.csv' -NoSort }
        $worstN = 0; if ($top.Count -gt 0) { $worstN = [int]$top[0].Failures }
        $sev = 'GREEN'; if ($worstN -ge 10) { $sev = 'RED' } elseif ($worstN -ge 5) { $sev = 'AMBER' }
        $name = 'none'; if ($top.Count -gt 0) { $name = [string]$top[0].Application }
        Add-Finding $sev 'Most repeatedly failing application' ('{0} ({1} failures)' -f $name, $worstN) 'AMBER >= 5, RED >= 10 failures of one application in 7 days' 'Update or repair the named application; check for add-ins or a bad update.' 'stability'
        $bySource = @($rec | Group-Object SourceName | Sort-Object Count -Descending | Select-Object -First 12 | ForEach-Object { [pscustomobject]@{ Source = $_.Name; Records = $_.Count } })
        Add-Table -Data $bySource -Title 'Reliability records by source (last 7 days)' -NoSort
    }

    # Bugchecks (30 days) with decoded codes
    $names = @{
        '0x0000000a' = 'IRQL_NOT_LESS_OR_EQUAL'; '0x0000001e' = 'KMODE_EXCEPTION_NOT_HANDLED'; '0x0000003b' = 'SYSTEM_SERVICE_EXCEPTION'
        '0x00000050' = 'PAGE_FAULT_IN_NONPAGED_AREA'; '0x0000007e' = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED'; '0x0000009f' = 'DRIVER_POWER_STATE_FAILURE'
        '0x000000d1' = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL'; '0x000000ef' = 'CRITICAL_PROCESS_DIED'; '0x00000124' = 'WHEA_UNCORRECTABLE_ERROR'
        '0x0000001a' = 'MEMORY_MANAGEMENT'; '0x00000133' = 'DPC_WATCHDOG_VIOLATION'; '0x00000139' = 'KERNEL_SECURITY_CHECK_FAILURE'
        '0x00000116' = 'VIDEO_TDR_FAILURE'; '0x00000117' = 'VIDEO_TDR_TIMEOUT_DETECTED'; '0x000000c2' = 'BAD_POOL_CALLER'
        '0x000000fc' = 'ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY'; '0x0000007a' = 'KERNEL_DATA_INPAGE_ERROR'; '0x00000019' = 'BAD_POOL_HEADER'
    }
    $bc = @(Get-SafeValue {
            Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = (Get-Date).AddDays(-30) } -ErrorAction Stop
        })
    $bc = @($bc | Where-Object { $null -ne $_ })
    $rows = @($bc | ForEach-Object {
            $code = ''
            if ([string]$_.Message -match '(0x[0-9a-fA-F]{1,8})') { $code = ('0x{0:x8}' -f [Convert]::ToUInt32($Matches[1].Substring(2), 16)) }
            $nm = ''; if ($code -and $names.ContainsKey($code)) { $nm = $names[$code] }
            [pscustomobject]@{ Time = $_.TimeCreated; BugcheckCode = $code; Name = $nm }
        })
    if ($rows.Count -gt 0) { Add-Table -Data $rows -Title 'Bugchecks (blue screens), last 30 days' -CsvName 'stability_bugchecks.csv' -Max 50 -NoSort }
    $n7 = @($rows | Where-Object { $_.Time -ge $since }).Count
    $sev = 'GREEN'; if ($n7 -ge 1) { $sev = 'RED' } elseif ($rows.Count -ge 1) { $sev = 'AMBER' }
    Add-Finding $sev 'Blue screens (bugchecks)' ('{0} in 7 days, {1} in 30 days' -f $n7, $rows.Count) 'AMBER = any in 30 days, RED = any in 7 days' 'Note the bugcheck code above and analyse the dump (WinDbg or WhoCrashed). Repeating codes point at one driver or failing hardware.' 'stability'

    # Dump files
    $dumps = @()
    $md = Join-Path $env:windir 'Minidump'
    $accessible = $true
    try { $dumps = @(Get-ChildItem -LiteralPath $md -Filter *.dmp -ErrorAction Stop) }
    catch {
        if ($_.Exception -is [System.UnauthorizedAccessException]) { $accessible = $false }
        elseif (Test-Path -LiteralPath $md) { $accessible = $false }
    }
    $full = Join-Path $env:windir 'MEMORY.DMP'
    $fullInfo = $null; if (Test-Path -LiteralPath $full) { $fullInfo = Get-Item -LiteralPath $full -ErrorAction SilentlyContinue }
    if (-not $accessible) {
        Add-Note 'C:\Windows\Minidump could not be read (administrator rights are needed). Re-run elevated for a dump file count.'
    } else {
        $recent = @($dumps | Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-30) })
        $sev = 'GREEN'; if ($recent.Count -ge 3) { $sev = 'RED' } elseif ($recent.Count -ge 1) { $sev = 'AMBER' }
        $fv = ''; if ($fullInfo) { $fv = '; MEMORY.DMP from {0}' -f $fullInfo.LastWriteTime.ToString('yyyy-MM-dd') }
        Add-Finding $sev 'Crash dump files (last 30 days)' ('{0} minidump(s){1}' -f $recent.Count, $fv) 'AMBER >= 1, RED >= 3' 'Collect the newest .dmp files from C:\Windows\Minidump for analysis before they are cleaned up.' 'stability'
        if ($recent.Count -gt 0) {
            Add-Table -Data @($recent | Sort-Object LastWriteTime -Descending | Select-Object -First 15 | ForEach-Object { [pscustomobject]@{ File = $_.Name; Modified = $_.LastWriteTime; SizeKB = [math]::Round($_.Length / 1KB) } }) -Title 'Recent minidumps' -NoSort
        }
    }

    # Unexpected shutdowns (Kernel-Power 41), 30 days, to show a trend beyond the 7-day events check
    $kp = @(Get-SafeValue {
            Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = (Get-Date).AddDays(-30) } -ErrorAction Stop
        })
    $kp = @($kp | Where-Object { $null -ne $_ })
    Add-Finding 'INFO' 'Kernel-Power 41 (30 days)' "$($kp.Count)" 'Trend only; graded in the Event logs check' '' 'stability'
}
#endregion

#region CHECK 15: Boot and shutdown performance -----------------------------------------------------------------------
function Check-BootPerformance {
    $os = Get-SafeValue { Get-CimInstance Win32_OperatingSystem }
    $lbt = Get-P $os 'LastBootUpTime'
    if ($lbt) {
        $up = (Get-Date) - $lbt
        Add-KV ([ordered]@{ 'Last boot' = $lbt.ToString('yyyy-MM-dd HH:mm'); 'Uptime' = ('{0}d {1}h {2}m' -f $up.Days, $up.Hours, $up.Minutes) }) -Title 'Current session'
    }

    $log = 'Microsoft-Windows-Diagnostics-Performance/Operational'
    $denied = $false
    $evs = @()
    try { [void](Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction Stop) }
    catch { if ($_.Exception -is [System.UnauthorizedAccessException]) { $denied = $true } }
    if (-not $denied) {
    try {
        $evs = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = 100, 101, 102, 103, 106, 107, 108, 109, 110, 200; StartTime = (Get-Date).AddDays(-30) } -ErrorAction Stop)
    } catch {
        if ($_.Exception -is [System.UnauthorizedAccessException]) { $denied = $true }
        # "No events were found" is the normal healthy result, so it is not an error
    }
    }
    $evs = @($evs | Where-Object { $null -ne $_ })
    if ($denied) {
        Add-Note 'The Diagnostics-Performance log can only be read as administrator. Re-run elevated to get boot and shutdown timings.'
        Add-Finding 'INFO' 'Boot performance data' 'needs administrator' '' 'Re-run elevated.' 'boot'
        return
    }
    if ($evs.Count -eq 0) {
        Add-Note 'Windows logs these events only when a boot or shutdown is slower than normal. None were recorded in the last 30 days.'
        Add-Finding 'GREEN' 'Slow boot / shutdown events (30 days)' 'none recorded' 'AMBER = any slow event' '' 'boot'
        return
    }

    # Boot duration: event 100 (BootTime in ms)
    $boots = @($evs | Where-Object { $_.Id -eq 100 } | Sort-Object TimeCreated -Descending | ForEach-Object {
            $m = Get-EventDataMap $_
            $bt = 0.0; if ($m.ContainsKey('BootTime')) { [void][double]::TryParse($m['BootTime'], [ref]$bt) }
            $main = 0.0; if ($m.ContainsKey('MainPathBootTime')) { [void][double]::TryParse($m['MainPathBootTime'], [ref]$main) }
            $post = 0.0; if ($m.ContainsKey('BootPostBootTime')) { [void][double]::TryParse($m['BootPostBootTime'], [ref]$post) }
            [pscustomobject]@{ Time = $_.TimeCreated; BootSeconds = [math]::Round($bt / 1000, 1); MainPathSeconds = [math]::Round($main / 1000, 1); PostBootSeconds = [math]::Round($post / 1000, 1) }
        })
    if ($boots.Count -gt 0) {
        Add-Table -Data @($boots | Select-Object -First 15) -Title 'Recent boots flagged by Windows (event 100)' -CsvName 'boot_times.csv' -NoSort
        $recent = @($boots | Select-Object -First 5 | ForEach-Object { $_.BootSeconds })
        $avg = ($recent | Measure-Object -Average).Average
        $sev = 'GREEN'; if ($avg -ge 120) { $sev = 'RED' } elseif ($avg -ge 60) { $sev = 'AMBER' }
        Add-Finding $sev 'Boot time (average of latest boots)' ('{0:N0} s over {1} boot(s)' -f $avg, $recent.Count) 'AMBER >= 60 s, RED >= 120 s' 'See the slow items below: disable or update the slowest startup apps, services and drivers.' 'boot'
    } else {
        Add-Finding 'GREEN' 'Boot time degradation events' 'none in 30 days' 'AMBER >= 60 s, RED >= 120 s' '' 'boot'
    }

    # Slow items during boot: apps (101), drivers (102), services (103), background optimisation (106), devices (110)
    $kinds = @{ 101 = 'Startup app'; 102 = 'Driver'; 103 = 'Service'; 106 = 'Background service'; 107 = 'Device'; 108 = 'Device'; 109 = 'Device'; 110 = 'Device' }
    $items = @($evs | Where-Object { $kinds.ContainsKey([int]$_.Id) } | ForEach-Object {
            $m = Get-EventDataMap $_
            $nm = ''
            foreach ($k in 'Name', 'FriendlyName', 'FileName', 'DriverName') { if (-not $nm -and $m.ContainsKey($k) -and $m[$k]) { $nm = $m[$k] } }
            $tt = 0.0; if ($m.ContainsKey('TotalTime')) { [void][double]::TryParse($m['TotalTime'], [ref]$tt) }
            $dg = 0.0; if ($m.ContainsKey('DegradationTime')) { [void][double]::TryParse($m['DegradationTime'], [ref]$dg) }
            [pscustomobject]@{ Type = $kinds[[int]$_.Id]; Item = $nm; TotalSeconds = [math]::Round($tt / 1000, 1); DegradationSeconds = [math]::Round($dg / 1000, 1); Time = $_.TimeCreated }
        })
    $items = @($items | Where-Object { $_.Item })
    if ($items.Count -gt 0) {
        $agg = @($items | Group-Object Type, Item | ForEach-Object {
                $g = @($_.Group)
                [pscustomobject]@{
                    Type = $g[0].Type; Item = $g[0].Item; TimesSlow = $g.Count
                    AvgSeconds = [math]::Round((($g | ForEach-Object { $_.TotalSeconds } | Measure-Object -Average).Average), 1)
                    MaxSeconds = [math]::Round((($g | ForEach-Object { $_.TotalSeconds } | Measure-Object -Maximum).Maximum), 1)
                }
            } | Sort-Object AvgSeconds -Descending)
        Add-Table -Data @($agg | Select-Object -First 25) -Title 'Items that slowed boot (last 30 days, slowest first)' -CsvName 'boot_slow_items.csv' -NoSort
        $worst = $agg[0]
        $sev = 'GREEN'; if ($worst.AvgSeconds -ge 30) { $sev = 'RED' } elseif ($worst.AvgSeconds -ge 10) { $sev = 'AMBER' }
        Add-Finding $sev 'Slowest boot item' ('{0}: {1} ({2:N1} s average, {3} time(s))' -f $worst.Type, $worst.Item, $worst.AvgSeconds, $worst.TimesSlow) 'AMBER >= 10 s, RED >= 30 s average' 'Disable it at startup, update it, or remove it if it is not needed.' 'boot'
    }

    # Shutdown degradation (event 200)
    $sd = @($evs | Where-Object { $_.Id -eq 200 } | ForEach-Object {
            $m = Get-EventDataMap $_
            $t = 0.0; if ($m.ContainsKey('ShutdownTime')) { [void][double]::TryParse($m['ShutdownTime'], [ref]$t) }
            [pscustomobject]@{ Time = $_.TimeCreated; ShutdownSeconds = [math]::Round($t / 1000, 1) }
        })
    if ($sd.Count -gt 0) {
        $mx = ($sd | ForEach-Object { $_.ShutdownSeconds } | Measure-Object -Maximum).Maximum
        $sev = 'AMBER'; if ($mx -ge 60) { $sev = 'RED' }
        Add-Finding $sev 'Slow shutdowns (event 200)' ('{0} in 30 days, longest {1:N0} s' -f $sd.Count, $mx) 'AMBER = any, RED >= 60 s' 'Look for a service or app that holds up shutdown (see the Event logs and Startup checks).' 'boot'
    } else {
        Add-Finding 'GREEN' 'Slow shutdowns (event 200)' 'none in 30 days' 'AMBER = any' '' 'boot'
    }
}
#endregion

#region CHECK 11: System file integrity -------------------------------------------------------------------------------
function Check-Integrity {
    $cbs = "$env:windir\Logs\CBS\CBS.log"
    if (Test-Path -LiteralPath $cbs) {
        $fi = Get-Item -LiteralPath $cbs
        Add-Note ('CBS.log: {0:N1} MB, last written {1}. Only the last 60,000 lines are read.' -f ($fi.Length / 1MB), $fi.LastWriteTime)
        $sr = @(Invoke-Safe 'Read CBS.log' { Get-Content -LiteralPath $cbs -Tail 60000 -ErrorAction Stop | Where-Object { $_ -match '\[SR\]' } })
        $interest = @($sr | Where-Object { $_ -match 'Verify complete|Repairing corrupted|Cannot repair|Beginning Verify and Repair|Verifying \d+ components|found corrupt|repair complete' })
        if ($interest.Count -gt 0) {
            $tail = @($interest | Select-Object -Last 15)
            Add-SubHeading 'Latest SFC ([SR]) entries in CBS.log'
            Add-Pre ($tail -join "`n") 5000
            $cannot = @($interest | Where-Object { $_ -match 'Cannot repair' }).Count
            $repaired = @($interest | Where-Object { $_ -match 'Repairing corrupted|repair complete' }).Count
            $lastDate = ''
            $m = [regex]::Match($interest[$interest.Count - 1], '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')
            if ($m.Success) { $lastDate = $m.Groups[1].Value }
            if ($cannot -gt 0) { Add-Finding 'RED' 'SFC could not repair some files (CBS.log)' "$cannot 'Cannot repair' entries; last SFC entry $lastDate" 'RED if any Cannot repair entries' 'Manually run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow (elevated) in a maintenance window.' 'stability' }
            elseif ($repaired -gt 0) { Add-Finding 'AMBER' 'SFC repaired corrupted files (CBS.log)' "$repaired entries; last SFC entry $lastDate" 'AMBER if repairs recorded' 'Re-run sfc /verifyonly manually to confirm the system is now clean.' 'stability' }
            else { Add-Finding 'GREEN' 'Last SFC run in CBS.log shows no violations' "last SFC entry $lastDate" 'n/a' '' '' }
        } else {
            Add-Finding 'INFO' 'No SFC activity in the CBS.log tail' 'none found' 'Informational' 'Run sfc /verifyonly (or re-run this script with -RunIntegrityChecks).' 'stability'
        }
    } else { Add-Note 'CBS.log not found.' }

    $dism = "$env:windir\Logs\DISM\dism.log"
    if (Test-Path -LiteralPath $dism) {
        $dl = @(Invoke-Safe 'Read dism.log' { Get-Content -LiteralPath $dism -Tail 4000 -ErrorAction Stop | Where-Object { $_ -match 'Cleanup-Image|CheckHealth|ScanHealth|RestoreHealth|corrupt|repairable' } | Select-Object -Last 10 })
        Add-Note ('dism.log last written {0}.' -f (Get-Item -LiteralPath $dism).LastWriteTime)
        if ($dl.Count -gt 0) { Add-Pre ($dl -join "`n") 3000 }
    }
    $cbsState = [ordered]@{
        'RebootPending key'   = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        'PackagesPending key' = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending'
        'SessionsPending key' = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\SessionsPending'
    }
    Add-KV $cbsState 'Component-based servicing state'

    if ($RunIntegrityChecks) {
        if (-not $script:IsAdmin) { Add-Note 'Skipped -RunIntegrityChecks: requires Administrator.' }
        else {
            Write-Status 'Running DISM /CheckHealth ...'
            $dismOut = Invoke-Safe 'DISM /CheckHealth' { & "$env:windir\System32\dism.exe" /Online /Cleanup-Image /CheckHealth }
            $dt = (@($dismOut) -join "`n")
            Set-Content -LiteralPath (Join-Path $script:OutDir 'dism_checkhealth.txt') -Value $dt -Encoding UTF8
            Add-SubHeading 'DISM /CheckHealth output'; Add-Pre $dt 3000
            if ($dt -match 'repairable') { Add-Finding 'RED' 'DISM: component store is repairable (corrupt)' 'CheckHealth reports repairable' 'RED if repairable/corrupt' 'Manually run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow.' 'stability' }
            elseif ($dt -match 'No component store corruption') { Add-Finding 'GREEN' 'DISM CheckHealth' 'No component store corruption detected' 'n/a' '' '' }
            else { Add-Finding 'INFO' 'DISM CheckHealth result unclear' 'see dism_checkhealth.txt' 'Informational' 'Review the raw output.' 'stability' }

            Write-Status 'Running sfc /verifyonly (can take 10+ minutes) ...'
            $sfcOut = Invoke-Safe 'sfc /verifyonly' { & "$env:windir\System32\sfc.exe" /verifyonly }
            $st = ((@($sfcOut) -join "`n") -replace "`0", '')
            Set-Content -LiteralPath (Join-Path $script:OutDir 'sfc_verifyonly.txt') -Value $st -Encoding UTF8
            Add-SubHeading 'sfc /verifyonly output'; Add-Pre $st 3000
            if ($st -match 'did not find any integrity violations') { Add-Finding 'GREEN' 'sfc /verifyonly' 'No integrity violations' 'n/a' '' '' }
            elseif ($st -match 'found integrity violations') { Add-Finding 'RED' 'sfc /verifyonly found integrity violations' 'violations found' 'RED if violations found' 'Manually run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow.' 'stability' }
            else { Add-Finding 'INFO' 'sfc /verifyonly result unclear' 'see sfc_verifyonly.txt' 'Informational' 'Review the raw output.' 'stability' }
        }
    } else { Add-Note 'Active integrity scans were not run. Use -RunIntegrityChecks to run sfc /verifyonly and DISM /CheckHealth (read-only).' 'muted' }
}
#endregion

#region CHECK 12: Network ---------------------------------------------------------------------------------------------
function Check-Network {
    $ad = @(Invoke-Safe 'Get-NetAdapter' { Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } })
    $dns = @(Invoke-Safe 'Get-DnsClientServerAddress' { Get-DnsClientServerAddress -AddressFamily IPv4 })
    $arows = @($ad | ForEach-Object {
            $a = $_
            $servers = @($dns | Where-Object { $_.InterfaceIndex -eq $a.ifIndex } | ForEach-Object { $_.ServerAddresses }) -join ', '
            [pscustomobject]@{ Name = $a.Name; Description = $a.InterfaceDescription; Media = [string](Get-P $a 'PhysicalMediaType'); LinkSpeed = [string]$a.LinkSpeed; DnsServers = $servers }
        })
    Add-Table -Data $arows -Title 'Active physical adapters' -CsvName 'network_adapters.csv' -NoSort
    if ($arows.Count -eq 0) { Add-Note 'No physical adapters are Up.' }
    foreach ($a in $ad) {
        $bps = [double](Get-P $a 'Speed' 0)
        if ($bps -gt 0 -and $bps -lt 100e6) { Add-Finding 'AMBER' "Slow link speed: $($a.Name)" ([string]$a.LinkSpeed) 'AMBER < 100 Mbps' 'Check cabling/dock/Wi-Fi band; slow links stretch OneDrive sync time.' 'network' }
    }
    $profiles = @(Invoke-Safe 'Get-NetConnectionProfile' { Get-NetConnectionProfile })
    if ($profiles.Count -gt 0) { Add-Table -Data @($profiles | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Interface = $_.InterfaceAlias; Category = [string]$_.NetworkCategory; IPv4 = [string]$_.IPv4Connectivity } }) -Title 'Connection profiles' -NoSort }

    # Metered check via WinRT
    $cost = Invoke-Safe 'Metered connection (WinRT)' {
        [void][Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]
        $p = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
        if ($null -eq $p) { 'NoInternetProfile' } else { [string]$p.GetConnectionCost().NetworkCostType }
    }
    if ($cost) {
        $sev = 'GREEN'; if ($cost -eq 'Fixed' -or $cost -eq 'Variable') { $sev = 'AMBER' }
        Add-Finding $sev 'Internet connection cost (metered?)' $cost 'AMBER if Fixed/Variable (metered)' 'OneDrive can pause sync on metered networks. Turn off "Metered connection" for this network if appropriate (Settings > Network).' 'network'
    }

    # Wi-Fi details
    $wl = Invoke-Safe 'netsh wlan show interfaces' { & netsh.exe wlan show interfaces }
    $wlt = (@($wl) -join "`n")
    if ($wlt -match 'SSID') {
        $sig = [regex]::Match($wlt, '(?m)^\s*Signal\s*:\s*(\d+)%'); $rx = [regex]::Match($wlt, '(?m)^\s*Receive rate \(Mbps\)\s*:\s*([\d\.]+)')
        $radio = [regex]::Match($wlt, '(?m)^\s*Radio type\s*:\s*(.+)$')
        Add-KV ([ordered]@{ 'Signal' = $(if ($sig.Success) { $sig.Groups[1].Value + '%' } else { '?' }); 'Receive rate (Mbps)' = $(if ($rx.Success) { $rx.Groups[1].Value } else { '?' }); 'Radio type' = $(if ($radio.Success) { $radio.Groups[1].Value.Trim() } else { '?' }) }) 'Wi-Fi'
        if ($sig.Success) {
            $sv = [int]$sig.Groups[1].Value
            $sev = 'GREEN'; if ($sv -lt 50) { $sev = 'AMBER' }
            Add-Finding $sev 'Wi-Fi signal strength' "$sv%" 'AMBER < 50%' 'Move closer to the access point or use a wired dock; weak Wi-Fi slows OneDrive.' 'network'
        }
    }
    # DNS latency
    $dnsMs = Invoke-Safe 'DNS lookup' {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $null = Resolve-DnsName -Name 'login.microsoftonline.com' -Type A -DnsOnly -ErrorAction Stop
        $sw.Stop(); [math]::Round($sw.Elapsed.TotalMilliseconds, 0)
    }
    if ($null -ne $dnsMs) {
        $sev = 'GREEN'; if ($dnsMs -ge 500) { $sev = 'RED' } elseif ($dnsMs -ge 200) { $sev = 'AMBER' }
        Add-Finding $sev 'DNS lookup time (login.microsoftonline.com)' "$dnsMs ms" 'AMBER >= 200 ms, RED >= 500 ms (first lookup may be uncached)' 'Test alternate DNS servers or check VPN/DNS filter settings.' 'network'
    }
    $vpn = @($arows | Where-Object { $_.Description -match 'VPN|TAP|WireGuard|AnyConnect|GlobalProtect|Zscaler|Cisco' })
    if ($vpn.Count -gt 0) { Add-Finding 'INFO' 'VPN-type adapter active' (($vpn | ForEach-Object { $_.Name }) -join ', ') 'Informational' 'VPN or SSL inspection can slow cloud sync; test with the VPN disconnected.' 'network' }
}
#endregion

#region CHECK 13: Security products and kernel drivers ----------------------------------------------------------------
function Check-Security {
    $heavyRx = 'CrowdStrike|csagent|Sophos|SentinelOne|Sentinel|Symantec|Norton|McAfee|Trellix|Trend Micro|Kaspersky|Carbon Black|Cylance|Zscaler|Cisco|AnyConnect|Umbrella|Forcepoint|Netskope|Citrix|VMware|Acronis|Veeam|Dropbox|Box Drive|NordVPN|OpenVPN|WireGuard|Wintun|TAP-Windows|Elastic|Huntress|Datto|ScreenConnect|Bitdefender|ESET|Malwarebytes|Webroot|Check Point|Absolute|Ivanti|Pulse Secure|Tanium|Rapid7|Splashtop|Digital Guardian|Symantec DLP|Forcepoint DLP|Proofpoint|SafeNet|Lightspeed|Cloudflare|WARP|Palo Alto|GlobalProtect|Fortinet|FortiClient'
    $av = @(Invoke-Safe 'SecurityCenter2 AntiVirusProduct' { Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop })
    $avRows = @($av | ForEach-Object {
            $hex = '{0:X6}' -f [int](Get-P $_ 'productState' 0)
            $rt = $hex.Substring(2, 2); $sg = $hex.Substring(4, 2)
            [pscustomobject]@{ Product = Get-P $_ 'displayName'; RealTime = $(if ($rt -in '10', '11') { 'On' } else { 'Off' }); Signatures = $(if ($sg -eq '00') { 'Up to date' } else { 'Out of date' }); State = $hex; Exe = Get-P $_ 'pathToSignedProductExe' }
        })
    Add-Table -Data $avRows -Title 'Registered antivirus products (Security Center)' -CsvName 'av_products.csv' -NoSort
    $active = @($avRows | Where-Object { $_.RealTime -eq 'On' })
    $sev = 'GREEN'; if ($active.Count -ge 2) { $sev = 'AMBER' }
    Add-Finding $sev 'AV products with real-time protection on' "$($active.Count) ($((@($active | ForEach-Object { $_.Product })) -join ', '))" 'AMBER >= 2 (competing scanners)' 'Only one real-time AV should be primary; check that Defender is passive if a third-party AV is active.' 'scan'
    foreach ($a in $avRows) { if ($a.Signatures -eq 'Out of date') { Add-Finding 'AMBER' "AV signatures out of date: $($a.Product)" 'Out of date' 'AMBER if out of date' 'Update the product manually via its console.' 'scan' } }

    # Minifilters
    if ($script:IsAdmin) {
        $flt = @(Get-FltmcFilters)
        $msRx = '^(FileInfo|luafv|npsvctrig|Wof|WdFilter|storqosflt|FileCrypt|bindflt|UnionFS|CldFlt|applockerfltr|WcnFs|MsSecFlt|wcifs|SgrmAgent|FsDepends|Ntfs|Dfsc|PrjFlt|gpuenergydrv|dam|bfs|vhdmp)$'
        $frows = @($flt | ForEach-Object {
                $tp = $_.Name -notmatch $msRx
                [pscustomobject]@{ Flag = $(if ($tp) { 'INFO' } else { '' }); Name = $_.Name; Instances = $_.Instances; Altitude = $_.Altitude; Kind = $(if ($tp) { 'third-party?' } else { 'Microsoft' }) }
            })
        Add-Table -Data $frows -Title 'File-system minifilters (fltmc filters)' -CsvName 'minifilters.csv' -NoSort
        $tpn = @($frows | Where-Object { $_.Kind -eq 'third-party?' }).Count
        $sev = 'GREEN'; if ($tpn -ge 6) { $sev = 'AMBER' }
        Add-Finding $sev 'Third-party file-system minifilters' "$tpn" 'AMBER >= 6' 'Every filter sits in the I/O path of every file open. Review each with its vendor; consider removing unneeded products.' 'scan'
    } else { Add-Note 'fltmc filters requires Administrator; minifilter enumeration skipped.' }

    # Running non-Microsoft kernel drivers
    $sd = @(Invoke-Safe 'Win32_SystemDriver' { Get-CimInstance Win32_SystemDriver -Filter "State='Running'" })
    $drows = New-Object System.Collections.Generic.List[object]
    foreach ($d in $sd) {
        $path = Resolve-ExePath ([string](Get-P $d 'PathName' ''))
        $co = Get-Company $path
        if ($co -match '^Microsoft') { continue }
        $hit = ("$($d.Name) $($d.DisplayName) $co" -match $heavyRx)
        $drows.Add([pscustomobject]@{ Flag = $(if ($hit) { 'AMBER' } else { '' }); Driver = $d.Name; DisplayName = $d.DisplayName; Company = $co; Path = $path; KnownHeavyHitter = $hit })
    }
    $dl = @($drows | Sort-Object KnownHeavyHitter -Descending)
    Add-Table -Data $dl -Title 'Running non-Microsoft kernel drivers (AMBER = vendor commonly associated with performance impact)' -CsvName 'kernel_drivers_nonms.csv' -Max 120
    $hits = @($dl | Where-Object { $_.KnownHeavyHitter })
    $sev = 'GREEN'; if ($hits.Count -gt 0) { $sev = 'INFO' }
    Add-Finding $sev 'Kernel drivers from security/VPN/DLP/sync vendors' "$($hits.Count): $((@($hits | ForEach-Object { $_.Driver } | Select-Object -First 8)) -join ', ')" 'Informational (vendor list heuristic)' 'For each listed product confirm the version is current and check vendor advisories for known performance issues; test by temporarily stopping their scanning per vendor guidance (change control).' 'scan'

    # Installed software matching heavy hitters
    $unKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $sw = @(Invoke-Safe 'Uninstall registry' { Get-ItemProperty $unKeys -ErrorAction SilentlyContinue | Where-Object { (Get-P $_ 'DisplayName') -and ((Get-P $_ 'DisplayName') -match $heavyRx) } |
                ForEach-Object { [pscustomobject]@{ Software = $_.DisplayName; Version = (Get-P $_ 'DisplayVersion'); Publisher = (Get-P $_ 'Publisher') } } })
    Add-Table -Data $sw -Title 'Installed software matching the security/VPN/backup/sync vendor list' -CsvName 'software_of_interest.csv'
}
#endregion

#region Report assembly -----------------------------------------------------------------------------------------------
function New-ReportHtml {
    $rank = @{ RED = 4; AMBER = 3; GREEN = 2; INFO = 1 }
    $sorted = @($script:Findings | Sort-Object @{ e = { $rank[$_.Severity] }; Descending = $true }, Area)
    $nRed = @($script:Findings | Where-Object { $_.Severity -eq 'RED' }).Count
    $nAmb = @($script:Findings | Where-Object { $_.Severity -eq 'AMBER' }).Count
    $nGrn = @($script:Findings | Where-Object { $_.Severity -eq 'GREEN' }).Count
    $nInf = @($script:Findings | Where-Object { $_.Severity -eq 'INFO' }).Count

    $causes = @(Get-RankedCauses)

    $sb = New-Object System.Text.StringBuilder
    $title = "$script:AppName report - $script:Computer"
    if ($Label) { $title += " - $Label" }
    $cats = @(Get-CategoryScores)
    $css = @'
:root{--bg:#f6f7f9;--fg:#1c2330;--muted:#667085;--card:#fff;--line:#d9dde3;--red:#c62828;--amber:#e08600;--green:#2e7d32;--info:#1565c0}
@media (prefers-color-scheme:dark){:root{--bg:#12161c;--fg:#e6e9ee;--muted:#98a2b3;--card:#1b2129;--line:#2f3844}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 Segoe UI,Arial,sans-serif}
.wrap{max-width:1250px;margin:0 auto;padding:16px}
h1{margin:0 0 4px;font-size:22px}h2{margin:0;font-size:17px;display:inline}h3{margin:16px 0 6px;font-size:14px}
.meta{color:var(--muted);margin-bottom:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:12px 0}
details.sec{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:10px 0}
details.sec>summary{cursor:pointer;padding:10px 14px;list-style:none;display:flex;gap:10px;align-items:center}
details.sec>summary::-webkit-details-marker{display:none}
details.sec>summary::before{content:"\25B6";font-size:11px;color:var(--muted)}details.sec[open]>summary::before{content:"\25BC"}
.body{padding:0 16px 14px}
.tw{overflow-x:auto}table.grid{border-collapse:collapse;width:100%;margin:4px 0 8px;font-size:13px}
table.grid th{background:var(--bg);text-align:left;padding:5px 8px;border-bottom:2px solid var(--line);white-space:nowrap}
table.sortable th{cursor:pointer}table.sortable th:hover{text-decoration:underline}
table.grid td{padding:4px 8px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:11px;font-weight:700;letter-spacing:.3px}
.badge.red{background:var(--red)}.badge.amber{background:var(--amber)}.badge.green{background:var(--green)}.badge.info{background:var(--info)}
.counts span{margin-right:14px;font-weight:600}.muted,.note{color:var(--muted)}
pre{background:var(--bg);border:1px solid var(--line);padding:8px;overflow:auto;white-space:pre-wrap;font-size:12px}
.err{border-left:4px solid var(--red);background:var(--bg);padding:6px 10px;margin:6px 0;font-size:13px}
button{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:5px;padding:4px 10px;cursor:pointer}
.small{font-size:12px}code{background:var(--bg);padding:1px 4px;border-radius:3px}
.tiles{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0}
.tile{display:flex;flex-direction:column;min-width:150px;padding:8px 12px;border-radius:8px;color:#fff;text-decoration:none}
.tile span{font-size:18px;font-weight:700}.tile small{opacity:.9}
.tile.red{background:var(--red)}.tile.amber{background:var(--amber)}.tile.green{background:var(--green)}.tile.info{background:var(--info)}
h2.cat{display:block;margin:22px 0 4px;font-size:15px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px}
'@
    [void]$sb.Append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>$(Esc $title)</title><style>$css</style></head><body><div class='wrap'>")
    [void]$sb.Append("<h1>$(Esc $title)</h1>")
    $adminText = $(if ($script:IsAdmin) { 'elevated' } else { 'NOT elevated (reduced checks)' })
    [void]$sb.Append("<div class='meta'>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &middot; Label: <b>$(Esc $(if ($Label) { $Label } else { '(none)' }))</b> &middot; $adminText &middot; preset: $(Esc $script:PresetName) &middot; $(@($script:SelectedChecks).Count) checks$(if ($Quick) { ' (quick)' }) &middot; sample $SampleSeconds s &middot; $(Esc "$script:AppName $script:AppVersionText") &middot; read-only, no changes were made</div>")

    # Summary
    [void]$sb.Append("<div class='card'><h2>Summary</h2><p class='counts'><span>$(Get-Badge 'RED') $nRed</span><span>$(Get-Badge 'AMBER') $nAmb</span><span>$(Get-Badge 'GREEN') $nGrn</span><span>$(Get-Badge 'INFO') $nInf</span></p>")
    [void]$sb.Append("<div class='tiles'>")
    foreach ($c in $cats) {
        $tcls = $c.Worst.ToLower(); if (-not $tcls) { $tcls = 'info' }
        [void]$sb.Append("<a class='tile $tcls' href='#cat_$(($c.Name -replace '[^A-Za-z]',''))'><b>$(Esc $c.Name)</b><span>$(if ($c.Worst) { $c.Worst } else { 'n/a' })</span><small>$($c.Red) red / $($c.Amber) amber</small></a>")
    }
    [void]$sb.Append('</div>')
    if (-not $script:IsAdmin) { [void]$sb.Append("<p class='err'>Not running as Administrator: SMART/NVMe counters, minifilter list, Defender exclusions and integrity scans were skipped or limited.</p>") }
    $errSecs = @($script:Sections | Where-Object { $_.Errors.Count -gt 0 })
    if ($errSecs.Count -gt 0) { [void]$sb.Append("<p class='small'>Checks that recorded errors: " + ((@($errSecs | ForEach-Object { "<a href='#$($_.Id)'>$(Esc $_.Title)</a> ($($_.Errors.Count))" })) -join ', ') + '</p>') }
    [void]$sb.Append('<h3>Likely causes, ranked by evidence</h3>')
    if ($causes.Count -eq 0) { [void]$sb.Append("<p class='muted'>No RED/AMBER findings were tied to a cause. If the problem is intermittent, re-run while it is happening (for example -Label WhenSlow) and compare.</p>") }
    else {
        [void]$sb.Append('<ol>')
        foreach ($c in $causes) {
            [void]$sb.Append("<li><b>$(Esc $script:CauseInfo[$c.Cause])</b> <span class='muted'>(evidence score $($c.Score); RED=3, AMBER=1)</span><ul class='small'>")
            foreach ($e in $c.Evidence) { [void]$sb.Append("<li>$(Esc $e)</li>") }
            [void]$sb.Append('</ul></li>')
        }
        [void]$sb.Append('</ol>')
    }
    [void]$sb.Append('<h3>All findings</h3>')
    $frows = @($sorted | Where-Object { $_.Severity -ne 'GREEN' } | ForEach-Object { [pscustomobject]@{ Severity = $_.Severity; Area = $_.Area; Finding = $_.Title; Value = $_.Value; Threshold = $_.Threshold } })
    [void]$sb.Append((New-HtmlTable -Data $frows -Max 500))
    [void]$sb.Append("<details><summary class='small'>Show $nGrn GREEN findings</summary>")
    $grows = @($sorted | Where-Object { $_.Severity -eq 'GREEN' } | ForEach-Object { [pscustomobject]@{ Severity = $_.Severity; Area = $_.Area; Finding = $_.Title; Value = $_.Value; Threshold = $_.Threshold } })
    [void]$sb.Append((New-HtmlTable -Data $grows -Max 500))
    [void]$sb.Append('</details></div>')

    # Table of contents + expand/collapse
    [void]$sb.Append("<div class='card small'><b>Sections:</b> ")
    [void]$sb.Append(((@($script:Sections | ForEach-Object { "<a href='#$($_.Id)'>$(Esc $_.Title)</a>" })) -join ' &middot; '))
    if ($script:Cancelled) { [void]$sb.Append(" &middot; <b>run was cancelled; report is partial</b>") }
    [void]$sb.Append(" &middot; <a href='#next'>Recommended next steps</a> &middot; <a href='#compare'>How to compare</a> &nbsp; <button onclick=""document.querySelectorAll('details.sec').forEach(function(d){d.open=true})"">Expand all</button> <button onclick=""document.querySelectorAll('details.sec').forEach(function(d){d.open=false})"">Collapse all</button></div>")

    # Sections, grouped by category (explicit loops: Sort-Object is not stable in Windows PowerShell 5.1)
    $ordered = New-Object System.Collections.Generic.List[object]
    foreach ($cn in $script:CategoryOrder) { foreach ($s0 in $script:Sections) { if ($s0.Category -eq $cn) { $ordered.Add($s0) } } }
    $lastCat = ''
    foreach ($s in $ordered.ToArray()) {
        if ($s.Category -ne $lastCat) { $lastCat = $s.Category; [void]$sb.Append("<h2 class='cat' id='cat_$(($lastCat -replace '[^A-Za-z]',''))'>$(Esc $lastCat)</h2>") }
        $fs = @($script:Findings | Where-Object { $_.SectionId -eq $s.Id })
        $worst = 'INFO'; $wr = 0
        foreach ($f in $fs) { if ($rank[$f.Severity] -gt $wr) { $wr = $rank[$f.Severity]; $worst = $f.Severity } }
        if ($fs.Count -eq 0) { $worst = '' }
        $open = ''; if ($worst -eq 'RED' -or $worst -eq 'AMBER') { $open = ' open' }
        [void]$sb.Append("<details class='sec' id='$($s.Id)'$open><summary><h2>$(Esc $s.Title)</h2> $(Get-Badge $worst) <span class='muted small'>$($s.Seconds)s</span></summary><div class='body'>")
        foreach ($e in $s.Errors) { [void]$sb.Append("<div class='err'><b>Error:</b> $(Esc $e)</div>") }
        if ($fs.Count -gt 0) {
            [void]$sb.Append('<h3>Judgements (raw value vs threshold)</h3>')
            $jr = @($fs | Sort-Object @{ e = { $rank[$_.Severity] }; Descending = $true } | ForEach-Object { [pscustomobject]@{ Severity = $_.Severity; Finding = $_.Title; Value = $_.Value; Threshold = $_.Threshold } })
            [void]$sb.Append((New-HtmlTable -Data $jr -Max 300))
        }
        [void]$sb.Append($s.Html)
        [void]$sb.Append('</div></details>')
    }

    # Recommended next steps
    [void]$sb.Append("<div class='card' id='next'><h2>Recommended next steps</h2><p class='note'>Manual actions only. This script did not perform any of them.</p>")
    $actions = @($sorted | Where-Object { $_.Severity -ne 'GREEN' -and $_.Action } | ForEach-Object { [pscustomobject]@{ Severity = $_.Severity; Finding = $_.Title; Value = $_.Value; 'Manual action' = $_.Action } })
    [void]$sb.Append((New-HtmlTable -Data $actions -Max 500))
    [void]$sb.Append("<h3>General</h3><ul><li>Let the OneDrive initial sync complete (or pause it) before drawing conclusions; re-test afterwards.</li><li>Restart (not Shut down) and re-run with <code>-Label AfterReboot</code>; run again after the slowdown returns with <code>-Label WhenSlow</code>, then compare.</li><li>Keep drivers and firmware current from the device manufacturer (for Surface, the Surface driver and firmware pack for the model).</li></ul></div>")

    # How to compare
    $cmp = @'
$a = Import-Csv '<folder A>\metrics.csv'; $b = Import-Csv '<folder B>\metrics.csv'
$bh = @{}; $b | ForEach-Object { $bh[$_.Key] = $_.Value }
$a | ForEach-Object { [pscustomobject]@{ Key = $_.Key; A = $_.Value; B = $bh[$_.Key] } } | Where-Object { $_.A -ne $_.B } | Format-Table -Auto -Wrap
'@
    [void]$sb.Append("<div class='card' id='compare'><h2>How to compare</h2><p>Run the script twice with <code>-Label</code>, e.g. <code>-Label AfterReboot</code> right after a restart and <code>-Label WhenSlow</code> once the PC has slowed down. Every run writes <code>metrics.csv</code> (Key, Value) next to <code>report.html</code>. Metrics that grow over uptime (non-paged pool, handle counts, commit charge, OneDrive/Defender/Search working set, uptime) point at a leak; metrics that only differ in clock/thermal values point at throttling. To diff the two runs:</p><pre>$(Esc $cmp)</pre></div>")

    $elapsed = [math]::Round(((Get-Date) - $script:StartTime).TotalMinutes, 1)
    [void]$sb.Append("<p class='muted small'>$(Esc "$script:AppName $script:AppVersionText") &middot; completed in $elapsed min &middot; raw exports are in this folder.</p>")

    $js = @'
document.querySelectorAll('table.sortable th').forEach(function(th){th.addEventListener('click',function(){var t=th.closest('table'),i=Array.prototype.indexOf.call(th.parentNode.children,th),tb=t.tBodies[0],rows=Array.prototype.slice.call(tb.rows),asc=th.dataset.asc!=='1';th.dataset.asc=asc?'1':'0';rows.sort(function(a,b){var x=a.cells[i].innerText.trim(),y=b.cells[i].innerText.trim(),nx=parseFloat(x.replace(/[,%]/g,'')),ny=parseFloat(y.replace(/[,%]/g,''));if(!isNaN(nx)&&!isNaN(ny)){return asc?nx-ny:ny-nx}return asc?x.localeCompare(y):y.localeCompare(x)});rows.forEach(function(r){tb.appendChild(r)})})});
'@
    [void]$sb.Append("</div><script>$js</script></body></html>")
    return $sb.ToString()
}
#endregion

#region Summary data (shared by the HTML report, summary.json and the GUI) --------------------------------------------
function Get-RankedCauses {
    $agg = @{}
    foreach ($f in $script:Findings) {
        if (-not $f.Cause) { continue }
        $w = 0; if ($f.Severity -eq 'RED') { $w = 3 } elseif ($f.Severity -eq 'AMBER') { $w = 1 }
        if ($w -eq 0) { continue }
        if (-not $agg.ContainsKey($f.Cause)) {
            $agg[$f.Cause] = [pscustomobject]@{ Cause = $f.Cause; Description = $script:CauseInfo[$f.Cause]; Score = 0; Evidence = (New-Object System.Collections.Generic.List[string]) }
        }
        $agg[$f.Cause].Score += $w
        $agg[$f.Cause].Evidence.Add(('[{0}] {1}: {2}' -f $f.Severity, $f.Title, $f.Value))
    }
    return @($agg.Values | Sort-Object Score -Descending)
}

function Get-CategoryScores {
    $rank = @{ RED = 4; AMBER = 3; GREEN = 2; INFO = 1 }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($cn in $script:CategoryOrder) {
        $secIds = @($script:Sections | Where-Object { $_.Category -eq $cn } | ForEach-Object { $_.Id })
        if ($secIds.Count -eq 0) { continue }
        $fs = @($script:Findings | Where-Object { $secIds -contains $_.SectionId })
        $worst = ''; $wr = 0
        foreach ($f in $fs) { if ($rank[$f.Severity] -gt $wr) { $wr = $rank[$f.Severity]; $worst = $f.Severity } }
        $out.Add([pscustomobject]@{
                Name = $cn; Worst = $worst
                Red = @($fs | Where-Object { $_.Severity -eq 'RED' }).Count; Amber = @($fs | Where-Object { $_.Severity -eq 'AMBER' }).Count
                Green = @($fs | Where-Object { $_.Severity -eq 'GREEN' }).Count; Info = @($fs | Where-Object { $_.Severity -eq 'INFO' }).Count
            })
    }
    return $out.ToArray()
}

function Write-SummaryJson {
    param([string]$Path, [string]$ReportPath)
    $rank = @{ RED = 4; AMBER = 3; GREEN = 2; INFO = 1 }
    $find = @($script:Findings | Sort-Object @{ e = { $rank[$_.Severity] }; Descending = $true }, Category, Area | ForEach-Object {
            [pscustomobject]@{ Severity = $_.Severity; Category = $_.Category; Area = $_.Area; Finding = $_.Title; Value = $_.Value; Threshold = $_.Threshold; Action = $_.Action; Cause = $_.Cause }
        })
    $obj = [ordered]@{
        Computer = $script:Computer; Label = $Label; Preset = $script:PresetName; Tool = $script:AppName; Version = $script:AppVersion; Build = $script:AppBuild
        Generated = (Get-Date).ToString('s'); Elevated = $script:IsAdmin; Cancelled = $script:Cancelled; Quick = [bool]$Quick
        ReportPath = $ReportPath
        Counts = [ordered]@{
            Red = @($find | Where-Object { $_.Severity -eq 'RED' }).Count; Amber = @($find | Where-Object { $_.Severity -eq 'AMBER' }).Count
            Green = @($find | Where-Object { $_.Severity -eq 'GREEN' }).Count; Info = @($find | Where-Object { $_.Severity -eq 'INFO' }).Count
        }
        Categories = @(Get-CategoryScores)
        Causes = @(Get-RankedCauses | ForEach-Object { [pscustomobject]@{ Description = $_.Description; Score = $_.Score; Evidence = @($_.Evidence) } })
        Findings = $find
        Sections = @($script:Sections | ForEach-Object { [pscustomobject]@{ Id = $_.Id; Title = $_.Title; Category = $_.Category; Seconds = $_.Seconds; Errors = @($_.Errors) } })
    }
    ($obj | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $Path -Encoding UTF8
}
#endregion

#region Tasks ---------------------------------------------------------------------------------------------------------
# UNLIKE the diagnostics, these tasks CHANGE the machine (install an update, uninstall software, change the edition) or write
# a file (Autopilot hardware ID). They need administrator rights and are only run on request: from the GUI "Tasks" tab after a
# confirmation, or from the command line with -RunTask <ids> -ConfirmTasks. Everything is logged to <OutputPath>\TaskLogs.
$script:TaskRegistry = @(
    @{ Id = '25h2'; Order = 1; Group = 'Maintenance'; Function = 'Invoke-Task25H2'; Title = 'Install Windows 11 25H2 update'
        Desc = 'Applies the 25H2 enablement package (wusa). May need a restart to finish.' }
    @{ Id = 'wolf'; Order = 2; Group = 'Maintenance'; Function = 'Invoke-TaskRemoveHPWolf'; Title = 'Remove HP Wolf Security'
        Desc = 'Uninstalls HP Wolf Security, its console, and the HP Security Update Service.' }
    @{ Id = 'hwid'; Order = 3; Group = 'Deployment'; Function = 'Invoke-TaskHwid'; Title = 'Collect Autopilot Hardware ID'
        Desc = 'Reads this PC''s hardware hash and saves it as a CSV, ready for Autopilot registration.' }
    @{ Id = 'dumps'; Order = 5; Group = 'Troubleshooting'; Function = 'Invoke-TaskDumps'; Title = 'Collect crash dump files'
        Desc = 'Copies minidumps (optionally MEMORY.DMP) to a folder, with a zip and the recent bugcheck codes. Dumps can contain sensitive data.' }
    @{ Id = 'pro';  Order = 4; Group = 'Deployment'; Function = 'Invoke-TaskUpgradePro'; Title = 'Upgrade Windows Home to Pro'
        Desc = 'Switches the edition using Microsoft''s generic Pro key. Needs internet access and a restart; the machine still needs a genuine Pro licence to show as activated.' }
)
$script:MsuPath = $MsuPath
if (-not $script:MsuPath -and $PSScriptRoot) { $script:MsuPath = Join-Path $PSScriptRoot 'Files\25H2 installer.msu' }
$script:RestartNeeded = $false
$script:TaskLogger = $null      # GUI sets a scriptblock(text) to receive log lines
$script:TaskPump = $null        # GUI sets a scriptblock that keeps the window responsive during long tasks
$script:TaskLogFile = $null
$script:TaskOptions = @{ Ticket = $Ticket; HwidFolder = $HwidFolder; DumpFolder = $DumpFolder; DumpSource = $DumpSource; IncludeFullDump = [bool]$IncludeFullDump; AskFolder = $null }

function Write-TaskLog {
    param([string]$Message, [ValidateSet('Info', 'Success', 'Warning', 'Error')][string]$Level = 'Info')
    $prefix = switch ($Level) { 'Success' { '[OK]   ' } 'Warning' { '[WARN] ' } 'Error' { '[FAIL] ' } default { '       ' } }
    if ($script:TaskLogger) { & $script:TaskLogger ($prefix + $Message) }
    else {
        $lvl = switch ($Level) { 'Success' { 'OK' } 'Warning' { 'WARN' } 'Error' { 'ERROR' } default { 'INFO' } }
        Write-Status $Message $lvl
    }
    if ($script:TaskLogFile) { try { Add-Content -LiteralPath $script:TaskLogFile -Value ('[{0}] {1}{2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $prefix, $Message) } catch { } }
}

# Wait for a process to exit while keeping the GUI responsive.
function Wait-TaskProcess {
    param([System.Diagnostics.Process]$Process)
    $null = $Process.Handle        # cache the handle so ExitCode is readable after exit
    while (-not $Process.HasExited) {
        Start-Sleep -Milliseconds 200
        if ($script:TaskPump) { & $script:TaskPump }
    }
    return $Process.ExitCode
}

# Windows 11 25H2 is build 26200; anything at or above that already has the 25H2 update (or newer).
$script:Build25H2 = 26200
function Get-WinBuildNumber {
    try { return [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).CurrentBuildNumber } catch { return 0 }
}

function Invoke-Task25H2 {
    $build = Get-WinBuildNumber
    if ($build -ge $script:Build25H2) {
        Write-TaskLog "This PC is already on build $build (25H2 or later); nothing to install." 'Info'
        return
    }
    if (-not $script:MsuPath -or -not (Test-Path -LiteralPath $script:MsuPath)) {
        Write-TaskLog "25H2 update file not found at: $script:MsuPath (use -MsuPath, or put it in a Files folder next to the script)" 'Error'
        return
    }
    Write-TaskLog 'Installing Windows 11 25H2 update...'
    $proc = Start-Process -FilePath 'wusa.exe' -ArgumentList "`"$script:MsuPath`" /quiet /norestart" -PassThru
    $exitCode = Wait-TaskProcess -Process $proc
    switch ($exitCode) {
        0 { Write-TaskLog '25H2 update installed successfully.' 'Success' }
        3010 { Write-TaskLog '25H2 update installed. A restart is needed to finish.' 'Success'; $script:RestartNeeded = $true }
        2359302 { Write-TaskLog '25H2 update is already installed.' 'Info' }
        default { Write-TaskLog "25H2 update failed (exit code $exitCode)." 'Error' }
    }
}

function Invoke-TaskRemoveHPWolf {
    $uninstallRoots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    $targets = @(Get-ItemProperty -Path $uninstallRoots -ErrorAction SilentlyContinue |
            Where-Object { (Get-P $_ 'DisplayName' '') -match 'HP Wolf Security|HP Security Update Service' })
    if ($targets.Count -eq 0) { Write-TaskLog 'HP Wolf Security is not installed.' 'Info'; return }

    foreach ($app in $targets) {
        $name = [string](Get-P $app 'DisplayName' '')
        $uninst = [string](Get-P $app 'UninstallString' '')
        Write-TaskLog "Removing $name..."
        try {
            if ($uninst -match '(\{[0-9A-Fa-f-]{36}\})') {
                $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList "/x $($Matches[1]) /qn /norestart" -PassThru
            } elseif ($uninst) {
                # Not an MSI-based uninstaller: fall back to the vendor's uninstall string as-is (untested against a real HP Wolf install).
                Write-TaskLog "$name does not use MSI, attempting its native uninstaller." 'Warning'
                $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList "/c `"$uninst`" /quiet /norestart" -PassThru
            } else {
                Write-TaskLog "$name has no uninstall string - remove it manually." 'Warning'; continue
            }
            $exitCode = Wait-TaskProcess -Process $proc
            if ($exitCode -in 0, 3010) {
                Write-TaskLog "$name removed." 'Success'
                if ($exitCode -eq 3010) { $script:RestartNeeded = $true }
            } else { Write-TaskLog "$name uninstall returned exit code $exitCode - check manually." 'Warning' }
        } catch { Write-TaskLog "Failed to remove ${name}: $($_.Exception.Message)" 'Error' }
    }
}

function Invoke-TaskHwid {
    Write-TaskLog 'Reading serial number...'
    try { $serial = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop).SerialNumber }
    catch { Write-TaskLog "Failed to read the serial number: $($_.Exception.Message)" 'Error'; return }

    Write-TaskLog 'Reading hardware hash...'
    try {
        $dev = Get-CimInstance -Namespace 'root/cimv2/mdm/dmmap' -ClassName 'MDM_DevDetail_Ext01' -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" -ErrorAction Stop
        $hash = [string](Get-P $dev 'DeviceHardwareData' '')
    } catch {
        Write-TaskLog "Could not read the hardware hash from this PC: $($_.Exception.Message)" 'Error'
        Write-TaskLog "If this keeps happening, fall back to Microsoft's official 'Get-WindowsAutoPilotInfo' script." 'Warning'
        return
    }
    if ([string]::IsNullOrWhiteSpace($hash)) { Write-TaskLog 'Hardware hash came back empty - unable to generate the CSV.' 'Error'; return }

    $folder = [string]$script:TaskOptions.HwidFolder
    if (-not $folder -and $script:TaskOptions.AskFolder) { $folder = [string](& $script:TaskOptions.AskFolder 'Choose where to save the Autopilot HWID CSV') }
    if (-not $folder) { Write-TaskLog 'HWID collection cancelled - no folder chosen.' 'Warning'; return }
    if (-not (Test-Path -LiteralPath $folder)) {
        try { [void](New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop) } catch { Write-TaskLog "Cannot create '$folder': $($_.Exception.Message)" 'Error'; return }
    }
    $tag = ([string]$script:TaskOptions.Ticket).Trim()
    $fileName = if ($tag) { "AutopilotHWID_${serial}_${tag}.csv" } else { "AutopilotHWID_${serial}.csv" }
    $outPath = Join-Path $folder $fileName
    # Same format/encoding as Microsoft's Get-WindowsAutoPilotInfo script
    'Device Serial Number,Windows Product ID,Hardware Hash' | Out-File -FilePath $outPath -Encoding Unicode
    "$serial,,$hash" | Out-File -FilePath $outPath -Encoding Unicode -Append
    Write-TaskLog "Saved to $outPath" 'Success'
}

# Crash dump configuration from the registry (where Windows writes dumps and what kind).
function Get-CrashDumpSettings {
    $cc = Get-SafeValue { Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction Stop }
    $types = @{ 0 = 'None (crash dumps disabled)'; 1 = 'Complete memory dump'; 2 = 'Kernel memory dump'; 3 = 'Small memory dump (minidump)'; 7 = 'Automatic memory dump' }
    $en = [int](Get-P $cc 'CrashDumpEnabled' -1)
    [pscustomobject]@{
        Enabled     = $en
        TypeText    = $(if ($types.ContainsKey($en)) { $types[$en] } else { "Unknown ($en)" })
        AutoReboot  = Get-P $cc 'AutoReboot'
        MinidumpDir = [Environment]::ExpandEnvironmentVariables([string](Get-P $cc 'MinidumpDir' '%SystemRoot%\Minidump'))
        DumpFile    = [Environment]::ExpandEnvironmentVariables([string](Get-P $cc 'DumpFile' '%SystemRoot%\MEMORY.DMP'))
    }
}

# Copies the crash dump files (minidumps, optionally MEMORY.DMP) into <folder>\CrashDumps_<host>_<time>, writes a manifest and a
# dump-info.txt (settings + recent bugcheck codes) and zips the small files. Nothing is deleted or moved. Analysis (WinDbg
# !analyze -v) is a manual follow-up; dumps can contain sensitive data, so handle the output accordingly.
function Invoke-TaskDumps {
    $cs = Get-CrashDumpSettings
    $miniDir = $cs.MinidumpDir; $fullFile = $cs.DumpFile
    $src = [string]$script:TaskOptions.DumpSource
    if ($src) {
        if (Test-Path -LiteralPath (Join-Path $src 'Minidump')) { $miniDir = Join-Path $src 'Minidump'; $fullFile = Join-Path $src 'MEMORY.DMP' }
        else { $miniDir = $src; $fullFile = $null }
        Write-TaskLog "Collecting from the supplied source: $src"
    } else {
        Write-TaskLog ('Crash dump type: {0}; minidump folder: {1}' -f $cs.TypeText, $miniDir)
        if ($cs.Enabled -eq 0) { Write-TaskLog 'Crash dumps are disabled on this PC, so new crashes will not leave a dump.' 'Warning' }
    }

    $mini = @()
    try { $mini = @(Get-ChildItem -LiteralPath $miniDir -Filter '*.dmp' -File -ErrorAction Stop | Sort-Object LastWriteTime) }
    catch { Write-TaskLog "Could not read '$miniDir': $($_.Exception.Message)" 'Info' }
    $full = $null
    if ($fullFile -and [IO.File]::Exists($fullFile)) { $full = Get-Item -LiteralPath $fullFile -ErrorAction SilentlyContinue }
    if ($full) { Write-TaskLog ('Full memory dump present: {0} ({1:N2} GB, {2})' -f $full.FullName, ($full.Length / 1GB), $full.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) }
    $takeFull = ($full -and $script:TaskOptions.IncludeFullDump)
    if ($full -and -not $takeFull) { Write-TaskLog 'The full memory dump was NOT copied (tick "include the full memory dump" to copy it).' 'Info' }
    if ($mini.Count -eq 0 -and -not $takeFull) { Write-TaskLog 'No crash dump files found, so there is nothing to collect.' 'Info'; return }
    Write-TaskLog ('Found {0} minidump file(s).' -f $mini.Count)

    $base = [string]$script:TaskOptions.DumpFolder
    if (-not $base -and $script:TaskOptions.AskFolder) { $base = [string](& $script:TaskOptions.AskFolder 'Choose where to save the crash dump files') }
    if (-not $base) { Write-TaskLog 'Dump collection cancelled - no folder chosen.' 'Warning'; return }
    $name = 'CrashDumps_{0}_{1}' -f $script:Computer, (Get-Date -Format 'yyyyMMdd_HHmmss')
    $dest = Join-Path $base $name
    try { [void](New-Item -ItemType Directory -Path $dest -Force -ErrorAction Stop) } catch { Write-TaskLog "Cannot create '$dest': $($_.Exception.Message)" 'Error'; return }

    $manifest = New-Object System.Collections.Generic.List[object]
    $copied = @()
    foreach ($f in $mini) {
        try { Copy-Item -LiteralPath $f.FullName -Destination $dest -ErrorAction Stop; $ok = $true; $copied += (Join-Path $dest $f.Name) }
        catch { $ok = $false; Write-TaskLog "Could not copy $($f.Name): $($_.Exception.Message)" 'Warning' }
        $manifest.Add([pscustomobject]@{ File = $f.Name; Kind = 'Minidump'; SizeKB = [math]::Round($f.Length / 1KB, 0); LastWrite = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); Copied = $ok })
    }
    if ($takeFull) {
        Write-TaskLog ('Copying the full memory dump ({0:N2} GB); this can take a while...' -f ($full.Length / 1GB))
        $rc = Wait-TaskProcess -Process (Start-Process -FilePath 'robocopy.exe' -ArgumentList ('"{0}" "{1}" "{2}" /R:1 /W:1 /NP /NFL /NDL /NJH /NJS' -f $full.DirectoryName, $dest, $full.Name) -PassThru -WindowStyle Hidden)
        $ok = ($rc -lt 8)
        Write-TaskLog $(if ($ok) { 'Full memory dump copied.' } else { "robocopy failed copying MEMORY.DMP (exit code $rc)." }) $(if ($ok) { 'Success' } else { 'Error' })
        $manifest.Add([pscustomobject]@{ File = $full.Name; Kind = 'Full memory dump'; SizeKB = [math]::Round($full.Length / 1KB, 0); LastWrite = $full.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); Copied = $ok })
    }
    $manifest | Export-Csv -LiteralPath (Join-Path $dest 'manifest.csv') -NoTypeInformation -Encoding UTF8

    # Recent bugcheck events (the stop codes behind the dumps)
    $bug = @()
    try {
        $bug = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = (Get-Date).AddDays(-90) } -MaxEvents 20 -ErrorAction Stop)
    } catch { if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') { Write-TaskLog "Could not read bugcheck events: $($_.Exception.Message)" 'Warning' } }
    $cv = Get-SafeValue { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop }
    $info = New-Object System.Collections.Generic.List[string]
    $info.Add(("Crash dump collection - {0} - {1}" -f $script:Computer, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
    $info.Add(("Collected by {0} {1}" -f $script:AppName, $script:AppVersionText))
    $info.Add(("Windows: build {0}.{1} ({2})" -f (Get-P $cv 'CurrentBuildNumber' '?'), (Get-P $cv 'UBR' '?'), (Get-P $cv 'DisplayVersion' '?')))
    $info.Add(("Crash dump type: {0}; AutoReboot: {1}" -f $cs.TypeText, $cs.AutoReboot))
    $info.Add(("Source: {0}" -f $(if ($src) { $src } else { $miniDir })))
    $info.Add('')
    $info.Add('Files collected:')
    foreach ($m in $manifest) { $info.Add(('  {0}  {1} KB  {2}  copied={3}' -f $m.File, $m.SizeKB, $m.LastWrite, $m.Copied)) }
    $info.Add('')
    $info.Add('Bugcheck events (System log, last 90 days, newest first):')
    if ($bug.Count -eq 0) { $info.Add('  none found') }
    foreach ($e in $bug) {
        $msg = ([string]$e.Message -replace '\s+', ' '); if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) + '...' }
        $info.Add(('  {0}  {1}' -f $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $msg))
    }
    $info.Add('')
    $info.Add('Next steps: open a dump in WinDbg (Microsoft Store) and run "!analyze -v", or send the zip to the vendor. Dumps can contain sensitive data.')
    Set-Content -LiteralPath (Join-Path $dest 'dump-info.txt') -Value $info -Encoding UTF8

    # Zip the small files (minidumps + info); Compress-Archive in Windows PowerShell 5.1 cannot handle very large files.
    $zip = Join-Path $base ($name + '.zip')
    try {
        $items = @($copied) + @((Join-Path $dest 'manifest.csv'), (Join-Path $dest 'dump-info.txt'))
        $total = 0; foreach ($i in $items) { if ([IO.File]::Exists($i)) { $total += ([IO.FileInfo]$i).Length } }
        if ($total -gt 1GB) { Write-TaskLog 'Minidumps are over 1 GB, so no zip was created; use the folder.' 'Warning' }
        else { Compress-Archive -LiteralPath @($items | Where-Object { [IO.File]::Exists($_) }) -DestinationPath $zip -Force -ErrorAction Stop; Write-TaskLog "Zip: $zip" }
    } catch { Write-TaskLog "Could not create the zip: $($_.Exception.Message)" 'Warning' }
    Write-TaskLog "Saved to $dest" 'Success'
    Write-TaskLog 'Note: dumps can contain passwords and other sensitive data from memory. Share them only with people who need them.' 'Info'
}

function Invoke-TaskUpgradePro {
    $productKey = 'VK7JG-NPHTM-C97JM-9MPGT-3V66T'     # Microsoft's generic Pro key: changes edition only, does not activate
    Write-TaskLog 'Switching edition to Windows Pro (needs internet access to verify the key)...'
    $proc = Start-Process -FilePath 'changepk.exe' -ArgumentList "/productkey $productKey" -PassThru
    $exitCode = Wait-TaskProcess -Process $proc
    if ($exitCode -eq 0) {
        Write-TaskLog 'Edition switch started. A restart is needed to finish, and the machine will still need a genuine Pro licence to activate.' 'Success'
        $script:RestartNeeded = $true
    } else { Write-TaskLog "changepk.exe exited with code $exitCode - check the edition manually under Settings > System > About." 'Warning' }
}

# Run the chosen tasks in a fixed order (25H2, Wolf, HWID, Pro). Returns nothing; check $script:RestartNeeded afterwards.
function Invoke-TaskList {
    param([string[]]$Ids)
    $script:RestartNeeded = $false
    try {
        $dir = Join-Path $OutputPath 'TaskLogs'
        [void](New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop)
        $script:TaskLogFile = Join-Path $dir ('Tasks_{0}_{1}.log' -f $script:Computer, (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Add-Content -LiteralPath $script:TaskLogFile -Value ('{0} {1} - tasks: {2} - user: {3}' -f $script:AppName, $script:AppVersionText, ($Ids -join ','), [Environment]::UserName)
    } catch { $script:TaskLogFile = $null }
    foreach ($t in @($script:TaskRegistry | Sort-Object { $_.Order })) {
        if ($Ids -notcontains $t.Id) { continue }
        Write-TaskLog ('--- {0} ---' -f $t.Title)
        try { & $t.Function } catch { Write-TaskLog ('{0} failed: {1}' -f $t.Title, $_.Exception.Message) 'Error' }
    }
    Write-TaskLog 'Done.'
    if ($script:TaskLogFile) { Write-TaskLog "Log: $script:TaskLogFile" }
}

function Invoke-TaskCli {
    $ids = @($RunTask | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
    $known = @($script:TaskRegistry | ForEach-Object { $_.Id })
    foreach ($i in $ids) { if ($known -notcontains $i) { Write-Status "Unknown task '$i'. Valid: $($known -join ', ')" 'ERROR'; exit 1 } }
    if (-not $script:IsAdmin) { Write-Status 'Tasks need administrator rights. Re-run from an elevated prompt.' 'ERROR'; exit 1 }
    Write-Status ('Tasks selected: ' + ((@($script:TaskRegistry | Where-Object { $ids -contains $_.Id } | Sort-Object { $_.Order } | ForEach-Object { $_.Title })) -join '; '))
    if (-not $ConfirmTasks) {
        Write-Status 'These tasks CHANGE this PC. Nothing was run. Add -ConfirmTasks to run them.' 'WARN'
        exit 2
    }
    if (-not $script:TaskOptions.HwidFolder) { $script:TaskOptions.HwidFolder = Join-Path $OutputPath 'HWID' }
    if (-not $script:TaskOptions.DumpFolder) { $script:TaskOptions.DumpFolder = Join-Path $OutputPath 'Dumps' }
    Invoke-TaskList -Ids $ids
    if ($script:RestartNeeded) { Write-Status 'A restart is needed to finish applying changes (not performed automatically).' 'WARN' }
}
#endregion

#region GUI -----------------------------------------------------------------------------------------------------------
# The GUI never runs checks itself. It starts this same script as a child process in -NoGui mode (optionally elevated via
# UAC), follows its progress through a status file, and cancels it by creating <StatusFile>.cancel. The window therefore
# never freezes and elevation does not require relaunching the GUI.
function Start-DiagnosticGui {
    if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        Start-Process powershell.exe -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -STA -File "{0}" -Gui' -f $PSCommandPath)
        return
    }
    if (-not $PSCommandPath) { Write-Warning 'The GUI must be started from a saved .ps1 file (it launches this file to run the checks).'; return }
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

    # Hide the console window when this process owns it (double-click / right-click Run), but not an interactive shell.
    try {
        if (-not ('DiagWin32' -as [type])) {
            Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class DiagWin32 {
  [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
  [DllImport("kernel32.dll")] public static extern uint GetConsoleProcessList(uint[] list, uint count);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
}
'@
        }
        $pl = New-Object 'uint32[]' 4
        if ([DiagWin32]::GetConsoleProcessList($pl, 4) -le 1) { [void][DiagWin32]::ShowWindow([DiagWin32]::GetConsoleWindow(), 0) }
    } catch { }

    if (-not ('DiagCheckItem' -as [type])) {
        Add-Type -TypeDefinition @'
using System.ComponentModel;
public class DiagCheckItem : INotifyPropertyChanged {
  public event PropertyChangedEventHandler PropertyChanged;
  void N(string p) { if (PropertyChanged != null) PropertyChanged(this, new PropertyChangedEventArgs(p)); }
  bool _c; public bool IsChecked { get { return _c; } set { _c = value; N("IsChecked"); } }
  public string Id { get; set; } public string Title { get; set; } public string Category { get; set; }
  public int Est { get; set; } public string EstText { get; set; } public string Admin { get; set; }
  string _s = "Pending"; public string Status { get { return _s; } set { _s = value; N("Status"); } }
  string _t = ""; public string Time { get { return _t; } set { _t = value; N("Time"); } }
  string _r = ""; public string Result { get { return _r; } set { _r = value; N("Result"); } }
}
'@
    }

    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Rob's Toolkit" Width="1120" Height="760" MinWidth="940" MinHeight="620"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="13" Background="#F4F6F9">
  <Window.Resources>
    <Style x:Key="Btn" TargetType="Button">
      <Setter Property="Padding" Value="14,6"/><Setter Property="Margin" Value="0,0,8,0"/>
      <Setter Property="Background" Value="White"/><Setter Property="BorderBrush" Value="#C5CBD6"/>
    </Style>
    <Style x:Key="BtnPrimary" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Background" Value="#1F6FEB"/><Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderBrush" Value="#1F6FEB"/><Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="NavBtn" TargetType="Button">
      <Setter Property="Foreground" Value="White"/><Setter Property="Background" Value="Transparent"/>
      <Setter Property="Margin" Value="6,0,0,0"/><Setter Property="Cursor" Value="Hand"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" CornerRadius="4" Padding="16,7">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Lbl" TargetType="TextBlock">
      <Setter Property="Margin" Value="0,12,0,3"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Foreground" Value="#344054"/>
    </Style>
    <Style x:Key="Hint" TargetType="TextBlock">
      <Setter Property="Margin" Value="22,1,0,0"/><Setter Property="FontSize" Value="11.5"/><Setter Property="Foreground" Value="#667085"/><Setter Property="TextWrapping" Value="Wrap"/>
    </Style>
  </Window.Resources>
  <DockPanel>
    <Border DockPanel.Dock="Top" Background="#1F2A44" Padding="20,12">
      <DockPanel>
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
          <Button x:Name="BtnNavDiag" Content="Diagnostics" Style="{StaticResource NavBtn}"/>
          <Button x:Name="BtnNavTasks" Content="Tasks" Style="{StaticResource NavBtn}"/>
        </StackPanel>
        <TextBlock x:Name="TxtHost" DockPanel.Dock="Right" Foreground="#B8C2D9" VerticalAlignment="Center" Margin="0,0,24,0"/>
        <StackPanel>
          <TextBlock Text="Rob's Toolkit" Foreground="White" FontSize="20" FontWeight="SemiBold"/>
          <TextBlock x:Name="TxtVer" Foreground="#B8C2D9" FontSize="12"/>
        </StackPanel>
      </DockPanel>
    </Border>
    <Border DockPanel.Dock="Bottom" Background="#E7EBF2" Padding="20,5">
      <DockPanel>
        <Button x:Name="BtnReboot" DockPanel.Dock="Right" Content="Restart PC..." Style="{StaticResource Btn}" Margin="10,0,0,0" Padding="14,3"/>
        <Button x:Name="BtnAbortReboot" DockPanel.Dock="Right" Content="Cancel restart" Style="{StaticResource BtnPrimary}" Margin="10,0,0,0" Padding="14,3" Visibility="Collapsed"/>
        <TextBlock x:Name="TxtFoot" Foreground="#475467" FontSize="12" VerticalAlignment="Center"/>
      </DockPanel>
    </Border>
    <Grid Margin="20,14,20,14">

      <!-- SETUP -->
      <Grid x:Name="PnlSetup">
        <Grid.ColumnDefinitions><ColumnDefinition Width="350"/><ColumnDefinition Width="20"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
        <ScrollViewer VerticalScrollBarVisibility="Auto">
          <StackPanel>
            <TextBlock Text="Preset" Style="{StaticResource Lbl}" Margin="0,0,0,3"/>
            <ComboBox x:Name="CmbPreset"/>
            <TextBlock x:Name="TxtPresetDesc" Foreground="#667085" FontSize="12" TextWrapping="Wrap" Margin="0,4,0,0"/>
            <TextBlock Text="Label (optional)" Style="{StaticResource Lbl}"/>
            <TextBox x:Name="TxtLabel" Padding="4" ToolTip="e.g. WhenSlow or AfterReboot. Letters, digits, - and _ only."/>
            <TextBlock Text="Output folder" Style="{StaticResource Lbl}"/>
            <DockPanel>
              <Button x:Name="BtnBrowse" DockPanel.Dock="Right" Content="Browse..." Style="{StaticResource Btn}" Margin="6,0,0,0"/>
              <TextBox x:Name="TxtOut" Padding="4"/>
            </DockPanel>
            <TextBlock Text="Performance sample (seconds)" Style="{StaticResource Lbl}"/>
            <TextBox x:Name="TxtSample" Padding="4" Width="80" HorizontalAlignment="Left" Text="60"/>
            <CheckBox x:Name="ChkQuick" Content="Quick mode" Margin="0,16,0,0"/>
            <TextBlock Style="{StaticResource Hint}" Text="Sampling capped at 15 s, shorter OneDrive count, no Windows Update search, no sfc/DISM."/>
            <CheckBox x:Name="ChkIntegrity" Content="Also run sfc /verifyonly and DISM /CheckHealth" Margin="0,10,0,0"/>
            <TextBlock Style="{StaticResource Hint}" Text="Read-only, but sfc can take 10+ minutes. Needs administrator rights."/>
            <CheckBox x:Name="ChkElevate" Content="Run with administrator rights (UAC prompt)" Margin="0,10,0,0"/>
            <TextBlock x:Name="TxtElev" Style="{StaticResource Hint}"/>
            <Button x:Name="BtnStart" Content="Run diagnostics" Style="{StaticResource BtnPrimary}" Margin="0,20,0,0" HorizontalAlignment="Left" Padding="24,9"/>
          </StackPanel>
        </ScrollViewer>
        <DockPanel Grid.Column="2">
          <DockPanel DockPanel.Dock="Top" Margin="0,0,0,6">
            <StackPanel Orientation="Horizontal" DockPanel.Dock="Right">
              <Button x:Name="BtnAll" Content="Select all" Style="{StaticResource Btn}"/>
              <Button x:Name="BtnNone" Content="Select none" Style="{StaticResource Btn}" Margin="0"/>
            </StackPanel>
            <TextBlock x:Name="TxtSelInfo" VerticalAlignment="Center" FontWeight="SemiBold"/>
          </DockPanel>
          <ListView x:Name="LstChecks">
            <ListView.View>
              <GridView>
                <GridViewColumn Width="40">
                  <GridViewColumn.CellTemplate><DataTemplate><CheckBox IsChecked="{Binding IsChecked, Mode=TwoWay}"/></DataTemplate></GridViewColumn.CellTemplate>
                </GridViewColumn>
                <GridViewColumn Header="Check" Width="290" DisplayMemberBinding="{Binding Title}"/>
                <GridViewColumn Header="Category" Width="160" DisplayMemberBinding="{Binding Category}"/>
                <GridViewColumn Header="Est. time" Width="80" DisplayMemberBinding="{Binding EstText}"/>
                <GridViewColumn Header="Admin" Width="130" DisplayMemberBinding="{Binding Admin}"/>
              </GridView>
            </ListView.View>
          </ListView>
        </DockPanel>
      </Grid>

      <!-- RUN -->
      <Grid x:Name="PnlRun" Visibility="Collapsed">
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
        <StackPanel>
          <TextBlock x:Name="TxtRunTitle" FontSize="16" FontWeight="SemiBold"/>
          <ProgressBar x:Name="PrgRun" Height="16" Margin="0,8,0,4" Minimum="0" Maximum="100"/>
          <TextBlock x:Name="TxtRunStatus" Foreground="#475467"/>
        </StackPanel>
        <Grid Grid.Row="1" Margin="0,12,0,0">
          <Grid.ColumnDefinitions><ColumnDefinition Width="440"/><ColumnDefinition Width="12"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <ListView x:Name="LstRun">
            <ListView.View>
              <GridView>
                <GridViewColumn Header="Check" Width="230" DisplayMemberBinding="{Binding Title}"/>
                <GridViewColumn Header="Status" Width="85" DisplayMemberBinding="{Binding Status}"/>
                <GridViewColumn Header="Result" Width="60" DisplayMemberBinding="{Binding Result}"/>
                <GridViewColumn Header="Time" Width="50" DisplayMemberBinding="{Binding Time}"/>
              </GridView>
            </ListView.View>
          </ListView>
          <TextBox x:Name="TxtLog" Grid.Column="2" IsReadOnly="True" FontFamily="Consolas" FontSize="12"
                   VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" TextWrapping="NoWrap"/>
        </Grid>
        <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,12,0,0">
          <Button x:Name="BtnCancel" Content="Cancel run" Style="{StaticResource Btn}"/>
          <TextBlock x:Name="TxtCancelNote" VerticalAlignment="Center" Foreground="#667085"/>
        </StackPanel>
      </Grid>

      <!-- RESULTS -->
      <Grid x:Name="PnlResults" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <DockPanel Margin="0,0,0,10">
          <StackPanel Orientation="Horizontal" DockPanel.Dock="Right">
            <Button x:Name="BtnOpenReport" Content="Open HTML report" Style="{StaticResource BtnPrimary}"/>
            <Button x:Name="BtnOpenFolder" Content="Open folder" Style="{StaticResource Btn}"/>
            <Button x:Name="BtnCopy" Content="Copy summary" Style="{StaticResource Btn}"/>
            <Button x:Name="BtnNew" Content="New run" Style="{StaticResource Btn}" Margin="0"/>
          </StackPanel>
          <TextBlock x:Name="TxtResTitle" FontSize="16" FontWeight="SemiBold" VerticalAlignment="Center"/>
        </DockPanel>
        <ItemsControl x:Name="IcCats" Grid.Row="1">
          <ItemsControl.ItemsPanel><ItemsPanelTemplate><WrapPanel/></ItemsPanelTemplate></ItemsControl.ItemsPanel>
          <ItemsControl.ItemTemplate>
            <DataTemplate>
              <Border Background="{Binding Color}" CornerRadius="6" Padding="12,8" Margin="0,0,8,8" MinWidth="150">
                <StackPanel>
                  <TextBlock Text="{Binding Name}" Foreground="White" FontWeight="SemiBold"/>
                  <TextBlock Text="{Binding Label}" Foreground="White" FontSize="18" FontWeight="Bold"/>
                  <TextBlock Text="{Binding Detail}" Foreground="White" FontSize="11" Opacity="0.9"/>
                </StackPanel>
              </Border>
            </DataTemplate>
          </ItemsControl.ItemTemplate>
        </ItemsControl>
        <Expander Grid.Row="2" Header="Likely causes, ranked by evidence" IsExpanded="True" Margin="0,0,0,8">
          <TextBox x:Name="TxtCauses" IsReadOnly="True" TextWrapping="Wrap" MaxHeight="150" VerticalScrollBarVisibility="Auto" Background="White" Padding="6"/>
        </Expander>
        <Grid Grid.Row="3">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
          <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
            <TextBlock Text="Show:" VerticalAlignment="Center" Margin="0,0,6,0" FontWeight="SemiBold"/>
            <ComboBox x:Name="CmbSev" Width="190"/>
            <TextBlock x:Name="TxtFindCount" VerticalAlignment="Center" Margin="12,0,0,0" Foreground="#667085"/>
          </StackPanel>
          <DataGrid x:Name="GrdFind" Grid.Row="1" AutoGenerateColumns="False" IsReadOnly="True" HeadersVisibility="Column"
                    GridLinesVisibility="Horizontal" SelectionMode="Single" CanUserAddRows="False" RowBackground="White" AlternatingRowBackground="#F8F9FB">
            <DataGrid.Columns>
              <DataGridTemplateColumn Header="Severity" Width="85">
                <DataGridTemplateColumn.CellTemplate>
                  <DataTemplate>
                    <Border CornerRadius="9" Padding="7,1" HorizontalAlignment="Left" Margin="2">
                      <Border.Style>
                        <Style TargetType="Border">
                          <Setter Property="Background" Value="#1565C0"/>
                          <Style.Triggers>
                            <DataTrigger Binding="{Binding Severity}" Value="RED"><Setter Property="Background" Value="#C62828"/></DataTrigger>
                            <DataTrigger Binding="{Binding Severity}" Value="AMBER"><Setter Property="Background" Value="#E08600"/></DataTrigger>
                            <DataTrigger Binding="{Binding Severity}" Value="GREEN"><Setter Property="Background" Value="#2E7D32"/></DataTrigger>
                          </Style.Triggers>
                        </Style>
                      </Border.Style>
                      <TextBlock Text="{Binding Severity}" Foreground="White" FontWeight="Bold" FontSize="11"/>
                    </Border>
                  </DataTemplate>
                </DataGridTemplateColumn.CellTemplate>
              </DataGridTemplateColumn>
              <DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="150"/>
              <DataGridTextColumn Header="Finding" Binding="{Binding Finding}" Width="*"/>
              <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="300"/>
            </DataGrid.Columns>
          </DataGrid>
          <TextBox x:Name="TxtDetail" Grid.Row="2" IsReadOnly="True" TextWrapping="Wrap" Height="120" Margin="0,8,0,0"
                   VerticalScrollBarVisibility="Auto" Background="White" Padding="6"/>
        </Grid>
      </Grid>

      <!-- TASKS (these change the PC) -->
      <Grid x:Name="PnlTasks" Visibility="Collapsed">
        <Grid.ColumnDefinitions><ColumnDefinition Width="500"/><ColumnDefinition Width="20"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
        <ScrollViewer VerticalScrollBarVisibility="Auto">
          <StackPanel Margin="0,0,10,0">
            <TextBlock x:Name="TxtDevice" FontWeight="SemiBold" Foreground="#344054" TextWrapping="Wrap"/>
            <Border x:Name="BrdTaskAdmin" Background="#FFF4E5" BorderBrush="#E08600" BorderThickness="1" CornerRadius="4" Padding="10" Margin="0,10,0,0">
              <DockPanel>
                <Button x:Name="BtnTaskElevate" DockPanel.Dock="Right" Content="Restart as administrator" Style="{StaticResource Btn}" Margin="10,0,0,0"/>
                <TextBlock Text="Tasks need administrator rights, and they CHANGE this PC (unlike the diagnostics)." TextWrapping="Wrap" VerticalAlignment="Center"/>
              </DockPanel>
            </Border>
            <TextBlock Text="DEPLOYMENT" FontWeight="Bold" FontSize="11" Foreground="#1F6FEB" Margin="0,16,0,8"/>
            <CheckBox x:Name="ChkHWID" Margin="0,0,0,2" Content="Collect Autopilot Hardware ID" FontWeight="SemiBold"/>
            <TextBlock Style="{StaticResource Hint}" Text="Reads this PC's hardware hash and saves it as a CSV, ready for Autopilot registration."/>
            <DockPanel Margin="22,6,0,10">
              <TextBlock Text="Ticket/tag:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#667085"/>
              <TextBox x:Name="TxtTicket" Padding="4"/>
            </DockPanel>
            <CheckBox x:Name="ChkPro" Margin="0,4,0,2" Content="Upgrade Windows Home to Pro" FontWeight="SemiBold"/>
            <TextBlock Style="{StaticResource Hint}" Text="Switches the edition using Microsoft's generic Pro key. Needs internet access and a restart; the machine still needs a genuine Pro licence to show as activated."/>
            <TextBlock Text="MAINTENANCE" FontWeight="Bold" FontSize="11" Foreground="#1F6FEB" Margin="0,20,0,8"/>
            <CheckBox x:Name="Chk25H2" Margin="0,0,0,2" Content="Install Windows 11 25H2 update" FontWeight="SemiBold"/>
            <TextBlock Style="{StaticResource Hint}" Text="Applies the 25H2 enablement package. May need a restart to finish."/>
            <TextBlock x:Name="TxtMsu" Style="{StaticResource Hint}"/>
            <CheckBox x:Name="ChkWolf" Margin="0,12,0,2" Content="Remove HP Wolf Security" FontWeight="SemiBold"/>
            <TextBlock Style="{StaticResource Hint}" Text="Uninstalls HP Wolf Security, its console, and the HP Security Update Service."/>
            <TextBlock Text="TROUBLESHOOTING" FontWeight="Bold" FontSize="11" Foreground="#1F6FEB" Margin="0,20,0,8"/>
            <CheckBox x:Name="ChkDumps" Margin="0,0,0,2" Content="Collect crash dump files (minidumps)" FontWeight="SemiBold"/>
            <TextBlock Style="{StaticResource Hint}" Text="Copies the .dmp files from C:\Windows\Minidump to a folder you choose, with a zip, a file list and the recent bugcheck codes. Nothing is deleted. Dumps can contain sensitive data."/>
            <CheckBox x:Name="ChkFullDump" Margin="22,6,0,0" Content="Also include the full memory dump (MEMORY.DMP, can be several GB)" IsEnabled="{Binding IsChecked, ElementName=ChkDumps}"/>
            <Button x:Name="BtnRunTasks" Content="Run selected tasks" Style="{StaticResource BtnPrimary}" Margin="0,22,0,0" HorizontalAlignment="Left" Padding="24,9"/>
          </StackPanel>
        </ScrollViewer>
        <DockPanel Grid.Column="2">
          <TextBlock DockPanel.Dock="Top" Text="Task log" FontWeight="SemiBold" Margin="0,0,0,6"/>
          <TextBox x:Name="TxtTaskLog" IsReadOnly="True" FontFamily="Consolas" FontSize="12" TextWrapping="Wrap" AcceptsReturn="True" VerticalScrollBarVisibility="Auto"/>
        </DockPanel>
      </Grid>

    </Grid>
  </DockPanel>
</Window>
'@

    $win = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$xaml)))
    $c = @{}
    foreach ($n in 'BtnReboot', 'BtnAbortReboot', 'ChkDumps', 'ChkFullDump', 'BtnNavDiag', 'BtnNavTasks', 'PnlTasks', 'TxtDevice', 'BrdTaskAdmin', 'BtnTaskElevate', 'ChkHWID', 'TxtTicket', 'ChkPro', 'Chk25H2', 'TxtMsu',
        'ChkWolf', 'BtnRunTasks', 'TxtTaskLog', 'TxtHost', 'TxtVer', 'TxtFoot', 'PnlSetup', 'PnlRun', 'PnlResults', 'CmbPreset', 'TxtPresetDesc', 'TxtLabel', 'TxtOut', 'BtnBrowse', 'TxtSample',
        'ChkQuick', 'ChkIntegrity', 'ChkElevate', 'TxtElev', 'BtnStart', 'BtnAll', 'BtnNone', 'TxtSelInfo', 'LstChecks', 'TxtRunTitle', 'PrgRun',
        'TxtRunStatus', 'LstRun', 'TxtLog', 'BtnCancel', 'TxtCancelNote', 'TxtResTitle', 'BtnOpenReport', 'BtnOpenFolder', 'BtnCopy', 'BtnNew',
        'IcCats', 'TxtCauses', 'CmbSev', 'TxtFindCount', 'GrdFind', 'TxtDetail') { $c[$n] = $win.FindName($n) }

    $script:G = @{
        Win = $win; C = $c; Items = @(); StatusFile = ''; Pos = 0; Buf = ''; Proc = $null; OutDir = ''; Running = $false
        Timer = $null; Json = $null; All = @(); Done = $false; Idle = 0; DiagPanel = 'PnlSetup'; TaskBusy = $false
    }
    $presetDesc = @{
        General     = 'Broad health check without the slow OneDrive file count.'
        Performance = 'Everything, including OneDrive: for slow or sluggish PCs.'
        Stability   = 'Crashes, unexpected reboots, hardware errors, drivers and corruption.'
        Network     = 'Connectivity, DNS, Wi-Fi, metering and OneDrive sync.'
        Security    = 'Defender, AV products, filter drivers, updates and integrity.'
        Update      = 'Windows Update state, drivers, servicing and disk space.'
    }

    # ---- helpers (all state lives in $script:G so the event handlers can reach it) ----
    $fmtEst = { param($s) if ($s -ge 90) { '~{0:N0} min' -f ($s / 60) } else { '~{0} s' -f $s } }
    $updateSel = {
        $sel = @($script:G.Items | Where-Object { $_.IsChecked })
        $secs = 0; foreach ($i in $sel) { $secs += $i.Est }
        $script:G.C.TxtSelInfo.Text = '{0} of {1} checks selected ({2})' -f $sel.Count, $script:G.Items.Count, (& $fmtEst $secs)
        $script:G.C.BtnStart.IsEnabled = ($sel.Count -gt 0)
    }
    $applyPreset = {
        $name = [string]$script:G.C.CmbPreset.SelectedItem
        if (-not $name) { return }
        $ids = @($script:PresetMap[$name])
        foreach ($i in $script:G.Items) { $i.IsChecked = ($ids -contains $i.Id) }
        $script:G.C.TxtPresetDesc.Text = $presetDesc[$name]
        & $updateSel
    }
    $showPanel = {
        param($Name)
        $g = $script:G
        foreach ($p in 'PnlSetup', 'PnlRun', 'PnlResults', 'PnlTasks') { $g.C[$p].Visibility = $(if ($p -eq $Name) { 'Visible' } else { 'Collapsed' }) }
        if ($Name -ne 'PnlTasks') { $g.DiagPanel = $Name }
        $isTasks = ($Name -eq 'PnlTasks')
        $bc = New-Object Windows.Media.BrushConverter
        $g.C.BtnNavDiag.Background = $bc.ConvertFromString($(if ($isTasks) { '#00000000' } else { '#3B4A75' }))
        $g.C.BtnNavTasks.Background = $bc.ConvertFromString($(if ($isTasks) { '#3B4A75' } else { '#00000000' }))
        $g.C.TxtVer.Text = '{0}  |  {1}' -f $script:AppVersionText, $(if ($isTasks) { 'Tasks CHANGE this PC' } else { 'Diagnostics are read-only: nothing on this PC is changed' })
    }
    $addLog = {
        param($Text)
        $script:G.C.TxtLog.AppendText($Text + "`r`n"); $script:G.C.TxtLog.ScrollToEnd()
    }
    $sevColor = @{ RED = '#C62828'; AMBER = '#E08600'; GREEN = '#2E7D32'; INFO = '#1565C0' }

    # ---- initialise setup panel ----
    $admin = Test-IsAdmin
    $script:IsAdmin = $admin
    # Header: computer name plus Windows edition, feature version (e.g. 24H2) and build
    $winText = ''
    try {
        $cvk = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $cap = ([string](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption) -replace '^Microsoft\s+', ''
        $dv = [string](Get-P $cvk 'DisplayVersion' (Get-P $cvk 'ReleaseId' ''))
        $winText = ('{0} {1} (build {2}.{3})' -f $cap, $dv, (Get-P $cvk 'CurrentBuildNumber' '?'), (Get-P $cvk 'UBR' '?')).Replace('  ', ' ')
    } catch { }
    $c.TxtHost.Text = $(if ($winText) { '{0}  |  {1}' -f $env:COMPUTERNAME, $winText } else { $env:COMPUTERNAME })
    $c.TxtVer.Text = '{0}  |  Read-only: nothing on this PC is changed' -f $script:AppVersionText
    $win.Title = '{0} {1}' -f $script:AppName, $script:AppVersionText
    $c.TxtFoot.Text = $(if ($admin) { 'Running as administrator: all checks available.' } else { 'Not elevated: the run can request administrator rights via UAC for full results.' })
    $c.TxtOut.Text = $OutputPath
    foreach ($k in $script:PresetMap.Keys) { [void]$c.CmbPreset.Items.Add($k) }
    $items = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    foreach ($ck in $script:CheckRegistry) {
        $it = New-Object DiagCheckItem
        $it.Id = $ck.Id; $it.Title = $ck.Title; $it.Category = $ck.Category; $it.Est = [int]$ck.Est
        $it.EstText = (& $fmtEst ([int]$ck.Est)); $it.Admin = $(if ($ck.Admin) { 'Best with admin' } else { '' })
        $it.add_PropertyChanged({ & $updateSel })
        $items.Add($it)
    }
    $script:G.Items = @($items)
    $c.LstChecks.ItemsSource = $items
    $c.ChkElevate.IsChecked = $true
    if ($admin) { $c.ChkElevate.IsEnabled = $false; $c.TxtElev.Text = 'Already running as administrator.' }
    else { $c.TxtElev.Text = 'Without it, SMART/NVMe counters, minifilters, Defender exclusions and integrity scans are skipped.' }
    $c.CmbPreset.SelectedItem = $Preset
    & $applyPreset
    $c.CmbPreset.Add_SelectionChanged({ & $applyPreset })
    $c.BtnAll.Add_Click({ foreach ($i in $script:G.Items) { $i.IsChecked = $true } })
    $c.BtnNone.Add_Click({ foreach ($i in $script:G.Items) { $i.IsChecked = $false } })
    $c.BtnBrowse.Add_Click({
            $d = New-Object System.Windows.Forms.FolderBrowserDialog
            $d.Description = 'Choose where report folders are created'
            if ($d.ShowDialog() -eq 'OK') { $script:G.C.TxtOut.Text = $d.SelectedPath }
        })

    # ---- run: status file polling ----
    $readStatus = {
        $path = $script:G.StatusFile
        if (-not $path -or -not [IO.File]::Exists($path)) { return @() }
        $text = ''
        $fs = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            [void]$fs.Seek([long]$script:G.Pos, [IO.SeekOrigin]::Begin)
            $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
            $text = $sr.ReadToEnd()
            $script:G.Pos = $fs.Position
        } finally { $fs.Dispose() }
        $parts = @(($script:G.Buf + $text) -split "`n")
        $script:G.Buf = $parts[$parts.Count - 1]
        if ($parts.Count -le 1) { return @() }
        return @($parts[0..($parts.Count - 2)] | Where-Object { $_ })
    }
    $finishRun = {
        $script:G.Done = $true; $script:G.Running = $false
        if ($script:G.Timer) { $script:G.Timer.Stop() }
        $json = Join-Path $script:G.OutDir 'summary.json'
        if ($script:G.OutDir -and [IO.File]::Exists($json)) { & $showResults $json }
        else {
            [void][Windows.MessageBox]::Show('The run finished but no summary was produced. See the log for details.', $script:AppName, 'OK', 'Warning')
            $script:G.C.BtnCancel.IsEnabled = $false
        }
    }
    $handleLine = {
        param($Line)
        $f = $Line -split '\|'
        $g = $script:G; $cc = $g.C
        switch ($f[0]) {
            'OUTDIR' { $g.OutDir = $f[1] }
            'CHECKSTART' {
                $it = $g.Items | Where-Object { $_.Id -eq $f[1] } | Select-Object -First 1
                if ($it) { $it.Status = 'Running' ; $cc.TxtRunStatus.Text = 'Running: {0} ({1} of {2})' -f $it.Title, $f[2], $f[3] }
                $cc.PrgRun.Value = 100 * ([double]$f[2] - 1) / [double]$f[3]
            }
            'CHECKDONE' {
                $it = $g.Items | Where-Object { $_.Id -eq $f[1] } | Select-Object -First 1
                if ($it) {
                    $it.Status = $(if ([int]$f[4] -gt 0) { 'Done (errors)' } else { 'Done' }); $it.Result = $f[3]; $it.Time = $f[2] + 's'
                }
                $done = @($g.Items | Where-Object { $_.IsChecked -and ($_.Status -like 'Done*') }).Count
                $tot = @($g.Items | Where-Object { $_.IsChecked }).Count
                if ($tot -gt 0) { $cc.PrgRun.Value = 100 * $done / $tot }
            }
            'PROG' { $cc.TxtRunStatus.Text = $f[2] }
            'LOG' { & $addLog ('[{0}] {1}' -f $f[1], ($f[2..($f.Count - 1)] -join '|')) }
            'DONE' { & $finishRun }
            'FATAL' { & $addLog ('FATAL: ' + $f[1]); [void][Windows.MessageBox]::Show("The diagnostic stopped with an error:`n`n" + $f[1], $script:AppName, 'OK', 'Error') }
        }
    }
    $tick = {
        if ($script:G.Done) { return }
        foreach ($l in @(& $readStatus)) { & $handleLine $l; if ($script:G.Done) { return } }
        $exited = $false
        try { if ($script:G.Proc -and $script:G.Proc.HasExited) { $exited = $true } } catch { }
        if ($exited) {
            $script:G.Idle++
            if ($script:G.Idle -ge 3 -and -not $script:G.Done) {
                $script:G.Done = $true; $script:G.Running = $false; $script:G.Timer.Stop()
                [void][Windows.MessageBox]::Show('The diagnostic process ended before completing. Check the log for details.', $script:AppName, 'OK', 'Warning')
                $script:G.C.BtnCancel.Content = 'Back'; $script:G.C.BtnCancel.IsEnabled = $true
            }
        }
    }

    # ---- results ----
    $showResults = {
        param($JsonPath)
        $j = Get-Content -LiteralPath $JsonPath -Raw | ConvertFrom-Json
        $script:G.Json = $j; $cc = $script:G.C
        $cnt = $j.Counts
        $cc.TxtResTitle.Text = '{0}: {1} red, {2} amber, {3} green{4}' -f $j.Computer, $cnt.Red, $cnt.Amber, $cnt.Green, $(if ($j.Cancelled) { ' (cancelled: partial)' } else { '' })
        $tiles = @($j.Categories | ForEach-Object {
                $col = '#667085'; if ($_.Worst -and $sevColor.ContainsKey($_.Worst)) { $col = $sevColor[$_.Worst] }
                [pscustomobject]@{ Name = $_.Name; Label = $(if ($_.Worst) { $_.Worst } else { 'n/a' }); Detail = ('{0} red / {1} amber' -f $_.Red, $_.Amber); Color = $col }
            })
        $cc.IcCats.ItemsSource = $tiles
        $sb = New-Object System.Text.StringBuilder
        $n = 0
        foreach ($cz in @($j.Causes)) {
            $n++; [void]$sb.AppendLine(('{0}. {1}  (score {2})' -f $n, $cz.Description, $cz.Score))
            foreach ($e in @($cz.Evidence)) { [void]$sb.AppendLine('      ' + $e) }
        }
        if ($n -eq 0) { [void]$sb.Append('No RED/AMBER findings were tied to a cause.') }
        $cc.TxtCauses.Text = $sb.ToString().TrimEnd()
        $script:G.All = @($j.Findings)
        $cc.CmbSev.Items.Clear()
        foreach ($o in 'Issues (RED + AMBER)', 'All', 'RED', 'AMBER', 'INFO', 'GREEN') { [void]$cc.CmbSev.Items.Add($o) }
        $cc.CmbSev.SelectedIndex = 0
        $cc.TxtDetail.Text = 'Select a finding to see its value, threshold and recommended manual action.'
        & $showPanel 'PnlResults'
    }
    $applyFilter = {
        $sel = [string]$script:G.C.CmbSev.SelectedItem
        $rows = @($script:G.All)
        if ($sel -like 'Issues*') { $rows = @($rows | Where-Object { $_.Severity -eq 'RED' -or $_.Severity -eq 'AMBER' }) }
        elseif ($sel -and $sel -ne 'All') { $rows = @($rows | Where-Object { $_.Severity -eq $sel }) }
        $script:G.C.GrdFind.ItemsSource = $rows
        $script:G.C.TxtFindCount.Text = '{0} findings' -f $rows.Count
    }
    $c.CmbSev.Add_SelectionChanged({ & $applyFilter })
    $c.GrdFind.Add_SelectionChanged({
            $r = $script:G.C.GrdFind.SelectedItem
            if ($r) {
                $script:G.C.TxtDetail.Text = ("{0}  [{1}]`r`nValue: {2}`r`nThreshold: {3}`r`nRecommended manual action: {4}" -f $r.Finding, $r.Severity, $r.Value, $r.Threshold, $(if ($r.Action) { $r.Action } else { '(none)' }))
            }
        })
    $c.BtnOpenReport.Add_Click({ if ($script:G.Json) { Start-Process -FilePath $script:G.Json.ReportPath } })
    $c.BtnOpenFolder.Add_Click({ if ($script:G.OutDir) { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $script:G.OutDir) } })
    $c.BtnNew.Add_Click({ & $showPanel 'PnlSetup' })
    $c.BtnCopy.Add_Click({
            $j = $script:G.Json
            if (-not $j) { return }
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine(('Rob''s Toolkit - {0} - {1}{2}' -f $j.Computer, $j.Generated, $(if ($j.Label) { ' - ' + $j.Label } else { '' })))
            [void]$sb.AppendLine(('Result: {0} red, {1} amber, {2} green. Report: {3}' -f $j.Counts.Red, $j.Counts.Amber, $j.Counts.Green, $j.ReportPath))
            if (@($j.Causes).Count -gt 0) {
                [void]$sb.AppendLine(''); [void]$sb.AppendLine('Likely causes:')
                $n = 0; foreach ($cz in @($j.Causes)) { $n++; [void]$sb.AppendLine(('{0}. {1} (score {2})' -f $n, $cz.Description, $cz.Score)) }
            }
            [void]$sb.AppendLine(''); [void]$sb.AppendLine('Findings needing attention:')
            foreach ($f in @($j.Findings | Where-Object { $_.Severity -eq 'RED' -or $_.Severity -eq 'AMBER' })) {
                [void]$sb.AppendLine(('- [{0}] {1}: {2} = {3}' -f $f.Severity, $f.Category, $f.Finding, $f.Value))
                if ($f.Action) { [void]$sb.AppendLine('    Action: ' + $f.Action) }
            }
            [Windows.Clipboard]::SetText($sb.ToString())
            $script:G.C.TxtFoot.Text = 'Summary copied to the clipboard.'
        })

    # ---- start / cancel ----
    $c.BtnStart.Add_Click({
            $cc = $script:G.C
            $ids = @($script:G.Items | Where-Object { $_.IsChecked } | ForEach-Object { $_.Id })
            if ($ids.Count -eq 0) { return }
            $sample = 0
            if (-not [int]::TryParse($cc.TxtSample.Text.Trim(), [ref]$sample) -or $sample -lt 10 -or $sample -gt 600) {
                [void][Windows.MessageBox]::Show('Sample seconds must be a number between 10 and 600.', $script:AppName, 'OK', 'Warning'); return
            }
            $lbl = $cc.TxtLabel.Text.Trim()
            if ($lbl -and $lbl -notmatch '^[A-Za-z0-9_\-]{1,40}$') {
                [void][Windows.MessageBox]::Show('Label may only contain letters, digits, - and _ (max 40 characters).', $script:AppName, 'OK', 'Warning'); return
            }
            $out = $cc.TxtOut.Text.Trim().TrimEnd('\')
            if (-not $out) { [void][Windows.MessageBox]::Show('Choose an output folder.', $script:AppName, 'OK', 'Warning'); return }
            if ($out -match '^[A-Za-z]:$') { $out += '\.' }

            $dir = Join-Path $env:TEMP ('WinDiag_' + [guid]::NewGuid().ToString('N'))
            [void](New-Item -ItemType Directory -Path $dir -Force)
            $script:G.StatusFile = Join-Path $dir 'status.log'
            [IO.File]::WriteAllText($script:G.StatusFile, '')
            $script:G.Pos = 0; $script:G.Buf = ''; $script:G.OutDir = ''; $script:G.Done = $false; $script:G.Idle = 0; $script:G.Json = $null

            $a = New-Object System.Collections.Generic.List[string]
            $a.AddRange([string[]]@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath), '-NoGui',
                    '-Preset', ([string]$cc.CmbPreset.SelectedItem), '-Include', ('"{0}"' -f ($ids -join ',')),
                    '-OutputPath', ('"{0}"' -f $out), '-SampleSeconds', [string]$sample, '-StatusFile', ('"{0}"' -f $script:G.StatusFile)))
            if ($lbl) { $a.Add('-Label'); $a.Add($lbl) }
            if ($cc.ChkQuick.IsChecked) { $a.Add('-Quick') }
            if ($cc.ChkIntegrity.IsChecked) { $a.Add('-RunIntegrityChecks') }
            $sp = @{ FilePath = 'powershell.exe'; ArgumentList = ($a -join ' '); WindowStyle = 'Hidden'; PassThru = $true }
            if ($cc.ChkElevate.IsChecked -and -not $script:IsAdmin) { $sp['Verb'] = 'RunAs' }
            try { $script:G.Proc = Start-Process @sp }
            catch {
                [void][Windows.MessageBox]::Show("Could not start the diagnostic (was the UAC prompt cancelled?)`n`n" + $_.Exception.Message, $script:AppName, 'OK', 'Warning')
                return
            }
            foreach ($i in $script:G.Items) { $i.Status = $(if ($i.IsChecked) { 'Pending' } else { 'Not selected' }); $i.Result = ''; $i.Time = '' }
            $cc.LstRun.ItemsSource = @($script:G.Items | Where-Object { $_.IsChecked })
            $cc.TxtLog.Clear(); $cc.PrgRun.Value = 0; $cc.BtnCancel.Content = 'Cancel run'; $cc.BtnCancel.IsEnabled = $true; $cc.TxtCancelNote.Text = ''
            $cc.TxtRunTitle.Text = 'Running {0} checks ({1})' -f $ids.Count, [string]$cc.CmbPreset.SelectedItem
            $cc.TxtRunStatus.Text = 'Starting...'
            $script:G.Running = $true
            & $showPanel 'PnlRun'
            if (-not $script:G.Timer) {
                $t = New-Object System.Windows.Threading.DispatcherTimer
                $t.Interval = [TimeSpan]::FromMilliseconds(400)
                $t.Add_Tick({ & $tick })
                $script:G.Timer = $t
            }
            $script:G.Timer.Start()
        })
    $c.BtnCancel.Add_Click({
            if (-not $script:G.Running) { $script:G.C.BtnCancel.Content = 'Cancel run'; & $showPanel 'PnlSetup'; return }
            try { [IO.File]::WriteAllText($script:G.StatusFile + '.cancel', '1') } catch { }
            $script:G.C.BtnCancel.IsEnabled = $false
            $script:G.C.TxtCancelNote.Text = '  Stopping after the current step; a partial report will still be written.'
        })
    $win.Add_Closing({
            if ($script:G.Running) { try { [IO.File]::WriteAllText($script:G.StatusFile + '.cancel', '1') } catch { } }
        })

    # ---- Restart button (footer, every tab) ----
    # Schedules a restart in 15 seconds through shutdown.exe so it can still be cancelled with "Cancel restart".
    $rebootDelay = 15
    $doReboot = {
        $cc = $script:G.C
        try {
            $p = Start-Process -FilePath 'shutdown.exe' -ArgumentList ('/r /t {0} /c "Restart requested from {1}"' -f $rebootDelay, $script:AppName) -PassThru -WindowStyle Hidden -Wait
            if ($p.ExitCode -ne 0) { throw "shutdown.exe returned exit code $($p.ExitCode)" }
        } catch {
            [void][Windows.MessageBox]::Show("Could not schedule the restart.`n`n" + $_.Exception.Message, $script:AppName, 'OK', 'Warning')
            return
        }
        $cc.TxtFoot.Text = "Restarting in $rebootDelay seconds. Save your work, or click Cancel restart."
        $cc.BtnReboot.Visibility = 'Collapsed'; $cc.BtnAbortReboot.Visibility = 'Visible'
    }
    $c.BtnReboot.Add_Click({
            $warn = ''
            if ($script:G.Running) { $warn = "`n`nA diagnostic run is in progress and will be interrupted." }
            if ($script:G.TaskBusy) { $warn = "`n`nTasks are still running; restarting now may leave them unfinished." }
            $ans = [Windows.MessageBox]::Show("Restart this PC now? Unsaved work in other programs will be lost." + $warn, $script:AppName, 'YesNo', 'Warning')
            if ($ans -eq 'Yes') { & $doReboot }
        })
    $c.BtnAbortReboot.Add_Click({
            $cc = $script:G.C
            try { [void](Start-Process -FilePath 'shutdown.exe' -ArgumentList '/a' -PassThru -WindowStyle Hidden -Wait) } catch { }
            $cc.TxtFoot.Text = 'Restart cancelled.'
            $cc.BtnAbortReboot.Visibility = 'Collapsed'; $cc.BtnReboot.Visibility = 'Visible'
        })

    # ---- Tasks tab (changes the PC; needs administrator rights) ----
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $bi = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $model = $(if ($cs.Model -match "^$([regex]::Escape($cs.Manufacturer))") { $cs.Model } else { "$($cs.Manufacturer) $($cs.Model)" })
        $c.TxtDevice.Text = "$model  |  Serial: $($bi.SerialNumber)"
    } catch { $c.TxtDevice.Text = 'Unable to read device model/serial number' }
    $c.BrdTaskAdmin.Visibility = $(if ($admin) { 'Collapsed' } else { 'Visible' })
    $c.BtnRunTasks.IsEnabled = $admin
    $c.TxtMsu.Text = $(if ($script:MsuPath -and (Test-Path -LiteralPath $script:MsuPath)) { 'Update file: ' + $script:MsuPath } else { 'Update file NOT found: ' + $script:MsuPath + ' (use -MsuPath, or put it in a Files folder next to the script)' })

    # Already on 25H2 or later: the update option makes no sense, so untick and disable it.
    $curBuild = Get-WinBuildNumber
    if ($curBuild -ge $script:Build25H2) {
        $c.Chk25H2.IsChecked = $false
        $c.Chk25H2.IsEnabled = $false
        $c.TxtMsu.Text = "Not needed: this PC is already on build $curBuild (25H2 or later)."
    }

    $c.BtnNavDiag.Add_Click({ & $showPanel $script:G.DiagPanel })
    $c.BtnNavTasks.Add_Click({ & $showPanel 'PnlTasks' })
    $c.BtnTaskElevate.Add_Click({
            try {
                Start-Process powershell.exe -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -STA -File "{0}" -Gui -Tab Tasks' -f $PSCommandPath) -Verb RunAs -ErrorAction Stop
                $script:G.Win.Close()
            } catch {
                [void][Windows.MessageBox]::Show("Could not restart as administrator (was the UAC prompt cancelled?)`n`n" + $_.Exception.Message, $script:AppName, 'OK', 'Warning')
            }
        })
    $c.BtnRunTasks.Add_Click({
            $cc = $script:G.C
            $ids = @()
            if ($cc.Chk25H2.IsChecked) { $ids += '25h2' }
            if ($cc.ChkWolf.IsChecked) { $ids += 'wolf' }
            if ($cc.ChkHWID.IsChecked) { $ids += 'hwid' }
            if ($cc.ChkPro.IsChecked) { $ids += 'pro' }
            if ($cc.ChkDumps.IsChecked) { $ids += 'dumps' }
            if ($ids.Count -eq 0) { $cc.TxtTaskLog.AppendText("[WARN] No tasks selected.`r`n"); return }
            $titles = @($script:TaskRegistry | Where-Object { $ids -contains $_.Id } | Sort-Object { $_.Order } | ForEach-Object { '  - ' + $_.Title })
            $ans = [Windows.MessageBox]::Show("These tasks will CHANGE this PC:`n`n" + ($titles -join "`n") + "`n`nContinue?", $script:AppName, 'YesNo', 'Warning')
            if ($ans -ne 'Yes') { return }

            $script:G.TaskBusy = $true
            foreach ($b in 'BtnRunTasks', 'BtnNavDiag', 'BtnNavTasks') { $cc[$b].IsEnabled = $false }
            $cc.TxtTaskLog.Clear()
            $script:TaskOptions.Ticket = $cc.TxtTicket.Text
            $script:TaskOptions.HwidFolder = ''
            $script:TaskOptions.DumpFolder = ''
            $script:TaskOptions.DumpSource = ''
            $script:TaskOptions.IncludeFullDump = [bool]$cc.ChkFullDump.IsChecked
            $script:TaskOptions.AskFolder = {
                param($Description)
                $d = New-Object System.Windows.Forms.FolderBrowserDialog
                $d.Description = $Description
                if ($d.ShowDialog() -eq 'OK') { $d.SelectedPath } else { '' }
            }
            $script:TaskPump = { $script:G.C.TxtTaskLog.Dispatcher.Invoke([action] {}, [System.Windows.Threading.DispatcherPriority]::Background) | Out-Null }
            $script:TaskLogger = { param($t) $l = $script:G.C.TxtTaskLog; $l.AppendText($t + "`r`n"); $l.ScrollToEnd(); & $script:TaskPump }
            try { Invoke-TaskList -Ids $ids }
            finally { $script:TaskLogger = $null; $script:TaskPump = $null; $script:TaskOptions.AskFolder = $null }

            if ($script:RestartNeeded) {
                $r = [Windows.MessageBox]::Show('A restart is needed to finish applying changes. Restart now?', 'Restart required', 'YesNo', 'Question')
                if ($r -eq 'Yes') { & $doReboot }
            }
            foreach ($b in 'BtnRunTasks', 'BtnNavDiag', 'BtnNavTasks') { $cc[$b].IsEnabled = $true }
            if (-not $script:IsAdmin) { $cc.BtnRunTasks.IsEnabled = $false }
            $script:G.TaskBusy = $false
        })

    & $showPanel $(if ($Tab -eq 'Tasks') { 'PnlTasks' } else { 'PnlSetup' })
    [void]$win.ShowDialog()
}
#endregion

#region Main ----------------------------------------------------------------------------------------------------------
if ($Version) {
    '{0} {1}' -f $script:AppName, $script:AppVersionText
    return
}

if ($ListChecks) {
    $script:CheckRegistry | ForEach-Object {
        $id = $_.Id
        [pscustomobject]@{
            Id = $id; Title = $_.Title; Category = $_.Category; NeedsAdmin = $_.Admin; EstSeconds = $_.Est
            Presets = (@($script:PresetMap.Keys | Where-Object { $script:PresetMap[$_] -contains $id }) -join ',')
        }
    } | Format-Table -AutoSize
    Write-Host "`nTasks (these CHANGE the PC; run with -RunTask <ids> -ConfirmTasks, needs administrator):"
    $script:TaskRegistry | Sort-Object { $_.Order } | ForEach-Object { [pscustomobject]@{ Id = $_.Id; Title = $_.Title; Group = $_.Group } } | Format-Table -AutoSize
    return
}

if (@($RunTask).Count -gt 0) {
    $script:IsAdmin = Test-IsAdmin
    Invoke-TaskCli
    return
}

if ($script:UseGui) {
    Start-DiagnosticGui
    return
}

# ---- Command-line / engine mode ----
try {
    $script:IsAdmin = Test-IsAdmin
    if (-not $script:IsAdmin) {
        Write-Warning 'Not running as Administrator. Continuing with reduced checks (SMART/NVMe counters, minifilters, Defender exclusions and integrity scans will be skipped or limited).'
    }
    $script:SelectedChecks = @(Resolve-CheckSelection -Preset $Preset -Include $Include -Exclude $Exclude)
    if ($script:SelectedChecks.Count -eq 0) { throw 'No checks selected. Use -ListChecks to see the available ids.' }
    if (@($Include).Count -gt 0) { $script:PresetName = 'Custom' }

    if ($Quick) {
        $SampleSeconds = [math]::Min($SampleSeconds, 15)
        $FileCountTimeLimitSeconds = [math]::Min($FileCountTimeLimitSeconds, 30)
        $RunIntegrityChecks = $false
        $script:SkipUpdateSearch = $true
    }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $folder = '{0}_{1}' -f $script:Computer, $stamp
    if ($Label) { $folder += "_$Label" }
    $script:OutDir = Join-Path $OutputPath $folder
    try { New-Item -ItemType Directory -Path $script:OutDir -Force -ErrorAction Stop | Out-Null }
    catch { throw "Cannot create output folder '$script:OutDir': $($_.Exception.Message)" }
    Write-Status "Output folder: $script:OutDir" 'OK'
    Send-Status 'OUTDIR' @($script:OutDir)

    $i = 0; $total = $script:SelectedChecks.Count
    foreach ($chk in $script:SelectedChecks) {
        $i++
        if (Test-Cancelled) { Write-Status 'Cancelled: remaining checks skipped.' 'WARN'; break }
        Invoke-Check -Check $chk -Index $i -Total $total
    }
    Write-Progress -Id 1 -Activity $script:AppName -Completed
    $null = Test-Cancelled

    Write-Status 'Building report ...'
    $script:Ctx = [pscustomobject]@{ Id = 'report'; Title = 'Report'; Category = 'System'; Html = (New-Object System.Text.StringBuilder); Errors = (New-Object System.Collections.Generic.List[string]) }
    $html = New-ReportHtml
    $reportPath = Join-Path $script:OutDir 'report.html'
    [System.IO.File]::WriteAllText($reportPath, $html, (New-Object System.Text.UTF8Encoding($true)))
    $script:Metrics | Export-Csv -LiteralPath (Join-Path $script:OutDir 'metrics.csv') -NoTypeInformation -Encoding UTF8
    $script:Findings | Export-Csv -LiteralPath (Join-Path $script:OutDir 'findings.csv') -NoTypeInformation -Encoding UTF8
    Write-SummaryJson -Path (Join-Path $script:OutDir 'summary.json') -ReportPath $reportPath

    $r = @($script:Findings | Where-Object { $_.Severity -eq 'RED' }).Count
    $a = @($script:Findings | Where-Object { $_.Severity -eq 'AMBER' }).Count
    $g = @($script:Findings | Where-Object { $_.Severity -eq 'GREEN' }).Count
    Write-Status ('Done. RED={0} AMBER={1} GREEN={2}' -f $r, $a, $g) 'OK'
    Write-Status "Report: $reportPath" 'OK'
    Send-Status 'DONE' @($reportPath, $script:Cancelled, $r, $a, $g)
} catch {
    Write-Status ('Fatal: ' + $_.Exception.Message) 'ERROR'
    Send-Status 'FATAL' @($_.Exception.Message)
    if (-not $script:StatusFile) { throw }
}
#endregion
