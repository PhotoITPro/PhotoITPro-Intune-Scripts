# Written by Rob Young | PhotoITPro
# Website:    https://photoitpro.co.uk
# Repository: https://github.com/PhotoITPro/PhotoITPro-Intune-Scripts
# Licence:    MIT
#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only "slow PC" diagnostics for Microsoft Surface (Intel) laptops on Windows 10/11.
    Produces a self-contained HTML report plus raw CSV/TXT exports.

.DESCRIPTION
    Collects system, performance, memory-leak, CPU-throttling, disk, OneDrive, Search/Defender,
    startup, driver/firmware/update, event-log, integrity, network and security-product evidence.
    Each finding is graded RED / AMBER / GREEN (or INFO) against a stated threshold, and the raw
    value used is recorded. Output goes to:

        <OutputPath>\<COMPUTERNAME>_<yyyyMMdd_HHmmss>[_<Label>]\report.html (+ CSV/TXT)

    READ-ONLY: the script does not change settings, delete anything, or start/stop/restart
    services. The only files it writes are inside the output folder. With -RunIntegrityChecks it
    additionally runs the verification-only 'sfc /verifyonly' and 'DISM /Online /Cleanup-Image
    /CheckHealth' (neither performs a repair).

    Run elevated for full results. A non-elevated run warns and continues with reduced checks.

.PARAMETER OutputPath
    Root folder for reports. Default: C:\SlowPCReport

.PARAMETER SampleSeconds
    Length of the performance sampling window in seconds (10-600). Default: 60.

.PARAMETER Label
    Optional tag (e.g. AfterReboot, WhenSlow) appended to the report folder name and shown in the
    report. Run once with each label and compare the two metrics.csv files.

.PARAMETER RunIntegrityChecks
    Also run 'sfc /verifyonly' (can take 10-20+ minutes) and 'DISM /Online /Cleanup-Image
    /CheckHealth'. Verification only, no repair. Requires elevation.

.PARAMETER FileCountTimeLimitSeconds
    Total time budget for recursively counting files under the OneDrive roots (10-3600).
    Default: 300. If the budget is exhausted the count is reported as a partial lower bound.

.EXAMPLE
    .\Get-SlowPCReport.ps1 -Label AfterReboot

.EXAMPLE
    .\Get-SlowPCReport.ps1 -Label WhenSlow -SampleSeconds 120

.EXAMPLE
    .\Get-SlowPCReport.ps1 -RunIntegrityChecks -OutputPath D:\Diag

.NOTES
    Usage (elevated Windows PowerShell 5.1):
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Get-SlowPCReport.ps1 -Label WhenSlow
    Built-in cmdlets and Windows tools only; no external modules or downloads.
    Performance counter paths are English. On non-English Windows the script falls back to
    WMI formatted counters (disk latency is then not available).
#>
[CmdletBinding()]
param(
    [string]$OutputPath = 'C:\SlowPCReport',
    [ValidateRange(10, 600)][int]$SampleSeconds = 60,
    [string]$Label = '',
    [switch]$RunIntegrityChecks,
    [ValidateRange(10, 3600)][int]$FileCountTimeLimitSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

#region ------------------------------------------------------------------ Script state
$script:ScriptVersion  = '1.0'
$script:StartTime      = Get-Date
$script:Findings       = New-Object System.Collections.Generic.List[object]
$script:Metrics        = New-Object System.Collections.Generic.List[object]
$script:Sections       = New-Object System.Collections.Generic.List[object]
$script:CurrentSection = $null
$script:Perf           = @{}          # counter key -> stats object (Avg/Min/Max/Last/Samples)
$script:PerfSource     = 'None'
$script:Procs          = @()          # merged process snapshot incl. CPU% over the sample window
$script:OS             = $null
$script:CS             = $null
$script:CPU            = @()
$script:LogicalCPUs    = [int]$env:NUMBER_OF_PROCESSORS
$script:NativeLoaded   = $false
$script:OneDriveRoots  = @()
$script:EventCache     = @{}
$script:CompanyCache   = @{}
$script:CheckIndex     = 0
$script:CheckTotal     = 13
$script:IsAdmin        = $false
$script:OutDir         = ''

# Likely-cause catalogue. Findings reference these keys; RED = 3 points, AMBER = 1 point.
$script:CauseInfo = [ordered]@{
    OneDriveSync   = 'OneDrive sync backlog / very large synced file set'
    MemoryLeak     = 'Resource leak (kernel pool, handles or process memory growing with uptime)'
    CommitPressure = 'Memory pressure (RAM / commit exhaustion, heavy paging)'
    Throttling     = 'CPU throttling (thermal, power policy, firmware or battery limits)'
    CPULoad        = 'Sustained background CPU load'
    DiskIO         = 'Storage latency, health or free-space problems'
    AVScan         = 'Antivirus / Defender real-time scanning load'
    Indexer        = 'Windows Search indexing load'
    StartupLoad    = 'Startup and background application load'
    Drivers        = 'Outdated, faulting or high-DPC drivers / firmware'
    FastStartup    = 'Fast Startup preventing a clean kernel start on shutdown'
    Stability      = 'Hardware / OS stability errors (WHEA, crashes, unexpected shutdowns)'
    Updates        = 'Pending updates / pending reboot'
    Network        = 'Network constraints affecting sync (metered or weak link)'
    Integrity      = 'System file / component store corruption'
    ThirdParty     = 'Third-party security or kernel-mode software overhead'
}

# Well-known pool tags (subset) to help interpret the pool tag table.
$script:PoolTagHints = @{
    'MmSt' = 'Mm section prototype PTEs (file-mapping metadata; grows with many cached/mapped files)'
    'Ntff' = 'NTFS file control blocks (FCB)'
    'NtFs' = 'NTFS general allocations'
    'FMfn' = 'Filter Manager file name cache'
    'FMfc' = 'Filter Manager file context'
    'FMsl' = 'Filter Manager stream list'
    'File' = 'File objects'
    'Toke' = 'Token objects'
    'Proc' = 'Process objects'
    'Thre' = 'Thread objects'
    'Even' = 'Event objects'
    'EtwB' = 'ETW trace buffers'
    'CM31' = 'Registry (configuration manager)'
    'CM25' = 'Registry (configuration manager)'
    'CM16' = 'Registry (configuration manager)'
    'smNp' = 'Store Manager (memory compression)'
    'Irp ' = 'I/O request packets'
    'Mdl ' = 'Memory descriptor lists'
    'AlMs' = 'ALPC messages'
}
#endregion

#region ------------------------------------------------------------------ Generic helpers
function Write-Status {
    param([string]$Message, [string]$Color = 'Gray')
    Write-Host ('[{0:HH:mm:ss}] {1}' -f (Get-Date), $Message) -ForegroundColor $Color
}

# HTML-encode any value.
function HE {
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

# StrictMode-safe property read (returns $Default when the property does not exist).
function Get-PropValue {
    param($InputObject, [string]$Name, $Default = $null)
    if ($null -eq $InputObject) { return $Default }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $Default
    }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $p) { return $p.Value }
    return $Default
}

# Read a single registry value, $null if missing.
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        return $k.GetValue($Name, $null)
    } catch { return $null }
}

# All values under a registry key as rows.
function Get-RegValuesTable {
    param([string]$Path)
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        foreach ($n in $k.GetValueNames()) {
            $out.Add([pscustomobject]@{ Key = $Path; Name = $n; Value = (Format-Value $k.GetValue($n)) })
        }
    } catch { }
    return $out.ToArray()
}

function Format-Value {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) { return ([math]::Round([double]$Value, 2)).ToString() }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [byte[]]) { return (($Value | Select-Object -First 16 | ForEach-Object { '{0:X2}' -f $_ }) -join ' ') }
    if ($Value -is [System.Collections.IEnumerable]) { return ((@($Value) | ForEach-Object { [string]$_ }) -join '; ') }
    return [string]$Value
}

function ConvertTo-MB { param($Bytes) if ($null -eq $Bytes) { return $null }; return [math]::Round([double]$Bytes / 1MB, 1) }

# Avg/Min/Max/Last of a numeric series.
function Get-Stats {
    param($Values)
    $v = @($Values | Where-Object { $null -ne $_ } | ForEach-Object { [double]$_ })
    if ($v.Count -eq 0) { return $null }
    $sum = 0.0; $min = [double]::MaxValue; $max = [double]::MinValue
    foreach ($x in $v) { $sum += $x; if ($x -lt $min) { $min = $x }; if ($x -gt $max) { $max = $x } }
    return [pscustomobject]@{ Avg = $sum / $v.Count; Min = $min; Max = $max; Last = $v[$v.Count - 1]; Samples = $v.Count }
}

function Get-PerfStat {
    param([string]$Key, [string]$Stat = 'Avg')
    $s = $script:Perf[$Key]
    if ($null -eq $s) { return $null }
    return $s.$Stat
}

# Grade a value. Default: higher is worse. -LowerIsWorse flips it.
function Get-Severity {
    param($Value, [double]$Amber, [double]$Red, [switch]$LowerIsWorse)
    if ($null -eq $Value) { return 'INFO' }
    $v = [double]$Value
    if ($LowerIsWorse) {
        if ($v -le $Red) { return 'RED' }; if ($v -le $Amber) { return 'AMBER' }; return 'GREEN'
    }
    if ($v -ge $Red) { return 'RED' }; if ($v -ge $Amber) { return 'AMBER' }; return 'GREEN'
}

# Extract the executable/image path from a command line or service ImagePath.
function Get-ExePathFromCommand {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|lnk|vbs|ps1|dll|sys))(\s|,|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

# Normalise kernel-style image paths (\SystemRoot\..., \??\C:\..., System32\...).
function Resolve-ImagePath {
    param([string]$Path)
    $p = Get-ExePathFromCommand $Path
    if (-not $p) { return $null }
    $p = $p -replace '^\\\?\?\\', ''
    $p = $p -replace '^\\SystemRoot\\', ($env:windir + '\')
    if ($p -match '^(?i)system32\\') { $p = Join-Path $env:windir $p }
    return $p
}

function Get-FileCompany {
    param([string]$Path)
    if (-not $Path) { return $null }
    if ($script:CompanyCache.ContainsKey($Path)) { return $script:CompanyCache[$Path] }
    $co = $null
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) { $co = (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo.CompanyName }
    } catch { }
    $script:CompanyCache[$Path] = $co
    return $co
}

function Get-FileVersion {
    param([string]$Path)
    if (-not $Path) { return $null }
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) { return (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo.FileVersion }
    } catch { }
    return $null
}

# Read the tail of a (possibly locked) text file.
function Read-FileTail {
    param([string]$Path, [long]$MaxBytes = 8MB)
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
    try {
        if ($fs.Length -gt $MaxBytes) { [void]$fs.Seek(-$MaxBytes, [System.IO.SeekOrigin]::End) }
        $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8, $true)
        return $sr.ReadToEnd()
    } finally { $fs.Dispose() }
}

# Get-WinEvent wrapper: returns nothing (not an error) when no events match.
function Get-EventsSafe {
    param([hashtable]$Filter, [int]$Max = 2000)
    try { return @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) }
    catch {
        if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound' -or $_.Exception.Message -match 'No events were found') { return @() }
        throw
    }
}

# Warning/Error/Critical events for the last 7 days, cached per log.
function Get-CachedEvents {
    param([string]$LogName)
    if (-not $script:EventCache.ContainsKey($LogName)) {
        $script:EventCache[$LogName] = @(Get-EventsSafe @{ LogName = $LogName; Level = 1, 2, 3; StartTime = (Get-Date).AddDays(-7) } 20000)
    }
    return $script:EventCache[$LogName]
}

# EventData name/value map from an event record.
function Get-EventDataMap {
    param($EventRecord)
    $h = @{}
    try {
        $x = [xml]$EventRecord.ToXml()
        foreach ($d in @($x.GetElementsByTagName('Data'))) {
            $n = $d.GetAttribute('Name')
            if ($n) { $h[$n] = $d.InnerText }
        }
    } catch { }
    return $h
}

function Get-ShortText {
    param([string]$Text, [int]$Length = 400)
    if (-not $Text) { return '' }
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Length) { return $t.Substring(0, $Length) + '...' }
    return $t
}
#endregion

#region ------------------------------------------------------------------ Report plumbing
function Add-Html { param([string]$Html) if ($null -ne $script:CurrentSection) { [void]$script:CurrentSection.Html.AppendLine($Html) } }
function Add-Heading { param([string]$Text) Add-Html ('<h3>' + (HE $Text) + '</h3>') }
function Add-Note { param([string]$Text, [string]$Class = 'note') Add-Html ('<p class="' + $Class + '">' + (HE $Text) + '</p>') }
function Add-Pre { param([string]$Text) Add-Html ('<pre>' + (HE $Text) + '</pre>') }

function ConvertTo-HtmlTableString {
    param($Rows, [string[]]$Columns, [int]$MaxRows = 300)
    $list = @($Rows | Where-Object { $null -ne $_ })
    if ($list.Count -eq 0) { return '<p class="muted">No data.</p>' }
    if (-not $Columns) { $Columns = @($list[0].PSObject.Properties | ForEach-Object { $_.Name }) }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="tblwrap"><table class="sortable"><thead><tr>')
    foreach ($c in $Columns) { [void]$sb.Append('<th>' + (HE $c) + '</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    $n = 0
    foreach ($r in $list) {
        if ($n -ge $MaxRows) { break }
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) { [void]$sb.Append('<td>' + (HE (Format-Value (Get-PropValue $r $c))) + '</td>') }
        [void]$sb.Append('</tr>')
        $n++
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($list.Count -gt $MaxRows) { [void]$sb.Append('<p class="muted">Showing ' + $MaxRows + ' of ' + $list.Count + ' rows. Full data is in the CSV export.</p>') }
    return $sb.ToString()
}

function Add-Table { param($Rows, [string[]]$Columns, [int]$MaxRows = 300) Add-Html (ConvertTo-HtmlTableString -Rows $Rows -Columns $Columns -MaxRows $MaxRows) }

function Add-KeyValue {
    param([System.Collections.IDictionary]$Data)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table class="kv">')
    foreach ($k in $Data.Keys) { [void]$sb.Append('<tr><th>' + (HE $k) + '</th><td>' + (HE (Format-Value $Data[$k])) + '</td></tr>') }
    [void]$sb.Append('</table>')
    Add-Html $sb.ToString()
}

# Record a graded finding. Area is taken from the current section.
function Add-Finding {
    param(
        [ValidateSet('RED', 'AMBER', 'GREEN', 'INFO')][string]$Severity,
        [string]$Title,
        [string]$Observed = '',
        [string]$Threshold = '',
        [string]$Recommendation = '',
        [string]$Cause = ''
    )
    $area = ''; $sid = ''
    if ($null -ne $script:CurrentSection) { $area = $script:CurrentSection.Title; $sid = $script:CurrentSection.Id }
    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity; Area = $area; Title = $Title; Observed = $Observed
        Threshold = $Threshold; Recommendation = $Recommendation; Cause = $Cause; SectionId = $sid
    })
}

# Numeric metric used for before/after comparison (metrics.csv).
function Add-Metric {
    param([string]$MetricName, $Value, [string]$Unit = '')
    if ($null -eq $Value) { return }
    $area = ''
    if ($null -ne $script:CurrentSection) { $area = $script:CurrentSection.Title }
    $script:Metrics.Add([pscustomobject]@{ Area = $area; Name = $MetricName; Value = $Value; Unit = $Unit })
}

# Write a raw export into the output folder.
function Export-Raw {
    param($Data, [string]$FileName)
    try {
        $rows = @($Data)
        if ($rows.Count -eq 0) { return }
        $path = Join-Path $script:OutDir $FileName
        if ($FileName -like '*.csv') { $rows | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 }
        else { $rows | Out-File -LiteralPath $path -Encoding UTF8 -Width 500 }
        if ($null -ne $script:CurrentSection) { $script:CurrentSection.Files.Add($FileName) }
    } catch { Write-Status "  Could not write $FileName : $($_.Exception.Message)" 'Yellow' }
}

# Run one numbered check; any terminating error is recorded against the section.
function Invoke-Check {
    param([string]$CheckId, [string]$CheckTitle, [scriptblock]$CheckBody)
    $script:CheckIndex++
    $__pct = [int](($script:CheckIndex - 1) / $script:CheckTotal * 100)
    $__status = 'Check {0}/{1}: {2}' -f $script:CheckIndex, $script:CheckTotal, $CheckTitle
    Write-Progress -Activity 'Slow PC report (read-only)' -Status $__status -PercentComplete $__pct
    Write-Status $__status 'Cyan'
    $__section = [pscustomobject]@{
        Id = $CheckId; Number = $script:CheckIndex; Title = $CheckTitle
        Html = (New-Object System.Text.StringBuilder)
        Errors = (New-Object System.Collections.Generic.List[string])
        Files = (New-Object System.Collections.Generic.List[string])
        Seconds = 0
    }
    $script:Sections.Add($__section)
    $script:CurrentSection = $__section
    $__sw = [System.Diagnostics.Stopwatch]::StartNew()
    try { & $CheckBody }
    catch {
        $__msg = 'Check failed: {0} (line {1})' -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber
        $__section.Errors.Add($__msg)
        Write-Status "  $__msg" 'Yellow'
    }
    $__sw.Stop()
    $__section.Seconds = [math]::Round($__sw.Elapsed.TotalSeconds, 1)
}

# Run a sub-step inside a check so one failure does not abort the rest of the check.
function Invoke-Step {
    param([string]$StepName, [scriptblock]$StepBody)
    try { & $StepBody }
    catch {
        $__msg = '{0} failed: {1} (line {2})' -f $StepName, $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber
        if ($null -ne $script:CurrentSection) { $script:CurrentSection.Errors.Add($__msg) }
        Write-Status "  $__msg" 'Yellow'
        Add-Html ('<p class="err">' + (HE $__msg) + '</p>')
    }
}
#endregion

#region ------------------------------------------------------------------ Native helpers (compiled in-box with Add-Type)
# NtQuerySystemInformation(SystemPoolTagInformation) = what poolmon shows; and a fast,
# time-limited, non-hydrating file counter for OneDrive folders. Both are read-only.
$script:NativeSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace SlowPCReport
{
    public class PoolTagEntry
    {
        public string Tag { get; set; }
        public long PagedAllocs { get; set; }
        public long PagedFrees { get; set; }
        public long PagedUsed { get; set; }
        public long NonPagedAllocs { get; set; }
        public long NonPagedFrees { get; set; }
        public long NonPagedUsed { get; set; }
    }

    public class FileCountResult
    {
        public string Root { get; set; }
        public long Files { get; set; }
        public long Directories { get; set; }
        public long Bytes { get; set; }
        public long OnlineOnly { get; set; }
        public long LocallyAvailable { get; set; }
        public long AlwaysKeep { get; set; }
        public long AccessErrors { get; set; }
        public bool TimedOut { get; set; }
        public double ElapsedSeconds { get; set; }
    }

    public static class Native
    {
        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returnLength);

        public static List<PoolTagEntry> GetPoolTags()
        {
            int size = 0x40000;
            for (int attempt = 0; attempt < 8; attempt++)
            {
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    int ret;
                    int status = NtQuerySystemInformation(22, buf, size, out ret);
                    if (status == unchecked((int)0xC0000004)) { size = Math.Max(size * 2, ret + 0x10000); continue; }
                    if (status != 0) throw new InvalidOperationException("NtQuerySystemInformation returned 0x" + status.ToString("X8"));
                    int count = Marshal.ReadInt32(buf);
                    bool x64 = IntPtr.Size == 8;
                    int offset = x64 ? 8 : 4;
                    int entrySize = x64 ? 40 : 28;
                    var list = new List<PoolTagEntry>(count);
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr p = IntPtr.Add(buf, offset + i * entrySize);
                        byte[] tb = new byte[4];
                        Marshal.Copy(p, tb, 0, 4);
                        char[] chars = new char[4];
                        for (int c = 0; c < 4; c++) chars[c] = (tb[c] >= 32 && tb[c] < 127) ? (char)tb[c] : '.';
                        var e = new PoolTagEntry();
                        e.Tag = new string(chars);
                        e.PagedAllocs = (uint)Marshal.ReadInt32(p, 4);
                        e.PagedFrees = (uint)Marshal.ReadInt32(p, 8);
                        if (x64)
                        {
                            e.PagedUsed = Marshal.ReadInt64(p, 16);
                            e.NonPagedAllocs = (uint)Marshal.ReadInt32(p, 24);
                            e.NonPagedFrees = (uint)Marshal.ReadInt32(p, 28);
                            e.NonPagedUsed = Marshal.ReadInt64(p, 32);
                        }
                        else
                        {
                            e.PagedUsed = (uint)Marshal.ReadInt32(p, 12);
                            e.NonPagedAllocs = (uint)Marshal.ReadInt32(p, 16);
                            e.NonPagedFrees = (uint)Marshal.ReadInt32(p, 20);
                            e.NonPagedUsed = (uint)Marshal.ReadInt32(p, 24);
                        }
                        list.Add(e);
                    }
                    return list;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            throw new InvalidOperationException("Pool tag buffer could not be sized.");
        }

        // Counts files using directory enumeration metadata only (never opens files, so
        // online-only OneDrive placeholders are NOT hydrated).
        public static FileCountResult CountFiles(string root, int timeoutSeconds)
        {
            var r = new FileCountResult();
            r.Root = root;
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var stack = new Stack<string>();
            stack.Push(root);
            while (stack.Count > 0)
            {
                if (sw.Elapsed.TotalSeconds > timeoutSeconds) { r.TimedOut = true; break; }
                string dir = stack.Pop();
                try
                {
                    foreach (var fsi in new DirectoryInfo(dir).EnumerateFileSystemInfos())
                    {
                        int attr = (int)fsi.Attributes;
                        if ((attr & 0x10) != 0) { r.Directories++; stack.Push(fsi.FullName); continue; }
                        r.Files++;
                        try { r.Bytes += ((FileInfo)fsi).Length; } catch { }
                        // 0x400000 RECALL_ON_DATA_ACCESS, 0x40000 RECALL_ON_OPEN => online-only placeholder
                        if ((attr & 0x400000) != 0 || (attr & 0x40000) != 0) r.OnlineOnly++; else r.LocallyAvailable++;
                        if ((attr & 0x80000) != 0) r.AlwaysKeep++;   // FILE_ATTRIBUTE_PINNED
                        if ((r.Files & 0x3FFF) == 0 && sw.Elapsed.TotalSeconds > timeoutSeconds) { r.TimedOut = true; break; }
                    }
                }
                catch { r.AccessErrors++; }
            }
            r.ElapsedSeconds = Math.Round(sw.Elapsed.TotalSeconds, 1);
            return r;
        }
    }
}
'@

function Initialize-NativeHelpers {
    try {
        if (-not ('SlowPCReport.Native' -as [type])) { Add-Type -TypeDefinition $script:NativeSource -Language CSharp -ErrorAction Stop }
        $script:NativeLoaded = $true
    } catch {
        $script:NativeLoaded = $false
        Write-Status "Native helpers unavailable ($($_.Exception.Message)). Pool tags skipped; file counting uses slower PowerShell fallback." 'Yellow'
    }
}
#endregion

#region ------------------------------------------------------------------ Process snapshot helpers
function Get-ProcessSnapshot {
    return [pscustomobject]@{ Time = (Get-Date); Procs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop) }
}

# Merge two Win32_Process snapshots into per-process rows with CPU% over the interval.
function Merge-ProcessSnapshots {
    param($Before, $After)
    $lp = [math]::Max(1, $script:LogicalCPUs)
    $map = @{}
    $elapsed = 0
    if ($null -ne $Before) {
        $elapsed = ($After.Time - $Before.Time).TotalSeconds
        foreach ($p in $Before.Procs) { $map['{0}|{1}' -f $p.ProcessId, $p.CreationDate] = ([double]$p.KernelModeTime + [double]$p.UserModeTime) }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($p in $After.Procs) {
        $cpuNow = [double]$p.KernelModeTime + [double]$p.UserModeTime     # 100 ns units
        $pct = $null
        if ($null -ne $Before -and $elapsed -gt 0) {
            $key = '{0}|{1}' -f $p.ProcessId, $p.CreationDate
            $delta = 0.0
            if ($map.ContainsKey($key)) { $delta = $cpuNow - $map[$key] }
            elseif ($p.CreationDate -and $p.CreationDate -gt $Before.Time) { $delta = $cpuNow }
            $pct = [math]::Round(($delta / 1e7) / $elapsed / $lp * 100, 2)
        }
        $out.Add([pscustomobject]@{
            Name         = [string]$p.Name
            PID          = [int]$p.ProcessId
            ParentPID    = [int]$p.ParentProcessId
            CPUPct       = $pct
            CPUTotalSec  = [math]::Round($cpuNow / 1e7, 1)
            WorkingSetMB = ConvertTo-MB $p.WorkingSetSize
            PrivateMB    = ConvertTo-MB $p.PrivatePageCount     # Win32_Process reports private bytes here
            Handles      = [int]$p.HandleCount
            Threads      = [int]$p.ThreadCount
            Started      = $p.CreationDate
            Path         = $p.ExecutablePath
        })
    }
    return $out.ToArray()
}

# Process rows from the performance window, or a static snapshot if that check failed.
function Get-ProcsSafe {
    if (@($script:Procs).Count -eq 0) {
        try { $script:Procs = @(Merge-ProcessSnapshots -Before $null -After (Get-ProcessSnapshot)) } catch { $script:Procs = @() }
    }
    return $script:Procs
}

function Get-IntelGeneration {
    param([string]$CpuName)
    if (-not $CpuName) { return $null }
    if ($CpuName -match 'Core\(TM\) Ultra|Core Ultra') { return 14 }
    $g = [regex]::Match($CpuName, '(\d{1,2})th Gen')
    if ($g.Success) { return [int]$g.Groups[1].Value }
    # Model numbers: i7-620M (gen 1), i7-8650U (gen 8), i7-1065G7 / i7-1255U (gen 10/12), i7-10510U (gen 10)
    $m = [regex]::Match($CpuName, 'i[3579]-(\d{3,5})')
    if (-not $m.Success) { return $null }
    $n = $m.Groups[1].Value
    if ($n.Length -eq 3) { return 1 }
    if ($n.Length -eq 5 -or $n.StartsWith('1')) { return [int]$n.Substring(0, 2) }
    return [int]$n.Substring(0, 1)
}
#endregion

#region ------------------------------------------------------------------ Check 1: System overview
function Test-SystemOverview {
    $ctx = @{}
    $info = [ordered]@{}

    Invoke-Step 'Computer/OS/BIOS/CPU (WMI)' {
        $script:CS  = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $script:OS  = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $script:CPU = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
        $ctx['Bios'] = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $lp = Get-PropValue $script:CS 'NumberOfLogicalProcessors'
        if ($lp) { $script:LogicalCPUs = [int]$lp }
    }
    $cs = $script:CS; $os = $script:OS; $bios = $ctx['Bios']

    if ($cs) {
        $info['Manufacturer'] = $cs.Manufacturer
        $info['Model'] = $cs.Model
        $info['System SKU'] = Get-PropValue $cs 'SystemSKUNumber'
        $info['Installed RAM (GB)'] = [math]::Round([double]$cs.TotalPhysicalMemory / 1GB, 1)
    }
    if ($bios) {
        $info['Serial number'] = $bios.SerialNumber
        $info['UEFI/BIOS version'] = $bios.SMBIOSBIOSVersion
        $info['UEFI/BIOS release date'] = $bios.ReleaseDate
    }
    $info['Firmware type'] = $env:firmware_type
    if ($script:IsAdmin) {
        try { $info['Secure Boot'] = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $info['Secure Boot'] = 'Unknown / not supported' }
    }

    $uptime = $null
    if ($os) {
        $cv = $null
        try { $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop } catch { }
        $info['OS'] = $os.Caption
        $info['OS version'] = '{0} (build {1}.{2})' -f (Get-PropValue $cv 'DisplayVersion' (Get-PropValue $cv 'ReleaseId' '')), $os.BuildNumber, (Get-PropValue $cv 'UBR' '?')
        $info['OS architecture'] = $os.OSArchitecture
        $info['Install date'] = $os.InstallDate
        $info['Last boot'] = $os.LastBootUpTime
        $uptime = (Get-Date) - $os.LastBootUpTime
        $info['Uptime'] = '{0}d {1}h {2}m' -f $uptime.Days, $uptime.Hours, $uptime.Minutes
        Add-Metric 'Uptime' ([math]::Round($uptime.TotalHours, 1)) 'hours'
    }
    $cpuName = ''
    foreach ($p in $script:CPU) {
        $cpuName = ([string]$p.Name).Trim()
        $info['CPU'] = '{0} - {1} cores / {2} logical, base {3} MHz' -f $cpuName, $p.NumberOfCores, $p.NumberOfLogicalProcessors, $p.MaxClockSpeed
    }

    # Fast Startup / hibernate
    $hiberboot = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled'
    $hibernate = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled'
    $info['Fast Startup (HiberbootEnabled)'] = $hiberboot
    $info['Hibernate enabled (HibernateEnabled)'] = $hibernate

    # Kernel-Boot 27: 0x0 cold boot, 0x1 Fast Startup (hybrid), 0x2 resume from hibernate
    Invoke-Step 'Last boot type (Kernel-Boot 27)' {
        $ev = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Boot'; Id = 27 } 1)
        if ($ev.Count -gt 0) {
            $code = $null
            try { $code = [int]$ev[0].Properties[0].Value } catch { }
            if ($null -eq $code) {
                $m = [regex]::Match([string]$ev[0].Message, '0x([0-9a-fA-F]+)')
                if ($m.Success) { $code = [Convert]::ToInt32($m.Groups[1].Value, 16) }
            }
            $txt = 'Unknown'
            switch ($code) { 0 { $txt = 'Cold boot (full restart)' } 1 { $txt = 'Fast Startup (hybrid boot - kernel session resumed from disk)' } 2 { $txt = 'Resume from hibernate' } }
            $ctx['BootType'] = $code
            $info['Last boot type'] = '{0} (0x{1:X}, {2:yyyy-MM-dd HH:mm})' -f $txt, $code, $ev[0].TimeCreated
        }
    }

    # Virtualization-based security
    Invoke-Step 'Virtualization-based security' {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        $vbs = Get-PropValue $dg 'VirtualizationBasedSecurityStatus'
        $vbsText = 'Unknown'
        switch ([int]$vbs) { 0 { $vbsText = 'Not enabled' } 1 { $vbsText = 'Enabled, not running' } 2 { $vbsText = 'Running' } }
        $names = @(foreach ($r in @(Get-PropValue $dg 'SecurityServicesRunning')) {
            switch ([int]$r) { 1 { 'Credential Guard' } 2 { 'HVCI (Memory integrity)' } 3 { 'System Guard Secure Launch' } 4 { 'SMM Firmware Measurement' } }
        })
        $info['VBS status'] = $vbsText
        $info['VBS services running'] = ($names -join ', ')
        $ctx['HVCI'] = ($names -contains 'HVCI (Memory integrity)')
    }

    Add-KeyValue $info

    # ---- Findings
    if ($cs -and $cs.Manufacturer -notmatch 'Microsoft') {
        Add-Finding 'INFO' 'Device is not a Microsoft Surface' ('Manufacturer: {0}' -f $cs.Manufacturer) 'n/a' 'Surface-specific guidance may not apply.'
    }
    if ($uptime) {
        $d = [math]::Round($uptime.TotalDays, 1)
        if ($d -gt 7) {
            Add-Finding 'AMBER' 'Long uptime' "$d days since last boot" 'AMBER > 7 days' 'Symptoms that build up over time are expected at this uptime. Capture this report as -Label WhenSlow, then Restart (not Shut down) and capture -Label AfterReboot to compare leak indicators.'
        } else {
            Add-Finding 'GREEN' 'Uptime' "$d days since last boot" 'AMBER > 7 days'
        }
    }
    if ($hiberboot -eq 1) {
        Add-Finding 'AMBER' 'Fast Startup is enabled' 'HiberbootEnabled = 1' 'AMBER if 1 (Shut down does not reset the kernel)' 'With Fast Startup, "Shut down" hibernates the kernel session, so kernel pool leaks and driver state survive. Use Restart, or disable Fast Startup (Control Panel > Power Options > Choose what the power buttons do, or powercfg /h off).' 'FastStartup'
    } elseif ($null -ne $hiberboot) {
        Add-Finding 'GREEN' 'Fast Startup disabled' "HiberbootEnabled = $hiberboot" 'AMBER if 1'
    }
    if ($ctx['BootType'] -eq 1) {
        Add-Finding 'AMBER' 'Last boot was a Fast Startup (hybrid) boot' 'Kernel-Boot event 27 boot type 0x1' 'AMBER if 0x1' 'The kernel was not freshly started at last boot, so uptime-related leaks may be older than the reported uptime. Use Restart for a clean start.' 'FastStartup'
    }
    if ($cs) {
        $ram = [math]::Round([double]$cs.TotalPhysicalMemory / 1GB, 1)
        Add-Metric 'Installed RAM' $ram 'GB'
        if ($ram -le 8.5) {
            Add-Finding 'AMBER' 'Limited RAM for a very large sync set' "$ram GB installed" 'AMBER <= 8 GB' 'With 8 GB, OneDrive, Defender and the indexer processing hundreds of thousands of files compete for memory. Reduce concurrent load (see OneDrive findings).' 'CommitPressure'
        } else {
            Add-Finding 'GREEN' 'Installed RAM' "$ram GB installed" 'AMBER <= 8 GB'
        }
    }
    $gen = Get-IntelGeneration $cpuName
    if ($ctx['HVCI'] -and $gen -and $gen -lt 8) {
        Add-Finding 'AMBER' 'Memory integrity (HVCI) on a pre-8th-gen Intel CPU' "CPU generation $gen with HVCI running" 'AMBER if HVCI on gen < 8 (no MBEC)' 'HVCI is emulated without MBEC on older CPUs and can cost noticeable performance. Evaluate the security trade-off before changing it.' 'Throttling'
    }
}
#endregion

#region ------------------------------------------------------------------ Check 2: Performance snapshot
$script:CounterMap = [ordered]@{
    'CPU%'             = '\Processor(_Total)\% Processor Time'
    'DPC%'             = '\Processor(_Total)\% DPC Time'
    'Interrupt%'       = '\Processor(_Total)\% Interrupt Time'
    'ProcPerf%'        = '\Processor Information(_Total)\% Processor Performance'
    'ProcFreqMHz'      = '\Processor Information(_Total)\Processor Frequency'
    'PerfLimit%'       = '\Processor Information(_Total)\% Performance Limit'
    'ProcQueue'        = '\System\Processor Queue Length'
    'AvailMB'          = '\Memory\Available MBytes'
    'CommittedBytes'   = '\Memory\Committed Bytes'
    'CommitLimit'      = '\Memory\Commit Limit'
    'PagesPerSec'      = '\Memory\Pages/sec'
    'PageFaultsPerSec' = '\Memory\Page Faults/sec'
    'PoolNPBytes'      = '\Memory\Pool Nonpaged Bytes'
    'PoolPBytes'       = '\Memory\Pool Paged Bytes'
    'DiskQueue'        = '\PhysicalDisk(_Total)\Avg. Disk Queue Length'
    'DiskSecRead'      = '\PhysicalDisk(_Total)\Avg. Disk sec/Read'
    'DiskSecWrite'     = '\PhysicalDisk(_Total)\Avg. Disk sec/Write'
    'DiskIdle%'        = '\PhysicalDisk(_Total)\% Idle Time'
    'DiskBytesPerSec'  = '\PhysicalDisk(_Total)\Disk Bytes/sec'
}

# Sample via Get-Counter in ~10 s chunks so console progress can be updated.
function Invoke-CounterSampling {
    param([int]$Seconds)
    $samples = New-Object System.Collections.Generic.List[object]
    $paths = @($script:CounterMap.Values)
    $lookup = @{}
    foreach ($k in $script:CounterMap.Keys) { $lookup[$script:CounterMap[$k].ToLowerInvariant()] = $k }
    $interval = 2
    $total = [math]::Max(2, [int][math]::Floor($Seconds / $interval))
    $taken = 0
    while ($taken -lt $total) {
        $n = [math]::Min(5, $total - $taken)
        Write-Progress -Id 1 -Activity 'Sampling performance counters' -Status ('{0} of ~{1} s' -f ($taken * $interval), $Seconds) -PercentComplete ([int]($taken / $total * 100))
        $res = Get-Counter -Counter $paths -SampleInterval $interval -MaxSamples $n -ErrorAction SilentlyContinue
        if (-not $res) { break }
        foreach ($set in @($res)) {
            foreach ($smp in @($set.CounterSamples)) {
                $p = ($smp.Path -replace '^\\\\[^\\]+', '').ToLowerInvariant()
                if ($lookup.ContainsKey($p)) {
                    $samples.Add([pscustomobject]@{ Time = $set.Timestamp; Key = $lookup[$p]; Path = $script:CounterMap[$lookup[$p]]; Value = [double]$smp.CookedValue })
                }
            }
        }
        $taken += $n
    }
    Write-Progress -Id 1 -Activity 'Sampling performance counters' -Completed
    return $samples.ToArray()
}

# Fallback for non-English systems: WMI formatted counters (language independent).
function Invoke-WmiPerfSampling {
    param([int]$Seconds)
    $samples = New-Object System.Collections.Generic.List[object]
    $add = { param($k, $v, $t) if ($null -ne $v) { $samples.Add([pscustomobject]@{ Time = $t; Key = $k; Path = "WMI:$k"; Value = [double]$v }) } }
    $end = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $end) {
        $t = Get-Date
        Write-Progress -Id 1 -Activity 'Sampling performance (WMI fallback)' -Status ('{0:N0} s remaining' -f ($end - $t).TotalSeconds)
        try {
            $c = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop
            & $add 'CPU%' $c.PercentProcessorTime $t; & $add 'DPC%' $c.PercentDPCTime $t; & $add 'Interrupt%' $c.PercentInterruptTime $t
        } catch { }
        try {
            $pi = Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "Name='_Total'" -ErrorAction Stop
            & $add 'ProcPerf%' (Get-PropValue $pi 'PercentProcessorPerformance') $t
            & $add 'ProcFreqMHz' (Get-PropValue $pi 'ProcessorFrequency') $t
            & $add 'PerfLimit%' (Get-PropValue $pi 'PercentPerformanceLimit') $t
        } catch { }
        try {
            $m = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -ErrorAction Stop
            & $add 'AvailMB' $m.AvailableMBytes $t; & $add 'CommittedBytes' $m.CommittedBytes $t; & $add 'CommitLimit' $m.CommitLimit $t
            & $add 'PagesPerSec' $m.PagesPersec $t; & $add 'PageFaultsPerSec' $m.PageFaultsPersec $t
            & $add 'PoolNPBytes' $m.PoolNonpagedBytes $t; & $add 'PoolPBytes' $m.PoolPagedBytes $t
        } catch { }
        try { $s = Get-CimInstance Win32_PerfFormattedData_PerfOS_System -ErrorAction Stop; & $add 'ProcQueue' $s.ProcessorQueueLength $t } catch { }
        try {
            $d = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction Stop
            & $add 'DiskQueue' $d.AvgDiskQueueLength $t; & $add 'DiskIdle%' $d.PercentIdleTime $t; & $add 'DiskBytesPerSec' $d.DiskBytesPersec $t
        } catch { }
        Start-Sleep -Seconds 2
    }
    Write-Progress -Id 1 -Activity 'Sampling performance (WMI fallback)' -Completed
    return $samples.ToArray()
}

function Test-Performance {
    $ctx = @{ Samples = @() }
    Add-Note ("Sampling for about {0} seconds. Process CPUPct is the share of total CPU capacity used during that window (all {1} logical processors = 100%)." -f $SampleSeconds, $script:LogicalCPUs)

    $before = $null
    try { $before = Get-ProcessSnapshot } catch { Add-Note "Process snapshot failed: $($_.Exception.Message)" 'err' }

    Invoke-Step 'Performance counters' {
        Write-Status ("  Sampling performance counters for ~{0}s..." -f $SampleSeconds)
        $s = @(Invoke-CounterSampling -Seconds $SampleSeconds)
        if ($s.Count -gt 0) { $script:PerfSource = 'Get-Counter' }
        else {
            Write-Status '  Get-Counter returned no data (non-English counter names?) - using WMI fallback.' 'Yellow'
            $s = @(Invoke-WmiPerfSampling -Seconds $SampleSeconds)
            if ($s.Count -gt 0) { $script:PerfSource = 'WMI formatted counters (fallback)' }
        }
        $ctx['Samples'] = $s
    }

    Invoke-Step 'Process CPU/memory snapshot' {
        $after = Get-ProcessSnapshot
        $script:Procs = @(Merge-ProcessSnapshots -Before $before -After $after)
    }

    $samples = @($ctx['Samples'])
    foreach ($g in @($samples | Group-Object Key)) { $script:Perf[$g.Name] = Get-Stats @($g.Group | ForEach-Object { $_.Value }) }
    Export-Raw ($samples | Select-Object Time, Key, Path, Value) 'perf_samples.csv'

    # ---- Evaluate counters
    $ramMB = 0
    if ($script:CS) { $ramMB = [double]$script:CS.TotalPhysicalMemory / 1MB }
    $rows = New-Object System.Collections.Generic.List[object]
    $addRow = {
        param($Metric, $Key, $Scale, $Unit, $Threshold, $Sev)
        $st = $script:Perf[$Key]
        if ($null -eq $st) { $rows.Add([pscustomobject]@{ Metric = $Metric; Avg = 'n/a'; Min = ''; Max = ''; Unit = $Unit; Threshold = $Threshold; Status = 'n/a'; Counter = $script:CounterMap[$Key] }); return }
        $rows.Add([pscustomobject]@{ Metric = $Metric; Avg = [math]::Round($st.Avg * $Scale, 2); Min = [math]::Round($st.Min * $Scale, 2); Max = [math]::Round($st.Max * $Scale, 2); Unit = $Unit; Threshold = $Threshold; Status = $Sev; Counter = $script:CounterMap[$Key] })
    }

    $cpuAvg = Get-PerfStat 'CPU%'
    $cpuSev = Get-Severity $cpuAvg 50 80
    & $addRow 'CPU utilisation' 'CPU%' 1 '%' 'AMBER >= 50, RED >= 80 (avg)' $cpuSev

    $dpc = Get-PerfStat 'DPC%'; $intr = Get-PerfStat 'Interrupt%'
    $dpcSum = $null; if ($null -ne $dpc -and $null -ne $intr) { $dpcSum = $dpc + $intr }
    $dpcSev = Get-Severity $dpcSum 5 15
    & $addRow 'DPC time' 'DPC%' 1 '%' 'DPC+Interrupt: AMBER >= 5, RED >= 15' $dpcSev
    & $addRow 'Interrupt time' 'Interrupt%' 1 '%' 'see DPC' $dpcSev

    $pq = Get-PerfStat 'ProcQueue'
    $pqSev = Get-Severity $pq (2 * $script:LogicalCPUs) (4 * $script:LogicalCPUs)
    & $addRow 'Processor queue length' 'ProcQueue' 1 'threads' ('AMBER >= {0}, RED >= {1}' -f (2 * $script:LogicalCPUs), (4 * $script:LogicalCPUs)) $pqSev

    & $addRow '% Processor Performance' 'ProcPerf%' 1 '% of base' 'See CPU throttling section' 'INFO'
    & $addRow 'Processor frequency' 'ProcFreqMHz' 1 'MHz' 'See CPU throttling section' 'INFO'
    & $addRow '% Performance Limit' 'PerfLimit%' 1 '%' 'See CPU throttling section' 'INFO'

    $avail = Get-PerfStat 'AvailMB'
    $availSev = 'INFO'
    if ($null -ne $avail -and $ramMB -gt 0) {
        $availPct = $avail / $ramMB * 100
        if ($availPct -le 5 -or $avail -le 500) { $availSev = 'RED' } elseif ($availPct -le 10 -or $avail -le 1000) { $availSev = 'AMBER' } else { $availSev = 'GREEN' }
    }
    & $addRow 'Available memory' 'AvailMB' 1 'MB' 'AMBER <= 10% of RAM or 1000 MB, RED <= 5% or 500 MB' $availSev
    & $addRow 'Committed bytes' 'CommittedBytes' (1 / 1GB) 'GB' 'See memory section' 'INFO'
    & $addRow 'Commit limit' 'CommitLimit' (1 / 1GB) 'GB' 'See memory section' 'INFO'

    $pages = Get-PerfStat 'PagesPerSec'
    $pagesSev = Get-Severity $pages 1000 3000
    & $addRow 'Pages/sec (hard faults)' 'PagesPerSec' 1 '/s' 'AMBER >= 1000, RED >= 3000 (avg)' $pagesSev
    & $addRow 'Page faults/sec (all)' 'PageFaultsPerSec' 1 '/s' 'Informational (mostly soft faults)' 'INFO'
    & $addRow 'Pool non-paged' 'PoolNPBytes' (1 / 1MB) 'MB' 'See memory section' 'INFO'
    & $addRow 'Pool paged' 'PoolPBytes' (1 / 1MB) 'MB' 'See memory section' 'INFO'

    $rd = Get-PerfStat 'DiskSecRead'; $wr = Get-PerfStat 'DiskSecWrite'
    $latMs = $null
    if ($null -ne $rd -or $null -ne $wr) { $latMs = [math]::Max([double]$rd, [double]$wr) * 1000 }
    $latSev = Get-Severity $latMs 20 50
    & $addRow 'Disk read latency' 'DiskSecRead' 1000 'ms' 'max(read,write): AMBER >= 20 ms, RED >= 50 ms' $latSev
    & $addRow 'Disk write latency' 'DiskSecWrite' 1000 'ms' 'see read latency' $latSev
    $dq = Get-PerfStat 'DiskQueue'
    $dqSev = Get-Severity $dq 4 10
    & $addRow 'Disk queue length' 'DiskQueue' 1 'IOs' 'AMBER >= 4, RED >= 10 (avg)' $dqSev
    $idle = Get-PerfStat 'DiskIdle%'
    $idleSev = Get-Severity $idle 20 5 -LowerIsWorse
    & $addRow 'Disk idle time' 'DiskIdle%' 1 '%' 'AMBER <= 20, RED <= 5 (avg)' $idleSev
    & $addRow 'Disk throughput' 'DiskBytesPerSec' (1 / 1MB) 'MB/s' 'Informational' 'INFO'

    Add-Heading ('Counter summary (source: {0})' -f $script:PerfSource)
    Add-Table $rows.ToArray()
    Export-Raw $rows.ToArray() 'perf_summary.csv'

    # ---- Top processes
    $procs = @($script:Procs | Where-Object { $_.PID -ne 0 })
    $cols = @('Name', 'PID', 'CPUPct', 'CPUTotalSec', 'WorkingSetMB', 'PrivateMB', 'Handles', 'Threads', 'Started', 'Path')
    $topCpu = @($procs | Where-Object { $null -ne $_.CPUPct } | Sort-Object CPUPct -Descending | Select-Object -First 15)
    Add-Heading 'Top 15 processes by CPU during the sample window'; Add-Table $topCpu $cols
    Add-Heading 'Top 15 processes by working set'; Add-Table @($procs | Sort-Object WorkingSetMB -Descending | Select-Object -First 15) $cols
    Add-Heading 'Top 15 processes by private bytes'; Add-Table @($procs | Sort-Object PrivateMB -Descending | Select-Object -First 15) $cols
    Add-Heading 'Top 15 processes by handle count'; Add-Table @($procs | Sort-Object Handles -Descending | Select-Object -First 15) $cols
    Export-Raw ($procs | Select-Object $cols) 'processes.csv'

    # ---- Findings + metrics
    $topName = ''
    if ($topCpu.Count -gt 0) { $topName = '{0} ({1}%)' -f $topCpu[0].Name, $topCpu[0].CPUPct }
    if ($null -ne $cpuAvg) {
        Add-Metric 'CPU utilisation avg' ([math]::Round($cpuAvg, 1)) '%'
        Add-Finding $cpuSev 'Average CPU utilisation' ('avg {0:N1}% / max {1:N1}% over {2}s; top: {3}' -f $cpuAvg, (Get-PerfStat 'CPU%' 'Max'), $SampleSeconds, $topName) 'AMBER >= 50%, RED >= 80% average' ('Identify the top CPU consumers in the table ({0}) and check whether they are sync/scan/index related.' -f $topName) 'CPULoad'
    }
    if ($null -ne $dpcSum) {
        Add-Metric 'DPC+Interrupt avg' ([math]::Round($dpcSum, 2)) '%'
        Add-Finding $dpcSev 'DPC + interrupt time' ('{0:N2}% average' -f $dpcSum) 'AMBER >= 5%, RED >= 15%' 'High DPC/ISR time points to a driver (network, storage, graphics, ACPI). Capture a WPR trace (wpr -start CPU) when slow and review in WPA.' 'Drivers'
    }
    if ($null -ne $pq) { Add-Finding $pqSev 'Processor queue length' ('{0:N1} average' -f $pq) ('AMBER >= {0}, RED >= {1}' -f (2 * $script:LogicalCPUs), (4 * $script:LogicalCPUs)) 'Threads are waiting for CPU; correlate with top CPU processes and the throttling section.' 'CPULoad' }
    if ($null -ne $avail) {
        Add-Metric 'Available memory avg' ([math]::Round($avail, 0)) 'MB'
        Add-Finding $availSev 'Available physical memory' ('{0:N0} MB average of {1:N0} MB' -f $avail, $ramMB) 'AMBER <= 10% or 1000 MB, RED <= 5% or 500 MB' 'Check private bytes / working set leaders and the memory section.' 'CommitPressure'
    }
    if ($null -ne $pages) {
        Add-Metric 'Pages/sec avg' ([math]::Round($pages, 0)) '/s'
        Add-Finding $pagesSev 'Hard page faults (Pages/sec)' ('{0:N0}/s average' -f $pages) 'AMBER >= 1000/s, RED >= 3000/s' 'Sustained hard faulting means the working set does not fit in RAM or large files are being read through memory-mapped I/O (e.g. sync hashing).' 'CommitPressure'
    }
    if ($null -ne $latMs) {
        Add-Metric 'Disk latency avg (max of read/write)' ([math]::Round($latMs, 2)) 'ms'
        Add-Finding $latSev 'Disk latency' ('read {0:N1} ms / write {1:N1} ms average' -f ([double]$rd * 1000), ([double]$wr * 1000)) 'AMBER >= 20 ms, RED >= 50 ms' 'Use Resource Monitor > Disk to see which process drives the I/O (OneDrive, MsMpEng, SearchIndexer are common during a large sync).' 'DiskIO'
    }
    if ($null -ne $idle) { Add-Finding $idleSev 'Disk busy time' ('{0:N1}% idle on average' -f $idle) 'AMBER <= 20% idle, RED <= 5% idle' 'The disk is saturated; identify the I/O source in Resource Monitor.' 'DiskIO' }
    if ($null -ne $dq) { Add-Finding $dqSev 'Disk queue length' ('{0:N2} average' -f $dq) 'AMBER >= 4, RED >= 10' 'Correlate with disk latency and the top I/O processes.' 'DiskIO' }
    if ($script:PerfSource -eq 'None') { Add-Finding 'INFO' 'No performance counter data collected' 'Get-Counter and WMI fallback both returned nothing' 'n/a' 'Check that the Performance Counter DLL Host / WMI are healthy (lodctr /q).' }
}
#endregion

#region ------------------------------------------------------------------ Check 3: Memory leak indicators
function Test-MemoryLeak {
    $ctx = @{}
    Invoke-Step 'Memory counters (WMI)' { $ctx['Mem'] = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory -ErrorAction Stop }
    $m = $ctx['Mem']

    $np = Get-PropValue $m 'PoolNonpagedBytes' (Get-PerfStat 'PoolNPBytes' 'Last')
    $pp = Get-PropValue $m 'PoolPagedBytes' (Get-PerfStat 'PoolPBytes' 'Last')
    $committed = Get-PerfStat 'CommittedBytes'; if ($null -eq $committed) { $committed = Get-PropValue $m 'CommittedBytes' }
    $limit = Get-PerfStat 'CommitLimit'; if ($null -eq $limit) { $limit = Get-PropValue $m 'CommitLimit' }
    $commitPct = $null
    if ($committed -and $limit) { $commitPct = [double]$committed / [double]$limit * 100 }

    $uptimeDays = $null
    if ($script:OS) { $uptimeDays = ((Get-Date) - $script:OS.LastBootUpTime).TotalDays }
    $procs = @(Get-ProcsSafe)
    $totalHandles = 0; $totalThreads = 0
    foreach ($p in $procs) { $totalHandles += $p.Handles; $totalThreads += $p.Threads }

    $info = [ordered]@{}
    $info['Committed (GB, sampled avg)'] = if ($committed) { [math]::Round([double]$committed / 1GB, 2) } else { 'n/a' }
    $info['Commit limit (GB)'] = if ($limit) { [math]::Round([double]$limit / 1GB, 2) } else { 'n/a' }
    $info['Commit in use (%)'] = if ($null -ne $commitPct) { [math]::Round($commitPct, 1) } else { 'n/a' }
    $info['Non-paged pool (MB)'] = ConvertTo-MB $np
    $info['Paged pool (MB)'] = ConvertTo-MB $pp
    $info['Paged pool resident (MB)'] = ConvertTo-MB (Get-PropValue $m 'PoolPagedResidentBytes')
    $info['System cache (MB)'] = ConvertTo-MB (Get-PropValue $m 'CacheBytes')
    $info['Modified page list (MB)'] = ConvertTo-MB (Get-PropValue $m 'ModifiedPageListBytes')
    $sb = 0.0; foreach ($n in 'StandbyCacheCoreBytes', 'StandbyCacheNormalPriorityBytes', 'StandbyCacheReserveBytes') { $sb += [double](Get-PropValue $m $n 0) }
    $info['Standby list (MB)'] = ConvertTo-MB $sb
    $info['Free + zero (MB)'] = ConvertTo-MB (Get-PropValue $m 'FreeAndZeroPageListBytes')
    $info['Available (MB)'] = Get-PropValue $m 'AvailableMBytes'
    $info['System driver total (MB)'] = ConvertTo-MB (Get-PropValue $m 'SystemDriverTotalBytes')
    $info['Processes / threads / handles'] = '{0} / {1} / {2}' -f $procs.Count, $totalThreads, $totalHandles
    if ($uptimeDays -and $uptimeDays -ge 0.5 -and $np) { $info['Non-paged pool per day of uptime (MB/day, heuristic)'] = [math]::Round(([double]$np / 1MB) / $uptimeDays, 1) }
    Add-KeyValue $info

    Add-Metric 'Commit in use' $(if ($null -ne $commitPct) { [math]::Round($commitPct, 1) } else { $null }) '%'
    Add-Metric 'Non-paged pool' (ConvertTo-MB $np) 'MB'
    Add-Metric 'Paged pool' (ConvertTo-MB $pp) 'MB'
    Add-Metric 'Total handles' $totalHandles 'count'
    Add-Metric 'Total threads' $totalThreads 'count'
    Add-Metric 'Process count' $procs.Count 'count'

    Invoke-Step 'Page file' {
        $pf = @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop | Select-Object Name, @{n = 'AllocatedMB'; e = { $_.AllocatedBaseSize } }, @{n = 'CurrentUsageMB'; e = { $_.CurrentUsage } }, @{n = 'PeakUsageMB'; e = { $_.PeakUsage } })
        Add-Heading 'Page file'
        Add-Table $pf
        Add-Note ('Automatic page file management: {0}' -f (Get-PropValue $script:CS 'AutomaticManagedPagefile' 'unknown'))
    }

    # ---- Findings: commit, pools, handles
    if ($null -ne $commitPct) {
        Add-Finding (Get-Severity $commitPct 80 90) 'Commit charge vs limit' ('{0:N1}% ({1:N1} of {2:N1} GB)' -f $commitPct, ([double]$committed / 1GB), ([double]$limit / 1GB)) 'AMBER >= 80%, RED >= 90%' 'Near the commit limit Windows pages heavily and may log Resource-Exhaustion 2004. Check the private-bytes leaders; confirm the page file is system-managed.' 'CommitPressure'
    }
    if ($np) {
        $npMB = [double]$np / 1MB
        Add-Finding (Get-Severity $npMB 512 1024) 'Non-paged pool size' ('{0:N0} MB' -f $npMB) 'AMBER >= 512 MB, RED >= 1 GB' 'Growing non-paged pool is a classic driver leak. Use the pool tag table below to find the tag, map it to a driver with: findstr /m /l <TAG> C:\Windows\System32\drivers\*.sys, then update or remove that driver. Compare AfterReboot vs WhenSlow runs.' 'MemoryLeak'
    }
    if ($pp) {
        $ppMB = [double]$pp / 1MB
        Add-Finding (Get-Severity $ppMB 1536 3072) 'Paged pool size' ('{0:N0} MB' -f $ppMB) 'AMBER >= 1.5 GB, RED >= 3 GB' 'Large paged pool is often registry, file-mapping metadata (MmSt) or filter-driver caches; with ~800k synced files MmSt/FMfn growth is plausible. Check the pool tag table.' 'MemoryLeak'
    }
    Add-Finding (Get-Severity $totalHandles 150000 300000) 'System-wide handle count' ('{0:N0} handles across {1} processes' -f $totalHandles, $procs.Count) 'AMBER >= 150,000, RED >= 300,000' 'Look at the top processes by handle count; a steadily increasing count between runs indicates a handle leak.' 'MemoryLeak'

    $bigHandles = @($procs | Where-Object { $_.Handles -ge 20000 } | Sort-Object Handles -Descending)
    if ($bigHandles.Count -gt 0) {
        $sev = 'AMBER'; if (@($bigHandles | Where-Object { $_.Handles -ge 50000 }).Count -gt 0) { $sev = 'RED' }
        Add-Finding $sev 'Processes with very high handle counts' ((@($bigHandles | Select-Object -First 5 | ForEach-Object { '{0} (PID {1}): {2:N0}' -f $_.Name, $_.PID, $_.Handles }) -join '; ')) 'AMBER >= 20,000, RED >= 50,000 per process' 'Restart the named process (or its app) as a test and see whether performance recovers; report persistent leaks to the vendor.' 'MemoryLeak'
    } else { Add-Finding 'GREEN' 'Per-process handle counts' 'No process >= 20,000 handles' 'AMBER >= 20,000' }

    $bigPriv = @($procs | Where-Object { $_.PrivateMB -ge 2048 -and $_.Name -notin @('Memory Compression', 'vmmem', 'vmmemWSL') } | Sort-Object PrivateMB -Descending)
    if ($bigPriv.Count -gt 0) {
        $sev = 'AMBER'; if (@($bigPriv | Where-Object { $_.PrivateMB -ge 4096 }).Count -gt 0) { $sev = 'RED' }
        Add-Finding $sev 'Processes with large private bytes' ((@($bigPriv | Select-Object -First 5 | ForEach-Object { '{0} (PID {1}): {2:N0} MB' -f $_.Name, $_.PID, $_.PrivateMB }) -join '; ')) 'AMBER >= 2 GB, RED >= 4 GB per process' 'Compare between runs; steady growth with uptime indicates a user-mode leak in that process.' 'MemoryLeak'
    }
    $bigThreads = @($procs | Where-Object { $_.Threads -ge 500 -and $_.PID -gt 4 } | Sort-Object Threads -Descending)
    if ($bigThreads.Count -gt 0) {
        Add-Finding 'AMBER' 'Processes with very high thread counts' ((@($bigThreads | Select-Object -First 5 | ForEach-Object { '{0} (PID {1}): {2}' -f $_.Name, $_.PID, $_.Threads }) -join '; ')) 'AMBER >= 500 threads per process (excl. System)' 'High thread counts can indicate a thread leak or a runaway worker pool.' 'MemoryLeak'
    }

    Add-Heading 'Top 15 processes by handle count'
    Add-Table @($procs | Sort-Object Handles -Descending | Select-Object -First 15) @('Name', 'PID', 'Handles', 'Threads', 'PrivateMB', 'WorkingSetMB', 'Started')
    Add-Heading 'Top 15 processes by thread count'
    Add-Table @($procs | Sort-Object Threads -Descending | Select-Object -First 15) @('Name', 'PID', 'Threads', 'Handles', 'PrivateMB', 'Started')

    # ---- Pool tags (driver-attributable pool usage, like poolmon)
    Invoke-Step 'Kernel pool tags' {
        if (-not $script:NativeLoaded) { Add-Note 'Pool tag data unavailable (native helper not loaded).'; return }
        $tags = @([SlowPCReport.Native]::GetPoolTags() | ForEach-Object {
            $hint = ''
            if ($script:PoolTagHints.ContainsKey($_.Tag)) { $hint = $script:PoolTagHints[$_.Tag] }
            [pscustomobject]@{
                Tag = $_.Tag
                NonPagedMB = ConvertTo-MB $_.NonPagedUsed
                NonPagedOutstanding = $_.NonPagedAllocs - $_.NonPagedFrees
                PagedMB = ConvertTo-MB $_.PagedUsed
                PagedOutstanding = $_.PagedAllocs - $_.PagedFrees
                Hint = $hint
            }
        })
        Export-Raw $tags 'pooltags.csv'
        Add-Heading 'Top 20 pool tags by non-paged usage'
        Add-Table @($tags | Sort-Object NonPagedMB -Descending | Select-Object -First 20)
        Add-Heading 'Top 20 pool tags by paged usage'
        Add-Table @($tags | Sort-Object PagedMB -Descending | Select-Object -First 20)
        Add-Note 'Map an unknown tag to its driver (read-only): findstr /m /l "TAG" C:\Windows\System32\drivers\*.sys   (tags are case-sensitive; include trailing spaces). Outstanding = allocations minus frees; a count that rises between runs is the strongest leak signal.'

        $npHog = @($tags | Where-Object { $_.NonPagedMB -ge 200 } | Sort-Object NonPagedMB -Descending)
        $pHog = @($tags | Where-Object { $_.PagedMB -ge 500 } | Sort-Object PagedMB -Descending)
        if ($npHog.Count -gt 0) {
            $sev = 'AMBER'; if ($npHog[0].NonPagedMB -ge 500) { $sev = 'RED' }
            Add-Finding $sev 'Single pool tag dominating non-paged pool' ((@($npHog | Select-Object -First 3 | ForEach-Object { "'{0}' {1:N0} MB" -f $_.Tag, $_.NonPagedMB }) -join '; ')) 'AMBER >= 200 MB, RED >= 500 MB for one tag' 'Identify the owning driver with findstr (see note in the memory section) and update/remove it.' 'MemoryLeak'
        }
        if ($pHog.Count -gt 0) {
            Add-Finding 'AMBER' 'Single pool tag dominating paged pool' ((@($pHog | Select-Object -First 3 | ForEach-Object { "'{0}' {1:N0} MB" -f $_.Tag, $_.PagedMB }) -join '; ')) 'AMBER >= 500 MB for one tag' 'MmSt / Ntff / FM* growth tracks the number of files touched (large sync); other tags usually map to a specific driver.' 'MemoryLeak'
        }
    }
}
#endregion

#region ------------------------------------------------------------------ Check 4: CPU throttling
function Test-CpuThrottling {
    $ctx = @{}
    $info = [ordered]@{}
    foreach ($p in $script:CPU) {
        $info['CPU'] = ([string]$p.Name).Trim()
        $info['Base (MaxClockSpeed, MHz)'] = $p.MaxClockSpeed
        $info['CurrentClockSpeed (MHz, WMI - often stale)'] = $p.CurrentClockSpeed
        $info['LoadPercentage (instant)'] = Get-PropValue $p 'LoadPercentage'
    }

    # Use the performance-window samples; if missing, take a short WMI sample here.
    if ($null -eq $script:Perf['ProcPerf%']) {
        Invoke-Step 'Processor performance (WMI, 10 s)' {
            $pp = New-Object System.Collections.Generic.List[double]; $pf = New-Object System.Collections.Generic.List[double]; $pl = New-Object System.Collections.Generic.List[double]
            for ($i = 0; $i -lt 10; $i++) {
                $pi = Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "Name='_Total'" -ErrorAction Stop
                $pp.Add([double](Get-PropValue $pi 'PercentProcessorPerformance' 0)); $pf.Add([double](Get-PropValue $pi 'ProcessorFrequency' 0)); $pl.Add([double](Get-PropValue $pi 'PercentPerformanceLimit' 100))
                Start-Sleep -Seconds 1
            }
            $script:Perf['ProcPerf%'] = Get-Stats $pp.ToArray(); $script:Perf['ProcFreqMHz'] = Get-Stats $pf.ToArray(); $script:Perf['PerfLimit%'] = Get-Stats $pl.ToArray()
        }
    }
    $perfAvg = Get-PerfStat 'ProcPerf%'; $perfMax = Get-PerfStat 'ProcPerf%' 'Max'
    $limAvg = Get-PerfStat 'PerfLimit%'; $limMin = Get-PerfStat 'PerfLimit%' 'Min'
    $freqAvg = Get-PerfStat 'ProcFreqMHz'
    $cpuAvg = Get-PerfStat 'CPU%'
    $info['% Processor Performance avg / max (100 = base clock, >100 = turbo)'] = '{0:N1} / {1:N1}' -f $perfAvg, $perfMax
    $info['Processor frequency avg (MHz)'] = if ($null -ne $freqAvg) { [math]::Round($freqAvg, 0) } else { 'n/a' }
    $info['% Performance Limit avg / min (100 = not limited)'] = '{0:N1} / {1:N1}' -f $limAvg, $limMin
    $info['CPU utilisation avg during sample (%)'] = if ($null -ne $cpuAvg) { [math]::Round($cpuAvg, 1) } else { 'n/a' }

    # ---- Power configuration (powercfg queries are read-only)
    $powerText = New-Object System.Text.StringBuilder
    Invoke-Step 'Power scheme (powercfg)' {
        $active = (& powercfg.exe /getactivescheme | Out-String).Trim()
        $info['Active power scheme'] = $active
        [void]$powerText.AppendLine("== powercfg /getactivescheme`r`n$active`r`n")
        $sleep = (& powercfg.exe /a | Out-String).Trim()
        [void]$powerText.AppendLine("== powercfg /a`r`n$sleep`r`n")
        foreach ($setting in 'PROCTHROTTLEMAX', 'PROCTHROTTLEMIN', 'PERFBOOSTMODE') {
            $q = (& powercfg.exe /query SCHEME_CURRENT SUB_PROCESSOR $setting | Out-String)
            [void]$powerText.AppendLine("== powercfg /query SCHEME_CURRENT SUB_PROCESSOR $setting`r`n$q")
            $hex = @([regex]::Matches($q, '0x([0-9a-fA-F]{8})') | ForEach-Object { [Convert]::ToInt32($_.Groups[1].Value, 16) })
            if ($hex.Count -ge 2) {
                $ac = $hex[$hex.Count - 2]; $dc = $hex[$hex.Count - 1]
                $info["$setting (AC / DC)"] = "$ac / $dc"
                $ctx[$setting] = @($ac, $dc)
            }
        }
    }
    Invoke-Step 'Power mode overlay' {
        $map = @{
            '961cc777-2547-4f9d-8174-7d86181b8a7a' = 'Best power efficiency'
            '00000000-0000-0000-0000-000000000000' = 'Balanced'
            '3af9b8d9-7c97-431d-ad78-34a8bfea439f' = 'Better performance'
            'ded574b5-45a0-4f42-8737-46345c09c238' = 'Best performance'
        }
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'
        foreach ($n in 'ActiveOverlayAcPowerScheme', 'ActiveOverlayDcPowerScheme') {
            $v = Get-RegValue $key $n
            if ($v) {
                $name = $v; if ($map.ContainsKey(([string]$v).ToLower())) { $name = $map[([string]$v).ToLower()] }
                $info["Power mode ($n)"] = $name
                $ctx[$n] = $name
            }
        }
    }
    Invoke-Step 'Energy saver' {
        $null = [Windows.System.Power.PowerManager, Windows.System.Power, ContentType = WindowsRuntime]
        $es = [Windows.System.Power.PowerManager]::EnergySaverStatus
        $info['Battery/Energy saver'] = [string]$es
        $ctx['EnergySaver'] = [string]$es
    }

    # ---- Battery
    Invoke-Step 'Battery' {
        $bat = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop)
        if ($bat.Count -eq 0) { $info['Battery'] = 'None detected'; return }
        $statusMap = @{ 1 = 'Discharging (on battery)'; 2 = 'On AC'; 3 = 'Fully charged'; 4 = 'Low'; 5 = 'Critical'; 6 = 'Charging'; 7 = 'Charging/High'; 8 = 'Charging/Low'; 9 = 'Charging/Critical'; 10 = 'Undefined'; 11 = 'Partially charged' }
        foreach ($b in $bat) {
            $st = [int]$b.BatteryStatus
            $stText = [string]$st; if ($statusMap.ContainsKey($st)) { $stText = $statusMap[$st] }
            $info['Battery status'] = '{0}, {1}% charge' -f $stText, $b.EstimatedChargeRemaining
            if ($st -eq 1) { $ctx['OnBattery'] = $true }
        }
        try {
            $design = 0.0; $full = 0.0
            foreach ($d in @(Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction Stop)) { $design += [double]$d.DesignedCapacity }
            foreach ($f in @(Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop)) { $full += [double]$f.FullChargedCapacity }
            if ($design -gt 0) {
                $health = [math]::Round($full / $design * 100, 1)
                $info['Battery design / full-charge capacity (mWh)'] = '{0:N0} / {1:N0} ({2}% of design)' -f $design, $full, $health
                $ctx['BatteryHealth'] = $health
                Add-Metric 'Battery full-charge vs design' $health '%'
            }
        } catch { $info['Battery capacity'] = 'Not available: ' + $_.Exception.Message }
    }

    # ---- Thermal zones
    $zones = New-Object System.Collections.Generic.List[object]
    Invoke-Step 'Thermal zones (perf counters, 5 samples)' {
        for ($i = 0; $i -lt 5; $i++) {
            foreach ($z in @(Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ThermalZoneInformation -ErrorAction Stop)) {
                $k = [double](Get-PropValue $z 'HighPrecisionTemperature' 0) / 10
                if ($k -le 0) { $k = [double](Get-PropValue $z 'Temperature' 0) }
                $zones.Add([pscustomobject]@{ Zone = $z.Name; TempC = [math]::Round($k - 273.15, 1); PassiveLimitPct = Get-PropValue $z 'PercentPassiveLimit'; ThrottleReasons = Get-PropValue $z 'ThrottleReasons' })
            }
            Start-Sleep -Milliseconds 800
        }
    }
    Invoke-Step 'MSAcpi_ThermalZoneTemperature' {
        if (-not $script:IsAdmin) { Add-Note 'MSAcpi_ThermalZoneTemperature requires elevation - skipped.'; return }
        foreach ($z in @(Get-CimInstance -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop)) {
            $zones.Add([pscustomobject]@{ Zone = 'ACPI:' + $z.InstanceName; TempC = [math]::Round([double]$z.CurrentTemperature / 10 - 273.15, 1); PassiveLimitPct = $null; ThrottleReasons = $null })
        }
    }
    $zoneSummary = @($zones | Group-Object Zone | ForEach-Object {
        $t = Get-Stats @($_.Group | ForEach-Object { $_.TempC })
        $pl = Get-Stats @($_.Group | ForEach-Object { $_.PassiveLimitPct })
        $tr = @($_.Group | ForEach-Object { $_.ThrottleReasons } | Where-Object { $null -ne $_ } | Sort-Object -Unique)
        [pscustomobject]@{ Zone = $_.Name; TempC_Max = $(if ($t) { $t.Max } else { $null }); PassiveLimitPct_Min = $(if ($pl) { $pl.Min } else { $null }); ThrottleReasons = ($tr -join ',') }
    })

    Add-KeyValue $info
    Add-Heading 'Thermal zones'
    if ($zoneSummary.Count -gt 0) { Add-Table $zoneSummary } else { Add-Note 'No thermal zone data exposed by firmware (common on Surface).' }
    Add-Note 'Interpretation: % Performance Limit < 100 means firmware (thermal/power/PL1-PL2) is capping the CPU. % Processor Performance < 100 at low load is normal idle behaviour; below ~50 while the CPU is busy indicates throttling. Kernel-Processor-Power event 37 (events section) is Windows logging firmware-imposed speed limits.'
    [void]$powerText.AppendLine(($info.GetEnumerator() | ForEach-Object { '{0}: {1}' -f $_.Key, (Format-Value $_.Value) }) -join "`r`n")
    Export-Raw $powerText.ToString() 'power_and_throttling.txt'

    # ---- Findings
    if ($null -ne $limAvg) {
        Add-Metric '% Performance Limit avg' ([math]::Round($limAvg, 1)) '%'
        Add-Finding (Get-Severity $limAvg 99 80 -LowerIsWorse) 'Firmware performance limit (% Performance Limit)' ('avg {0:N1}% / min {1:N1}%' -f $limAvg, $limMin) 'AMBER < 99% avg, RED <= 80% avg (100 = unrestricted)' 'The CPU is being capped by firmware (thermal or power). Test on AC power, in Best performance mode, on a hard surface; update Surface UEFI/SMF firmware and the Intel Dynamic Tuning (DTT) driver; check event ID 37.' 'Throttling'
    }
    if ($null -ne $perfAvg) {
        Add-Metric '% Processor Performance avg' ([math]::Round($perfAvg, 1)) '%'
        $sev = 'GREEN'; $obs = '{0:N1}% of base avg, max {1:N1}%, CPU load {2:N1}%' -f $perfAvg, $perfMax, $cpuAvg
        if ($perfAvg -lt 50 -and $null -ne $cpuAvg -and $cpuAvg -ge 25) { $sev = 'RED' }
        elseif ($perfAvg -lt 80 -and $null -ne $cpuAvg -and $cpuAvg -ge 25) { $sev = 'AMBER' }
        elseif ($perfAvg -lt 80) { $sev = 'INFO'; $obs += ' (low load - may be normal idle down-clocking)' }
        Add-Finding $sev 'Sustained clock vs base speed' $obs 'RED < 50% of base while CPU >= 25% busy; AMBER < 80% of base while busy' 'Clock held below base under load = throttling. Correlate with thermal zones, power mode, battery health and event ID 37. Re-run while the machine feels slow.' 'Throttling'
    }
    foreach ($z in $zoneSummary) {
        if ($null -ne $z.PassiveLimitPct_Min -and $z.PassiveLimitPct_Min -lt 100) {
            Add-Finding 'RED' ('Thermal zone {0} is passively throttling' -f $z.Zone) ('PercentPassiveLimit min {0}%' -f $z.PassiveLimitPct_Min) 'RED if < 100%' 'Active thermal throttling. Check vents/fan, ambient temperature, sustained background load (sync/scan), and Surface firmware/DTT drivers.' 'Throttling'
        }
        if ($null -ne $z.TempC_Max -and $z.TempC_Max -gt 0) {
            $sev = Get-Severity $z.TempC_Max 80 90
            if ($sev -ne 'GREEN') { Add-Finding $sev ('High temperature in zone {0}' -f $z.Zone) ('{0} C max' -f $z.TempC_Max) 'AMBER >= 80 C, RED >= 90 C' 'Sustained high temperature will cause throttling. Reduce background load and check cooling.' 'Throttling' }
        }
        if ($z.ThrottleReasons -and $z.ThrottleReasons -ne '0') {
            Add-Finding 'AMBER' ('Thermal zone {0} reports throttle reasons' -f $z.Zone) ('ThrottleReasons = {0}' -f $z.ThrottleReasons) 'AMBER if non-zero' 'Firmware reports an active throttle reason; see thermal guidance above.' 'Throttling'
        }
    }
    foreach ($n in 'ActiveOverlayAcPowerScheme', 'ActiveOverlayDcPowerScheme') {
        if ($ctx[$n] -eq 'Best power efficiency') {
            Add-Finding 'AMBER' "Power mode set to Best power efficiency ($n)" $ctx[$n] 'AMBER if Best power efficiency' 'Settings > System > Power & battery > Power mode: choose Balanced or Best performance (especially on AC).' 'Throttling'
        }
    }
    $ptm = $ctx['PROCTHROTTLEMAX']
    if ($ptm -and ($ptm[0] -lt 100 -or $ptm[1] -lt 100)) {
        Add-Finding 'AMBER' 'Maximum processor state below 100%' ('AC {0}% / DC {1}%' -f $ptm[0], $ptm[1]) 'AMBER if < 100%' 'A power plan or policy caps the CPU. Review the plan (powercfg /query SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX) and any GPO/MDM power policy.' 'Throttling'
    }
    $boost = $ctx['PERFBOOSTMODE']
    if ($boost -and ($boost[0] -eq 0 -or $boost[1] -eq 0)) {
        Add-Finding 'AMBER' 'Turbo boost disabled in power plan' ('PERFBOOSTMODE AC {0} / DC {1} (0 = disabled)' -f $boost[0], $boost[1]) 'AMBER if 0' 'Turbo is disabled by the power plan; review the plan or policy.' 'Throttling'
    }
    if ($ctx['EnergySaver'] -eq 'On') {
        Add-Finding 'AMBER' 'Energy saver is ON' 'EnergySaverStatus = On' 'AMBER if On' 'Energy saver reduces performance and can pause OneDrive sync. Plug in / turn it off before judging performance.' 'Throttling'
    }
    if ($ctx['OnBattery']) {
        Add-Finding 'INFO' 'Running on battery during this report' 'BatteryStatus = Discharging' 'n/a' 'Re-run on AC for a fair comparison; Surface firmware limits power on battery.'
    }
    $bh = $ctx['BatteryHealth']
    if ($null -ne $bh) {
        Add-Finding (Get-Severity $bh 70 50 -LowerIsWorse) 'Battery health (full-charge vs design capacity)' ("$bh% of design capacity") 'AMBER <= 70%, RED <= 50%' 'A worn battery can make Surface firmware limit peak power even on AC. Generate powercfg /batteryreport for detail and consider a battery service.' 'Throttling'
    }
}
#endregion

#region ------------------------------------------------------------------ Check 5: Disk health and space
function Test-Disk {
    Invoke-Step 'Volumes' {
        $vols = @(Get-Volume -ErrorAction Stop | Where-Object { $_.DriveType -eq 'Fixed' -and $_.Size -gt 0 } | ForEach-Object {
            [pscustomobject]@{
                Drive = $_.DriveLetter; Label = $_.FileSystemLabel; FileSystem = $_.FileSystem
                SizeGB = [math]::Round($_.Size / 1GB, 1); FreeGB = [math]::Round($_.SizeRemaining / 1GB, 1)
                FreePct = [math]::Round($_.SizeRemaining / $_.Size * 100, 1); Health = $_.HealthStatus
            }
        })
        Add-Heading 'Fixed volumes'
        Add-Table $vols
        Export-Raw $vols 'volumes.csv'
        $sysLetter = ($env:SystemDrive).TrimEnd(':')
        foreach ($v in $vols) {
            if (-not $v.Drive) { continue }
            $sev = 'GREEN'
            if ($v.FreePct -le 10 -or $v.FreeGB -le 10) { $sev = 'RED' } elseif ($v.FreePct -le 20 -or $v.FreeGB -le 25) { $sev = 'AMBER' }
            if ([string]$v.Drive -eq $sysLetter) { Add-Metric 'System drive free' $v.FreeGB 'GB' }
            Add-Finding $sev ('Free space on {0}:' -f $v.Drive) ('{0} GB free of {1} GB ({2}%)' -f $v.FreeGB, $v.SizeGB, $v.FreePct) 'AMBER <= 20% or 25 GB, RED <= 10% or 10 GB' 'Free space: Storage Sense, Disk Cleanup, and OneDrive "Free up space" on large folders (converts them to online-only).' 'DiskIO'
            if ($v.Health -and [string]$v.Health -ne 'Healthy') { Add-Finding 'RED' ('Volume {0}: health {1}' -f $v.Drive, $v.Health) ([string]$v.Health) 'RED if not Healthy' 'Run chkdsk <drive>: /scan (online, read-only scan) and review NTFS events.' 'DiskIO' }
        }
    }

    Invoke-Step 'Physical disks and reliability counters' {
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($d in @(Get-PhysicalDisk -ErrorAction Stop)) {
            $rc = $null
            if ($script:IsAdmin) { try { $rc = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch { } }
            $rows.Add([pscustomobject]@{
                Disk = $d.FriendlyName; Media = [string]$d.MediaType; Bus = [string]$d.BusType
                SizeGB = [math]::Round($d.Size / 1GB, 0); Firmware = $d.FirmwareVersion
                Health = [string]$d.HealthStatus; Operational = (@($d.OperationalStatus) -join ',')
                TempC = Get-PropValue $rc 'Temperature'; TempMaxC = Get-PropValue $rc 'TemperatureMax'
                WearPct = Get-PropValue $rc 'Wear'; PowerOnHours = Get-PropValue $rc 'PowerOnHours'
                ReadErrorsUncorrected = Get-PropValue $rc 'ReadErrorsUncorrected'; WriteErrorsUncorrected = Get-PropValue $rc 'WriteErrorsUncorrected'
                ReadLatencyMaxMs = Get-PropValue $rc 'ReadLatencyMax'; WriteLatencyMaxMs = Get-PropValue $rc 'WriteLatencyMax'
            })
        }
        Add-Heading 'Physical disks (SMART / NVMe reliability counters)'
        Add-Table $rows.ToArray()
        Export-Raw $rows.ToArray() 'physical_disks.csv'
        if (-not $script:IsAdmin) { Add-Note 'Reliability counters (wear, temperature, errors) need elevation.' }
        foreach ($r in $rows) {
            if ($r.Health -ne 'Healthy') { Add-Finding 'RED' ('Disk {0} health: {1}' -f $r.Disk, $r.Health) $r.Health 'RED if not Healthy' 'Back up now and contact Surface support.' 'DiskIO' }
            else { Add-Finding 'GREEN' ('Disk {0} health' -f $r.Disk) 'Healthy' 'RED if not Healthy' }
            if ($null -ne $r.WearPct) {
                Add-Metric ("Disk wear ({0})" -f $r.Disk) $r.WearPct '%'
                Add-Finding (Get-Severity $r.WearPct 70 90) ('SSD wear {0}' -f $r.Disk) ('{0}% of rated endurance used' -f $r.WearPct) 'AMBER >= 70%, RED >= 90%' 'High wear lowers write performance; plan replacement.' 'DiskIO'
            }
            if ($null -ne $r.TempC -and $r.TempC -gt 0) {
                $sev = Get-Severity $r.TempC 70 80
                if ($sev -ne 'GREEN') { Add-Finding $sev ('SSD temperature {0}' -f $r.Disk) ('{0} C now, {1} C max' -f $r.TempC, $r.TempMaxC) 'AMBER >= 70 C, RED >= 80 C' 'NVMe drives throttle when hot; sustained sync I/O plus poor cooling can trigger this.' 'DiskIO' }
            }
            $unc = [double](Get-PropValue $r 'ReadErrorsUncorrected' 0) + [double](Get-PropValue $r 'WriteErrorsUncorrected' 0)
            if ($unc -gt 0) { Add-Finding 'RED' ('Uncorrected media errors on {0}' -f $r.Disk) "$unc uncorrected read/write errors" 'RED if > 0' 'Back up and arrange disk replacement.' 'DiskIO' }
        }
    }

    Invoke-Step 'TRIM state' {
        $trim = (& fsutil.exe behavior query DisableDeleteNotify | Out-String).Trim()
        Add-Heading 'TRIM (fsutil behavior query DisableDeleteNotify)'
        Add-Pre $trim
        if ($trim -match 'NTFS DisableDeleteNotify\s*=\s*1') { Add-Finding 'AMBER' 'TRIM disabled for NTFS' 'DisableDeleteNotify = 1' 'AMBER if 1' 'Re-enable TRIM (fsutil behavior set DisableDeleteNotify 0) after confirming why it was disabled.' 'DiskIO' }
    }

    Invoke-Step 'BitLocker conversion state' {
        if (-not $script:IsAdmin) { Add-Note 'BitLocker state needs elevation - skipped.'; return }
        if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { Add-Note 'BitLocker module not available.'; return }
        $bl = @(Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, EncryptionMethod)
        Add-Heading 'BitLocker'
        Add-Table $bl
        foreach ($b in $bl) {
            if ([string]$b.VolumeStatus -match 'InProgress') { Add-Finding 'AMBER' ('BitLocker conversion in progress on {0}' -f $b.MountPoint) ('{0}, {1}%' -f $b.VolumeStatus, $b.EncryptionPercentage) 'AMBER while converting' 'Encryption/decryption adds background I/O until complete.' 'DiskIO' }
        }
    }

    Invoke-Step 'Disk-related events (7 days)' {
        $providers = @('disk', 'Ntfs', 'Microsoft-Windows-Ntfs', 'stornvme', 'storahci', 'Microsoft-Windows-StorPort', 'iaStorAC', 'iaStorAVC', 'iaStorVD', 'volmgr', 'volsnap')
        $ev = @(Get-CachedEvents 'System' | Where-Object { $providers -contains $_.ProviderName })
        $sum = @($ev | Group-Object ProviderName, Id | ForEach-Object {
            $last = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
            [pscustomobject]@{ Provider = $last.ProviderName; Id = $last.Id; Count = $_.Count; MostRecent = $last.TimeCreated; Example = (Get-ShortText $last.Message 300) }
        } | Sort-Object Count -Descending)
        Add-Heading 'Disk / storage events, last 7 days (warning and above)'
        Add-Table $sum
        $serious = @($ev | Where-Object { @(7, 11, 51, 129, 153, 154, 55, 50, 140) -contains $_.Id })
        if ($serious.Count -gt 0) {
            Add-Finding 'RED' 'Storage error events in the last 7 days' ('{0} events (IDs: {1})' -f $serious.Count, ((@($serious | ForEach-Object { $_.Id } | Sort-Object -Unique)) -join ', ')) 'RED if any disk 7/11/51/153/154, storport 129, NTFS 50/55/140' 'Resets/timeouts (129, 153) and bad blocks (7) cause freezes. Update storage/Surface firmware; run chkdsk /scan; check disk health.' 'DiskIO'
        } elseif ($ev.Count -gt 0) {
            Add-Finding 'AMBER' 'Storage warnings in the last 7 days' ('{0} events' -f $ev.Count) 'AMBER if any warnings' 'Review the table above.' 'DiskIO'
        } else { Add-Finding 'GREEN' 'No storage warnings/errors in 7 days' '0 events' 'AMBER if any' }
    }
}
#endregion

#region ------------------------------------------------------------------ Check 6: OneDrive
# Enumerate OneDrive accounts / synced libraries for every loaded user hive.
function Get-OneDriveAccounts {
    $rows = New-Object System.Collections.Generic.List[object]
    $sids = @(Get-ChildItem -Path Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object { $_.PSChildName })
    foreach ($sid in $sids) {
        $user = $sid
        try { $user = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
        $base = "Registry::HKEY_USERS\$sid\Software\Microsoft\OneDrive"
        $ver = Get-RegValue $base 'Version'
        foreach ($k in @(Get-ChildItem -Path "$base\Accounts" -ErrorAction SilentlyContinue)) {
            $folder = $k.GetValue('UserFolder', $null)
            if (-not $folder) { continue }
            $type = 'Personal'; if ($k.PSChildName -like 'Business*') { $type = 'Business' }
            $rows.Add([pscustomobject]@{ User = $user; Source = 'Account'; Id = $k.PSChildName; Type = $type; Name = $k.GetValue('DisplayName', ''); Path = $folder; ClientVersion = $ver })
        }
        foreach ($k in @(Get-ChildItem -Path "Registry::HKEY_USERS\$sid\Software\SyncEngines\Providers\OneDrive" -ErrorAction SilentlyContinue)) {
            $mp = $k.GetValue('MountPoint', $null)
            if (-not $mp) { continue }
            $rows.Add([pscustomobject]@{ User = $user; Source = 'Synced library / shortcut'; Id = $k.PSChildName; Type = [string]$k.GetValue('LibraryType', ''); Name = [string]$k.GetValue('UrlNamespace', ''); Path = $mp; ClientVersion = $ver })
        }
    }
    return $rows.ToArray()
}

# Recursive count with time budget. Uses the compiled helper, else a PowerShell fallback.
function Measure-FolderTree {
    param([string]$Root, [int]$TimeLimit)
    if ($script:NativeLoaded) { return [SlowPCReport.Native]::CountFiles($Root, $TimeLimit) }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = [pscustomobject]@{ Root = $Root; Files = [long]0; Directories = [long]0; Bytes = [long]0; OnlineOnly = [long]0; LocallyAvailable = [long]0; AlwaysKeep = [long]0; AccessErrors = [long]0; TimedOut = $false; ElapsedSeconds = 0.0 }
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Root)
    while ($stack.Count -gt 0 -and -not $r.TimedOut) {
        $dir = $stack.Pop()
        try {
            foreach ($i in (New-Object System.IO.DirectoryInfo($dir)).EnumerateFileSystemInfos()) {
                $a = [int]$i.Attributes
                if ($a -band 0x10) { $r.Directories++; $stack.Push($i.FullName); continue }
                $r.Files++
                try { $r.Bytes += $i.Length } catch { }
                if (($a -band 0x400000) -or ($a -band 0x40000)) { $r.OnlineOnly++ } else { $r.LocallyAvailable++ }
                if ($a -band 0x80000) { $r.AlwaysKeep++ }
            }
        } catch { $r.AccessErrors++ }
        if ($sw.Elapsed.TotalSeconds -ge $TimeLimit) { $r.TimedOut = $true }
    }
    $r.ElapsedSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    return $r
}

function Test-OneDrive {
    $ctx = @{}
    $procNames = @('OneDrive.exe', 'FileSyncHelper.exe', 'FileCoAuth.exe', 'OneDriveStandaloneUpdater.exe', 'Microsoft.SharePoint.exe')
    $procs = @(Get-ProcsSafe | Where-Object { $procNames -contains $_.Name })

    Add-Heading 'OneDrive processes (measured during the performance window)'
    if ($procs.Count -gt 0) {
        Add-Table @($procs | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; PID = $_.PID; CPUPct = $_.CPUPct; CPUTotalSec = $_.CPUTotalSec; WorkingSetMB = $_.WorkingSetMB; PrivateMB = $_.PrivateMB; Handles = $_.Handles; Threads = $_.Threads; Started = $_.Started; Version = (Get-FileVersion $_.Path); Path = $_.Path }
        })
    } else { Add-Note 'OneDrive.exe is not running.' }

    $od = @($procs | Where-Object { $_.Name -eq 'OneDrive.exe' })
    $syncProcs = @($procs | Where-Object { $_.Name -in @('OneDrive.exe', 'FileSyncHelper.exe', 'Microsoft.SharePoint.exe') })
    $odCpu = 0.0; $odHandles = 0; $odWs = 0.0
    foreach ($p in $syncProcs) { if ($null -ne $p.CPUPct) { $odCpu += $p.CPUPct }; $odHandles += $p.Handles; $odWs += $p.WorkingSetMB }

    # Accounts and folders
    $accounts = @()
    Invoke-Step 'OneDrive accounts (registry)' {
        $a = @(Get-OneDriveAccounts)
        foreach ($e in 'OneDrive', 'OneDriveCommercial', 'OneDriveConsumer') {
            $v = [Environment]::GetEnvironmentVariable($e)
            if ($v) { $a += [pscustomobject]@{ User = $env:USERNAME; Source = "Env:$e"; Id = ''; Type = ''; Name = ''; Path = $v; ClientVersion = '' } }
        }
        $ctx['Accounts'] = $a
    }
    $accounts = @($ctx['Accounts'] | Where-Object { $null -ne $_ })
    Add-Heading 'OneDrive accounts, synced libraries and shortcuts'
    Add-Table $accounts
    Export-Raw $accounts 'onedrive_accounts.csv'

    # Unique, non-nested, existing roots
    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($p in @($accounts | ForEach-Object { ([string]$_.Path).TrimEnd('\') } | Where-Object { $_ } | Sort-Object -Unique | Sort-Object Length)) {
        $nested = $false
        foreach ($r in $roots) { if ($p -ieq $r -or $p.StartsWith($r + '\', [StringComparison]::OrdinalIgnoreCase)) { $nested = $true; break } }
        if (-not $nested -and (Test-Path -LiteralPath $p)) { $roots.Add($p) }
    }
    $script:OneDriveRoots = $roots.ToArray()

    # File counts (metadata only, placeholders are not hydrated)
    $counts = New-Object System.Collections.Generic.List[object]
    Invoke-Step 'OneDrive file counts' {
        $budget = [System.Diagnostics.Stopwatch]::StartNew()
        foreach ($root in $roots) {
            $remaining = [int]($FileCountTimeLimitSeconds - $budget.Elapsed.TotalSeconds)
            if ($remaining -lt 5) { $counts.Add([pscustomobject]@{ Root = $root; Files = $null; Directories = $null; SizeGB = $null; OnlineOnly = $null; LocallyAvailable = $null; AlwaysKeep = $null; AccessErrors = $null; TimedOut = $true; ElapsedSeconds = 0 }); continue }
            Write-Status ("  Counting files under {0} (budget {1}s)..." -f $root, $remaining)
            Write-Progress -Id 1 -Activity 'Counting OneDrive files (read-only, no hydration)' -Status $root
            $res = Measure-FolderTree -Root $root -TimeLimit $remaining
            $counts.Add([pscustomobject]@{ Root = $root; Files = $res.Files; Directories = $res.Directories; SizeGB = [math]::Round($res.Bytes / 1GB, 2); OnlineOnly = $res.OnlineOnly; LocallyAvailable = $res.LocallyAvailable; AlwaysKeep = $res.AlwaysKeep; AccessErrors = $res.AccessErrors; TimedOut = $res.TimedOut; ElapsedSeconds = $res.ElapsedSeconds })
        }
        Write-Progress -Id 1 -Activity 'Counting OneDrive files (read-only, no hydration)' -Completed
    }
    Add-Heading ('File counts per OneDrive root (time budget {0}s total)' -f $FileCountTimeLimitSeconds)
    Add-Table $counts.ToArray()
    Add-Note 'Counts come from directory enumeration metadata only; online-only placeholders are not downloaded. SizeGB is logical size (includes online-only files). TimedOut = True means the count is a lower bound.'
    Export-Raw $counts.ToArray() 'onedrive_file_counts.csv'

    $totalFiles = [long]0; $partial = $false; $online = [long]0; $local = [long]0
    foreach ($c in $counts) { if ($null -ne $c.Files) { $totalFiles += $c.Files; $online += $c.OnlineOnly; $local += $c.LocallyAvailable }; if ($c.TimedOut) { $partial = $true } }

    # Files On-Demand and cldflt
    $fodInfo = [ordered]@{}
    $fodPolicy = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' 'FilesOnDemandEnabled'
    $fodInfo['FilesOnDemandEnabled policy (HKLM)'] = if ($null -ne $fodPolicy) { $fodPolicy } else { 'Not set' }
    $fodInfo['Online-only placeholders found'] = $online
    $fodInfo['Locally available files found'] = $local
    $fodInfo['Files On-Demand state (inferred)'] = if ($online -gt 0) { 'Active (placeholders present)' } elseif ($totalFiles -gt 0) { 'No online-only placeholders found (all files local)' } else { 'Unknown' }
    Invoke-Step 'Cloud Files filter (cldflt.sys)' {
        $drv = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='CldFlt'" -ErrorAction Stop
        if ($drv) { $fodInfo['cldflt.sys driver'] = '{0} (start mode {1})' -f $drv.State, $drv.StartMode; $ctx['CldFlt'] = $drv.State } else { $fodInfo['cldflt.sys driver'] = 'Not found'; $ctx['CldFlt'] = 'Missing' }
        if ($script:IsAdmin) {
            $f = @(& fltmc.exe filters | Where-Object { $_ -match '^\s*CldFlt\s' })
            $fodInfo['cldflt minifilter (fltmc)'] = if ($f.Count -gt 0) { ($f[0] -replace '\s+', ' ').Trim() } else { 'Not attached' }
        }
    }
    Add-Heading 'Files On-Demand / Cloud Files filter'
    Add-KeyValue $fodInfo

    # Policies
    Invoke-Step 'OneDrive policies' {
        $pol = @(Get-RegValuesTable 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive')
        foreach ($sid in @(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object { $_.PSChildName })) {
            $pol += @(Get-RegValuesTable "Registry::HKEY_USERS\$sid\Software\Policies\Microsoft\OneDrive")
        }
        Add-Heading 'OneDrive policies (HKLM and per-user)'
        Add-Table $pol
    }

    # SyncDiagnostics.log (plain-text sync state written by the client)
    Invoke-Step 'SyncDiagnostics.log' {
        $usersRoot = Split-Path $env:PUBLIC -Parent
        $logs = @(Get-ChildItem -Path (Join-Path $usersRoot '*\AppData\Local\Microsoft\OneDrive\logs\*\SyncDiagnostics.log') -ErrorAction SilentlyContinue)
        Add-Heading 'SyncDiagnostics.log (key lines)'
        if ($logs.Count -eq 0) { Add-Note 'No SyncDiagnostics.log found (or no access to other profiles without elevation).'; return }
        foreach ($l in $logs) {
            $text = Read-FileTail -Path $l.FullName -MaxBytes 2MB
            $safe = ($l.FullName -replace '^.*\\Users\\', '' -replace '[\\:]', '_')
            Export-Raw $text ("onedrive_{0}.txt" -f $safe)
            $keep = @($text -split "`r?`n" | Where-Object { $_ -match '(?i)(SyncProgressState|Files?To|Bytes?To|Changes|Pending|Download|Upload|Scan|Error|Throttl|Quota|UtcNow|Drive|Total|Count)' } | Select-Object -First 80)
            Add-Html ('<p><b>' + (HE $l.FullName) + '</b> (last written ' + (HE $l.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) + ')</p>')
            Add-Pre ($keep -join "`r`n")
        }
    }

    # OneDrive-related events
    Invoke-Step 'OneDrive-related events (7 days)' {
        $ev = @(Get-CachedEvents 'Application' | Where-Object { $_.ProviderName -match 'OneDrive|FileSync|Cloud ?Files' -or (@('Application Error', 'Application Hang') -contains $_.ProviderName -and [string]$_.Message -match 'OneDrive\.exe|FileSyncHelper|FileCoAuth') })
        $ev += @(Get-CachedEvents 'System' | Where-Object { $_.ProviderName -match 'CldFlt|Cloud ?Files' })
        $ctx['Events'] = $ev.Count
        Add-Heading 'OneDrive-related warning/error events (7 days)'
        Add-Table @($ev | Sort-Object TimeCreated -Descending | Select-Object -First 50 | ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated; Log = $_.LogName; Provider = $_.ProviderName; Id = $_.Id; Message = (Get-ShortText $_.Message 300) } })
    }

    # ---- Metrics and findings
    Add-Metric 'OneDrive files (all roots)' $totalFiles 'files'
    Add-Metric 'OneDrive locally available files' $local 'files'
    Add-Metric 'OneDrive sync processes CPU' ([math]::Round($odCpu, 2)) '%'
    Add-Metric 'OneDrive sync processes handles' $odHandles 'count'
    Add-Metric 'OneDrive sync processes working set' ([math]::Round($odWs, 0)) 'MB'

    $partialText = ''; if ($partial) { $partialText = ' (partial - time budget reached, true total is higher)' }
    if ($roots.Count -eq 0) {
        Add-Finding 'INFO' 'No OneDrive folders found' 'No accounts in loaded user hives' 'n/a' 'Run the script as the user who signs in to OneDrive (elevated), so their hive is loaded.'
    } else {
        $sev = 'GREEN'; if ($totalFiles -gt 300000) { $sev = 'RED' } elseif ($totalFiles -gt 150000) { $sev = 'AMBER' } elseif ($partial) { $sev = 'INFO' }
        Add-Finding $sev 'Total files in OneDrive-synced folders' ('{0:N0} files across {1} root(s){2}; {3:N0} online-only, {4:N0} local' -f $totalFiles, $roots.Count, $partialText, $online, $local) 'AMBER > 150,000, RED > 300,000 (Microsoft guidance: best performance below 300,000 files)' 'Reduce the synced set: stop syncing unneeded SharePoint libraries and "Add shortcut to My files" shortcuts, use Choose folders, and let the initial sync finish. Then re-run with -Label AfterSync.' 'OneDriveSync'
    }
    if ($od.Count -eq 0 -and $roots.Count -gt 0) {
        Add-Finding 'AMBER' 'OneDrive is configured but not running' 'OneDrive.exe not found' 'AMBER' 'If it crashed or was closed, the sync backlog will resume on next start. Check the events table.' 'OneDriveSync'
    }
    if ($syncProcs.Count -gt 0) {
        Add-Finding (Get-Severity $odCpu 10 25) 'OneDrive CPU during sample' ('{0:N1}% of total CPU' -f $odCpu) 'AMBER >= 10%, RED >= 25%' 'Expected while a large backlog processes. Pause sync (OneDrive icon > Pause syncing) as a test; if the machine recovers, sync load is the cause.' 'OneDriveSync'
        Add-Finding (Get-Severity $odHandles 20000 50000) 'OneDrive handle count' ('{0:N0} handles' -f $odHandles) 'AMBER >= 20,000, RED >= 50,000' 'High and rising handle count across runs suggests a client leak: update OneDrive and restart it.' 'OneDriveSync'
        Add-Finding (Get-Severity $odWs 1024 2048) 'OneDrive memory (working set)' ('{0:N0} MB' -f $odWs) 'AMBER >= 1 GB, RED >= 2 GB' 'Large file sets increase client memory; reducing the synced set is the lasting fix.' 'OneDriveSync'
    }
    if ($roots.Count -gt 0 -and $ctx['CldFlt'] -and $ctx['CldFlt'] -ne 'Running') {
        Add-Finding 'AMBER' 'Cloud Files filter driver not running' ('cldflt state: {0}' -f $ctx['CldFlt']) 'AMBER if not Running' 'Files On-Demand depends on cldflt.sys; check the CldFlt service configuration.' 'OneDriveSync'
    }
    if ($local -gt 200000) {
        Add-Finding 'AMBER' 'Very many locally available OneDrive files' ('{0:N0} files stored locally' -f $local) 'AMBER > 200,000' 'Every hydrated file is scanned by Defender and indexed by Search. Use "Free up space" on folders that do not need to be offline.' 'OneDriveSync'
    }
    if ($ctx['Events'] -gt 0) {
        Add-Finding 'AMBER' 'OneDrive-related errors in event logs' ('{0} events in 7 days' -f $ctx['Events']) 'AMBER if any' 'Review the events table; crashes/hangs of OneDrive.exe restart sync processing from scratch.' 'OneDriveSync'
    }
}
#endregion

#region ------------------------------------------------------------------ Check 7: Windows Search and Defender
function Test-SearchDefender {
    $ctx = @{}
    $procs = @(Get-ProcsSafe)
    $cols = @('Name', 'PID', 'CPUPct', 'CPUTotalSec', 'WorkingSetMB', 'PrivateMB', 'Handles', 'Threads', 'Started')

    # ---------------- Windows Search
    $sp = @($procs | Where-Object { $_.Name -in @('SearchIndexer.exe', 'SearchProtocolHost.exe', 'SearchFilterHost.exe') })
    $idxCpu = 0.0; foreach ($p in $sp) { if ($null -ne $p.CPUPct) { $idxCpu += $p.CPUPct } }
    Add-Heading 'Windows Search processes'
    Add-Table $sp $cols
    $sinfo = [ordered]@{}
    Invoke-Step 'WSearch service' {
        $svc = Get-Service -Name WSearch -ErrorAction Stop
        $sinfo['WSearch service'] = '{0} (start type {1})' -f $svc.Status, $svc.StartType
    }
    Invoke-Step 'Index database files' {
        if (-not $script:IsAdmin) { Add-Note 'Index database size needs elevation - skipped.'; return }
        $dataDir = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows Search' 'DataDirectory'
        if (-not $dataDir) { $dataDir = Join-Path $env:ProgramData 'Microsoft\Search\Data\' }
        $dir = Join-Path $dataDir 'Applications\Windows'
        $files = @(Get-ChildItem -LiteralPath $dir -File -ErrorAction Stop | Where-Object { $_.Name -match '^Windows.*\.(edb|db)$' })
        $total = 0.0; foreach ($f in $files) { $total += $f.Length }
        $sinfo['Index location'] = $dir
        $sinfo['Index database size (MB)'] = ConvertTo-MB $total
        $ctx['IndexMB'] = ConvertTo-MB $total
    }
    Invoke-Step 'Index item count (Search OLE DB, 30 s cap)' {
        $conn = New-Object -ComObject ADODB.Connection
        $rs = New-Object -ComObject ADODB.Recordset
        try {
            $conn.CommandTimeout = 120
            $conn.Open("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';")
            try { $rs.Open('SELECT System.ItemUrl FROM SYSTEMINDEX', $conn) }
            catch { $sinfo['Indexed items visible to this account'] = 'Not available (query failed/timed out: ' + $_.Exception.Message + ')'; return }
            $sw = [System.Diagnostics.Stopwatch]::StartNew(); $n = 0; $partial = $false
            while (-not $rs.EOF) {
                $n++; $rs.MoveNext()
                if (($n % 1000) -eq 0 -and $sw.Elapsed.TotalSeconds -gt 30) { $partial = $true; break }
            }
            $sinfo['Indexed items visible to this account'] = if ($partial) { ">= $n (30 s cap reached)" } else { $n }
            $ctx['IndexCount'] = $n
        } finally {
            try { $rs.Close() } catch { }
            try { $conn.Close() } catch { }
        }
    }
    Invoke-Step 'Search performance counters' {
        $sets = @(Get-Counter -ListSet 'Search Indexer', 'Search Gatherer', 'Search Gatherer Projects' -ErrorAction SilentlyContinue)
        $paths = New-Object System.Collections.Generic.List[string]
        foreach ($s in $sets) {
            if ([string]$s.CounterSetType -eq 'SingleInstance') { foreach ($p in $s.Paths) { $paths.Add($p) } }
            else { foreach ($p in @($s.PathsWithInstances | Where-Object { $_ -match 'SystemIndex' })) { $paths.Add($p) } }
        }
        if ($paths.Count -gt 0) {
            $res = Get-Counter -Counter $paths.ToArray() -MaxSamples 1 -ErrorAction SilentlyContinue
            if ($res) {
                Add-Heading 'Search indexer counters (single sample)'
                Add-Table @($res.CounterSamples | ForEach-Object { [pscustomobject]@{ Counter = ($_.Path -replace '^\\\\[^\\]+', ''); Value = [math]::Round($_.CookedValue, 2) } }) -MaxRows 80
            }
        }
    }
    Invoke-Step 'Indexed locations' {
        $rulesKey = 'HKLM:\SOFTWARE\Microsoft\Windows Search\CrawlScopeManager\Windows\SystemIndex\WorkingSetRules'
        $rules = @(Get-ChildItem -Path $rulesKey -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ URL = $_.GetValue('URL', ''); Include = $_.GetValue('Include', ''); Default = $_.GetValue('Default', '') } })
        Add-Heading 'Index scope rules (Include 1 = indexed)'
        Add-Table $rules
    }
    Add-KeyValue $sinfo
    Add-Metric 'Search indexer CPU' ([math]::Round($idxCpu, 2)) '%'
    if ($null -ne $ctx['IndexCount']) { Add-Metric 'Indexed items (visible)' $ctx['IndexCount'] 'items' }
    if ($null -ne $ctx['IndexMB']) { Add-Metric 'Index database size' $ctx['IndexMB'] 'MB' }

    Add-Finding (Get-Severity $idxCpu 10 25) 'Search indexer CPU during sample' ('{0:N1}% of total CPU' -f $idxCpu) 'AMBER >= 10%, RED >= 25%' 'Indexing a large new OneDrive file set is CPU/disk heavy. Temporarily exclude big synced folders (Settings > Privacy & security > Searching Windows > Excluded folders) until sync completes.' 'Indexer'
    if ($null -ne $ctx['IndexMB']) { Add-Finding (Get-Severity $ctx['IndexMB'] 4096 10240) 'Search index database size' ('{0:N0} MB' -f $ctx['IndexMB']) 'AMBER >= 4 GB, RED >= 10 GB' 'A very large index slows queries and maintenance; consider narrowing scope or rebuilding the index after sync completes.' 'Indexer' }
    if ($null -ne $ctx['IndexCount'] -and $ctx['IndexCount'] -gt 500000) { Add-Finding 'AMBER' 'Very large number of indexed items' ('>= {0:N0} items' -f $ctx['IndexCount']) 'AMBER > 500,000' 'Narrow indexing scope for large synced libraries.' 'Indexer' }

    # ---------------- Defender
    $dp = @($procs | Where-Object { $_.Name -in @('MsMpEng.exe', 'MpDefenderCoreService.exe', 'NisSrv.exe', 'MsSense.exe') })
    $avCpu = 0.0; foreach ($p in $dp) { if ($null -ne $p.CPUPct) { $avCpu += $p.CPUPct } }
    Add-Heading 'Defender processes'
    Add-Table $dp $cols
    Add-Metric 'Defender CPU' ([math]::Round($avCpu, 2)) '%'
    if ($dp.Count -gt 0) {
        Add-Finding (Get-Severity $avCpu 10 25) 'Defender (MsMpEng) CPU during sample' ('{0:N1}% of total CPU' -f $avCpu) 'AMBER >= 10%, RED >= 25%' 'Every file OneDrive writes is scanned on access. Record a scan-performance trace (New-MpPerformanceRecording, then Get-MpPerformanceReport) to see the hottest paths/processes. Do not exclude OneDrive folders without a risk review.' 'AVScan'
    }
    Invoke-Step 'Get-MpComputerStatus' {
        if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { Add-Note 'Defender module not available.'; return }
        $st = Get-MpComputerStatus -ErrorAction Stop
        $d = [ordered]@{}
        foreach ($n in 'AMRunningMode', 'AMProductVersion', 'AMServiceEnabled', 'AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled', 'OnAccessProtectionEnabled', 'IoavProtectionEnabled', 'IsTamperProtected', 'AntivirusSignatureAge', 'AntivirusSignatureLastUpdated', 'QuickScanStartTime', 'QuickScanEndTime', 'QuickScanAge', 'FullScanStartTime', 'FullScanEndTime', 'FullScanAge') {
            $d[$n] = Get-PropValue $st $n
        }
        Add-Heading 'Defender status (Get-MpComputerStatus)'
        Add-KeyValue $d
        $qs = $d['QuickScanStartTime']; $qe = $d['QuickScanEndTime']; $fs = $d['FullScanStartTime']; $fe = $d['FullScanEndTime']
        if (($qs -and $qe -and $qs -gt $qe) -or ($fs -and $fe -and $fs -gt $fe)) {
            Add-Finding 'AMBER' 'A Defender scan appears to be in progress (or was interrupted)' ('Quick {0} -> {1}; Full {2} -> {3}' -f (Format-Value $qs), (Format-Value $qe), (Format-Value $fs), (Format-Value $fe)) 'AMBER if last start > last end' 'A scheduled/catch-up scan over hundreds of thousands of new files is heavy; let it finish or schedule for idle time.' 'AVScan'
        }
        if ($d['RealTimeProtectionEnabled'] -eq $false -and [string]$d['AMRunningMode'] -eq 'Normal') { Add-Finding 'AMBER' 'Defender real-time protection is off' 'RealTimeProtectionEnabled = False' 'AMBER (security)' 'Confirm this is intentional / managed by policy.' '' }
        $sigAge = $d['AntivirusSignatureAge']
        if ($null -ne $sigAge -and $sigAge -ge 0 -and $sigAge -lt 65535) { Add-Finding (Get-Severity $sigAge 3 7) 'Defender signature age' "$sigAge days" 'AMBER >= 3 days, RED >= 7 days' 'Check Windows Update / Defender update source.' 'Updates' }
    }
    Invoke-Step 'Get-MpPreference (exclusions and scan settings)' {
        if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) { return }
        $pref = Get-MpPreference -ErrorAction Stop
        $d = [ordered]@{}
        foreach ($n in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ScanAvgCPULoadFactor', 'EnableLowCpuPriority', 'ScanOnlyIfIdleEnabled', 'ScanScheduleDay', 'ScanScheduleTime', 'DisableCatchupFullScan', 'DisableCatchupQuickScan', 'DisableArchiveScanning', 'MAPSReporting', 'CloudBlockLevel', 'DisableRealtimeMonitoring') {
            $d[$n] = Get-PropValue $pref $n
        }
        Add-Heading 'Defender configuration (Get-MpPreference)'
        Add-KeyValue $d
        if (-not $script:IsAdmin) { Add-Note 'Exclusion lists are only visible when elevated.' }
    }
}
#endregion

#region ------------------------------------------------------------------ Check 8: Startup and background load
function Get-StartupApprovedMap {
    # StartupApproved\*: first byte odd (03/07...) = disabled in Task Manager / Settings.
    $map = @{}
    $hives = @('HKLM:')
    foreach ($sid in @(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object { $_.PSChildName })) { $hives += "Registry::HKEY_USERS\$sid" }
    foreach ($h in $hives) {
        foreach ($sub in 'Run', 'Run32', 'StartupFolder') {
            try {
                $k = Get-Item -LiteralPath "$h\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$sub" -ErrorAction Stop
                foreach ($n in $k.GetValueNames()) {
                    $b = $k.GetValue($n)
                    if ($b -is [byte[]] -and $b.Length -gt 0) { $map[$n.ToLowerInvariant()] = (($b[0] -band 1) -eq 0) }
                }
            } catch { }
        }
    }
    return $map
}

function Test-Startup {
    $ctx = @{}
    $procs = @(Get-ProcsSafe)
    $byName = @{}; $byPid = @{}
    foreach ($p in $procs) {
        $k = $p.Name.ToLowerInvariant()
        if (-not $byName.ContainsKey($k)) { $byName[$k] = New-Object System.Collections.Generic.List[object] }
        $byName[$k].Add($p); $byPid[$p.PID] = $p
    }
    $impactOf = {
        param($ExeLeaf)
        $cpu = 0.0; $ws = 0.0
        if ($ExeLeaf -and $byName.ContainsKey($ExeLeaf.ToLowerInvariant())) { foreach ($p in $byName[$ExeLeaf.ToLowerInvariant()]) { $cpu += $p.CPUTotalSec; $ws += $p.WorkingSetMB } }
        return @($cpu, $ws)
    }

    # Boot / app-start degradation data (Diagnostics-Performance)
    $degr = @{}
    Invoke-Step 'Boot performance (Diagnostics-Performance, 30 days)' {
        $ev = @(Get-EventsSafe @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; StartTime = (Get-Date).AddDays(-30) } 1000)
        $boots = New-Object System.Collections.Generic.List[object]
        $deg = New-Object System.Collections.Generic.List[object]
        foreach ($e in $ev) {
            $d = Get-EventDataMap $e
            if ($e.Id -eq 100) {
                $boots.Add([pscustomobject]@{ Time = $e.TimeCreated; BootSec = [math]::Round([double](Get-PropValue $d 'BootTime' 0) / 1000, 1); MainPathSec = [math]::Round([double](Get-PropValue $d 'MainPathBootTime' 0) / 1000, 1); PostBootSec = [math]::Round([double](Get-PropValue $d 'BootPostBootTime' 0) / 1000, 1) })
            } elseif ($e.Id -ge 101 -and $e.Id -le 110) {
                $name = [string](Get-PropValue $d 'Name' (Get-PropValue $d 'FileName' ''))
                $ms = [double](Get-PropValue $d 'DegradationTime' 0)
                $deg.Add([pscustomobject]@{ Time = $e.TimeCreated; EventId = $e.Id; Name = $name; FriendlyName = (Get-PropValue $d 'FriendlyName' ''); TotalMs = (Get-PropValue $d 'TotalTime' ''); DegradationMs = $ms })
                if ($name) {
                    $leaf = (Split-Path $name -Leaf).ToLowerInvariant()
                    if ($degr.ContainsKey($leaf)) { $degr[$leaf] += $ms } else { $degr[$leaf] = $ms }
                }
            }
        }
        Add-Heading 'Recent boots (event 100)'
        Add-Table @($boots | Select-Object -First 10)
        Add-Heading 'Boot degradation events (101-110)'
        Add-Table @($deg | Sort-Object DegradationMs -Descending | Select-Object -First 25)
        if ($boots.Count -gt 0) {
            $avgBoot = (Get-Stats @($boots | Select-Object -First 5 | ForEach-Object { $_.BootSec })).Avg
            Add-Metric 'Boot time avg (last 5)' ([math]::Round($avgBoot, 1)) 's'
            Add-Finding (Get-Severity $avgBoot 90 180) 'Boot duration (Diagnostics-Performance)' ('{0:N0} s average over last {1} boots' -f $avgBoot, [math]::Min(5, $boots.Count)) 'AMBER >= 90 s, RED >= 180 s' 'Review degradation events and non-Microsoft startup items below.' 'StartupLoad'
        }
    }

    $approved = @{}
    try { $approved = Get-StartupApprovedMap } catch { }
    $items = New-Object System.Collections.Generic.List[object]

    Invoke-Step 'Run keys and Startup folders (Win32_StartupCommand)' {
        foreach ($s in @(Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction Stop)) {
            $exe = Get-ExePathFromCommand $s.Command
            $leaf = ''; if ($exe) { $leaf = Split-Path $exe -Leaf }
            $enabled = 'Unknown'
            foreach ($cand in @([string]$s.Name, [string]$s.Command, ([string]$s.Name + '.lnk'))) { if ($cand -and $approved.ContainsKey($cand.ToLowerInvariant())) { $enabled = $approved[$cand.ToLowerInvariant()]; break } }
            $imp = & $impactOf $leaf
            $d = 0.0; if ($leaf -and $degr.ContainsKey($leaf.ToLowerInvariant())) { $d = $degr[$leaf.ToLowerInvariant()] }
            $co = Get-FileCompany $exe
            $items.Add([pscustomobject]@{ Type = 'Run key / Startup folder'; Name = $s.Name; Enabled = $enabled; Company = $co; User = $s.User; Location = $s.Location; Command = $s.Command; RunningCPUSec = $imp[0]; RunningWSMB = $imp[1]; DegradationMs = $d; ImpactScore = [math]::Round($imp[0] + $imp[1] / 10 + $d / 100, 1) })
        }
    }

    Invoke-Step 'Scheduled tasks at logon/boot' {
        $msCount = 0
        foreach ($t in @(Get-ScheduledTask -ErrorAction Stop | Where-Object { [string]$_.State -ne 'Disabled' })) {
            $types = @(@($t.Triggers) | Where-Object { $null -ne $_ } | ForEach-Object { $_.CimClass.CimClassName })
            $isLogon = $types -contains 'MSFT_TaskLogonTrigger'; $isBoot = $types -contains 'MSFT_TaskBootTrigger'
            if (-not ($isLogon -or $isBoot)) { continue }
            if ($t.TaskPath -like '\Microsoft\*') { $msCount++; continue }
            $acts = @(@($t.Actions) | Where-Object { $null -ne $_ } | ForEach-Object { $e = Get-PropValue $_ 'Execute'; if ($e) { ('{0} {1}' -f $e, (Get-PropValue $_ 'Arguments' '')).Trim() } else { '[COM handler]' } })
            $exe = $null; if ($acts.Count -gt 0) { $exe = Get-ExePathFromCommand $acts[0] }
            $leaf = ''; if ($exe) { $leaf = Split-Path $exe -Leaf }
            $imp = & $impactOf $leaf
            $d = 0.0; if ($leaf -and $degr.ContainsKey($leaf.ToLowerInvariant())) { $d = $degr[$leaf.ToLowerInvariant()] }
            $trig = @(); if ($isLogon) { $trig += 'Logon' }; if ($isBoot) { $trig += 'Boot' }
            $items.Add([pscustomobject]@{ Type = 'Scheduled task (' + ($trig -join '+') + ')'; Name = ($t.TaskPath + $t.TaskName); Enabled = $true; Company = (Get-FileCompany $exe); User = (Get-PropValue $t.Principal 'UserId' ''); Location = $t.TaskPath; Command = ($acts -join ' | '); RunningCPUSec = $imp[0]; RunningWSMB = $imp[1]; DegradationMs = $d; ImpactScore = [math]::Round($imp[0] + $imp[1] / 10 + $d / 100, 1) })
        }
        $ctx['MsTasks'] = $msCount
    }

    Invoke-Step 'Auto-start non-Microsoft services' {
        foreach ($s in @(Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto'" -ErrorAction Stop)) {
            $img = Resolve-ImagePath $s.PathName
            if ($img -and (Split-Path $img -Leaf) -ieq 'svchost.exe') {
                $dll = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters" 'ServiceDll'
                if ($dll) { $img = [Environment]::ExpandEnvironmentVariables($dll) }
            }
            $co = Get-FileCompany $img
            if ($co -match 'Microsoft') { continue }
            $cpu = 0.0; $ws = 0.0
            if ($s.ProcessId -and $byPid.ContainsKey([int]$s.ProcessId)) { $p = $byPid[[int]$s.ProcessId]; $cpu = $p.CPUTotalSec; $ws = $p.WorkingSetMB }
            $items.Add([pscustomobject]@{ Type = 'Service (Auto)'; Name = ('{0} ({1})' -f $s.DisplayName, $s.Name); Enabled = [string]$s.State; Company = $co; User = $s.StartName; Location = 'Services'; Command = $s.PathName; RunningCPUSec = $cpu; RunningWSMB = $ws; DegradationMs = 0; ImpactScore = [math]::Round($cpu + $ws / 10, 1) })
        }
    }

    $all = @($items.ToArray())
    Export-Raw $all 'startup_items.csv'
    Add-Heading 'Top 20 startup / background items by estimated impact'
    Add-Note 'ImpactScore (heuristic) = total CPU seconds of matching running process(es) + working set MB / 10 + boot degradation ms / 100. CPU seconds accumulate since the process started, so compare between runs.'
    Add-Table @($all | Sort-Object ImpactScore -Descending | Select-Object -First 20)
    Add-Heading 'All startup items (Run keys, Startup folders, non-Microsoft logon/boot tasks, non-Microsoft auto services)'
    Add-Table @($all | Sort-Object Type, Name) -MaxRows 400
    Add-Note ('Microsoft logon/boot scheduled tasks (not listed): {0}' -f $ctx['MsTasks'])

    $nonMs = @($all | Where-Object { $_.Company -notmatch 'Microsoft' -and [string]$_.Enabled -ne 'False' })
    Add-Metric 'Non-Microsoft startup items' $nonMs.Count 'count'
    Add-Finding (Get-Severity $nonMs.Count 15 30) 'Non-Microsoft startup / background items' ('{0} enabled items' -f $nonMs.Count) 'AMBER >= 15, RED >= 30' 'Disable unneeded items in Task Manager > Startup apps, Task Scheduler, or services.msc (after confirming they are not required).' 'StartupLoad'
    $top = @($all | Sort-Object ImpactScore -Descending | Select-Object -First 3)
    if ($top.Count -gt 0) {
        Add-Finding 'INFO' 'Highest-impact startup items' ((@($top | ForEach-Object { '{0} (score {1})' -f $_.Name, $_.ImpactScore }) -join '; ')) 'Heuristic ranking' 'Review whether these need to start automatically.' ''
    }
}
#endregion

#region ------------------------------------------------------------------ Check 9: Drivers, firmware and updates
function Test-DriversUpdates {
    $ctx = @{}
    $now = Get-Date
    Invoke-Step 'PnP signed drivers' {
        $drv = @(Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop | Where-Object { $_.DeviceName } | ForEach-Object {
            $age = $null
            if ($_.DriverDate -and $_.DriverDate.Year -ge 1990) { $age = [math]::Round(($now - $_.DriverDate).TotalDays / 365.25, 1) }
            [pscustomobject]@{ Device = $_.DeviceName; Class = $_.DeviceClass; Provider = $_.DriverProviderName; Manufacturer = $_.Manufacturer; Version = $_.DriverVersion; Date = $_.DriverDate; AgeYears = $age; Inf = $_.InfName; Signed = $_.IsSigned }
        })
        Export-Raw $drv 'drivers.csv'

        $surfaceRx = '(?i)Surface|Management Engine|Graphics|Iris|UHD|Serial IO|Dynamic Tuning|Dynamic Platform|DPTF|Innovation Platform|Thermal|GNA|Smart Sound|Wi-?Fi|Wireless|Bluetooth|Precise Touch|HID Event Filter|Integrated Sensor|NVMe|Storage'
        $surf = @($drv | Where-Object { ($_.Device + ' ' + $_.Manufacturer + ' ' + $_.Provider) -match $surfaceRx } | Sort-Object Class, Device)
        Add-Heading 'Surface / platform-relevant drivers (Surface, Intel ME, graphics, DTT/thermal, Serial IO, wireless, storage)'
        Add-Table $surf @('Device', 'Class', 'Provider', 'Version', 'Date', 'AgeYears', 'Inf')

        $fw = @($drv | Where-Object { [string]$_.Class -eq 'FIRMWARE' })
        Add-Heading 'Firmware devices'
        Add-Table $fw @('Device', 'Provider', 'Version', 'Date', 'AgeYears')

        $old = @($drv | Where-Object { $_.Provider -notmatch 'Microsoft' -and $null -ne $_.AgeYears -and $_.AgeYears -gt 3 } | Sort-Object AgeYears -Descending)
        Add-Heading 'Non-Microsoft drivers older than 3 years'
        Add-Table $old @('Device', 'Class', 'Provider', 'Version', 'Date', 'AgeYears', 'Inf')
        Add-Note 'Dates before 1990 (e.g. Intel INF-only chipset entries dated 1968) are placeholders and excluded from age checks. Full list in drivers.csv.'
        if ($old.Count -gt 0) {
            Add-Finding 'AMBER' 'Non-Microsoft drivers older than 3 years' ('{0} drivers, e.g. {1}' -f $old.Count, ((@($old | Select-Object -First 4 | ForEach-Object { '{0} ({1:yyyy-MM-dd})' -f $_.Device, $_.Date }) -join '; '))) 'AMBER if any > 3 years' 'Install the latest Surface driver & firmware pack for this model (MSI from Microsoft) or check Windows Update optional driver updates.' 'Drivers'
        } else { Add-Finding 'GREEN' 'No non-Microsoft drivers older than 3 years' '0' 'AMBER if any > 3 years' }

        $gfx = @($drv | Where-Object { [string]$_.Class -eq 'DISPLAY' -and $_.Provider -match 'Intel' })
        foreach ($g in $gfx) { if ($null -ne $g.AgeYears -and $g.AgeYears -gt 2) { Add-Finding 'AMBER' 'Intel graphics driver is old' ('{0} {1} ({2:yyyy-MM-dd})' -f $g.Device, $g.Version, $g.Date) 'AMBER > 2 years' 'Update via the Surface driver pack / Windows Update (Surface uses OEM-customised graphics drivers).' 'Drivers' } }
        $dtt = @($drv | Where-Object { $_.Device -match '(?i)Dynamic Tuning|Dynamic Platform|DPTF|Innovation Platform' })
        if ($dtt.Count -eq 0 -and $script:CS -and $script:CS.Manufacturer -match 'Microsoft') {
            Add-Finding 'INFO' 'Intel thermal framework driver (DTT/DPTF) not found' 'No matching device' 'Informational' 'Most Intel Surface models ship Intel Dynamic Tuning; if missing, throttling can be more aggressive. Verify against the Surface driver pack for this model.' 'Throttling'
        }
    }

    Invoke-Step 'UEFI age' {
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        if ($bios.ReleaseDate) {
            $y = [math]::Round(($now - $bios.ReleaseDate).TotalDays / 365.25, 1)
            Add-Finding (Get-Severity $y 2 4) 'UEFI firmware age' ('{0} released {1:yyyy-MM-dd} ({2} years)' -f $bios.SMBIOSBIOSVersion, $bios.ReleaseDate, $y) 'AMBER >= 2 years, RED >= 4 years' 'Surface UEFI/SMF/ME firmware ships via Windows Update and the Surface driver pack; newer firmware often improves thermals and power management.' 'Drivers'
        }
    }

    Invoke-Step 'Pending reboot indicators' {
        $pr = [ordered]@{}
        $pr['CBS RebootPending'] = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        $pr['WindowsUpdate RebootRequired'] = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        $pr['PendingFileRenameOperations present'] = ($null -ne (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'))
        Add-Heading 'Pending reboot indicators'
        Add-KeyValue $pr
        if ($pr['CBS RebootPending'] -or $pr['WindowsUpdate RebootRequired']) {
            Add-Finding 'AMBER' 'A reboot is pending for servicing / Windows Update' (($pr.GetEnumerator() | Where-Object { $_.Value -eq $true } | ForEach-Object { $_.Key }) -join ', ') 'AMBER if CBS or WU reboot pending' 'Restart to complete servicing (TiWorker/TrustedInstaller activity can continue until then).' 'Updates'
        } else { Add-Finding 'GREEN' 'No servicing reboot pending' 'CBS/WU flags not set' 'AMBER if set' }
    }

    Invoke-Step 'Windows Update (cached search, no download/install)' {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $searcher.Online = $false        # use locally cached metadata only
        $res = $searcher.Search('IsInstalled=0 and IsHidden=0')
        $pending = @(foreach ($u in $res.Updates) {
            [pscustomobject]@{ Title = $u.Title; KB = (@($u.KBArticleIDs) -join ','); Severity = $u.MsrcSeverity; Downloaded = $u.IsDownloaded; Type = (@($u.Categories | ForEach-Object { $_.Name }) -join ', ') }
        })
        Add-Heading 'Pending updates (from last Windows Update scan)'
        Add-Table $pending
        Add-Metric 'Pending updates' $pending.Count 'count'
        if ($pending.Count -gt 0) { Add-Finding 'AMBER' 'Updates pending installation' ('{0} update(s): {1}' -f $pending.Count, ((@($pending | Select-Object -First 3 | ForEach-Object { $_.Title }) -join '; '))) 'AMBER if any' 'Install pending updates (especially Surface firmware/driver and cumulative updates) and restart.' 'Updates' }
        else { Add-Finding 'GREEN' 'No pending updates in last scan' '0' 'AMBER if any' }

        $count = $searcher.GetTotalHistoryCount()
        if ($count -gt 0) {
            $codes = @{ 0 = 'NotStarted'; 1 = 'InProgress'; 2 = 'Succeeded'; 3 = 'SucceededWithErrors'; 4 = 'Failed'; 5 = 'Aborted' }
            $hist = @(foreach ($h in $searcher.QueryHistory(0, [math]::Min(50, $count))) {
                $rc = [int]$h.ResultCode; $rt = [string]$rc; if ($codes.ContainsKey($rc)) { $rt = $codes[$rc] }
                [pscustomobject]@{ Date = $h.Date; Title = $h.Title; Result = $rt; HResult = ('0x{0:X8}' -f $h.HResult) }
            })
            Add-Heading 'Update history (last 50)'
            Add-Table $hist
            Export-Raw $hist 'update_history.csv'
            $fail = @($hist | Where-Object { $_.Result -in @('Failed', 'Aborted') -and $_.Date -gt $now.AddDays(-30) })
            if ($fail.Count -gt 0) { Add-Finding 'AMBER' 'Failed update installs in the last 30 days' ('{0}: {1}' -f $fail.Count, ((@($fail | Select-Object -First 3 | ForEach-Object { '{0} ({1})' -f $_.Title, $_.HResult }) -join '; '))) 'AMBER if any' 'Repeated failed installs retry in the background; investigate the HRESULT (WindowsUpdate.log via Get-WindowsUpdateLog).' 'Updates' }
        }
    }
}
#endregion

#region ------------------------------------------------------------------ Check 10: Event logs (7 days)
function Test-EventLogs {
    $since = (Get-Date).AddDays(-7)
    # Rules with Ids are queried directly (all levels); rules without Ids use the warning+ cache.
    $rules = @(
        [pscustomobject]@{ Name = 'Resource exhaustion (low virtual memory)'; Log = 'System'; Providers = @('Microsoft-Windows-Resource-Exhaustion-Detector'); Ids = @(2004); Sev = 'RED'; Min = 1; Cause = 'CommitPressure'; Rec = 'Windows ran low on commit. The top consumers named in the event are listed below - they are the leak/pressure suspects.' }
        [pscustomobject]@{ Name = 'Unexpected shutdown (Kernel-Power 41)'; Log = 'System'; Providers = @('Microsoft-Windows-Kernel-Power'); Ids = @(41); Sev = 'AMBER'; Min = 1; Cause = 'Stability'; Rec = 'Hard resets/hangs; check BugcheckCode in the event, WHEA events and minidumps (C:\Windows\Minidump).' }
        [pscustomobject]@{ Name = 'Unexpected shutdown (EventLog 6008)'; Log = 'System'; Providers = @('EventLog'); Ids = @(6008); Sev = 'AMBER'; Min = 1; Cause = 'Stability'; Rec = 'Correlate with Kernel-Power 41.' }
        [pscustomobject]@{ Name = 'CPU speed limited by firmware (Kernel-Processor-Power 37)'; Log = 'System'; Providers = @('Microsoft-Windows-Kernel-Processor-Power'); Ids = @(37); Sev = 'AMBER'; Min = 1; Cause = 'Throttling'; Rec = 'Firmware is limiting CPU speed (thermal/power). Update Surface firmware and DTT driver; check cooling and battery health.' }
        [pscustomobject]@{ Name = 'WHEA hardware errors'; Log = 'System'; Providers = @('Microsoft-Windows-WHEA-Logger'); Ids = $null; Sev = 'AMBER'; Min = 1; Cause = 'Stability'; Rec = 'Corrected hardware errors (often PCIe/CPU cache) can cause stalls; update firmware; persistent errors warrant hardware service.' }
        [pscustomobject]@{ Name = 'Disk / controller errors'; Log = 'System'; Providers = @('disk', 'stornvme', 'storahci', 'Microsoft-Windows-StorPort', 'iaStorAC', 'iaStorAVC', 'iaStorVD', 'volmgr'); Ids = $null; Sev = 'RED'; Min = 1; Cause = 'DiskIO'; Rec = 'I/O timeouts/resets cause freezes; update storage firmware and check disk health.' }
        [pscustomobject]@{ Name = 'NTFS errors'; Log = 'System'; Providers = @('Ntfs', 'Microsoft-Windows-Ntfs'); Ids = $null; Sev = 'AMBER'; Min = 1; Cause = 'DiskIO'; Rec = 'Run chkdsk C: /scan (online) and review the messages.' }
        [pscustomobject]@{ Name = 'Display driver timeout/recovery (TDR 4101)'; Log = 'System'; Providers = @('Display'); Ids = @(4101); Sev = 'AMBER'; Min = 1; Cause = 'Drivers'; Rec = 'Update the Intel graphics driver from the Surface driver pack.' }
        [pscustomobject]@{ Name = 'Service / driver start failures and crashes'; Log = 'System'; Providers = @('Service Control Manager'); Ids = @(7000, 7001, 7009, 7011, 7022, 7023, 7024, 7026, 7031, 7034, 7043); Sev = 'AMBER'; Min = 3; Cause = 'Drivers'; Rec = 'Review failing services/drivers; repeated crash-restart loops (7031/7034) consume resources.' }
        [pscustomobject]@{ Name = 'Driver install / PnP load failures'; Log = 'System'; Providers = @('Microsoft-Windows-Kernel-PnP'); Ids = @(219, 411); Sev = 'AMBER'; Min = 1; Cause = 'Drivers'; Rec = 'A device driver failed to load; check Device Manager for problem devices.' }
        [pscustomobject]@{ Name = 'Application crashes (1000)'; Log = 'Application'; Providers = @('Application Error'); Ids = @(1000); Sev = 'AMBER'; Min = 10; Cause = 'Stability'; Rec = 'See the top faulting applications below.' }
        [pscustomobject]@{ Name = 'Application hangs (1002)'; Log = 'Application'; Providers = @('Application Hang'); Ids = @(1002); Sev = 'AMBER'; Min = 5; Cause = 'CommitPressure'; Rec = 'Frequent hangs are the user-visible symptom of resource starvation; see top hanging applications below.' }
        [pscustomobject]@{ Name = 'Live kernel events / bugchecks (WER 1001)'; Log = 'Application'; Providers = @('Windows Error Reporting'); Ids = @(1001); Sev = 'AMBER'; Min = 1; Cause = 'Stability'; Rec = 'LiveKernelEvent 141/117 = GPU hangs; others indicate driver problems. Check C:\Windows\LiveKernelReports.'; Filter = 'LiveKernelEvent|BlueScreen' }
    )

    $allEvents = New-Object System.Collections.Generic.List[object]
    $summary = New-Object System.Collections.Generic.List[object]
    $total = $rules.Count; $i = 0
    foreach ($r in $rules) {
        $i++
        Write-Progress -Id 1 -Activity 'Reading event logs' -Status $r.Name -PercentComplete ([int]($i / $total * 100))
        Invoke-Step ('Events: ' + $r.Name) {
            if ($r.Ids) { $ev = @(Get-EventsSafe @{ LogName = $r.Log; Id = $r.Ids; StartTime = $since } 2000) }
            else { $ev = @(Get-CachedEvents $r.Log) }
            $ev = @($ev | Where-Object { $r.Providers -contains $_.ProviderName })
            $flt = Get-PropValue $r 'Filter'
            if ($flt) { $ev = @($ev | Where-Object { [string]$_.Message -match $flt }) }
            foreach ($e in $ev) { $allEvents.Add([pscustomobject]@{ Rule = $r.Name; Time = $e.TimeCreated; Log = $e.LogName; Provider = $e.ProviderName; Id = $e.Id; Level = $e.LevelDisplayName; Message = (Get-ShortText $e.Message 1000) }) }
            foreach ($g in @($ev | Group-Object ProviderName, Id)) {
                $last = $g.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
                $summary.Add([pscustomobject]@{ Category = $r.Name; Provider = $last.ProviderName; Id = $last.Id; Count = $g.Count; MostRecent = $last.TimeCreated; Example = (Get-ShortText $last.Message 400) })
            }
            $sev = 'GREEN'; if ($ev.Count -ge $r.Min) { $sev = $r.Sev } elseif ($ev.Count -gt 0) { $sev = 'INFO' }
            Add-Finding $sev $r.Name ('{0} event(s) in 7 days' -f $ev.Count) ('{0} if >= {1}' -f $r.Sev, $r.Min) $(if ($ev.Count -gt 0) { $r.Rec } else { '' }) $(if ($sev -in @('RED', 'AMBER')) { $r.Cause } else { '' })

            # Extra detail for specific rules
            if ($r.Ids -contains 2004 -and $ev.Count -gt 0) {
                $cons = @{}
                foreach ($e in $ev) {
                    foreach ($m in [regex]::Matches([string]$e.Message, '([^\s,:]+\.exe) \((\d+)\) consumed (\d+) bytes')) {
                        $n = $m.Groups[1].Value; $b = [double]$m.Groups[3].Value
                        if (-not $cons.ContainsKey($n) -or $cons[$n] -lt $b) { $cons[$n] = $b }
                    }
                }
                Add-Heading 'Resource-Exhaustion 2004: largest virtual-memory consumers named'
                Add-Table @($cons.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15 | ForEach-Object { [pscustomobject]@{ Process = $_.Key; MaxCommitMB = ConvertTo-MB $_.Value } })
            }
            if (($r.Ids -contains 1000 -or $r.Ids -contains 1002) -and $ev.Count -gt 0) {
                Add-Heading ('Top applications: ' + $r.Name)
                Add-Table @($ev | ForEach-Object { $a = ''; try { $a = [string]$_.Properties[0].Value } catch { }; $a } | Group-Object | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { [pscustomobject]@{ Application = $_.Name; Count = $_.Count } })
            }
        }
    }
    Write-Progress -Id 1 -Activity 'Reading event logs' -Completed
    Add-Heading 'Summary by event ID (last 7 days)'
    Add-Table @($summary | Sort-Object Count -Descending)
    Export-Raw $allEvents.ToArray() 'events_7days.csv'
}
#endregion

#region ------------------------------------------------------------------ Check 11: System file integrity
function Test-Integrity {
    $txt = New-Object System.Text.StringBuilder
    Invoke-Step 'CBS.log (last sfc results)' {
        $path = Join-Path $env:windir 'Logs\CBS\CBS.log'
        $text = Read-FileTail -Path $path -MaxBytes 16MB
        $lines = @($text -split "`r?`n")
        $sr = @($lines | Where-Object { $_ -match '\[SR\]' })
        $cannot = @($lines | Where-Object { $_ -match 'Cannot repair member file' }).Count
        $repaired = @($lines | Where-Object { $_ -match '\[SR\] Repairing corrupted file|Repaired file' }).Count
        $corrupt = @($lines | Where-Object { $_ -match 'CSI Payload Corrupt|Corrupt File' }).Count
        Add-Heading 'CBS.log - last sfc ([SR]) entries (tail of current log only)'
        if ($sr.Count -gt 0) { Add-Pre (($sr | Select-Object -Last 40) -join "`r`n") } else { Add-Note 'No [SR] (sfc) entries in the current CBS.log; sfc has not run since the log last rolled over.' }
        [void]$txt.AppendLine("CBS [SR] lines: $($sr.Count); 'Cannot repair': $cannot; repaired: $repaired; corrupt markers: $corrupt")
        if ($cannot -gt 0) { Add-Finding 'RED' 'sfc could not repair some files (CBS.log)' "$cannot 'Cannot repair member file' lines" 'RED if any' 'Run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow (these DO modify the system - run manually in a maintenance window).' 'Integrity' }
        elseif ($corrupt -gt 0) { Add-Finding 'AMBER' 'Corruption markers in CBS.log' "$corrupt corrupt-payload/file lines" 'AMBER if any' 'Run DISM /Online /Cleanup-Image /ScanHealth (read-only) to confirm, then RestoreHealth manually if needed.' 'Integrity' }
        elseif ($sr.Count -gt 0) { Add-Finding 'GREEN' 'Last sfc run in CBS.log shows no unrepairable files' "$($sr.Count) [SR] lines, 0 'Cannot repair'" 'RED if any Cannot repair' }
        else { Add-Finding 'INFO' 'No recent sfc run recorded' 'No [SR] lines in current CBS.log' 'n/a' 'Optionally re-run this script with -RunIntegrityChecks (verify only).' }
    }
    Invoke-Step 'DISM.log (last health checks)' {
        $path = Join-Path $env:windir 'Logs\DISM\dism.log'
        $text = Read-FileTail -Path $path -MaxBytes 8MB
        $hits = @($text -split "`r?`n" | Where-Object { $_ -match '(?i)CheckHealth|ScanHealth|RestoreHealth|repairable|corruption|Image health' } | Select-Object -Last 30)
        Add-Heading 'DISM.log - last health-related lines'
        if ($hits.Count -gt 0) { Add-Pre ($hits -join "`r`n") } else { Add-Note 'No health-check entries in the current dism.log.' }
        [void]$txt.AppendLine("DISM health lines:`r`n" + ($hits -join "`r`n"))
    }

    if ($RunIntegrityChecks) {
        if (-not $script:IsAdmin) {
            Add-Note '-RunIntegrityChecks requested but the session is not elevated - skipped.' 'err'
        } else {
            Invoke-Step 'DISM /CheckHealth (read-only)' {
                Write-Status '  Running DISM /Online /Cleanup-Image /CheckHealth (read-only)...'
                $out = (& "$env:windir\System32\dism.exe" /Online /Cleanup-Image /CheckHealth | Out-String)
                $code = $LASTEXITCODE
                Add-Heading ('DISM /CheckHealth output (exit code {0})' -f $code)
                Add-Pre $out
                [void]$txt.AppendLine("== DISM /CheckHealth (exit $code)`r`n$out")
                if ($out -match '(?i)repairable|corrupt') { Add-Finding 'RED' 'DISM CheckHealth reports component store corruption' 'See output' 'RED if repairable/corrupt' 'Run DISM /Online /Cleanup-Image /RestoreHealth manually (modifies the system).' 'Integrity' }
                elseif ($code -eq 0) { Add-Finding 'GREEN' 'DISM CheckHealth: no corruption flagged' "exit $code" 'RED if corruption reported' }
            }
            Invoke-Step 'sfc /verifyonly (read-only)' {
                Write-Status '  Running sfc /verifyonly (read-only; may take 10-20 minutes)...' 'Yellow'
                $out = ((& "$env:windir\System32\sfc.exe" /verifyonly | Out-String) -replace "`0", '')
                $code = $LASTEXITCODE
                Add-Heading ('sfc /verifyonly output (exit code {0})' -f $code)
                Add-Pre $out
                [void]$txt.AppendLine("== sfc /verifyonly (exit $code)`r`n$out")
                if ($out -match '(?i)found integrity violations') { Add-Finding 'RED' 'sfc /verifyonly found integrity violations' 'See output' 'RED if violations' 'Run DISM RestoreHealth then sfc /scannow manually (modifies the system).' 'Integrity' }
                elseif ($out -match '(?i)did not find any integrity violations') { Add-Finding 'GREEN' 'sfc /verifyonly: no integrity violations' 'Clean' 'RED if violations' }
                else { Add-Finding 'INFO' 'sfc /verifyonly result not recognised' "exit $code" 'n/a' 'Review the output text.' }
            }
        }
    } else {
        Add-Note 'Live verification not run. Use -RunIntegrityChecks to run sfc /verifyonly and DISM /CheckHealth (both verification-only).'
    }
    Export-Raw $txt.ToString() 'integrity.txt'
}
#endregion

#region ------------------------------------------------------------------ Check 12: Network
function Test-Network {
    Invoke-Step 'Adapters' {
        $ad = @(Get-NetAdapter -ErrorAction Stop | Select-Object Name, InterfaceDescription, Status, LinkSpeed, @{ n = 'SpeedMbps'; e = { [math]::Round([double]$_.Speed / 1e6, 0) } }, MediaType, DriverVersion, DriverDate, DriverProvider)
        Add-Heading 'Network adapters'
        Add-Table $ad
        $up = @($ad | Where-Object { [string]$_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch '(?i)virtual|hyper-v|loopback|vpn|tap|wan miniport' })
        foreach ($a in $up) {
            if ($a.SpeedMbps -gt 0 -and $a.SpeedMbps -lt 100) { Add-Finding 'AMBER' ('Low link speed on {0}' -f $a.Name) ('{0}' -f $a.LinkSpeed) 'AMBER < 100 Mbps' 'Slow links prolong a large OneDrive sync; move closer to the AP or use wired.' 'Network' }
        }
        $vpn = @($ad | Where-Object { [string]$_.Status -eq 'Up' -and $_.InterfaceDescription -match '(?i)vpn|anyconnect|globalprotect|fortinet|zscaler|wireguard|tap-' })
        if ($vpn.Count -gt 0) { Add-Finding 'INFO' 'VPN / tunnel adapter active' ((@($vpn | ForEach-Object { $_.InterfaceDescription }) -join '; ')) 'n/a' 'Full-tunnel VPNs can throttle OneDrive traffic; consider split-tunnel for Microsoft 365 endpoints.' '' }
    }
    Invoke-Step 'IP / DNS / profiles' {
        Add-Heading 'IPv4 addresses'
        Add-Table @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -ne '127.0.0.1' } | Select-Object InterfaceAlias, IPAddress, PrefixLength, PrefixOrigin)
        Add-Heading 'DNS servers'
        Add-Table @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { @($_.ServerAddresses).Count -gt 0 } | Select-Object InterfaceAlias, @{ n = 'DNS'; e = { @($_.ServerAddresses) -join ', ' } })
        Add-Heading 'Connection profiles'
        Add-Table @(Get-NetConnectionProfile -ErrorAction Stop | Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity)
    }
    Invoke-Step 'Metered connection (WinRT)' {
        $null = [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]
        $cp = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
        if ($null -eq $cp) { Add-Note 'No internet connection profile.'; Add-Finding 'AMBER' 'No internet connection profile' 'GetInternetConnectionProfile() returned null' 'AMBER' 'OneDrive cannot sync without connectivity.' 'Network'; return }
        $cost = $cp.GetConnectionCost()
        $d = [ordered]@{ 'Profile' = $cp.ProfileName; 'NetworkCostType' = [string]$cost.NetworkCostType; 'Roaming' = $cost.Roaming; 'OverDataLimit' = $cost.OverDataLimit; 'ApproachingDataLimit' = $cost.ApproachingDataLimit }
        Add-Heading 'Internet connection cost'
        Add-KeyValue $d
        if ([string]$cost.NetworkCostType -in @('Fixed', 'Variable')) {
            Add-Finding 'AMBER' 'Internet connection is metered' ('NetworkCostType = {0} on {1}' -f $cost.NetworkCostType, $cp.ProfileName) 'AMBER if Fixed/Variable' 'OneDrive pauses sync on metered networks by default, so the backlog never drains. Turn off "Set as metered connection" for this network or allow sync on metered in OneDrive settings.' 'Network'
        } else { Add-Finding 'GREEN' 'Connection not metered' ('NetworkCostType = {0}' -f $cost.NetworkCostType) 'AMBER if Fixed/Variable' }
    }
    Invoke-Step 'Wi-Fi details (netsh)' {
        $w = (& netsh.exe wlan show interfaces | Out-String)
        if ($w -match '(?i)There is no wireless interface|service .* is not running') { return }
        Add-Heading 'Wi-Fi interface (netsh wlan show interfaces)'
        Add-Pre $w.Trim()
        $m = [regex]::Match($w, '(?im)^\s*Signal\s*:\s*(\d+)%')
        if ($m.Success) {
            $sig = [int]$m.Groups[1].Value
            Add-Metric 'Wi-Fi signal' $sig '%'
            Add-Finding (Get-Severity $sig 60 40 -LowerIsWorse) 'Wi-Fi signal quality' "$sig%" 'AMBER <= 60%, RED <= 40%' 'Weak signal reduces throughput and prolongs sync.' 'Network'
        }
    }
    Invoke-Step 'WinHTTP proxy' {
        Add-Heading 'WinHTTP proxy (netsh winhttp show proxy)'
        Add-Pre ((& netsh.exe winhttp show proxy | Out-String).Trim())
    }
}
#endregion

#region ------------------------------------------------------------------ Check 13: Security products and kernel drivers
function Test-SecurityProducts {
    $heavyRx = '(?i)McAfee|Symantec|Norton|Sophos|CrowdStrike|SentinelOne|Sentinel Labs|Carbon Black|Cylance|Trend Micro|Kaspersky|ESET|Avast|AVG|Bitdefender|Webroot|Malwarebytes|Acronis|Veeam|Citrix|VMware|VirtualBox|Zscaler|Netskope|Forcepoint|Digital Guardian|Ivanti|AppSense|Palo Alto|Fortinet|Riot Games|Vanguard|EasyAntiCheat|BattlEye|Dropbox|Razer|Logitech|ASUS|Corsair|Nahimic|A-Volute|Rivet|Killer|Dell|Lenovo|HP Inc|Hewlett'
    Invoke-Step 'Security Center products' {
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($cls in 'AntiVirusProduct', 'AntiSpywareProduct', 'FirewallProduct') {
            foreach ($p in @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName $cls -ErrorAction SilentlyContinue)) {
                $hex = '{0:X6}' -f [int]$p.productState
                $enabled = $hex.Substring(2, 2) -in @('10', '11')
                $upToDate = $hex.Substring(4, 2) -eq '00'
                $rows.Add([pscustomobject]@{ Type = $cls; Name = $p.displayName; Enabled = $enabled; UpToDate = $upToDate; ProductState = "0x$hex"; Path = Get-PropValue $p 'pathToSignedProductExe' })
            }
        }
        Add-Heading 'Registered security products (Security Center)'
        Add-Table $rows.ToArray()
        $av = @($rows | Where-Object { $_.Type -eq 'AntiVirusProduct' -and $_.Enabled })
        if ($av.Count -gt 1) { Add-Finding 'AMBER' 'More than one active antivirus product' ((@($av | ForEach-Object { $_.Name }) -join '; ')) 'AMBER if > 1 enabled AV' 'Two real-time scanners double the per-file cost of a large sync. Keep one active (Defender goes passive automatically when a third-party AV registers correctly).' 'ThirdParty' }
        elseif ($av.Count -eq 1) { Add-Finding 'GREEN' 'Single active antivirus' $av[0].Name 'AMBER if > 1' }
    }
    Invoke-Step 'Non-Microsoft kernel drivers (running)' {
        $drv = @(Get-CimInstance -ClassName Win32_SystemDriver -Filter "State='Running'" -ErrorAction Stop | ForEach-Object {
            $img = Resolve-ImagePath $_.PathName
            [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; Company = (Get-FileCompany $img); Version = (Get-FileVersion $img); Path = $img }
        })
        $nonMs = @($drv | Where-Object { $_.Company -notmatch 'Microsoft' } | Sort-Object Company, Name)
        $flagged = @($nonMs | Where-Object { ('{0} {1} {2}' -f $_.Company, $_.DisplayName, $_.Name) -match $heavyRx })
        Add-Heading 'Running non-Microsoft kernel drivers'
        Add-Table $nonMs
        Export-Raw $drv 'kernel_drivers.csv'
        $script:NonMsDrivers = $drv
        if ($flagged.Count -gt 0) {
            Add-Finding 'AMBER' 'Third-party kernel drivers from vendors often linked to slowdowns' ((@($flagged | Select-Object -First 6 | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Company }) -join '; ')) 'AMBER if any match the known list' 'Security agents, VPN/SASE, backup, virtualisation and OEM utility drivers intercept file/network I/O. Make sure they are current and, for security agents, that OneDrive/SharePoint paths follow vendor guidance.' 'ThirdParty'
        } else { Add-Finding 'GREEN' 'No commonly problematic third-party kernel drivers' ('{0} non-Microsoft drivers running' -f $nonMs.Count) 'AMBER if known vendors present' }
    }
    Invoke-Step 'File system minifilters (fltmc)' {
        if (-not $script:IsAdmin) { Add-Note 'fltmc needs elevation - skipped.'; return }
        $filters = @(foreach ($l in @(& fltmc.exe filters)) {
            if ($l -match '^\s*(\S+)\s+(\d+)\s+([\d\.]+)\s+(\d+)\s*$') {
                $n = $Matches[1]; $co = ''
                $d = @($script:NonMsDrivers | Where-Object { $_.Name -ieq $n } | Select-Object -First 1)
                if ($d.Count -gt 0) { $co = $d[0].Company }
                [pscustomobject]@{ Filter = $n; Instances = [int]$Matches[2]; Altitude = $Matches[3]; Company = $co }
            }
        })
        Add-Heading 'File system minifilters (every file I/O passes through these)'
        Add-Table $filters
        $third = @($filters | Where-Object { $_.Company -and $_.Company -notmatch 'Microsoft' })
        Add-Finding (Get-Severity $third.Count 3 6) 'Third-party file system minifilters' ('{0}: {1}' -f $third.Count, ((@($third | ForEach-Object { $_.Filter }) -join ', '))) 'AMBER >= 3, RED >= 6' 'Each minifilter adds per-file overhead that is multiplied by an 800k-file sync. Review whether each is needed and up to date.' 'ThirdParty'
    }
}
$script:NonMsDrivers = @()
#endregion

#region ------------------------------------------------------------------ HTML report
$script:Css = @'
:root{--red:#c62828;--amber:#d97a00;--green:#2e7d32;--info:#546e7a;--bg:#f4f6f8;--card:#fff;--text:#1f2328;--muted:#5f6b76;--border:#d8dde3;--head:#1f2a36}
*{box-sizing:border-box}
body{font-family:"Segoe UI",Arial,sans-serif;margin:0;background:var(--bg);color:var(--text);font-size:14px;line-height:1.45}
header{background:var(--head);color:#fff;padding:18px 24px}
header h1{margin:0 0 4px;font-size:22px}
header .meta{color:#c8d1db;font-size:13px}
main{max-width:1400px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:14px 16px;margin:12px 0}
.cards{display:flex;gap:12px;flex-wrap:wrap}
.count{flex:1;min-width:140px;border-radius:6px;padding:12px 16px;color:#fff}
.count b{display:block;font-size:28px}
.count.RED{background:var(--red)}.count.AMBER{background:var(--amber)}.count.GREEN{background:var(--green)}.count.INFO{background:var(--info)}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-weight:600;font-size:11px;letter-spacing:.3px}
.badge.RED{background:var(--red)}.badge.AMBER{background:var(--amber)}.badge.GREEN{background:var(--green)}.badge.INFO{background:var(--info)}
tr.sev-RED td{background:#fdecea}tr.sev-AMBER td{background:#fff5e5}
details.section{background:var(--card);border:1px solid var(--border);border-radius:6px;margin:10px 0}
details.section>summary{cursor:pointer;padding:10px 14px;font-weight:600;font-size:15px;list-style:none}
details.section>summary::-webkit-details-marker{display:none}
details.section>summary:before{content:"\25B8";display:inline-block;width:16px;color:var(--muted)}
details.section[open]>summary:before{content:"\25BE"}
details.section .content{padding:0 16px 14px}
h2{font-size:18px;margin:4px 0 10px}h3{font-size:14px;margin:16px 0 6px;color:#2b3a4a}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th,td{border:1px solid var(--border);padding:4px 6px;text-align:left;vertical-align:top;word-break:break-word}
table.sortable th{background:#eef1f4;cursor:pointer;position:sticky;top:0;white-space:nowrap}
table.sortable th[data-sort=asc]:after{content:" \25B2"}table.sortable th[data-sort=desc]:after{content:" \25BC"}
table.kv{width:auto;min-width:50%}table.kv th{background:#f3f5f7;width:320px}
.tblwrap{max-height:540px;overflow:auto;margin:6px 0 12px}
pre{background:#f0f2f4;border:1px solid var(--border);padding:8px;overflow:auto;max-height:420px;font-size:12px;white-space:pre-wrap}
.note{color:var(--muted);font-size:12.5px}.muted{color:var(--muted)}.err{color:var(--red);font-weight:600}
.toolbar button{margin-right:6px;padding:4px 10px;border:1px solid var(--border);background:#fff;border-radius:4px;cursor:pointer}
ol.causes li{margin:4px 0}
code{background:#f0f2f4;padding:1px 4px;border-radius:3px}
'@

$script:Js = @'
function sevRank(t){return {"RED":0,"AMBER":1,"INFO":2,"GREEN":3}[t]!==undefined?{"RED":0,"AMBER":1,"INFO":2,"GREEN":3}[t]:null;}
document.querySelectorAll("table.sortable").forEach(function(tbl){
  var ths=tbl.tHead?tbl.tHead.rows[0].cells:[];
  Array.prototype.forEach.call(ths,function(th,idx){
    th.addEventListener("click",function(){
      var asc=th.getAttribute("data-sort")!=="asc";
      Array.prototype.forEach.call(ths,function(h){h.removeAttribute("data-sort");});
      th.setAttribute("data-sort",asc?"asc":"desc");
      var body=tbl.tBodies[0];var rows=Array.prototype.slice.call(body.rows);
      rows.sort(function(a,b){
        var x=a.cells[idx]?a.cells[idx].textContent.trim():"",y=b.cells[idx]?b.cells[idx].textContent.trim():"";
        var sx=sevRank(x),sy=sevRank(y),r;
        if(sx!==null&&sy!==null){r=sx-sy;}
        else{var nx=Number(x),ny=Number(y);
          if(x!==""&&y!==""&&!isNaN(nx)&&!isNaN(ny)){r=nx-ny;}else{r=x.localeCompare(y,undefined,{numeric:true,sensitivity:"base"});}}
        return asc?r:-r;});
      rows.forEach(function(r){body.appendChild(r);});
    });
  });
});
function setAll(open){document.querySelectorAll("details.section").forEach(function(d){d.open=open;});}
'@

function Get-SevRank { param([string]$Severity) switch ($Severity) { 'RED' { 0 } 'AMBER' { 1 } 'INFO' { 2 } default { 3 } } }

function Get-FindingsTableHtml {
    param($Rows, [switch]$WithRecommendation)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="tblwrap"><table class="sortable"><thead><tr><th>Severity</th><th>Area</th><th>Finding</th><th>Observed value</th><th>Threshold</th>')
    if ($WithRecommendation) { [void]$sb.Append('<th>Recommended manual action</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($f in @($Rows)) {
        [void]$sb.Append('<tr class="sev-' + $f.Severity + '"><td><span class="badge ' + $f.Severity + '">' + $f.Severity + '</span></td><td><a href="#' + (HE $f.SectionId) + '">' + (HE $f.Area) + '</a></td><td>' + (HE $f.Title) + '</td><td>' + (HE $f.Observed) + '</td><td>' + (HE $f.Threshold) + '</td>')
        if ($WithRecommendation) { [void]$sb.Append('<td>' + (HE $f.Recommendation) + '</td>') }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

function New-HtmlReport {
    $findings = @($script:Findings | Sort-Object @{ e = { Get-SevRank $_.Severity } }, Area, Title)
    $cnt = @{ RED = 0; AMBER = 0; GREEN = 0; INFO = 0 }
    foreach ($f in $findings) { $cnt[$f.Severity]++ }

    # Likely causes ranked by evidence (RED = 3, AMBER = 1)
    $scores = @{}; $evidence = @{}
    foreach ($f in $findings) {
        if (-not $f.Cause -or $f.Severity -notin @('RED', 'AMBER')) { continue }
        $pts = 1; if ($f.Severity -eq 'RED') { $pts = 3 }
        if (-not $scores.ContainsKey($f.Cause)) { $scores[$f.Cause] = 0; $evidence[$f.Cause] = New-Object System.Collections.Generic.List[string] }
        $scores[$f.Cause] += $pts
        $evidence[$f.Cause].Add(('{0}: {1}' -f $f.Severity, $f.Title))
    }
    $causes = @($scores.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8)

    $elevText = 'No (reduced checks)'; if ($script:IsAdmin) { $elevText = 'Yes' }
    $labelText = '(none)'; if ($Label) { $labelText = $Label }
    $duration = [math]::Round(((Get-Date) - $script:StartTime).TotalMinutes, 1)
    $model = ''; if ($script:CS) { $model = '{0} {1}' -f $script:CS.Manufacturer, $script:CS.Model }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$sb.Append('<title>Slow PC Report - ' + (HE $env:COMPUTERNAME) + ' - ' + (HE $labelText) + '</title><style>' + $script:Css + '</style></head><body>')
    [void]$sb.Append('<header><h1>Slow PC Report: ' + (HE $env:COMPUTERNAME) + '</h1><div class="meta">' + (HE $model) + ' &middot; Label: <b>' + (HE $labelText) + '</b> &middot; Run: ' + (HE $script:StartTime.ToString('yyyy-MM-dd HH:mm:ss')) + ' &middot; Duration: ' + $duration + ' min &middot; Elevated: ' + (HE $elevText) + ' &middot; Sample: ' + $SampleSeconds + ' s &middot; Counter source: ' + (HE $script:PerfSource) + ' &middot; Script v' + $script:ScriptVersion + '</div></header><main>')

    # Summary
    [void]$sb.Append('<div class="card"><h2>Summary</h2><div class="cards">')
    foreach ($s in 'RED', 'AMBER', 'GREEN', 'INFO') { [void]$sb.Append('<div class="count ' + $s + '"><b>' + $cnt[$s] + '</b>' + $s + '</div>') }
    [void]$sb.Append('</div><p class="note">Read-only diagnostic: nothing on this PC was changed. Each finding shows the raw value and the threshold used.')
    if (-not $script:IsAdmin) { [void]$sb.Append(' <span class="err">Not elevated: some checks were skipped or limited.</span>') }
    [void]$sb.Append('</p>')

    [void]$sb.Append('<h3>Likely causes (ranked by evidence: RED = 3 points, AMBER = 1)</h3>')
    if ($causes.Count -eq 0) { [void]$sb.Append('<p>No RED/AMBER evidence pointing to a specific cause.</p>') }
    else {
        [void]$sb.Append('<ol class="causes">')
        foreach ($c in $causes) {
            $strength = 'Weak'; if ($c.Value -ge 6) { $strength = 'Strong' } elseif ($c.Value -ge 3) { $strength = 'Moderate' }
            $desc = $c.Key; if ($script:CauseInfo.Contains($c.Key)) { $desc = $script:CauseInfo[$c.Key] }
            [void]$sb.Append('<li><b>' + (HE $desc) + '</b> - score ' + $c.Value + ' (' + $strength + ')<br><span class="note">' + (HE (($evidence[$c.Key] | Select-Object -First 6) -join ' | ')) + '</span></li>')
        }
        [void]$sb.Append('</ol>')
    }
    [void]$sb.Append('<h3>RED and AMBER findings</h3>')
    [void]$sb.Append((Get-FindingsTableHtml -Rows @($findings | Where-Object { $_.Severity -in @('RED', 'AMBER') })))
    [void]$sb.Append('<details><summary>All findings including GREEN / INFO (' + $findings.Count + ')</summary>' + (Get-FindingsTableHtml -Rows $findings) + '</details>')
    [void]$sb.Append('</div>')

    # Recommended next steps
    [void]$sb.Append('<div class="card"><h2>Recommended next steps</h2><p class="note">Manual actions mapped to each finding, most severe first. The script has not performed any of them.</p>')
    [void]$sb.Append((Get-FindingsTableHtml -Rows @($findings | Where-Object { $_.Severity -in @('RED', 'AMBER') -and $_.Recommendation }) -WithRecommendation))
    [void]$sb.Append('<p><b>General approach for "slow over time, reboot fixes it":</b> compare a fresh-restart run with a when-slow run (below). Metrics that grow between the two (non-paged/paged pool, a pool tag, a process''s handles or private bytes) identify a leak; a falling % Performance Limit or rising temperatures identify throttling; OneDrive/Defender/Search CPU and disk I/O that stay high identify sync-driven load.</p></div>')

    # How to compare
    [void]$sb.Append('<div class="card"><h2>How to compare</h2><ol>')
    [void]$sb.Append('<li>Restart (use <b>Restart</b>, not Shut down, if Fast Startup is on) and after ~10 minutes run: <code>.\Get-SlowPCReport.ps1 -Label AfterReboot</code></li>')
    [void]$sb.Append('<li>When the PC feels slow, run: <code>.\Get-SlowPCReport.ps1 -Label WhenSlow</code></li>')
    [void]$sb.Append('<li>Open both report.html files side by side, or diff the key metrics:</li></ol>')
    [void]$sb.Append('<pre>' + (HE @'
$a = Import-Csv 'C:\SlowPCReport\<PC>_<time>_AfterReboot\metrics.csv'
$b = Import-Csv 'C:\SlowPCReport\<PC>_<time>_WhenSlow\metrics.csv'
foreach ($m in $a) {
    $o = $b | Where-Object { $_.Name -eq $m.Name } | Select-Object -First 1
    [pscustomobject]@{ Metric = $m.Name; AfterReboot = $m.Value; WhenSlow = $(if ($o) { $o.Value }); Unit = $m.Unit }
} | Format-Table -AutoSize
'@) + '</pre>')
    [void]$sb.Append('<p class="note">Also compare pooltags.csv (NonPagedMB / Outstanding per tag) and processes.csv (Handles / PrivateMB per process). Growth that correlates with uptime is the leak signature.</p>')
    [void]$sb.Append('<h3>Key metrics for this run</h3>' + (ConvertTo-HtmlTableString -Rows $script:Metrics.ToArray() -MaxRows 200) + '</div>')

    # Sections
    [void]$sb.Append('<div class="toolbar"><button onclick="setAll(true)">Expand all</button><button onclick="setAll(false)">Collapse all</button></div>')
    foreach ($sec in $script:Sections) {
        $sf = @($findings | Where-Object { $_.SectionId -eq $sec.Id })
        $badges = ''
        foreach ($s in 'RED', 'AMBER', 'GREEN') { $n = @($sf | Where-Object { $_.Severity -eq $s }).Count; if ($n -gt 0) { $badges += ' <span class="badge ' + $s + '">' + $n + ' ' + $s + '</span>' } }
        if ($sec.Errors.Count -gt 0) { $badges += ' <span class="badge INFO">' + $sec.Errors.Count + ' error(s)</span>' }
        $open = ''; if (@($sf | Where-Object { $_.Severity -eq 'RED' }).Count -gt 0) { $open = ' open' }
        [void]$sb.Append('<details class="section" id="' + (HE $sec.Id) + '"' + $open + '><summary>' + $sec.Number + '. ' + (HE $sec.Title) + $badges + ' <span class="note">(' + $sec.Seconds + ' s)</span></summary><div class="content">')
        if ($sf.Count -gt 0) { [void]$sb.Append('<h3>Findings</h3>' + (Get-FindingsTableHtml -Rows $sf -WithRecommendation)) }
        [void]$sb.Append($sec.Html.ToString())
        if ($sec.Errors.Count -gt 0) {
            [void]$sb.Append('<h3>Errors recorded in this check</h3><ul>')
            foreach ($e in $sec.Errors) { [void]$sb.Append('<li class="err">' + (HE $e) + '</li>') }
            [void]$sb.Append('</ul>')
        }
        if ($sec.Files.Count -gt 0) { [void]$sb.Append('<p class="note">Raw exports: ' + (HE (($sec.Files | Sort-Object -Unique) -join ', ')) + '</p>') }
        [void]$sb.Append('</div></details>')
    }
    [void]$sb.Append('<p class="note">Output folder: ' + (HE $script:OutDir) + '</p></main><script>' + $script:Js + '</script></body></html>')
    return $sb.ToString()
}
#endregion

#region ------------------------------------------------------------------ Main
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Status ('Get-SlowPCReport v{0} - read-only diagnostics' -f $script:ScriptVersion) 'Green'
if (-not $script:IsAdmin) {
    Write-Warning 'Not running as Administrator. Continuing with reduced checks (reliability counters, exclusions, minifilters, ACPI thermal, BitLocker, other profiles, CBS log may be unavailable). Re-run from an elevated PowerShell for full results.'
}
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    Write-Warning 'Running in 32-bit PowerShell on 64-bit Windows. Use 64-bit PowerShell for accurate results.'
}

# Output folder (the only place the script writes)
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$folderName = '{0}_{1}' -f $env:COMPUTERNAME, $stamp
$safeLabel = $Label -replace '[^\w\-]', ''
if ($safeLabel) { $folderName += '_' + $safeLabel }
$script:OutDir = Join-Path $OutputPath $folderName
try { New-Item -ItemType Directory -Path $script:OutDir -Force -ErrorAction Stop | Out-Null }
catch { Write-Error "Cannot create output folder '$script:OutDir': $($_.Exception.Message)"; return }
Write-Status "Output folder: $script:OutDir"

$transcriptOn = $false
try { Start-Transcript -LiteralPath (Join-Path $script:OutDir 'console_transcript.txt') -ErrorAction Stop | Out-Null; $transcriptOn = $true } catch { }

try {
    Initialize-NativeHelpers

    Invoke-Check 'sys'     'System overview'                       { Test-SystemOverview }
    Invoke-Check 'perf'    'Performance snapshot'                  { Test-Performance }
    Invoke-Check 'mem'     'Memory leak indicators'                { Test-MemoryLeak }
    Invoke-Check 'cpu'     'CPU throttling and power'              { Test-CpuThrottling }
    Invoke-Check 'disk'    'Disk health and space'                 { Test-Disk }
    Invoke-Check 'od'      'OneDrive'                              { Test-OneDrive }
    Invoke-Check 'search'  'Windows Search and Defender'           { Test-SearchDefender }
    Invoke-Check 'startup' 'Startup and background load'           { Test-Startup }
    Invoke-Check 'drivers' 'Drivers, firmware and updates'         { Test-DriversUpdates }
    Invoke-Check 'events'  'Event logs (last 7 days)'              { Test-EventLogs }
    Invoke-Check 'sfc'     'System file integrity'                 { Test-Integrity }
    Invoke-Check 'net'     'Network'                               { Test-Network }
    Invoke-Check 'sec'     'Security products and kernel drivers'  { Test-SecurityProducts }

    Write-Progress -Activity 'Slow PC report (read-only)' -Status 'Writing report' -PercentComplete 99
    $script:CurrentSection = $null
    $script:Findings | Select-Object Severity, Area, Title, Observed, Threshold, Recommendation, Cause | Export-Csv -LiteralPath (Join-Path $script:OutDir 'findings.csv') -NoTypeInformation -Encoding UTF8
    $script:Metrics | Export-Csv -LiteralPath (Join-Path $script:OutDir 'metrics.csv') -NoTypeInformation -Encoding UTF8
    $html = New-HtmlReport
    $reportPath = Join-Path $script:OutDir 'report.html'
    [System.IO.File]::WriteAllText($reportPath, $html, (New-Object System.Text.UTF8Encoding($false)))

    Write-Progress -Activity 'Slow PC report (read-only)' -Completed
    $red = @($script:Findings | Where-Object { $_.Severity -eq 'RED' }).Count
    $amber = @($script:Findings | Where-Object { $_.Severity -eq 'AMBER' }).Count
    Write-Status ('Done. RED: {0}  AMBER: {1}' -f $red, $amber) 'Green'
    Write-Status "Report: $reportPath" 'Green'
}
finally {
    if ($transcriptOn) { try { Stop-Transcript | Out-Null } catch { } }
}
#endregion