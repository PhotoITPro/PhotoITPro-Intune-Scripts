<#
.SYNOPSIS
    Collects the Autopilot hardware hash from the local device and saves it as a CSV
    ready to import in Intune (Devices > Enrollment > Windows Autopilot > Import).
.DESCRIPTION
    Reads the hash from the MDM_DevDetail_Ext01 WMI class, so it needs no extra modules.
    Must be run in an elevated PowerShell session on the device itself.
.PARAMETER OutputFile
    Path of the CSV to create. Default: .\AutopilotHWID.csv
.PARAMETER GroupTag
    Optional Autopilot group tag to include in the CSV.
.EXAMPLE
    .\Get-AutopilotHardwareHash.ps1 -GroupTag 'Sales' -OutputFile C:\Temp\hwid.csv
#>
[CmdletBinding()]
param(
    [string]$OutputFile = '.\AutopilotHWID.csv',
    [string]$GroupTag = ''
)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this script from an elevated (administrator) PowerShell session.' }

$serial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber

$devDetail = Get-CimInstance -Namespace 'root/cimv2/mdm/dmmap' `
    -ClassName 'MDM_DevDetail_Ext01' -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" `
    -ErrorAction Stop

if (-not $devDetail.DeviceHardwareData) { throw 'Hardware hash not available on this device.' }

[pscustomobject]@{
    'Device Serial Number' = $serial
    'Windows Product ID'   = ''
    'Hardware Hash'        = $devDetail.DeviceHardwareData
    'Group Tag'            = $GroupTag
} | Export-Csv -Path $OutputFile -NoTypeInformation

Write-Output "Hardware hash for serial $serial saved to $OutputFile"
