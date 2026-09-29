# Written by Rob Young | PhotoITPro
# Website:    https://photoitpro.co.uk
# Repository: https://github.com/PhotoITPro/PhotoITPro-Intune-Scripts
# Licence:    MIT
<#
.SYNOPSIS
    Win32 app requirement rule: device must have enough free space on C:.
.DESCRIPTION
    Configure the requirement rule as: output data type = Integer (or Boolean),
    operator = Equals, value = 1 (or True). Edit $MinFreeGB below.
#>

$MinFreeGB = 10

$disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
$freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)

if ($freeGB -ge $MinFreeGB) { Write-Output 1 } else { Write-Output 0 }
exit 0
