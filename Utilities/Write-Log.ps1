# Written by Rob Young | PhotoITPro
# Website:    https://photoitpro.co.uk
# Repository: https://github.com/PhotoITPro/PhotoITPro-Intune-Scripts
# Licence:    MIT
<#
.SYNOPSIS
    Simple timestamped logging helper. Dot-source it: . .\Write-Log.ps1
.EXAMPLE
    Write-Log -Message 'Starting install' -Level Info
#>

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')][string]$Level = 'Info',
        [string]$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\Custom-Script.log"
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpper(), $Message
    $dir = Split-Path $LogPath -Parent
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    Add-Content -Path $LogPath -Value $line
    Write-Verbose $line
}
