# Written by Rob Young | PhotoITPro
# Website:    https://photoitpro.co.uk
# Repository: https://github.com/PhotoITPro/PhotoITPro-Intune-Scripts
# Licence:    MIT
<#
.SYNOPSIS
    Win32 app detection: checks an installed app's version via the Uninstall registry keys.
.DESCRIPTION
    Intune treats exit code 0 plus any STDOUT output as "detected".
    Edit $AppName and $MinimumVersion below.
#>

$AppName        = 'Contoso App'      # DisplayName (wildcards allowed)
$MinimumVersion = [version]'1.0.0'

$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$app = Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like $AppName } |
    Select-Object -First 1

if ($app -and $app.DisplayVersion) {
    $installed = $null
    if ([version]::TryParse($app.DisplayVersion, [ref]$installed) -and $installed -ge $MinimumVersion) {
        Write-Output "Detected $($app.DisplayName) $($app.DisplayVersion)"
        exit 0
    }
}

# Not detected: no output, non-zero exit
exit 1
