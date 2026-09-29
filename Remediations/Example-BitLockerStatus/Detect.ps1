<#
.SYNOPSIS
    Remediation detection: is BitLocker protection on for the OS drive?
    Exit 0 = compliant, exit 1 = non-compliant (triggers Remediate.ps1).
#>

try {
    $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($vol.ProtectionStatus -eq 'On') {
        Write-Output 'Compliant: BitLocker protection is On'
        exit 0
    }
    Write-Output "Non-compliant: ProtectionStatus is $($vol.ProtectionStatus)"
    exit 1
}
catch {
    Write-Output "Error checking BitLocker: $($_.Exception.Message)"
    exit 1
}
