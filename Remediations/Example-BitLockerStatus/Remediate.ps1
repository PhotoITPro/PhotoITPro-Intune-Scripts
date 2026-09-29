<#
.SYNOPSIS
    Remediation: resume BitLocker protection if it has been suspended.
.NOTES
    Does not enable BitLocker on an unencrypted drive; use an Intune
    endpoint security disk encryption policy for that.
#>

try {
    $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($vol.VolumeStatus -eq 'FullyEncrypted' -and $vol.ProtectionStatus -eq 'Off') {
        Resume-BitLocker -MountPoint $env:SystemDrive -ErrorAction Stop | Out-Null
        Write-Output 'BitLocker protection resumed'
        exit 0
    }
    Write-Output "No action taken (VolumeStatus: $($vol.VolumeStatus))"
    exit 1
}
catch {
    Write-Output "Remediation failed: $($_.Exception.Message)"
    exit 1
}
