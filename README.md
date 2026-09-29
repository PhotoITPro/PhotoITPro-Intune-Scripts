# PhotoITPro Intune Scripts

PowerShell scripts for Microsoft Intune admins: Win32 app detection and requirement rules, Proactive Remediations, and handy utilities. Shared by [PhotoITPro](https://photoitpro.co.uk), a blog for sysadmins and engineers working in Microsoft environments.

## What's in here

| Folder | Purpose |
|---|---|
| `Win32-Apps/Detection` | Custom detection scripts for Win32 apps (exit code 0 + STDOUT = detected) |
| `Win32-Apps/Requirement` | Custom requirement scripts (for example, only install on devices with enough free disk space) |
| `Remediations` | Detection/remediation script pairs for Intune Remediations (Proactive Remediations) |
| `Utilities` | Reusable helpers, such as a logging function |

## How to use

1. Browse to the script you need and read the header comments.
2. Copy it into Intune (**Apps > Windows > Win32 app > Detection rules / Requirements**, or **Devices > Scripts and remediations**).
3. Test on a pilot device or group before broad deployment.

Detection scripts for Win32 apps must write to STDOUT and exit `0` when the app is detected. Remediation detection scripts exit `0` when compliant and `1` when not.

## Requirements

- Windows 10/11 managed by Microsoft Intune
- Windows PowerShell 5.1 (the default host for Intune scripts)
- Scripts run as SYSTEM unless the assignment says otherwise

## Contributing

Issues and pull requests are welcome. Please keep scripts self-contained, commented, and free of tenant-specific values.

## Disclaimer

Scripts are provided as is, with no warranty. Always test in a non-production environment first.

## Licence

[MIT](LICENSE) © 2026 Rob Young
