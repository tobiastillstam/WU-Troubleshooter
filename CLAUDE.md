# Windows Update Troubleshooting Toolset

Global conventions (PowerShell template, working style) live in
~/.claude/CLAUDE.md. This file is only what's specific to this project.

Target:  Windows Server 2025, ONLINE Windows Update (not WSUS).
Status:  v1.0.0, production-tested. Prepping GitHub release files (README / CHANGELOG / LICENSE / .gitignore).
Package: WU-Troubleshooting-Toolset.zip

## Scripts

- `Test-WUOnlineConnectivity.ps1` - reachability of online WU endpoints.
- `Test-WULocalClient.ps1`        - local WU client health and config.
- `Get-WUErrors.ps1`              - parse WU logs for errors (see below).
- `Invoke-WUDiagnostics.ps1`      - orchestrator that runs the above.

## Get-WUErrors.ps1 (the distinctive one)

- HRESULT-centric, NOT severity-keyword based.
- Output: per-code grouped summaries.
- Switches: `-IncludeText` and `-IncludeBenign` (both opt-in).
- Benign noise is filtered out by default.

## Key lesson (don't relearn this)

Modern converted WU logs on Server 2025 do NOT contain the legacy severity
keywords (e.g. WARNING/ERROR text markers). That's why Get-WUErrors keys off
HRESULT codes instead. Do not reintroduce severity-keyword parsing.

## Run

Full end-to-end (must be elevated):
  `.\Invoke-WUDiagnostics.ps1`

Common variants:
  `.\Invoke-WUDiagnostics.ps1 -PerStepCsv`
  `.\Invoke-WUDiagnostics.ps1 -Include Connectivity,LocalClient -RunLiveScan`
  `.\Invoke-WUDiagnostics.ps1 -PerStepCsv -ReportFolder 'D:\WU-Reports'`

Remediation switches live on Test-WULocalClient.ps1 and must be run directly
and deliberately - the orchestrator never triggers them.
