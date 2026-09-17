# Windows Update Troubleshooting Toolset

Global conventions (PowerShell template, working style) live in
~/.claude/CLAUDE.md. This file is only what's specific to this project.

Target:  Windows Server 2025, Windows Update client-side (online and/or WSUS-managed).
         WSUS *server*-side diagnostics (SUSDB, content store) are a separate, later task -
         out of scope here.
Status:  v1.1.0, production-tested. Prepping GitHub release files (README / CHANGELOG / LICENSE / .gitignore).
Package: WU-Troubleshooting-Toolset.zip

## Scripts

- `Test-WUOnlineConnectivity.ps1` - reachability of online WU endpoints, plus (when
  WSUS-managed) the configured WSUS server's DNS/TCP/TLS-chain and ClientWebService.
- `Test-WULocalClient.ps1`        - local WU client health and config.
- `Get-WUErrors.ps1`              - parse WU logs for errors (see below).
- `Invoke-WUDiagnostics.ps1`      - orchestrator that runs the above.

## WSUS awareness

All four scripts carry an identical, self-contained `Get-WUUpdateSourceInfo` function
(reads `WUServer`/`UseWUServer` and the Defender `FallbackOrder` policy keys) and an
`-UpdateSource Auto|Online|WSUS` parameter (default Auto = registry-detected). It is
**duplicated verbatim** in each script, not shared via a module - see "Clipboard-paste
constraint" below. When editing it, copy the change into all four scripts identically;
don't let them drift. A WSUS-managed box must report clean PASS/INFO, never a false-
positive FAIL/WARN, for the Microsoft endpoints it deliberately doesn't reach.

## Clipboard-paste constraint (don't relearn this)

These scripts are sometimes deployed to locked-down servers by clipboard-paste, no file
transfer. Every script must stay independently paste-able: no dot-sourcing, no shared
module, no cross-script runtime dependency. Any logic needed in more than one script
(currently just `Get-WUUpdateSourceInfo`) is duplicated verbatim rather than factored out.

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
  `.\Invoke-WUDiagnostics.ps1 -UpdateSource WSUS`

Remediation switches live on Test-WULocalClient.ps1 and must be run directly
and deliberately - the orchestrator never triggers them.
