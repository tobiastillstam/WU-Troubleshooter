# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-08-19

Added client-side WSUS awareness across all four scripts, so a WSUS-managed server no
longer produces false-positive connectivity failures or misleading guidance. WSUS
*server*-side diagnostics (SUSDB, content store) remain out of scope.

### Added
- **Shared update-source detection** - a new `Get-WUUpdateSourceInfo` function, identical
  in all four scripts (duplicated verbatim - these scripts remain independently
  clipboard-paste-able with no cross-script dependency), reads the WSUS policy keys
  (`WUServer`, `UseWUServer`) and, independently, the Windows Defender signature-update
  policy (`FallbackOrder`, `DefinitionUpdateFileSharesSources`) - a box can be WSUS-managed
  for OS updates while Defender still falls back to Microsoft Update. Every script gains a
  read-only `-UpdateSource Auto|Online|WSUS` parameter (default `Auto` = registry-detected).
- **Test-WUOnlineConnectivity.ps1** - unreachable Microsoft endpoints are reported as
  `INFO` instead of `FAIL`/`WARN` when WSUS-managed and Defender is not falling back to
  Microsoft Update (the endpoint is still probed either way). New `-Category Wsus` check:
  DNS/TCP/TLS-chain reachability of the configured WSUS server (chain-validated, not
  issuer-pinned - a WSUS server legitimately presents an internal-CA or self-signed
  certificate) plus a `ClientWebService/client.asmx` probe confirming the WSUS service
  itself responds, not just that the port is open.
- **Get-WUErrors.ps1** - known-issue hints for `0x8024500C`, `0x80244022`, `0x8024401C`,
  `0x80244019` and `0x80246007` now lead with WSUS-server-side causes (content sync,
  WsusPool health) rather than client connectivity when WSUS-managed.
- **Test-WULocalClient.ps1** - the WSUS policy check and the blocked-direct-internet-access
  check in the `Source` module no longer `WARN` just because WSUS management is in effect;
  `WARN` is retained only when the configuration is actually broken (`UseWUServer=1` with a
  missing/unparseable `WUServer`).
- **Invoke-WUDiagnostics.ps1** - new `-UpdateSource` parameter, resolved once and forwarded
  (as a resolved `Online`/`WSUS` value, never `Auto`) to every step that supports it, via
  the existing adaptive parameter forwarding. Recorded in the run header and
  `Combined-Summary.txt`.

## [1.0.0] - 2026-06-20

First public release. A four-part toolset for troubleshooting online Windows Update
(not WSUS) on Windows Server 2025, sharing a common script template, transcript logging,
and structured output.

### Added
- **Test-WUOnlineConnectivity.ps1** - DNS + TCP + TLS (1.2, certificate-issuer inspection
  to flag SSL inspection) + proxy-aware HTTP checks across the documented Windows Update,
  Microsoft Update, Delivery Optimization, and diagnostics endpoints. Tests both the
  direct and configured-proxy paths. Optional `-FlushDnsFirst`, `-ListEndpoints`, CSV export.
- **Test-WULocalClient.ps1** - read-only health checks (services, SYSTEM-context proxy,
  update source/policy, blockers, BITS, datastore, history, events) plus an optional live
  COM scan (`-RunLiveScan`). Opt-in, `ShouldProcess`-gated remediation: `-FixServices`,
  `-ImportWinhttpProxy`, `-ClearErroredBitsJobs`, `-ResetSoftwareDistribution`,
  `-RepairComponentStore` (DISM ScanHealth + RestoreHealth, optional `-IncludeSfc`).
- **Get-WUErrors.ps1** - converts the modern WU ETL logs and surfaces HRESULT-coded
  errors with benign-noise filtering and a per-code grouped summary annotated with known
  meanings and known-issue hints. `-UpdateId` timeline mode, `-ScanCbsCorruption` mode
  (component-store / language-pack corruption triage), CSV export.
- **Invoke-WUDiagnostics.ps1** - orchestrator that runs the three tools in order into a
  single timestamped run folder with a combined summary; parameter-adaptive forwarding.

[1.1.0]: https://github.com/tobiastillstam/WU-Troubleshooter/releases/tag/v1.1.0
[1.0.0]: https://github.com/tobiastillstam/WU-Troubleshooter/releases/tag/v1.0.0
