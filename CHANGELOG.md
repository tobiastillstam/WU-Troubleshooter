# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/tobiastillstam/WU-Troubleshooter/releases/tag/v1.0.0
