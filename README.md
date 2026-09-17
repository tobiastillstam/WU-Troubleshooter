# WU-Troubleshooter

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)
![Platform](https://img.shields.io/badge/Windows%20Server-2025-0078D6)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/version-1.1.0-blue)

A PowerShell toolset for troubleshooting Windows Update on **Windows Server 2025** -
whether the machine gets updates from **online Windows Update** or is **WSUS-managed**.
Update source is auto-detected from the WSUS/Defender policy registry keys, so a
WSUS-managed box reports a clean result instead of false-positive connectivity failures.
WSUS *server*-side diagnostics (SUSDB, content store state) are out of scope. The toolset
works the problem in the order that actually isolates it:

> **wire → client → errors → repair**

Prove the network path to Microsoft works, confirm the local update client is healthy and
correctly pointed at Windows Update, decode what the WU/CBS logs are actually saying, and
(only when you ask) run targeted, reversible repairs.

All four scripts share one template: comment-based help, `#Requires -RunAsAdministrator`,
`SupportsShouldProcess`, a single `try/catch/finally`, transcript logging to a `logs`
subfolder, and structured pipeline output alongside a readable console report.

---

## Contents

| Script | Purpose |
| --- | --- |
| `Test-WUOnlineConnectivity.ps1` | The **wire** - DNS, TCP, TLS (1.2 + cert-issuer inspection), and proxy-aware HTTP checks against the documented WU / Microsoft Update / Delivery Optimization / diagnostics endpoints, over both the direct and configured-proxy paths. When WSUS-managed, unreachable Microsoft endpoints report INFO instead of FAIL/WARN (unless Defender falls back to Microsoft Update), and a `-Category Wsus` check verifies the configured WSUS server (DNS/TCP/TLS-chain + ClientWebService). |
| `Test-WULocalClient.ps1` | The **client** - services, SYSTEM-context proxy, update source/policy, reboot/disk/TLS/time blockers, BITS, datastore, history, events; optional live COM scan; opt-in repairs. WSUS management is treated as a valid configuration, not a defect. |
| `Get-WUErrors.ps1` | The **errors** - converts the modern WU ETL logs and surfaces HRESULT-coded failures, with benign-noise filtering, a per-code summary, known-issue hints (WSUS-aware for a handful of codes), an update timeline mode, and a CBS component-store corruption scan. |
| `Invoke-WUDiagnostics.ps1` | The **orchestrator** - runs all three into one timestamped run folder with a combined summary, resolving and forwarding `-UpdateSource` to each. |

---

## Requirements

- Windows Server 2025 (also runs on Windows 10 / Server 2016+ and Windows 11 24H2).
- Windows PowerShell 5.1 (also works in PowerShell 7+).
- An **elevated** session (all scripts declare `#Requires -RunAsAdministrator`).

---

## Installation

```powershell
# clone, or download and extract the release zip, into a folder - keep all four scripts together
git clone https://github.com/tobiastillstam/WU-Troubleshooter.git
cd WU-Troubleshooter

# downloaded files are marked blocked by Windows; unblock them
Get-ChildItem *.ps1 | Unblock-File

# run from an elevated prompt; if your execution policy blocks unsigned scripts:
#   powershell -ExecutionPolicy Bypass -File .\Invoke-WUDiagnostics.ps1
```

The scripts are unsigned. Use `Unblock-File` (above) or an appropriate `Set-ExecutionPolicy`
for your environment.

---

## Quick start

```powershell
# everything, in order, into .\logs\WUDiag_<timestamp>\
.\Invoke-WUDiagnostics.ps1

# just the network path
.\Test-WUOnlineConnectivity.ps1

# the local client, plus a live online scan
.\Test-WULocalClient.ps1 -RunLiveScan

# recent WU errors from the last 3 days
.\Get-WUErrors.ps1 -HoursBack 72
```

Every script writes a transcript to a `logs` subfolder next to it and also returns objects
you can capture (`$r = .\Test-WULocalClient.ps1`).

---

## Usage

### Test-WUOnlineConnectivity.ps1

```powershell
.\Test-WUOnlineConnectivity.ps1 [-Category Core|DeliveryOptimization|MicrosoftUpdate|Diagnostics|Wsus|All]
                                [-UpdateSource Auto|Online|WSUS] [-TimeoutSeconds 5]
                                [-SkipProxyPath] [-FlushDnsFirst]
                                [-ListEndpoints] [-CsvPath <file>] [-LogPath <file>]
```

Each endpoint is tested only on its documented protocol (HTTP-80 endpoints are never probed
over HTTPS). For HTTPS endpoints the TLS handshake captures the server certificate issuer -
a **non-Microsoft issuer** is flagged as likely SSL inspection, which breaks WU's
certificate pinning. `-FlushDnsFirst` is the only state-changing action and is
`ShouldProcess`-gated.

`-Category Wsus` (included in `All` when the machine is WSUS-managed) tests the configured
WSUS server instead: DNS, TCP, a TLS **chain** validation (not issuer-pinned - an internal
CA or self-signed cert is expected and fine), and a `ClientWebService/client.asmx` probe
that confirms the WSUS service itself responds, not just that the port is open.

### Test-WULocalClient.ps1

```powershell
# diagnostics (read-only)
.\Test-WULocalClient.ps1 [-Category System|Services|Proxy|Source|Blockers|Bits|Datastore|History|Events|All]
                         [-UpdateSource Auto|Online|WSUS]
                         [-RunLiveScan] [-EventDays 7] [-EventCount 10] [-MinFreeGB 10]
                         [-CsvPath <file>] [-LogPath <file>]

# remediation (opt-in, each ShouldProcess-gated; supports -WhatIf / -Confirm)
.\Test-WULocalClient.ps1 -FixServices
.\Test-WULocalClient.ps1 -ImportWinhttpProxy
.\Test-WULocalClient.ps1 -ClearErroredBitsJobs
.\Test-WULocalClient.ps1 -ResetSoftwareDistribution
.\Test-WULocalClient.ps1 -RepairComponentStore [-IncludeSfc]
```

A plain run changes nothing. Remediation happens only when its switch is supplied; preview
any of it with `-WhatIf`.

### Get-WUErrors.ps1

```powershell
# coded errors in the last N hours (benign noise filtered, grouped by HRESULT)
.\Get-WUErrors.ps1 [-HoursBack 24] [-UpdateSource Auto|Online|WSUS]
                   [-IncludeText] [-IncludeBenign] [-PassThru] [-CsvPath <file>]

# full timeline for one update (download -> install -> failure)
.\Get-WUErrors.ps1 -UpdateId 4345BE8F -HoursBack 168

# component-store (CBS) corruption triage - groups flagged manifests by language tag
.\Get-WUErrors.ps1 -ScanCbsCorruption
```

### Invoke-WUDiagnostics.ps1

```powershell
.\Invoke-WUDiagnostics.ps1 [-Include Connectivity,LocalClient,Errors|All]
                           [-UpdateSource Auto|Online|WSUS]
                           [-RunLiveScan] [-PerStepCsv]
                           [-ScriptFolder <dir>] [-ReportFolder <dir>]
```

Runs the three tools in order into `logs\WUDiag_<timestamp>\` and writes
`Combined-Summary.txt`. It forwards parameters adaptively (only what each script supports)
and is **read-only** - it never triggers the local-client remediation switches.
`-UpdateSource` (default `Auto`, registry-detected) is resolved once and forwarded to
every step, so a locked-down WSUS box reports a clean result end to end.

---

## Reading the output

Checks report `PASS` / `WARN` / `FAIL` / `INFO`. `INFO` never affects the combined
PASS/WARN/FAIL roll-up - it's how WSUS-expected results are shown without being false
positives: an unreachable Microsoft endpoint on a WSUS-managed box, for example.
`Get-WUErrors` groups failures by HRESULT
and annotates known ones, for example:

```
By result code:
  0x8024402c  x3    WU_E_PT_WINHTTP_NAME_NOT_RESOLVED (DNS / proxy)
  0x80073712  x7    ERROR_SXS_COMPONENT_STORE_CORRUPT (servicing)

Known-issue hints:
  0x80073712: often a known CU install issue (DISM/SFC frequently do NOT fix it) - check release health for an OOB fix
  Release health: https://learn.microsoft.com/windows/release-health/status-windows-server-2025
```

Codes that point back at the wire (`0x8024402c`, `0x80072f8f`, ...) send you to
`Test-WUOnlineConnectivity`; servicing codes (`0x80073712`, `0x800f0922`) point at the
component store and `Get-WUErrors -ScanCbsCorruption`.

---

## Worked example: a CU failing with 0x80073712

A real failure mode this toolset was built to catch (sanitized):

1. Multiple servers (deployed from one image) fail the latest cumulative update. The
   wrapper shows **Connectivity PASS, LocalClient PASS, Errors FAIL** - so it is not the
   network and not the client.
2. `Get-WUErrors.ps1` groups the failure under **`0x80073712`** and prints the known-issue
   hint (DISM/SFC will likely not fix it).
3. `Get-WUErrors.ps1 -ScanCbsCorruption` shows the corruption concentrated in **`en-gb`**
   language-pack / `.resources` manifests - a corrupt language pack, not generic store rot.
4. Because the corruption is in a language pack, a plain `DISM /RestoreHealth` (online or
   US-media source) cannot repair it. The fix is to remove/re-add that language pack
   (`Uninstall-Language` / `Install-Language`) or do an in-place upgrade with
   matching-language media - and to rebuild the golden image so new servers are not born
   with it.

The point: the toolset localizes the problem precisely instead of sending you on a blind
repair loop.

---

## Safety notes

- Diagnostics are read-only. Remediation is opt-in per switch and `ShouldProcess`-gated -
  preview with `-WhatIf`.
- `-ResetSoftwareDistribution` renames folders (reversible); `-RepairComponentStore` runs
  DISM/SFC and can take several minutes.
- On domain controllers and before in-place upgrades, snapshot / back up first.
- Test in a non-production environment before relying on any remediation in production.

---

## License

[MIT](LICENSE) (c) 2026 Tobias Tillstam (Tillnet)

Provided as-is, without warranty. See [CHANGELOG.md](CHANGELOG.md) for version history.
