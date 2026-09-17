#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Converts the modern Windows Update ETL logs and reports update errors within a
    time window, on Windows Server 2025 (and Windows 10 / Server 2016+).

.DESCRIPTION
    Part of the Windows Update troubleshooting toolset. Windows Update no longer writes
    a readable WindowsUpdate.log directly; the data lives in ETL files under
    C:\Windows\Logs\WindowsUpdate. This script uses Get-WindowsUpdateLog to merge and
    convert those ETL files into a single readable text log, then scans that log for
    error signals within the requested look-back window.

    Matching model (modern log):
    The modern converted log does not use the legacy 'WARNING'/'FAILED' severity words.
    The reliable error signal is the HRESULT result code (0x8xxxxxxx), so by default the
    script matches those codes. Routine, known-benign lines are filtered out (for example
    'ResetPendingBlocks ... failed, 0x80070002', which is just WU clearing download
    directories that no longer exist). Use -IncludeBenign to keep them, and -IncludeText
    to additionally match the noisier word tokens (fail/error/fatal/abort/exception).

    Output:
      - Matching lines are written to the console, color-coded (codes red, text-only
        matches yellow).
      - A per-HRESULT grouped summary is printed, annotated with known code meanings.
      - By default a single summary object is emitted to the pipeline (PASS/WARN/FAIL).
      - With -PassThru, one object per matched line is emitted instead.
      - With -CsvPath, the full matched-line detail (including the HResult) is exported.

    Supports -WhatIf and -Confirm.

.PARAMETER HoursBack
    Look-back window in hours, applied to the converted log timestamps. Default 24.

.PARAMETER ConvertedLogPath
    Where Get-WindowsUpdateLog writes the merged, readable log. Default is
    "$env:TEMP\WindowsUpdate.log". The target directory is created if missing.

.PARAMETER IncludeText
    Also match word tokens (fail / error / fatal / abort / exception) in addition to
    HRESULT codes. Noisier; off by default.

.PARAMETER IncludeBenign
    Do not filter known-benign noise lines (off by default, i.e. noise is filtered).

.PARAMETER SeverityPattern
    Override the match regex entirely. When supplied, -IncludeText is ignored.

.PARAMETER UpdateSource
    How to interpret this machine's update source. Auto (default) detects it from the
    WSUS/Defender policy registry keys. Online or WSUS forces the interpretation
    regardless of what the registry says. Affects only the known-issue hint text: a
    handful of codes (0x8024500C, 0x80244022, 0x8024401C, 0x80244019, 0x80246007) get
    WSUS-server-side guidance instead of client-network guidance when WSUS-managed, since
    Microsoft Update being unreachable is expected in that mode. Read-only; not
    ShouldProcess-gated.

.PARAMETER PassThru
    Emit one object per matched line instead of a single summary object.

.PARAMETER UpdateId
    Build a full timeline for a single update instead of scanning for errors. Accepts an
    update ID or any substring of it (e.g. '4345BE8F'). Every line mentioning it is shown
    in time order regardless of severity, benign filtering is bypassed, and coded-error
    lines are highlighted. Combine with -HoursBack to widen the window.

.PARAMETER ScanCbsCorruption
    Scan the CBS log for component-store corruption instead of the WU ETL. Reports
    corruption markers (CorruptManifest / ERROR_SXS_COMPONENT_STORE_CORRUPT) and the
    manifests CBS flagged as missing/corrupt, grouped by language tag. Useful for spotting
    corrupt language-pack manifests (a common 0x80073712 cause). Skips ETL conversion.

.PARAMETER CbsLogPath
    CBS log to scan with -ScanCbsCorruption. Defaults to %windir%\Logs\CBS\CBS.log.

.PARAMETER LogPath
    Path for the PowerShell transcript log. Defaults to a timestamped file in a 'logs'
    subfolder beside the script. The target directory is created if it does not exist.
    Set to an empty string ('') to disable transcript logging.

.PARAMETER CsvPath
    Optional path to export the matched lines as CSV. The target folder is created if
    it does not exist.

.EXAMPLE
    .\Get-WUErrors.ps1
    Lists HRESULT-coded errors from the last 24 hours, benign noise filtered out.

.EXAMPLE
    .\Get-WUErrors.ps1 -HoursBack 168
    Scans the last 7 days.

.EXAMPLE
    .\Get-WUErrors.ps1 -UpdateId 4345BE8F -HoursBack 168
    Shows the full 7-day timeline for that update (download, install attempts, failures).

.EXAMPLE
    .\Get-WUErrors.ps1 -ScanCbsCorruption
    Scans CBS.log for component-store corruption and groups the flagged manifests by
    language tag (skips the ETL conversion). Handy for fleet triage of 0x80073712.

.EXAMPLE
    .\Get-WUErrors.ps1 -IncludeText -IncludeBenign
    Widest net: HRESULTs plus word tokens, with benign noise included.

.EXAMPLE
    .\Get-WUErrors.ps1 -PassThru | Where-Object Result -eq 'FAIL'
    Emit per-line objects and filter to coded errors for further processing.

.EXAMPLE
    .\Get-WUErrors.ps1 -CsvPath 'C:\Temp\wu-errors.csv'
    Export the matched lines to CSV (folder created if needed).

.EXAMPLE
    .\Get-WUErrors.ps1 -UpdateSource WSUS
    Scans as usual, but known-issue hints for WSUS-affected codes (e.g. 0x8024500C) lead
    with WSUS-side causes (content sync, WsusPool health) instead of client connectivity.

.NOTES
    Author        : Tobias Tillstam, Tillnet
    Webpage       : https://tillnet.se
    GitHub        : https://github.com/tobiastillstam
    Version       : 1.1.0
    Date Created  : 2026-06-08
    Last Modified : 2026-08-19

    Change Log
    ----------
    1.1.0 (2026-08-19) - Added WSUS awareness: known-issue hints for 0x8024500C,
                         0x80244022, 0x8024401C, 0x80244019 and 0x80246007 now lead with
                         WSUS-server-side causes when the shared Get-WUUpdateSourceInfo
                         detection block finds this machine is WSUS-managed, since MU being
                         unreachable is expected in that mode. New -UpdateSource
                         Auto|Online|WSUS parameter (default Auto).
    1.0.0 (2026-06-20) - First public release under the MIT license.
    0.5.0 (2026-06-18) - Added -ScanCbsCorruption mode: scans the CBS log for component-
                         store corruption and groups the flagged manifests by language tag
                         (surfaces corrupt language-pack manifests behind 0x80073712).
                         Skips ETL conversion; -CbsLogPath overrides the log location.
    0.4.1 (2026-06-18) - Added known-issue hints: when a code commonly tied to a Microsoft
                         CU install bug appears (e.g. 0x80073712, 0x800f0983), the summary
                         prints a one-line pointer to the Windows release-health dashboard.
    0.4.0 (2026-06-18) - Added -UpdateId timeline mode: pulls every log line for a single
                         update (download/install/failure) in time order, regardless of
                         severity, with benign filtering bypassed and coded errors highlighted.
    0.3.1 (2026-06-18) - Added observed codes to the known-code map (0x8024000b,
                         0x8024a10a, 0x80248014, 0x80070306).
    0.3.0 (2026-06-18) - Recalibrated for the modern converted log: default matching now
                         centers on HRESULT codes (0x8xxxxxxx) rather than the legacy
                         WARNING/FAILED tokens, which do not appear in the modern format.
                         Added context-aware benign-noise filtering (-IncludeBenign to
                         disable), optional word-token matching (-IncludeText), a
                         per-HRESULT grouped summary with known-code annotations, and an
                         HResult field on output. Removed -ErrorsOnly.
    0.2.1 (2026-06-18) - Timestamp parser now accepts both 'yyyy/MM/dd' (modern converted
                         log) and 'yyyy-MM-dd' (legacy) date separators. The previous
                         dash-only pattern failed to parse the modern format, which left
                         the time filter ungated and produced false "no errors found"
                         results. Added parsed-timestamp instrumentation and a guard warning.
    0.2.0 (2026-06-17) - Reworked onto the standard Tillnet template: comment-based help,
                         CmdletBinding/ShouldProcess, parameters, transcript logging,
                         structured output and optional CSV export. Now requires elevation.
    0.1.0 (2026-06-08) - Initial lightweight release (console-only ETL filter).

    Operational notes:
    - Target: Windows Server 2025 (Windows PowerShell 5.1; also runs on PowerShell 7+).
    - Get-WindowsUpdateLog conversion typically takes 30-60 seconds.
    - The known-code annotations are a convenience, not an exhaustive reference.
    - Companion to Test-WUOnlineConnectivity.ps1, Test-WULocalClient.ps1 and the
      Invoke-WUDiagnostics.ps1 wrapper.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # Look-back window in hours.
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 720)]
    [int]$HoursBack = 24,

    # Destination for the converted, readable log.
    [Parameter(Mandatory = $false)]
    [string]$ConvertedLogPath = "$env:TEMP\WindowsUpdate.log",

    # Also match word tokens (fail/error/fatal/abort/exception).
    [Parameter(Mandatory = $false)]
    [switch]$IncludeText,

    # Keep known-benign noise lines instead of filtering them.
    [Parameter(Mandatory = $false)]
    [switch]$IncludeBenign,

    # Full override of the match regex.
    [Parameter(Mandatory = $false)]
    [string]$SeverityPattern,

    # How to interpret the update source: Auto detects from the registry, or force
    # Online/WSUS regardless of what the registry says. Affects known-issue hint text only.
    [Parameter(Mandatory = $false)]
    [ValidateSet('Auto', 'Online', 'WSUS')]
    [string]$UpdateSource = 'Auto',

    # Emit one object per matched line instead of a summary object.
    [Parameter(Mandatory = $false)]
    [switch]$PassThru,

    # Build a full timeline for a single update instead of scanning for errors. Accepts
    # an update ID or any substring of it (e.g. '4345BE8F'); matches every line that
    # mentions it, regardless of severity, so the download/install/failure sequence is
    # visible end to end.
    [Parameter(Mandatory = $false)]
    [string]$UpdateId,

    # Scan the CBS log for component-store corruption (manifests) instead of the WU ETL.
    # Skips the ETL conversion entirely; fast enough for fleet triage.
    [Parameter(Mandatory = $false)]
    [switch]$ScanCbsCorruption,

    # CBS log to scan when -ScanCbsCorruption is used.
    [Parameter(Mandatory = $false)]
    [string]$CbsLogPath = "$env:windir\Logs\CBS\CBS.log",

    # Transcript log path. Defaults to a 'logs' subfolder beside the script.
    # Empty string disables the transcript.
    [Parameter(Mandatory = $false)]
    [string]$LogPath = (Join-Path -Path $(if ($PSScriptRoot) { Join-Path $PSScriptRoot 'logs' } else { Join-Path (Get-Location).Path 'logs' }) -ChildPath ("Get-WUErrors_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))),

    # Optional CSV export path for the matched lines.
    [Parameter(Mandatory = $false)]
    [string]$CsvPath
)

# -------------------------------------------------------------------------
# Begin script body
# -------------------------------------------------------------------------

Write-Verbose "Starting $($MyInvocation.MyCommand.Name)"

$transcriptStarted = $false
$CutoffTime        = (Get-Date).AddHours(-$HoursBack)
$TimestampPattern  = '^\d{4}[-/]\d{2}[-/]\d{2}\s+\d{2}:\d{2}:\d{2}'
$HResultPattern    = '0x8[0-9a-fA-F]{7}'
$TextPattern       = '\b(fail(ed|ure)?|error|fatal|abort|exception)\b'

# Effective match pattern. -UpdateId switches to timeline mode: match every line that
# mentions the update, regardless of severity (benign filtering is also bypassed).
$TimelineMode = [bool]$UpdateId
if ($TimelineMode) {
    $EffectivePattern = [regex]::Escape($UpdateId)
}
elseif ($PSBoundParameters.ContainsKey('SeverityPattern') -and $SeverityPattern) {
    $EffectivePattern = $SeverityPattern
}
elseif ($IncludeText) {
    $EffectivePattern = ('{0}|{1}' -f $HResultPattern, $TextPattern)
}
else {
    $EffectivePattern = $HResultPattern
}

# Context-aware benign-noise filters. A matched line dropped if it matches any of these
# (unless -IncludeBenign). Kept deliberately conservative and documented.
$BenignPatterns = @(
    'ResetPendingBlocks.*0x80070002'   # WU clearing download dirs that no longer exist
)

# Convenience map of common WU / network / servicing result codes (not exhaustive).
$KnownCodes = @{
    '0x80070002' = 'ERROR_FILE_NOT_FOUND (often benign cleanup)'
    '0x80070003' = 'ERROR_PATH_NOT_FOUND'
    '0x80072ee2' = 'ERROR_INTERNET_TIMEOUT (network/proxy)'
    '0x80072efd' = 'ERROR_INTERNET_CANNOT_CONNECT (network)'
    '0x80072f8f' = 'ERROR_INTERNET_SECURE_FAILURE (TLS / clock / cert)'
    '0x8024401c' = 'WU_E_PT_HTTP_STATUS_REQUEST_TIMEOUT'
    '0x8024402c' = 'WU_E_PT_WINHTTP_NAME_NOT_RESOLVED (DNS / proxy)'
    '0x80244022' = 'WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL'
    '0x80240022' = 'WU_E_ALL_UPDATES_FAILED'
    '0x80240438' = 'WU_E_PT_ENDPOINT_UNREACHABLE'
    '0x80246007' = 'WU_E_DM_NOTDOWNLOADED'
    '0x8024000b' = 'WU_E_CALL_CANCELLED (operation cancelled)'
    '0x8024a10a' = 'Download cancelled by Update Orchestrator (caller abort)'
    '0x80248014' = 'WU_E_DS_UNKNOWNSERVICE (data store: service not found)'
    '0x80070306' = 'Win32 install error 0x0306 (update install failed)'
    '0x80073712' = 'ERROR_SXS_COMPONENT_STORE_CORRUPT (servicing)'
    '0x800f0922' = 'CBS install failure'
    '0x8024500c' = 'WU_E_REDIRECTOR_ID_SMALLER (redirector / service metadata)'
}

# Codes commonly tied to Microsoft-acknowledged CU install issues rather than local
# corruption. When one of these shows up, the most useful next step is checking the
# release-health dashboard for an out-of-band fix rather than (only) running repairs.
$ReleaseHealthUrl = 'https://learn.microsoft.com/windows/release-health/status-windows-server-2025'
$KnownIssueHints = @{
    '0x80073712' = 'often a known CU install issue (DISM/SFC frequently do NOT fix it) - check release health for an OOB fix'
    '0x800f0983' = 'PSFX/servicing failure seen in known CU install issues - check release health for an OOB fix'
    '0x800f0922' = 'CBS install failure - if it recurs on a specific CU, check release health for a known issue'
}

# WSUS-mode hints for codes that, in an online client, would normally point at client
# network/firewall causes - but when this machine is WSUS-managed, Microsoft Update being
# unreachable is expected, so these lead with WSUS-server-side causes instead. Overlaid on
# top of $KnownIssueHints (not merged in) when Get-WUUpdateSourceInfo resolves to WSUS, so
# WSUS-mode text replaces the online-mode text for the same code rather than adding to it.
$WsusIssueHints = @{
    '0x8024500c' = 'check WSUS content sync status on the server - approved in the console does not mean the content file finished downloading to WsusContent'
    '0x80244022' = 'WSUS server-side: IIS site / WsusPool app pool likely down or recycling - check IIS on the WSUS server, not client connectivity'
    '0x8024401c' = 'WSUS server timeout - check WsusPool health and SUSDB load on the WSUS server'
    '0x80244019' = 'HTTP 404 from WSUS - content approved in the console but missing from WsusContent on the server'
    '0x80246007' = 'not downloaded - content approved but absent on the WSUS server, not a client download failure'
}

# -------------------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------------------

# --- Canonical update-source detection (keep identical across all four scripts) ---
# Determines whether this machine is managed by WSUS for OS updates and, independently,
# what source Windows Defender uses for signature updates. Self-contained: does not call
# any other helper in this script, so it can be copy-pasted verbatim into any of the four
# WU-Troubleshooter scripts.
function Get-WUUpdateSourceInfo {
    [CmdletBinding()]
    param(
        # Manual override; default Auto resolves from the registry.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Auto', 'Online', 'WSUS')]
        [string]$Override = 'Auto'
    )

    $wuPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $auPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $defenderPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates'

    # UseWUServer is documented under \AU; fall back to the parent key since misplaced
    # values do occur in the field.
    $useWUServer = (Get-ItemProperty -Path $auPolicyPath -Name 'UseWUServer' -ErrorAction SilentlyContinue).UseWUServer
    if ($null -eq $useWUServer) {
        $useWUServer = (Get-ItemProperty -Path $wuPolicyPath -Name 'UseWUServer' -ErrorAction SilentlyContinue).UseWUServer
    }
    $wuServer = (Get-ItemProperty -Path $wuPolicyPath -Name 'WUServer' -ErrorAction SilentlyContinue).WUServer
    $wuStatusServer = (Get-ItemProperty -Path $wuPolicyPath -Name 'WUStatusServer' -ErrorAction SilentlyContinue).WUStatusServer

    $wsusManaged = ($useWUServer -eq 1)

    # Parse the WSUS URL, defaulting the port from the scheme when the URL omits it.
    $wuServerScheme = $null
    $wuServerHost   = $null
    $wuServerPort   = $null
    $wuServerValid  = $false
    if ($wuServer) {
        try {
            $uri = [Uri]$wuServer
            $wuServerScheme = $uri.Scheme
            $wuServerHost   = $uri.Host
            $wuServerPort   = if ($uri.Port -gt 0) { $uri.Port } elseif ($uri.Scheme -eq 'https') { 443 } else { 80 }
            $wuServerValid  = [bool]$wuServerHost
        }
        catch {
            $wuServerValid = $false
        }
    }

    # Defender's signature-update source is independent of the OS-update source above -
    # a box can be WSUS-managed for OS updates but still fall back to MicrosoftUpdateServer
    # for Defender definitions.
    $fallbackRaw   = (Get-ItemProperty -Path $defenderPath -Name 'FallbackOrder' -ErrorAction SilentlyContinue).FallbackOrder
    $fileSharesRaw = (Get-ItemProperty -Path $defenderPath -Name 'DefinitionUpdateFileSharesSources' -ErrorAction SilentlyContinue).DefinitionUpdateFileSharesSources
    $defenderFallbackOrder = @()
    if ($fallbackRaw) { $defenderFallbackOrder = @($fallbackRaw -split '\|' | Where-Object { $_ }) }
    $defenderFileShares = @()
    if ($fileSharesRaw) { $defenderFileShares = @($fileSharesRaw -split '\|' | Where-Object { $_ }) }
    $defenderUsesMicrosoftUpdate = [bool]($defenderFallbackOrder | Where-Object { $_ -in 'MicrosoftUpdateServer', 'MMPC' })

    # Resolve the effective source: an explicit override always wins over the registry.
    $source = 'Registry'
    if ($Override -eq 'Online') {
        $resolvedSource = 'Online'; $source = 'Override'
    }
    elseif ($Override -eq 'WSUS') {
        $resolvedSource = 'WSUS'; $source = 'Override'
    }
    else {
        $resolvedSource = if ($wsusManaged) { 'WSUS' } else { 'Online' }
    }

    [pscustomobject]@{
        UpdateSource                = $resolvedSource
        Source                      = $source
        WsusManaged                 = $wsusManaged
        WUServer                    = $wuServer
        WUStatusServer              = $wuStatusServer
        WUServerScheme              = $wuServerScheme
        WUServerHost                = $wuServerHost
        WUServerPort                = $wuServerPort
        WUServerValid               = $wuServerValid
        DefenderFallbackOrder       = $defenderFallbackOrder
        DefenderFileShares          = $defenderFileShares
        DefenderUsesMicrosoftUpdate = $defenderUsesMicrosoftUpdate
        Summary                     = ('UpdateSource={0} ({1}) | WSUS={2}{3} | DefenderUsesMU={4}' -f `
                $resolvedSource, $source, $wsusManaged, `
                $(if ($wsusManaged -and $wuServer) { " ($wuServer)" } else { '' }), `
                $defenderUsesMicrosoftUpdate)
    }
}
# --- End canonical update-source detection ---

function Confirm-ParentDirectory {
    <#
        Creates the parent directory of a file path if it does not already exist.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FilePath)
    $dir = Split-Path -Path $FilePath -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Verbose ("Created directory: {0}" -f $dir)
    }
}

function Invoke-CbsCorruptionScan {
    <#
        Scans a CBS log for component-store corruption signals and the manifests CBS
        reported as missing/corrupt, then summarizes them - in particular grouping by
        language tag, since corrupt language-pack manifests (e.g. en-gb) are a common
        cause of 0x80073712 that online/US-media DISM repair cannot fix. Returns result
        rows; prints a focused report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CbsLogPath,
        [Parameter(Mandatory)][switch]$EmitPerItem
    )

    Write-Host ''
    Write-Host ('--- Component store (CBS) scan: {0} ---' -f $CbsLogPath) -ForegroundColor Cyan

    if (-not (Test-Path -LiteralPath $CbsLogPath)) {
        Write-Warning ("CBS log not found at {0}" -f $CbsLogPath)
        return [pscustomobject]@{ Category = 'CbsStore'; Check = 'Scan'; Result = 'WARN'; Detail = 'CBS log not found' }
    }

    $corruptPattern  = 'CorruptManifest|ERROR_SXS_COMPONENT_STORE_CORRUPT|mark store corrupt'
    $manifestPattern = 'Manifests\\[^\\"]+\.manifest'
    $scanPattern     = ('{0}|{1}' -f $corruptPattern, $manifestPattern)

    $corruptionMarkers = 0
    $manifests = @{}   # name -> [pscustomobject]@{ Lang; IsLangPack }

    Select-String -Path $CbsLogPath -Pattern $scanPattern -ErrorAction SilentlyContinue | ForEach-Object {
        $line = $_.Line
        if ($line -match $corruptPattern) { $corruptionMarkers++ }

        $mm = [regex]::Match($line, 'Manifests\\(?<name>[^\\"]+\.manifest)')
        if ($mm.Success) {
            $name = $mm.Groups['name'].Value
            if (-not $manifests.ContainsKey($name)) {
                $lang = '(none)'
                $lm = [regex]::Match($name, '_(?<lang>[a-z]{2}-[a-z]{2})_')
                if ($lm.Success) { $lang = $lm.Groups['lang'].Value }
                $manifests[$name] = [pscustomobject]@{
                    Lang       = $lang
                    IsLangPack = [bool]($name -match 'languagepack|\.resources')
                }
            }
        }
    }

    $distinct = $manifests.Count
    $storeCorrupt = ($corruptionMarkers -gt 0)

    Write-Host ('Store corruption markers : {0}' -f $corruptionMarkers) -ForegroundColor $(if ($storeCorrupt) { 'Red' } else { 'Green' })
    Write-Host ('Distinct manifests flagged: {0}' -f $distinct) -ForegroundColor Gray

    # Language breakdown (the diagnostic tell).
    $byLang = $manifests.Values | Group-Object Lang | Sort-Object Count -Descending
    if ($byLang) {
        Write-Host 'By language tag:' -ForegroundColor Cyan
        foreach ($g in $byLang) {
            Write-Host ('  {0,-8} x{1}' -f $g.Name, $g.Count) -ForegroundColor Gray
        }
    }

    # Sample a few affected manifests.
    if ($distinct -gt 0) {
        Write-Host 'Sample affected manifests:' -ForegroundColor Cyan
        $manifests.Keys | Select-Object -First 5 | ForEach-Object { Write-Host ('  {0}' -f $_) -ForegroundColor DarkGray }
    }

    # Hint: a dominant non-"(none)" language among language-pack/resource manifests.
    $langCulprit = $byLang | Where-Object { $_.Name -ne '(none)' } | Select-Object -First 1
    $result = if ($storeCorrupt) { 'FAIL' } elseif ($distinct -gt 0) { 'WARN' } else { 'PASS' }

    if ($storeCorrupt -and $langCulprit) {
        Write-Host ''
        Write-Host ("Hint: corruption concentrated in '{0}' language-pack/resource manifests." -f $langCulprit.Name) -ForegroundColor Yellow
        Write-Host '      Online or US-media DISM repair will NOT fix this. Remove/re-add that language' -ForegroundColor Yellow
        Write-Host '      pack (Uninstall-Language / Install-Language) or do an in-place upgrade with' -ForegroundColor Yellow
        Write-Host '      matching-language media. Older CBS entries may be in CbsPersist_*.log.' -ForegroundColor Yellow
    }

    $detail = if ($storeCorrupt) {
        ('Store corruption detected; {0} manifest(s) flagged{1}' -f $distinct, $(if ($langCulprit) { ", concentrated in '$($langCulprit.Name)'" } else { '' }))
    }
    elseif ($distinct -gt 0) {
        ('{0} manifest(s) flagged, no explicit corruption marker' -f $distinct)
    }
    else {
        'No component-store corruption signals found'
    }

    if ($EmitPerItem) {
        foreach ($kv in $manifests.GetEnumerator()) {
            [pscustomobject]@{
                Category = 'CbsStore'
                Check    = 'Manifest'
                Result   = $(if ($storeCorrupt) { 'FAIL' } else { 'WARN' })
                Detail   = ('{0} | lang={1} | langpack={2}' -f $kv.Key, $kv.Value.Lang, $kv.Value.IsLangPack)
            }
        }
    }

    [pscustomobject]@{ Category = 'CbsStore'; Check = 'Scan'; Result = $result; Detail = $detail }
}

# -------------------------------------------------------------------------
# Main logic
# -------------------------------------------------------------------------

try {
    # --- Transcript (best-effort) ------------------------------------------
    if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
        try {
            Confirm-ParentDirectory -FilePath $LogPath
            Start-Transcript -Path $LogPath -Append -ErrorAction Stop | Out-Null
            $transcriptStarted = $true
        }
        catch {
            Write-Warning ("Could not start transcript at '{0}': {1}" -f $LogPath, $_.Exception.Message)
        }
    }

    # --- CBS component-store scan mode (skips the ETL conversion) ----------
    if ($ScanCbsCorruption) {
        Invoke-CbsCorruptionScan -CbsLogPath $CbsLogPath -EmitPerItem:$PassThru
        return
    }

    # --- Update source detection (affects known-issue hint text only) ------
    $sourceInfo = Get-WUUpdateSourceInfo -Override $UpdateSource
    Write-Host ("Update source: {0}" -f $sourceInfo.Summary) -ForegroundColor Cyan

    # --- Convert ETL to a readable log -------------------------------------
    Write-Host ("Converting ETL files to {0} (this can take 30-60s)..." -f $ConvertedLogPath) -ForegroundColor Cyan
    Confirm-ParentDirectory -FilePath $ConvertedLogPath
    Get-WindowsUpdateLog -LogPath $ConvertedLogPath -ErrorAction Stop | Out-Null

    if (-not (Test-Path -LiteralPath $ConvertedLogPath)) {
        throw ("Converted log not found at {0}." -f $ConvertedLogPath)
    }

    # --- Parse and filter --------------------------------------------------
    if ($TimelineMode) {
        Write-Host ("Building timeline for update '{0}' in the last {1} hour(s)...`n" -f $UpdateId, $HoursBack) -ForegroundColor Cyan
    }
    else {
        Write-Host ("Scanning for errors in the last {0} hour(s)...`n" -f $HoursBack) -ForegroundColor Cyan
    }

    $matched       = New-Object System.Collections.Generic.List[object]
    $lastStamp     = $null
    $parsedStamps  = 0
    $totalLines    = 0
    $benignSkipped = 0

    Get-Content -LiteralPath $ConvertedLogPath | ForEach-Object {
        $line = $_
        $totalLines++

        # Track the most recent timestamp seen. The modern converted log uses
        # 'yyyy/MM/dd'; the legacy format uses 'yyyy-MM-dd'. Accept either and
        # normalize the separator before an invariant-culture parse.
        if ($line -match $TimestampPattern) {
            $stampStr = (($Matches[0] -replace '\s+', ' ') -replace '/', '-')
            $dt = [datetime]::MinValue
            if ([datetime]::TryParseExact($stampStr, 'yyyy-MM-dd HH:mm:ss',
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::None, [ref]$dt)) {
                $lastStamp = $dt
                $parsedStamps++
            }
        }

        # Emit lines within the window that match the effective pattern.
        if ($lastStamp -and $lastStamp -ge $CutoffTime -and $line -match $EffectivePattern) {

            # Drop known-benign noise unless asked to keep it (never in timeline mode).
            if (-not $IncludeBenign -and -not $TimelineMode) {
                $skip = $false
                foreach ($bp in $BenignPatterns) { if ($line -match $bp) { $skip = $true; break } }
                if ($skip) { $benignSkipped++; return }
            }

            $hm = [regex]::Match($line, $HResultPattern)
            $hr = if ($hm.Success) { $hm.Value.ToLower() } else { $null }
            $isError = [bool]$hr
            # In timeline mode, non-coded lines are context (INFO); in scan mode a non-
            # coded match is a text-token hit (WARN).
            if ($isError) {
                $result = 'FAIL'; $severity = 'Error'; $color = 'Red'
            }
            elseif ($TimelineMode) {
                $result = 'INFO'; $severity = 'Info'; $color = 'Gray'
            }
            else {
                $result = 'WARN'; $severity = 'Warning'; $color = 'Yellow'
            }

            Write-Host $line -ForegroundColor $color

            $matched.Add([pscustomobject]@{
                    Category  = 'WUErrors'
                    TimeStamp = $lastStamp
                    Severity  = $severity
                    Result    = $result
                    HResult   = $hr
                    Line      = $line
                })
        }
    }

    # --- Summary -----------------------------------------------------------
    $errCount  = @($matched | Where-Object Result -eq 'FAIL').Count
    $warnCount = @($matched | Where-Object Result -eq 'WARN').Count

    Write-Host "`n--- Done ---" -ForegroundColor Cyan
    Write-Verbose ("Scanned {0} line(s); parsed {1} timestamp(s)." -f $totalLines, $parsedStamps)

    if ($parsedStamps -eq 0) {
        Write-Warning ("Parsed 0 timestamps from the converted log - the time filter is not working, so a '0 matches' result is unreliable. Inspect the date format in {0}." -f $ConvertedLogPath)
    }

    if ($matched.Count -eq 0) {
        if ($TimelineMode) {
            Write-Host ("No log lines mention '{0}' in the last {1} hour(s)." -f $UpdateId, $HoursBack) -ForegroundColor Green
        }
        else {
            Write-Host ("No errors found in the last {0} hour(s)." -f $HoursBack) -ForegroundColor Green
        }
    }
    elseif ($TimelineMode) {
        $infoCount = @($matched | Where-Object Result -eq 'INFO').Count
        Write-Host ("{0} line(s) for '{1}': {2} coded error(s), {3} context line(s)." -f $matched.Count, $UpdateId, $errCount, $infoCount) -ForegroundColor Yellow
    }
    else {
        Write-Host ("{0} line(s) matched: {1} coded error(s), {2} text match(es)." -f $matched.Count, $errCount, $warnCount) -ForegroundColor Yellow
    }

    if ($benignSkipped -gt 0) {
        Write-Host ("{0} benign noise line(s) filtered (use -IncludeBenign to show)." -f $benignSkipped) -ForegroundColor DarkGray
    }

    # Per-HRESULT grouped summary, annotated with known meanings.
    $byCode = $matched | Where-Object HResult | Group-Object HResult | Sort-Object Count -Descending
    if ($byCode) {
        Write-Host ''
        Write-Host 'By result code:' -ForegroundColor Cyan
        foreach ($g in $byCode) {
            $meaning = if ($KnownCodes.ContainsKey($g.Name)) { $KnownCodes[$g.Name] } else { 'unmapped' }
            Write-Host ('  {0}  x{1,-4} {2}' -f $g.Name, $g.Count, $meaning) -ForegroundColor Gray
        }

        # Known-issue hints for codes commonly tied to Microsoft CU bugs. In WSUS mode,
        # $WsusIssueHints overlays (replaces, per-code) the online-mode text, since MU
        # being unreachable is expected there and the online hint would misdirect.
        $effectiveHints = $KnownIssueHints.Clone()
        if ($sourceInfo.UpdateSource -eq 'WSUS') {
            foreach ($key in $WsusIssueHints.Keys) { $effectiveHints[$key] = $WsusIssueHints[$key] }
        }
        $hintCodes = @($byCode.Name | Where-Object { $effectiveHints.ContainsKey($_) })
        if ($hintCodes) {
            Write-Host ''
            Write-Host ('Known-issue hints ({0} mode):' -f $sourceInfo.UpdateSource) -ForegroundColor Yellow
            foreach ($code in $hintCodes) {
                Write-Host ('  {0}: {1}' -f $code, $effectiveHints[$code]) -ForegroundColor Yellow
            }
            Write-Host ('  Release health: {0}' -f $ReleaseHealthUrl) -ForegroundColor DarkGray
        }
    }

    # --- Optional CSV export -----------------------------------------------
    if ($CsvPath) {
        try {
            Confirm-ParentDirectory -FilePath $CsvPath
            $matched | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
            Write-Host ("Matched lines exported to {0}" -f $CsvPath) -ForegroundColor DarkCyan
        }
        catch {
            Write-Warning ("CSV export failed: {0}" -f $_.Exception.Message)
        }
    }

    # --- Pipeline output ---------------------------------------------------
    if ($PassThru) {
        $matched
    }
    else {
        $summaryResult = if ($errCount -gt 0) { 'FAIL' } elseif ($warnCount -gt 0) { 'WARN' } else { 'PASS' }
        [pscustomobject]@{
            Category = 'WUErrors'
            Check    = 'Summary'
            Result   = $summaryResult
            Detail   = ('{0} coded error(s), {1} text match(es) in last {2}h ({3} benign filtered)' -f $errCount, $warnCount, $HoursBack, $benignSkipped)
        }
    }
}
catch {
    Write-Error $_
    throw
}
finally {
    if ($transcriptStarted) {
        try { Stop-Transcript | Out-Null } catch { }
        Write-Host ("Transcript: {0}" -f $LogPath) -ForegroundColor DarkGray
    }
    Write-Verbose "Finished $($MyInvocation.MyCommand.Name)"
}
