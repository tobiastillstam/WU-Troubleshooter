#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Orchestrates the Windows Update troubleshooting toolset end to end and writes a
    single combined report.

.DESCRIPTION
    Runs the three WU troubleshooting scripts in the logical order, collecting each
    one's output into a shared, timestamped run folder:

      1. Connectivity - Test-WUOnlineConnectivity.ps1 (the network path to Microsoft)
      2. LocalClient  - Test-WULocalClient.ps1         (the local update client)
      3. Errors       - Get-WUErrors.ps1               (WU error/ETL detail)

    The wrapper is adaptive: for each script it inspects the parameters that script
    actually declares and only forwards the ones it supports. This means it works
    whether Get-WUErrors.ps1 is still the lightweight version (no parameters) or has
    been brought up to the full template (with -LogPath etc.). Scripts that expose
    -LogPath get their transcript pointed into the shared run folder; scripts that do
    not are captured to a per-step log via Tee instead.

    The wrapper itself is read-only. It does not invoke any of the remediation switches
    on Test-WULocalClient.ps1 - run those directly and deliberately when needed.

    Supports -WhatIf and -Confirm (forwarded to the child scripts, which gate their own
    state-changing actions).

.PARAMETER Include
    Which steps to run. One or more of: Connectivity, LocalClient, Errors, All.
    Default: All. Steps always run in the fixed order above regardless of the order given.

.PARAMETER ScriptFolder
    Folder containing the three scripts. Defaults to the folder this wrapper lives in.

.PARAMETER ReportFolder
    Base folder for run output. A timestamped subfolder (WUDiag_<timestamp>) is created
    inside it for this run. Defaults to a 'logs' subfolder beside this wrapper.

.PARAMETER RunLiveScan
    Forwarded to Test-WULocalClient.ps1 (if it supports it) to perform a live online
    WU scan. Touches the network and can take several minutes.

.PARAMETER PerStepCsv
    For each step that supports -CsvPath, export that step's results to a CSV in the
    run folder.

.EXAMPLE
    .\Invoke-WUDiagnostics.ps1
    Runs connectivity, local-client and error checks; combined output under .\logs\WUDiag_*.

.EXAMPLE
    .\Invoke-WUDiagnostics.ps1 -Include Connectivity,LocalClient -RunLiveScan
    Runs the two test scripts and forwards -RunLiveScan to the local-client check.

.EXAMPLE
    .\Invoke-WUDiagnostics.ps1 -PerStepCsv -ReportFolder 'D:\WU-Reports'
    Runs everything and writes per-step CSVs under D:\WU-Reports\WUDiag_<timestamp>.

.NOTES
    Author        : Tobias Tillstam, Tillnet
    Webpage       : https://tillnet.se
    GitHub        : https://github.com/tobiastillstam
    Version       : 1.0.0
    Date Created  : 2026-06-17
    Last Modified : 2026-06-20

    Change Log
    ----------
    1.0.0 (2026-06-20) - First public release under the MIT license.
    0.1.0 (2026-06-17) - Initial release.

    Operational notes:
    - Target: Windows Server 2025 (Windows PowerShell 5.1; also runs on PowerShell 7+).
    - Expects the three scripts to sit alongside this wrapper (override with -ScriptFolder).
    - Read-only orchestration; no remediation is triggered.
    - The wrapper does not start its own transcript (to avoid nesting); each step's
      record lands in the shared run folder.
    - Production-tested on Windows Server 2025. Run elevated and review the run folder.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # Steps to run.
    [Parameter(Mandatory = $false)]
    [ValidateSet('Connectivity', 'LocalClient', 'Errors', 'All')]
    [string[]]$Include = 'All',

    # Folder containing the three scripts.
    [Parameter(Mandatory = $false)]
    [string]$ScriptFolder = $(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }),

    # Base output folder; a timestamped run subfolder is created inside it.
    [Parameter(Mandatory = $false)]
    [string]$ReportFolder = $(if ($PSScriptRoot) { Join-Path $PSScriptRoot 'logs' } else { Join-Path (Get-Location).Path 'logs' }),

    # Forward a live online scan request to the local-client check.
    [Parameter(Mandatory = $false)]
    [switch]$RunLiveScan,

    # Export per-step CSVs (for steps that support -CsvPath).
    [Parameter(Mandatory = $false)]
    [switch]$PerStepCsv
)

# -------------------------------------------------------------------------
# Begin script body
# -------------------------------------------------------------------------

Write-Verbose "Starting $($MyInvocation.MyCommand.Name)"

# Step definitions in fixed execution order.
$StepCatalog = @(
    [pscustomobject]@{ Key = 'Connectivity'; File = 'Test-WUOnlineConnectivity.ps1'; Title = 'Network connectivity' }
    [pscustomobject]@{ Key = 'LocalClient';  File = 'Test-WULocalClient.ps1';        Title = 'Local update client' }
    [pscustomobject]@{ Key = 'Errors';       File = 'Get-WUErrors.ps1';              Title = 'WU error / ETL detail' }
)

# -------------------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------------------

function Add-IfSupported {
    <#
        Adds a parameter to the splat hashtable only if the target script declares it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.CommandInfo]$Command,
        [Parameter(Mandatory)][hashtable]$Splat,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value
    )
    if ($Command.Parameters.ContainsKey($Name)) {
        $Splat[$Name] = $Value
        Write-Verbose ("  forwarding -{0}" -f $Name)
    }
    else {
        Write-Verbose ("  -{0} not supported by this script; skipping" -f $Name)
    }
}

# -------------------------------------------------------------------------
# Main logic
# -------------------------------------------------------------------------

try {
    $runAll = $Include -contains 'All'

    # --- Create the run folder ---------------------------------------------
    $runFolder = Join-Path $ReportFolder ('WUDiag_{0:yyyyMMdd_HHmmss}' -f (Get-Date))
    if (-not (Test-Path -LiteralPath $runFolder)) {
        New-Item -Path $runFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    Write-Host ''
    Write-Host '=== Windows Update diagnostics (combined run) ===' -ForegroundColor Cyan
    Write-Host ("Host: {0}    Date: {1}" -f $env:COMPUTERNAME, (Get-Date)) -ForegroundColor Cyan
    Write-Host ("Run folder: {0}" -f $runFolder) -ForegroundColor Cyan

    $stepSummaries = New-Object System.Collections.Generic.List[object]

    foreach ($step in $StepCatalog) {
        if (-not ($runAll -or $Include -contains $step.Key)) { continue }

        $path = Join-Path $ScriptFolder $step.File
        Write-Host ''
        Write-Host ('################  {0}  ({1})  ################' -f $step.Title, $step.File) -ForegroundColor Cyan

        if (-not (Test-Path -LiteralPath $path)) {
            Write-Warning ("Script not found: {0}" -f $path)
            $stepSummaries.Add([pscustomobject]@{ Step = $step.Key; Status = 'SKIPPED (missing)'; Pass = $null; Warn = $null; Fail = $null; Log = $null })
            continue
        }

        try {
            $cmd  = Get-Command -Name $path -ErrorAction Stop
            $stepLog = Join-Path $runFolder ('{0}.log' -f $step.Key)
            $splat = @{}

            # Forward shared/optional parameters only if the script supports them.
            Add-IfSupported -Command $cmd -Splat $splat -Name 'LogPath' -Value $stepLog
            if ($RunLiveScan) { Add-IfSupported -Command $cmd -Splat $splat -Name 'RunLiveScan' -Value $true }
            if ($PerStepCsv)  { Add-IfSupported -Command $cmd -Splat $splat -Name 'CsvPath' -Value (Join-Path $runFolder ('{0}.csv' -f $step.Key)) }

            # Run the step. If it supports -LogPath it writes its own transcript into the
            # run folder and we keep colored console output; otherwise we Tee a plain log.
            if ($cmd.Parameters.ContainsKey('LogPath')) {
                $rows = & $path @splat
            }
            else {
                $rows = & $path @splat *>&1 | Tee-Object -FilePath $stepLog
            }

            # Count structured results (steps that emit PASS/WARN/FAIL objects).
            $resultRows = @($rows | Where-Object {
                    $_ -is [pscustomobject] -and $_.PSObject.Properties.Name -contains 'Result'
                })

            if ($resultRows.Count -gt 0) {
                $p = @($resultRows | Where-Object Result -eq 'PASS').Count
                $w = @($resultRows | Where-Object Result -eq 'WARN').Count
                $f = @($resultRows | Where-Object Result -eq 'FAIL').Count
                $status = if ($f) { 'FAIL' } elseif ($w) { 'WARN' } else { 'PASS' }
            }
            else {
                $p = $null; $w = $null; $f = $null; $status = 'Completed (see log)'
            }

            $stepSummaries.Add([pscustomobject]@{ Step = $step.Key; Status = $status; Pass = $p; Warn = $w; Fail = $f; Log = $stepLog })
        }
        catch {
            Write-Warning ("Step '{0}' failed: {1}" -f $step.Key, $_.Exception.Message)
            $stepSummaries.Add([pscustomobject]@{ Step = $step.Key; Status = 'ERROR'; Pass = $null; Warn = $null; Fail = $null; Log = $null })
        }
    }

    # --- Combined summary ---------------------------------------------------
    Write-Host ''
    Write-Host '=== Combined summary ===' -ForegroundColor Cyan
    foreach ($s in $stepSummaries) {
        $color = switch -Wildcard ($s.Status) {
            'FAIL*'    { 'Red' }
            'ERROR*'   { 'Red' }
            'WARN*'    { 'Yellow' }
            'SKIPPED*' { 'DarkGray' }
            'PASS*'    { 'Green' }
            default    { 'Gray' }
        }
        $counts = if ($null -ne $s.Pass) { ('P:{0} W:{1} F:{2}' -f $s.Pass, $s.Warn, $s.Fail) } else { '' }
        Write-Host ('  {0,-13} {1,-22} {2}' -f $s.Step, $s.Status, $counts) -ForegroundColor $color
    }

    $overall = if ($stepSummaries.Status -match 'FAIL|ERROR') { 'FAIL' }
    elseif ($stepSummaries.Status -match 'WARN') { 'WARN' }
    else { 'PASS' }
    Write-Host ''
    Write-Host ("Overall: {0}" -f $overall) -ForegroundColor $(if ($overall -eq 'FAIL') { 'Red' } elseif ($overall -eq 'WARN') { 'Yellow' } else { 'Green' })

    # Write the combined summary to the run folder.
    $summaryFile = Join-Path $runFolder 'Combined-Summary.txt'
    $summaryText = @()
    $summaryText += ('Windows Update diagnostics - combined run')
    $summaryText += ('Host    : {0}' -f $env:COMPUTERNAME)
    $summaryText += ('Date    : {0}' -f (Get-Date))
    $summaryText += ('Overall : {0}' -f $overall)
    $summaryText += ''
    $summaryText += ($stepSummaries | Format-Table Step, Status, Pass, Warn, Fail, Log -AutoSize | Out-String)
    $summaryText -join [Environment]::NewLine | Set-Content -Path $summaryFile -Encoding UTF8
    Write-Host ("Combined summary: {0}" -f $summaryFile) -ForegroundColor DarkCyan

    # Emit the step summary objects to the pipeline.
    $stepSummaries
}
catch {
    Write-Error $_
    throw
}
finally {
    Write-Verbose "Finished $($MyInvocation.MyCommand.Name)"
}
