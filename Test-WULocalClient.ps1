#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Health and troubleshooting check for the local Windows Update CLIENT on
    Windows Server 2025 (online Windows Update, not on-prem WSUS).

.DESCRIPTION
    Companion to Test-WUOnlineConnectivity.ps1. Where that script proves the
    network path to Microsoft's update endpoints, this one inspects the local
    update client that is supposed to use that path.

    Diagnostic modules (read-only):
      System    - OS build/UBR, last boot.
      Services  - wuauserv, bits, DoSvc, cryptsvc, msiserver, TrustedInstaller,
                  UsoSvc, WaaSMedicSvc (state + start mode + logon account).
      Proxy     - WinHTTP proxy (the SYSTEM-context proxy WU actually uses) vs the
                  per-user WinINET proxy, flagging the classic "set in IE but never
                  imported to WinHTTP" mismatch.
      Source    - WindowsUpdate policy keys and the registered update services (WU
                  COM ServiceManager), confirming the client targets Windows Update
                  online and is not silently pointed at WSUS / blocked by policy.
      Blockers  - pending reboot, system-drive free space, TLS 1.2 / .NET strong
                  crypto, and Windows Time service state (clock skew breaks the
                  certificate-pinned TLS handshake).
      Bits      - BITS transfer jobs (all users), flagging errored/stuck jobs.
      Datastore - SoftwareDistribution / catroot2 size and age.
      History   - last successful detect/download/install times.
      Events    - recent WindowsUpdateClient/Operational errors+warnings (summary
                  only; defer deep error/ETL analysis to Get-WUErrors.ps1).

    Optional live test:
      -RunLiveScan performs a real scan via the Microsoft.Update COM API forced to
      Windows Update online (ServerSelection = ssWindowsUpdate) and reports the
      update count or the COM HRESULT. This touches the network and can take a while.

    Optional remediation (each opt-in by an explicit switch, each gated by
    ShouldProcess so -WhatIf / -Confirm apply):
      -FixServices             Set required services to their expected start type and
                               start the ones that must run.
      -ImportWinhttpProxy      Import the IE/WinINET proxy into WinHTTP (netsh).
      -ClearErroredBitsJobs    Remove BITS jobs in an error/transient-error state.
      -ResetSoftwareDistribution
                               Stop WU-related services, rename SoftwareDistribution
                               and catroot2 to .old (reversible), restart services.
      -RepairComponentStore    Repair the servicing component store with DISM ScanHealth
                               then RestoreHealth (uses Windows Update online as source).
                               Add -IncludeSfc to also run SFC /scannow afterwards.

    A plain run changes nothing. Remediation happens only when its switch is supplied.

    Supports -WhatIf and -Confirm.

.PARAMETER Category
    Which diagnostic module(s) to run. One or more of:
      System, Services, Proxy, Source, Blockers, Bits, Datastore, History, Events, All
    Default: All.

.PARAMETER RunLiveScan
    Perform a live Microsoft.Update COM scan against Windows Update online. Touches
    the network and may take several minutes.

.PARAMETER EventDays
    Look-back window in days for the Events module. Default 7.

.PARAMETER EventCount
    Maximum number of recent WU client events to list. Default 10.

.PARAMETER MinFreeGB
    Free-space threshold (GB) on the system drive below which a warning is raised.
    Default 10.

.PARAMETER FixServices
    Remediation. Set required services to their expected start type and start the
    services that must be running. ShouldProcess-gated.

.PARAMETER ImportWinhttpProxy
    Remediation. Import the IE/WinINET proxy configuration into WinHTTP. ShouldProcess-gated.

.PARAMETER ClearErroredBitsJobs
    Remediation. Remove BITS jobs that are in an error or transient-error state.
    ShouldProcess-gated.

.PARAMETER ResetSoftwareDistribution
    Remediation. Stop WU-related services, rename SoftwareDistribution and catroot2 to
    timestamped .old folders, then restart the services. Reversible. ShouldProcess-gated.

.PARAMETER RepairComponentStore
    Remediation. Repair the servicing component store: DISM /Online /Cleanup-Image
    /ScanHealth then /RestoreHealth (RestoreHealth pulls from Windows Update online).
    Targets servicing/install failures such as 0x80070306. ShouldProcess-gated; can take
    several minutes.

.PARAMETER IncludeSfc
    Modifier for -RepairComponentStore: also run SFC /scannow after the DISM repair. Has
    no effect on its own.

.PARAMETER LogPath
    Path for the PowerShell transcript log. Defaults to a timestamped file in a 'logs'
    subfolder beside the script. The target directory is created if it does not exist.
    Set to an empty string ('') to disable transcript logging.

.PARAMETER CsvPath
    Optional path to export the full per-check result set as CSV. The target folder is
    created if it does not exist.

.EXAMPLE
    .\Test-WULocalClient.ps1
    Runs every read-only diagnostic module. Changes nothing.

.EXAMPLE
    .\Test-WULocalClient.ps1 -Category Services,Source,Blockers -Verbose
    Runs a focused subset with verbose per-step output.

.EXAMPLE
    .\Test-WULocalClient.ps1 -RunLiveScan
    Runs diagnostics and then performs a live online scan via the WU COM API.

.EXAMPLE
    .\Test-WULocalClient.ps1 -FixServices -WhatIf
    Previews the service remediation without making any changes.

.EXAMPLE
    .\Test-WULocalClient.ps1 -ResetSoftwareDistribution -Confirm
    Runs diagnostics and performs the SoftwareDistribution/catroot2 reset, prompting
    before the change.

.EXAMPLE
    .\Test-WULocalClient.ps1 -RepairComponentStore -IncludeSfc -Confirm
    Repairs the component store with DISM (ScanHealth + RestoreHealth) and then runs
    SFC /scannow, prompting before the change. Useful for 0x80070306 install failures.

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
    0.3.0 (2026-06-18) - Added -RepairComponentStore remediation (DISM ScanHealth +
                         RestoreHealth, with optional -IncludeSfc for SFC /scannow),
                         targeting servicing/install failures such as 0x80070306.
    0.2.0 (2026-06-18) - Registry and event-log reads now use SilentlyContinue instead of
                         caught terminating errors, removing noisy transcript output for
                         absent keys / no-match event queries. Results unchanged.
    0.1.0 (2026-06-17) - Initial release.

    Operational notes:
    - Target: Windows Server 2025 (Windows PowerShell 5.1; also runs on PowerShell 7+).
    - Scope: local online Windows Update client. On-prem WSUS is out of scope.
    - Read-only by default; remediation is opt-in per switch and ShouldProcess-gated.
    - Companion to Test-WUOnlineConnectivity.ps1 (network path) and Get-WUErrors.ps1
      (deep WU error/ETL analysis).
    - -ResetSoftwareDistribution renames rather than deletes, so it can be rolled back
      by restoring the .old folders.
    - Not yet executed in production. Run elevated and review the transcript log.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # Diagnostic module(s) to run.
    [Parameter(Mandatory = $false)]
    [ValidateSet('System', 'Services', 'Proxy', 'Source', 'Blockers', 'Bits', 'Datastore', 'History', 'Events', 'All')]
    [string[]]$Category = 'All',

    # Perform a live Microsoft.Update COM scan against Windows Update online.
    [Parameter(Mandatory = $false)]
    [switch]$RunLiveScan,

    # Events module look-back window in days.
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 90)]
    [int]$EventDays = 7,

    # Maximum number of recent WU client events to list.
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$EventCount = 10,

    # System-drive free-space warning threshold in GB.
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 1000)]
    [int]$MinFreeGB = 10,

    # Remediation: fix service start types / start required services.
    [Parameter(Mandatory = $false)]
    [switch]$FixServices,

    # Remediation: import IE/WinINET proxy into WinHTTP.
    [Parameter(Mandatory = $false)]
    [switch]$ImportWinhttpProxy,

    # Remediation: remove errored BITS jobs.
    [Parameter(Mandatory = $false)]
    [switch]$ClearErroredBitsJobs,

    # Remediation: reset SoftwareDistribution and catroot2 (rename to .old).
    [Parameter(Mandatory = $false)]
    [switch]$ResetSoftwareDistribution,

    # Remediation: repair the component store (DISM ScanHealth + RestoreHealth).
    [Parameter(Mandatory = $false)]
    [switch]$RepairComponentStore,

    # Modifier for -RepairComponentStore: also run SFC /scannow afterwards.
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSfc,

    # Transcript log path. Defaults to a 'logs' subfolder beside the script.
    # Empty string disables the transcript.
    [Parameter(Mandatory = $false)]
    [string]$LogPath = (Join-Path -Path $(if ($PSScriptRoot) { Join-Path $PSScriptRoot 'logs' } else { Join-Path (Get-Location).Path 'logs' }) -ChildPath ("Test-WULocalClient_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))),

    # Optional CSV export path for the full result set.
    [Parameter(Mandatory = $false)]
    [string]$CsvPath
)

# -------------------------------------------------------------------------
# Begin script body
# -------------------------------------------------------------------------

Write-Verbose "Starting $($MyInvocation.MyCommand.Name)"

$transcriptStarted = $false

# Services that matter to Windows Update, with their expected start mode and
# whether they must be running for updates to work.
$ServiceBaseline = @(
    [pscustomobject]@{ Name = 'wuauserv';         Display = 'Windows Update';            Desired = 'Manual';    MustRun = $false }
    [pscustomobject]@{ Name = 'bits';             Display = 'BITS';                      Desired = 'Manual';    MustRun = $false }
    [pscustomobject]@{ Name = 'DoSvc';            Display = 'Delivery Optimization';     Desired = 'Manual';    MustRun = $false }
    [pscustomobject]@{ Name = 'cryptsvc';         Display = 'Cryptographic Services';    Desired = 'Automatic'; MustRun = $true }
    [pscustomobject]@{ Name = 'msiserver';        Display = 'Windows Installer';         Desired = 'Manual';    MustRun = $false }
    [pscustomobject]@{ Name = 'TrustedInstaller'; Display = 'Windows Modules Installer'; Desired = 'Manual';    MustRun = $false }
    [pscustomobject]@{ Name = 'UsoSvc';           Display = 'Update Orchestrator';       Desired = 'Automatic'; MustRun = $false }
    [pscustomobject]@{ Name = 'WaaSMedicSvc';     Display = 'Windows Update Medic';      Desired = 'Manual';    MustRun = $false }
)

# -------------------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------------------

function New-CheckResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Result,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Detail
    )
    [pscustomobject]@{
        Category = $Category
        Check    = $Check
        Result   = $Result
        Detail   = $Detail
    }
}

function Get-RegistryValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($item -and ($item.PSObject.Properties.Name -contains $Name)) { return $item.$Name }
    return $null
}

function Write-ResultLine {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Result)
    switch ($Result.Result) {
        'PASS'  { $color = 'Green' }
        'WARN'  { $color = 'Yellow' }
        'FAIL'  { $color = 'Red' }
        'INFO'  { $color = 'Gray' }
        default { $color = 'Gray' }
    }
    Write-Host ('  [{0}] {1,-26} {2}' -f $Result.Result, $Result.Check, $Result.Detail) -ForegroundColor $color
}

function Invoke-RepairCommand {
    <#
        Runs an external repair tool (DISM/SFC), streams a concise tail of its output to
        the console, and returns the exit code plus full captured output. These tools can
        run for several minutes; output is captured rather than shown live.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Exe,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Label
    )

    Write-Host ("  Running {0} (this can take several minutes)..." -f $Label) -ForegroundColor Magenta
    $output = & $Exe @Arguments 2>&1 | Out-String
    $code = $LASTEXITCODE

    # Show the last few non-empty lines as a concise result.
    $output -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 4 |
        ForEach-Object { Write-Host ("    {0}" -f $_.Trim()) -ForegroundColor Gray }

    [pscustomobject]@{ Label = $Label; ExitCode = $code; Output = $output }
}

function Get-WUSystemInfo {
    [CmdletBinding()]
    param()
    $cv  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = Get-RegistryValue -Path $cv -Name 'CurrentBuild'
    $ubr   = Get-RegistryValue -Path $cv -Name 'UBR'
    $name  = Get-RegistryValue -Path $cv -Name 'ProductName'
    $disp  = Get-RegistryValue -Path $cv -Name 'DisplayVersion'
    $os    = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $boot  = if ($os) { $os.LastBootUpTime } else { $null }

    New-CheckResult -Category 'System' -Check 'OS / build' -Result 'INFO' `
        -Detail ('{0} ({1}) build {2}.{3}' -f $name, $disp, $build, $ubr)
    New-CheckResult -Category 'System' -Check 'Last boot' -Result 'INFO' `
        -Detail ($(if ($boot) { '{0} (up {1:0.0} h)' -f $boot, ((Get-Date) - $boot).TotalHours } else { 'unknown' }))
}

function Get-WUServiceCheck {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Baseline)

    $svcMap = @{}
    try {
        Get-CimInstance Win32_Service -ErrorAction Stop |
            Where-Object { $Baseline.Name -contains $_.Name } |
            ForEach-Object { $svcMap[$_.Name] = $_ }
    }
    catch {
        Write-Verbose ("Win32_Service query failed: {0}" -f $_.Exception.Message)
    }

    foreach ($b in $Baseline) {
        $svc = $svcMap[$b.Name]
        if (-not $svc) {
            New-CheckResult -Category 'Services' -Check $b.Name -Result 'WARN' -Detail ('{0}: not found' -f $b.Display)
            continue
        }
        $state = $svc.State        # Running / Stopped
        $mode  = $svc.StartMode    # Auto / Manual / Disabled
        $acct  = $svc.StartName
        $detail = ('{0}: {1}, {2}, {3}' -f $b.Display, $state, $mode, $acct)

        $result = 'PASS'
        if ($mode -eq 'Disabled') {
            $result = 'WARN'; $detail += ' | DISABLED'
        }
        elseif ($b.MustRun -and $state -ne 'Running') {
            $result = 'WARN'; $detail += ' | should be Running'
        }
        New-CheckResult -Category 'Services' -Check $b.Name -Result $result -Detail $detail
    }
}

function Get-WUProxyCheck {
    [CmdletBinding()]
    param()

    # WinHTTP (SYSTEM context - what WU uses)
    $winhttpRaw = $null
    $winhttpProxy = $null
    try {
        $winhttpRaw = (netsh winhttp show proxy) 2>$null
        $m = [regex]::Match(($winhttpRaw -join ' '), '(?<h>[A-Za-z0-9\.\-]+):(?<p>\d{1,5})')
        if ($m.Success) { $winhttpProxy = ('{0}:{1}' -f $m.Groups['h'].Value, $m.Groups['p'].Value) }
    }
    catch { Write-Verbose ("netsh winhttp failed: {0}" -f $_.Exception.Message) }

    New-CheckResult -Category 'Proxy' -Check 'WinHTTP proxy' -Result 'INFO' `
        -Detail ($(if ($winhttpProxy) { $winhttpProxy } else { 'direct / none' }))

    # WinINET (per-user) proxy
    $inetPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $inetEnabled = Get-RegistryValue -Path $inetPath -Name 'ProxyEnable'
    $inetServer  = Get-RegistryValue -Path $inetPath -Name 'ProxyServer'
    $inetActive  = ($inetEnabled -eq 1 -and $inetServer)

    New-CheckResult -Category 'Proxy' -Check 'WinINET (user) proxy' -Result 'INFO' `
        -Detail ($(if ($inetActive) { $inetServer } else { 'direct / none' }))

    # The classic mismatch: user proxy set, WinHTTP direct -> WU (SYSTEM) bypasses it.
    if ($inetActive -and -not $winhttpProxy) {
        New-CheckResult -Category 'Proxy' -Check 'Proxy consistency' -Result 'WARN' `
            -Detail 'IE/WinINET proxy set but WinHTTP is direct; WU runs as SYSTEM and will not use the IE proxy (consider importing it)'
    }
    else {
        New-CheckResult -Category 'Proxy' -Check 'Proxy consistency' -Result 'PASS' `
            -Detail 'No WinHTTP/WinINET mismatch detected'
    }
}

function Get-WUSourceCheck {
    [CmdletBinding()]
    param()

    $wuPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $auPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'

    $useWUServer = Get-RegistryValue -Path $auPol -Name 'UseWUServer'
    $wuServer    = Get-RegistryValue -Path $wuPol -Name 'WUServer'
    $noInternet  = Get-RegistryValue -Path $wuPol -Name 'DoNotConnectToWindowsUpdateInternetLocations'
    $disableAll  = Get-RegistryValue -Path $wuPol -Name 'DisableWindowsUpdateAccess'

    if ($useWUServer -eq 1) {
        New-CheckResult -Category 'Source' -Check 'WSUS policy' -Result 'WARN' `
            -Detail ('UseWUServer=1 -> client targets WSUS ({0}), not Windows Update online' -f ($(if ($wuServer) { $wuServer } else { 'no WUServer set' })))
    }
    else {
        New-CheckResult -Category 'Source' -Check 'WSUS policy' -Result 'PASS' `
            -Detail 'UseWUServer not set -> not forced to WSUS'
    }

    if ($noInternet -eq 1) {
        New-CheckResult -Category 'Source' -Check 'Online access policy' -Result 'WARN' `
            -Detail 'DoNotConnectToWindowsUpdateInternetLocations=1 -> online WU blocked by policy'
    }
    if ($disableAll -eq 1) {
        New-CheckResult -Category 'Source' -Check 'WU access policy' -Result 'WARN' `
            -Detail 'DisableWindowsUpdateAccess=1 -> Windows Update features turned off by policy'
    }

    # Registered update services via COM
    try {
        $sm = New-Object -ComObject Microsoft.Update.ServiceManager
        $offersOnline = $false
        foreach ($s in $sm.Services) {
            $offers = $false
            try { $offers = [bool]$s.OffersWindowsUpdates } catch { }
            $isDefault = $false
            try { $isDefault = [bool]$s.IsDefaultAUService } catch { }
            if ($offers) { $offersOnline = $true }
            New-CheckResult -Category 'Source' -Check 'Registered service' -Result 'INFO' `
                -Detail ('{0} | offersWU={1} | default={2}' -f $s.Name, $offers, $isDefault)
        }
        New-CheckResult -Category 'Source' -Check 'Online service present' -Result $(if ($offersOnline) { 'PASS' } else { 'WARN' }) `
            -Detail ($(if ($offersOnline) { 'A registered service offers Windows Update content' } else { 'No registered service offers Windows Update content' }))
    }
    catch {
        New-CheckResult -Category 'Source' -Check 'WU ServiceManager (COM)' -Result 'WARN' `
            -Detail ('Could not enumerate update services: {0}' -f $_.Exception.Message)
    }
}

function Get-WUBlockerCheck {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$MinFreeGB)

    # Pending reboot
    $pending = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending += 'CBS' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending += 'WindowsUpdate' }
    $pfro = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations'
    if ($pfro) { $pending += 'PendingFileRename' }

    if ($pending.Count -gt 0) {
        New-CheckResult -Category 'Blockers' -Check 'Pending reboot' -Result 'WARN' -Detail ('Pending: {0}' -f ($pending -join ', '))
    }
    else {
        New-CheckResult -Category 'Blockers' -Check 'Pending reboot' -Result 'PASS' -Detail 'No pending reboot detected'
    }

    # Disk space
    $sysDrive = $env:SystemDrive
    try {
        $disk = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $sysDrive) -ErrorAction Stop
        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 1)
        $pct    = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 0)
        $res    = if ($freeGB -lt $MinFreeGB) { 'WARN' } else { 'PASS' }
        New-CheckResult -Category 'Blockers' -Check 'Free disk space' -Result $res -Detail ('{0} free: {1} GB ({2}%)' -f $sysDrive, $freeGB, $pct)
    }
    catch {
        New-CheckResult -Category 'Blockers' -Check 'Free disk space' -Result 'WARN' -Detail ('Could not read disk: {0}' -f $_.Exception.Message)
    }

    # TLS 1.2 (SChannel client) - only flag explicit disable; absence = OS default (enabled)
    $tls12 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
    $tlsEnabled = Get-RegistryValue -Path $tls12 -Name 'Enabled'
    $tlsDisabled = Get-RegistryValue -Path $tls12 -Name 'DisabledByDefault'
    if ($tlsEnabled -eq 0 -or $tlsDisabled -eq 1) {
        New-CheckResult -Category 'Blockers' -Check 'TLS 1.2 (SChannel)' -Result 'WARN' -Detail 'TLS 1.2 client appears explicitly disabled'
    }
    else {
        New-CheckResult -Category 'Blockers' -Check 'TLS 1.2 (SChannel)' -Result 'PASS' -Detail 'TLS 1.2 client enabled (or OS default)'
    }

    # .NET strong crypto (affects the Invoke-WebRequest / .NET path)
    $netKey = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
    $strong = Get-RegistryValue -Path $netKey -Name 'SchUseStrongCrypto'
    $sysdef = Get-RegistryValue -Path $netKey -Name 'SystemDefaultTlsVersions'
    if ($strong -eq 1 -and $sysdef -eq 1) {
        New-CheckResult -Category 'Blockers' -Check '.NET strong crypto' -Result 'PASS' -Detail 'SchUseStrongCrypto and SystemDefaultTlsVersions set'
    }
    else {
        New-CheckResult -Category 'Blockers' -Check '.NET strong crypto' -Result 'INFO' `
            -Detail ('SchUseStrongCrypto={0}, SystemDefaultTlsVersions={1} (OS default may still be fine)' -f $strong, $sysdef)
    }

    # Windows Time service
    $w32 = Get-Service -Name 'w32time' -ErrorAction SilentlyContinue
    if ($w32) {
        $res = if ($w32.Status -ne 'Running') { 'WARN' } else { 'PASS' }
        New-CheckResult -Category 'Blockers' -Check 'Windows Time (w32time)' -Result $res `
            -Detail ('{0} (clock skew breaks pinned TLS)' -f $w32.Status)
    }
}

function Get-WUBitsCheck {
    [CmdletBinding()]
    param()
    try {
        $jobs = @(Get-BitsTransfer -AllUsers -ErrorAction Stop)
        if ($jobs.Count -eq 0) {
            New-CheckResult -Category 'Bits' -Check 'BITS jobs' -Result 'PASS' -Detail 'No active BITS jobs'
            return
        }
        $bad = @($jobs | Where-Object { $_.JobState -in 'Error', 'TransientError' })
        New-CheckResult -Category 'Bits' -Check 'BITS jobs' -Result $(if ($bad.Count) { 'WARN' } else { 'INFO' }) `
            -Detail ('{0} job(s); {1} in error/transient' -f $jobs.Count, $bad.Count)
        foreach ($j in ($jobs | Select-Object -First 10)) {
            New-CheckResult -Category 'Bits' -Check 'BITS job' -Result $(if ($j.JobState -in 'Error', 'TransientError') { 'WARN' } else { 'INFO' }) `
                -Detail ('{0} | {1} | {2}/{3} bytes' -f $j.DisplayName, $j.JobState, $j.BytesTransferred, $j.BytesTotal)
        }
    }
    catch {
        New-CheckResult -Category 'Bits' -Check 'BITS jobs' -Result 'INFO' -Detail ('Could not query BITS: {0}' -f $_.Exception.Message)
    }
}

function Get-WUDatastoreCheck {
    [CmdletBinding()]
    param()

    $sd = Join-Path $env:windir 'SoftwareDistribution'
    if (Test-Path -LiteralPath $sd) {
        $lastWrite = (Get-Item -LiteralPath $sd).LastWriteTime
        $sizeGB = $null
        try {
            $sum = (Get-ChildItem -LiteralPath $sd -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
            if ($sum) { $sizeGB = [math]::Round($sum / 1GB, 2) }
        }
        catch { Write-Verbose ("SoftwareDistribution sizing failed: {0}" -f $_.Exception.Message) }
        $res = if ($sizeGB -and $sizeGB -gt 10) { 'WARN' } else { 'INFO' }
        New-CheckResult -Category 'Datastore' -Check 'SoftwareDistribution' -Result $res `
            -Detail ('{0} GB, last write {1}' -f ($(if ($null -ne $sizeGB) { $sizeGB } else { '?' }), $lastWrite))
    }
    else {
        New-CheckResult -Category 'Datastore' -Check 'SoftwareDistribution' -Result 'INFO' -Detail 'Folder not present'
    }

    $catroot2 = Join-Path $env:windir 'System32\catroot2'
    if (Test-Path -LiteralPath $catroot2) {
        $lw = (Get-Item -LiteralPath $catroot2).LastWriteTime
        New-CheckResult -Category 'Datastore' -Check 'catroot2' -Result 'INFO' -Detail ('present, last write {0}' -f $lw)
    }
}

function Get-WUHistoryCheck {
    [CmdletBinding()]
    param()
    $results = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results'
    foreach ($phase in 'Detect', 'Download', 'Install') {
        $t = Get-RegistryValue -Path (Join-Path $results $phase) -Name 'LastSuccessTime'
        if ($t) {
            $age = $null
            try { $age = ((Get-Date) - [datetime]$t).TotalDays } catch { }
            $res = if ($phase -eq 'Detect' -and $age -ne $null -and $age -gt 30) { 'WARN' } else { 'INFO' }
            New-CheckResult -Category 'History' -Check ('Last {0} success' -f $phase) -Result $res `
                -Detail ($(if ($age -ne $null) { '{0} ({1:0} days ago)' -f $t, $age } else { $t }))
        }
        else {
            New-CheckResult -Category 'History' -Check ('Last {0} success' -f $phase) -Result 'INFO' -Detail 'no record'
        }
    }
}

function Get-WUEventCheck {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$Days, [Parameter(Mandatory)][int]$Count)

    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-WindowsUpdateClient/Operational'
        Level     = 2, 3   # Error, Warning
        StartTime = (Get-Date).AddDays(-$Days)
    } -MaxEvents $Count -ErrorAction SilentlyContinue

    if (-not $events) {
        New-CheckResult -Category 'Events' -Check 'Recent WU errors/warnings' -Result 'PASS' `
            -Detail ('No Error/Warning events in last {0} day(s)' -f $Days)
        return
    }

    New-CheckResult -Category 'Events' -Check 'Recent WU errors/warnings' -Result 'WARN' `
        -Detail ('{0} event(s) in last {1} day(s); see Get-WUErrors.ps1 for deep analysis' -f $events.Count, $Days)
    foreach ($e in $events) {
        $msg = ($e.Message -split "`r?`n" | Select-Object -First 1)
        New-CheckResult -Category 'Events' -Check ('Event {0}' -f $e.Id) -Result 'INFO' `
            -Detail ('{0:yyyy-MM-dd HH:mm} | {1}' -f $e.TimeCreated, $msg)
    }
}

function Invoke-WULiveScan {
    [CmdletBinding()]
    param()
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        # Force Windows Update online (ssWindowsUpdate = 2) regardless of WSUS config.
        try { $searcher.ServerSelection = 2 } catch { Write-Verbose 'Could not set ServerSelection.' }
        $sw  = [System.Diagnostics.Stopwatch]::StartNew()
        $res = $searcher.Search('IsInstalled=0 and IsHidden=0')
        $sw.Stop()
        New-CheckResult -Category 'LiveScan' -Check 'Online scan' -Result 'PASS' `
            -Detail ('{0} update(s) available; scan took {1:0.0}s' -f $res.Updates.Count, $sw.Elapsed.TotalSeconds)
    }
    catch {
        $hr = $null
        try { $hr = ('0x{0:X8}' -f $_.Exception.HResult) } catch { }
        New-CheckResult -Category 'LiveScan' -Check 'Online scan' -Result 'FAIL' `
            -Detail ('Scan failed {0}: {1}' -f $hr, $_.Exception.Message)
    }
}

# -------------------------------------------------------------------------
# Main logic
# -------------------------------------------------------------------------

try {
    # --- Transcript (best-effort) ------------------------------------------
    if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
        try {
            $logDir = Split-Path -Path $LogPath -Parent
            if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Verbose ("Created log directory: {0}" -f $logDir)
            }
            Start-Transcript -Path $LogPath -Append -ErrorAction Stop | Out-Null
            $transcriptStarted = $true
        }
        catch {
            Write-Warning ("Could not start transcript at '{0}': {1}" -f $LogPath, $_.Exception.Message)
        }
    }

    Write-Host ''
    Write-Host '=== Windows Update LOCAL CLIENT health check ===' -ForegroundColor Cyan
    Write-Host ("Host: {0}    Date: {1}" -f $env:COMPUTERNAME, (Get-Date)) -ForegroundColor Cyan
    Write-Host ("Modules: {0}    LiveScan: {1}" -f ($Category -join ','), [bool]$RunLiveScan) -ForegroundColor Cyan

    $runAll  = $Category -contains 'All'
    $results = New-Object System.Collections.Generic.List[object]

    # --- Diagnostic modules -------------------------------------------------
    if ($runAll -or $Category -contains 'System')    { Get-WUSystemInfo                                  | ForEach-Object { $results.Add($_) } }
    if ($runAll -or $Category -contains 'Services')   { Get-WUServiceCheck -Baseline $ServiceBaseline     | ForEach-Object { $results.Add($_) } }
    if ($runAll -or $Category -contains 'Proxy')      { Get-WUProxyCheck                                  | ForEach-Object { $results.Add($_) } }
    if ($runAll -or $Category -contains 'Source')     { Get-WUSourceCheck                                 | ForEach-Object { $results.Add($_) } }
    if ($runAll -or $Category -contains 'Blockers')   { Get-WUBlockerCheck -MinFreeGB $MinFreeGB          | ForEach-Object { $results.Add($_) } }
    if ($runAll -or $Category -contains 'Bits')       { Get-WUBitsCheck                                   | ForEach-Object { $results.Add($_) } }
    if ($runAll -or $Category -contains 'Datastore')  { Get-WUDatastoreCheck                              | ForEach-Object { $results.Add($_) } }
    if ($runAll -or $Category -contains 'History')    { Get-WUHistoryCheck                                | ForEach-Object { $results.Add($_) } }
    if ($runAll -or $Category -contains 'Events')     { Get-WUEventCheck -Days $EventDays -Count $EventCount | ForEach-Object { $results.Add($_) } }

    # --- Optional live scan -------------------------------------------------
    if ($RunLiveScan) { Invoke-WULiveScan | ForEach-Object { $results.Add($_) } }

    # --- Report -------------------------------------------------------------
    foreach ($group in ($results | Group-Object Category)) {
        Write-Host ''
        Write-Host ('--- {0} ---' -f $group.Name) -ForegroundColor Cyan
        foreach ($row in $group.Group) { Write-ResultLine -Result $row }
    }

    Write-Host ''
    Write-Host '=== Summary ===' -ForegroundColor Cyan
    $pass = ($results | Where-Object Result -eq 'PASS').Count
    $warn = ($results | Where-Object Result -eq 'WARN').Count
    $fail = ($results | Where-Object Result -eq 'FAIL').Count
    Write-Host ("PASS: {0}   WARN: {1}   FAIL: {2}" -f $pass, $warn, $fail) `
        -ForegroundColor $(if ($fail) { 'Red' } elseif ($warn) { 'Yellow' } else { 'Green' })

    # --- Remediation (opt-in, ShouldProcess-gated) --------------------------

    if ($FixServices) {
        Write-Host ''
        Write-Host '--- Remediation: services ---' -ForegroundColor Magenta
        foreach ($b in $ServiceBaseline) {
            $svc = Get-Service -Name $b.Name -ErrorAction SilentlyContinue
            if (-not $svc) { Write-Warning ("Service not found: {0}" -f $b.Name); continue }
            try {
                $current = (Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $b.Name) -ErrorAction Stop).StartMode
            }
            catch { $current = $null }

            $needType = ($current -and (
                    ($b.Desired -eq 'Automatic' -and $current -ne 'Auto') -or
                    ($b.Desired -eq 'Manual'    -and $current -notin 'Manual', 'Auto')))

            if ($needType) {
                if ($PSCmdlet.ShouldProcess($b.Name, ('Set start type to {0}' -f $b.Desired))) {
                    try { Set-Service -Name $b.Name -StartupType $b.Desired -ErrorAction Stop; Write-Host ("  {0}: start type -> {1}" -f $b.Name, $b.Desired) -ForegroundColor Green }
                    catch { Write-Warning ("  {0}: could not set start type ({1})" -f $b.Name, $_.Exception.Message) }
                }
            }
            if ($b.MustRun -and $svc.Status -ne 'Running') {
                if ($PSCmdlet.ShouldProcess($b.Name, 'Start service')) {
                    try { Start-Service -Name $b.Name -ErrorAction Stop; Write-Host ("  {0}: started" -f $b.Name) -ForegroundColor Green }
                    catch { Write-Warning ("  {0}: could not start ({1})" -f $b.Name, $_.Exception.Message) }
                }
            }
        }
    }

    if ($ImportWinhttpProxy) {
        Write-Host ''
        Write-Host '--- Remediation: import WinHTTP proxy ---' -ForegroundColor Magenta
        if ($PSCmdlet.ShouldProcess('WinHTTP', 'Import proxy from IE (netsh winhttp import proxy source=ie)')) {
            try {
                $out = netsh winhttp import proxy source=ie 2>&1
                Write-Host ('  ' + ($out -join ' ')) -ForegroundColor Green
            }
            catch { Write-Warning ("  Import failed: {0}" -f $_.Exception.Message) }
        }
    }

    if ($ClearErroredBitsJobs) {
        Write-Host ''
        Write-Host '--- Remediation: clear errored BITS jobs ---' -ForegroundColor Magenta
        try {
            $bad = @(Get-BitsTransfer -AllUsers -ErrorAction Stop | Where-Object { $_.JobState -in 'Error', 'TransientError' })
            if ($bad.Count -eq 0) { Write-Host '  No errored BITS jobs.' -ForegroundColor Green }
            foreach ($j in $bad) {
                if ($PSCmdlet.ShouldProcess($j.DisplayName, 'Remove BITS job')) {
                    try { $j | Remove-BitsTransfer -ErrorAction Stop; Write-Host ("  removed: {0}" -f $j.DisplayName) -ForegroundColor Green }
                    catch { Write-Warning ("  could not remove {0}: {1}" -f $j.DisplayName, $_.Exception.Message) }
                }
            }
        }
        catch { Write-Warning ("  Could not query BITS: {0}" -f $_.Exception.Message) }
    }

    if ($ResetSoftwareDistribution) {
        Write-Host ''
        Write-Host '--- Remediation: reset SoftwareDistribution / catroot2 ---' -ForegroundColor Magenta
        $resetServices = 'wuauserv', 'bits', 'cryptsvc', 'msiserver', 'UsoSvc'
        if ($PSCmdlet.ShouldProcess('SoftwareDistribution and catroot2', 'Stop WU services, rename folders to .old, restart services')) {
            $stamp = '{0:yyyyMMdd_HHmmss}' -f (Get-Date)
            try {
                foreach ($s in $resetServices) {
                    Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
                }
                foreach ($folder in @((Join-Path $env:windir 'SoftwareDistribution'), (Join-Path $env:windir 'System32\catroot2'))) {
                    if (Test-Path -LiteralPath $folder) {
                        $target = ('{0}.old.{1}' -f $folder, $stamp)
                        Rename-Item -LiteralPath $folder -NewName (Split-Path $target -Leaf) -ErrorAction Stop
                        Write-Host ("  renamed {0} -> {1}" -f $folder, (Split-Path $target -Leaf)) -ForegroundColor Green
                    }
                }
            }
            catch {
                Write-Warning ("  Reset error: {0}" -f $_.Exception.Message)
            }
            finally {
                foreach ($s in $resetServices) {
                    Start-Service -Name $s -ErrorAction SilentlyContinue
                }
                Write-Host '  Services restarted. A reboot is recommended before re-scanning.' -ForegroundColor Green
            }
        }
    }

    if ($RepairComponentStore) {
        Write-Host ''
        Write-Host '--- Remediation: component store repair ---' -ForegroundColor Magenta
        $action = 'DISM ScanHealth + RestoreHealth'
        if ($IncludeSfc) { $action += ' + SFC /scannow' }

        if ($PSCmdlet.ShouldProcess('Windows component store', $action)) {
            try {
                $scan = Invoke-RepairCommand -Exe 'dism.exe' -Arguments @('/Online', '/Cleanup-Image', '/ScanHealth') -Label 'DISM ScanHealth'
                $restore = Invoke-RepairCommand -Exe 'dism.exe' -Arguments @('/Online', '/Cleanup-Image', '/RestoreHealth') -Label 'DISM RestoreHealth'

                $sfc = $null
                if ($IncludeSfc) {
                    $sfc = Invoke-RepairCommand -Exe 'sfc.exe' -Arguments @('/scannow') -Label 'SFC /scannow'
                }

                Write-Host ''
                Write-Host ('  DISM ScanHealth exit code   : {0}' -f $scan.ExitCode) -ForegroundColor $(if ($scan.ExitCode -eq 0) { 'Green' } else { 'Yellow' })
                Write-Host ('  DISM RestoreHealth exit code: {0}' -f $restore.ExitCode) -ForegroundColor $(if ($restore.ExitCode -eq 0) { 'Green' } else { 'Red' })
                if ($sfc) {
                    Write-Host ('  SFC exit code               : {0}' -f $sfc.ExitCode) -ForegroundColor $(if ($sfc.ExitCode -eq 0) { 'Green' } else { 'Yellow' })
                }

                if ($restore.ExitCode -eq 0) {
                    Write-Host '  Component store repair completed. Retry the update; a reboot may be advisable first.' -ForegroundColor Green
                }
                else {
                    Write-Host '  RestoreHealth did not return success - review the logs below.' -ForegroundColor Yellow
                }
                Write-Host '  Logs: C:\Windows\Logs\DISM\dism.log and C:\Windows\Logs\CBS\CBS.log' -ForegroundColor DarkGray
            }
            catch {
                Write-Warning ("  Component store repair error: {0}" -f $_.Exception.Message)
            }
        }
    }
    elseif ($IncludeSfc) {
        Write-Verbose '-IncludeSfc has no effect without -RepairComponentStore.'
    }

    # --- Optional CSV export ------------------------------------------------
    if ($CsvPath) {
        try {
            $csvDir = Split-Path -Path $CsvPath -Parent
            if ($csvDir -and -not (Test-Path -LiteralPath $csvDir)) {
                New-Item -Path $csvDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Verbose ("Created CSV output directory: {0}" -f $csvDir)
            }
            $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
            Write-Host ("Results exported to {0}" -f $CsvPath) -ForegroundColor DarkCyan
        }
        catch {
            Write-Warning ("CSV export failed: {0}" -f $_.Exception.Message)
        }
    }

    # Emit objects to the pipeline for further processing.
    $results
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
