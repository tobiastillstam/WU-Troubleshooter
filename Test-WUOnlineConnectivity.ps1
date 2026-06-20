#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Tests all network communication required for Windows Update ONLINE services
    (not on-prem WSUS) on Windows Server 2025.

.DESCRIPTION
    Diagnostic, read-only connectivity tester for the Microsoft-documented set of
    Windows Update / Microsoft Update / Delivery Optimization / diagnostics endpoints.

    For every endpoint the script can perform, depending on the endpoint's documented
    protocol:

      1. DNS resolution            (Resolve-DnsName, falling back to System.Net.Dns)
      2. Direct TCP reachability   (raw TcpClient - bypasses any proxy)
      3. Direct TLS handshake      (HTTPS endpoints only - raw SslStream, captures the
                                    server certificate so SSL/TLS inspection can be
                                    detected; WU connections are certificate-pinned,
                                    so a non-Microsoft issuer almost always means an
                                    inspecting proxy that will break updates)
      4. HTTP(S) request via proxy (a raw HttpWebRequest honoring the configured WinHTTP
                                    proxy, validating the application-layer path)

    IMPORTANT protocol rule (per Microsoft): endpoints that require HTTP must NOT be
    tested over HTTPS and vice versa - mixing them causes failures. Each endpoint is
    therefore tested ONLY on its documented protocol/port.

    The script changes nothing on the system. The single exception is the optional
    -FlushDnsFirst switch (Clear-DnsClientCache), which is the only action gated behind
    ShouldProcess.

    Supports -WhatIf and -Confirm.

.PARAMETER Category
    Which endpoint group(s) to test. One or more of:
      Core                 - Windows Update scan/metadata and content endpoints
      DeliveryOptimization - DO service and content (P2P/CDN) endpoints
      MicrosoftUpdate      - Microsoft Update catalog, licensing/activation, CRL
      Diagnostics          - Settings, telemetry and error-reporting endpoints
      All                  - every group (default)

.PARAMETER TimeoutSeconds
    Per-operation timeout in seconds for DNS, TCP, TLS and HTTP tests. Default 5.

.PARAMETER SkipProxyPath
    Skip the proxy-aware HTTP(S) test and run the direct TCP/TLS tests only.

.PARAMETER FlushDnsFirst
    Clear the DNS client resolver cache before testing. This is a state-changing
    action and is gated by ShouldProcess (supports -WhatIf / -Confirm).

.PARAMETER LogPath
    Path for the PowerShell transcript log. Defaults to a timestamped file in a 'logs'
    subfolder beside the script. The target directory is created if it does not exist.
    Set to an empty string ('') to disable transcript logging.

.PARAMETER CsvPath
    Optional path to export the full per-endpoint result set as CSV (for records / tickets).

.PARAMETER ListEndpoints
    Print the endpoint table that would be tested and exit without performing any tests.

.EXAMPLE
    .\Test-WUOnlineConnectivity.ps1
    Tests every endpoint group over both the direct and proxy paths.

.EXAMPLE
    .\Test-WUOnlineConnectivity.ps1 -Category Core,DeliveryOptimization -TimeoutSeconds 3
    Tests only the core WU and Delivery Optimization endpoints with a 3-second timeout.

.EXAMPLE
    .\Test-WUOnlineConnectivity.ps1 -SkipProxyPath -Verbose
    Direct TCP/TLS only, with verbose per-step output.

.EXAMPLE
    .\Test-WUOnlineConnectivity.ps1 -FlushDnsFirst -CsvPath 'C:\Temp\wu-connectivity.csv'
    Flushes the DNS cache first, tests everything, and exports results to CSV.
    The target folder (C:\Temp) is created automatically if it does not exist.

.EXAMPLE
    .\Test-WUOnlineConnectivity.ps1 -FlushDnsFirst -WhatIf
    Shows that only the DNS cache flush is gated by ShouldProcess; the connectivity tests
    themselves are read-only and always run.

.EXAMPLE
    .\Test-WUOnlineConnectivity.ps1 -ListEndpoints
    Prints the endpoint/protocol/port table without testing anything.

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
    0.4.0 (2026-06-18) - HTTP path now uses a raw HttpWebRequest instead of Invoke-WebRequest,
                         so expected 4xx responses no longer echo as terminating-error lines
                         in the transcript (notably under the ISE). Added an OptionalHosts
                         list: a DNS/connect failure on an ancillary host (e.g.
                         emdl.ws.microsoft.com) is now a WARN, not a run-failing FAIL.
    0.3.0 (2026-06-18) - Pinned the direct TLS handshake to TLS 1.2; the prior system-
                         default selection failed SslStream on PS 5.1 against TLS 1.3
                         endpoints, producing false "TLS FAILED" results while HTTPS was
                         actually fine. DNS resolution now uses SilentlyContinue to avoid
                         terminating-error noise and handle NXDOMAIN cleanly.
    0.2.0 (2026-06-17) - Log file now defaults to a 'logs' subfolder beside the script.
                         Log and CSV output directories are created if missing.
    0.1.0 (2026-06-17) - Initial release.

    Operational notes:
    - Target: Windows Server 2025 (Windows PowerShell 5.1; also runs on PowerShell 7+).
    - Scope: ONLINE Windows Update communication only. On-prem WSUS is out of scope.
    - Read-only. The only state-changing action is the optional -FlushDnsFirst.
    - Result interpretation:
        PASS - at least one valid path reached the endpoint as expected.
        WARN - paths disagree, a wildcard-derived host did not resolve, or the TLS
               certificate issuer is NOT Microsoft (likely SSL inspection - WU is
               certificate-pinned and this will break updates).
        FAIL - DNS failed for a non-wildcard host, or no path reached the endpoint.
    - Endpoint lists are CDN-backed and change over time. Wildcard endpoints are tested
      using representative hostnames; treat those DNS misses as warnings, not failures.
    - Not yet executed in production. Run elevated and review the transcript log.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # Endpoint group(s) to test.
    [Parameter(Mandatory = $false)]
    [ValidateSet('Core', 'DeliveryOptimization', 'MicrosoftUpdate', 'Diagnostics', 'All')]
    [string[]]$Category = 'All',

    # Per-operation timeout in seconds.
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 5,

    # Run direct TCP/TLS tests only; skip the proxy-aware HTTP path.
    [Parameter(Mandatory = $false)]
    [switch]$SkipProxyPath,

    # Clear the DNS client cache before testing (ShouldProcess-gated).
    [Parameter(Mandatory = $false)]
    [switch]$FlushDnsFirst,

    # Transcript log path. Defaults to a 'logs' subfolder beside the script.
    # Empty string disables the transcript.
    [Parameter(Mandatory = $false)]
    [string]$LogPath = (Join-Path -Path $(if ($PSScriptRoot) { Join-Path $PSScriptRoot 'logs' } else { Join-Path (Get-Location).Path 'logs' }) -ChildPath ("Test-WUOnlineConnectivity_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))),

    # Optional CSV export path for the full result set.
    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    # Print the endpoint table and exit without testing.
    [Parameter(Mandatory = $false)]
    [switch]$ListEndpoints
)

# -------------------------------------------------------------------------
# Begin script body
# -------------------------------------------------------------------------

Write-Verbose "Starting $($MyInvocation.MyCommand.Name)"

$TimeoutMs        = $TimeoutSeconds * 1000
$transcriptStarted = $false

# --- Endpoint definitions ------------------------------------------------
# Wildcard endpoints (*.x) are tested via a representative real hostname.
# Protocol is the Microsoft-documented one for that endpoint - do not
# "upgrade" HTTP endpoints to HTTPS.
$Endpoints = @(
    # ---- Core Windows Update (scan / metadata / content) ----
    [pscustomobject]@{ Category = 'Core'; HostName = 'windowsupdate.microsoft.com';   Port = 80;  Protocol = 'Http';  Wildcard = $false; Note = 'WU redirector' }
    [pscustomobject]@{ Category = 'Core'; HostName = 'sls.update.microsoft.com';      Port = 443; Protocol = 'Https'; Wildcard = $false; Note = 'Service locator / scan' }
    [pscustomobject]@{ Category = 'Core'; HostName = 'fe3.delivery.mp.microsoft.com'; Port = 443; Protocol = 'Https'; Wildcard = $false; Note = 'WU front-end (scan)' }
    [pscustomobject]@{ Category = 'Core'; HostName = 'ctldl.windowsupdate.com';       Port = 80;  Protocol = 'Http';  Wildcard = $false; Note = 'Cert trust list (CTL)' }
    [pscustomobject]@{ Category = 'Core'; HostName = 'download.windowsupdate.com';    Port = 80;  Protocol = 'Http';  Wildcard = $false; Note = 'Update content (CDN)' }
    [pscustomobject]@{ Category = 'Core'; HostName = 'au.download.windowsupdate.com'; Port = 80;  Protocol = 'Http';  Wildcard = $true;  Note = 'rep. *.download.windowsupdate.com' }

    # ---- Delivery Optimization ----
    [pscustomobject]@{ Category = 'DeliveryOptimization'; HostName = 'emdl.ws.microsoft.com';                     Port = 80;  Protocol = 'Http';  Wildcard = $false; Note = 'DO content metadata' }
    [pscustomobject]@{ Category = 'DeliveryOptimization'; HostName = 'dl.delivery.mp.microsoft.com';             Port = 80;  Protocol = 'Http';  Wildcard = $false; Note = 'DO content' }
    [pscustomobject]@{ Category = 'DeliveryOptimization'; HostName = 'tlu.dl.delivery.mp.microsoft.com';         Port = 80;  Protocol = 'Http';  Wildcard = $true;  Note = 'rep. *.dl.delivery.mp.microsoft.com' }
    [pscustomobject]@{ Category = 'DeliveryOptimization'; HostName = 'tsfe.trafficshaping.dsp.mp.microsoft.com'; Port = 443; Protocol = 'Https'; Wildcard = $false; Note = 'DO traffic shaping (TLS 1.2)' }
    [pscustomobject]@{ Category = 'DeliveryOptimization'; HostName = 'kv801.prod.do.dsp.mp.microsoft.com';       Port = 443; Protocol = 'Https'; Wildcard = $true;  Note = 'rep. *.prod.do.dsp.mp.microsoft.com' }

    # ---- Microsoft Update / catalog / licensing / cert revocation ----
    [pscustomobject]@{ Category = 'MicrosoftUpdate'; HostName = 'catalog.update.microsoft.com';   Port = 443; Protocol = 'Https'; Wildcard = $false; Note = 'Microsoft Update Catalog' }
    [pscustomobject]@{ Category = 'MicrosoftUpdate'; HostName = 'displaycatalog.mp.microsoft.com'; Port = 443; Protocol = 'Https'; Wildcard = $false; Note = 'Store/MU catalog' }
    [pscustomobject]@{ Category = 'MicrosoftUpdate'; HostName = 'licensing.mp.microsoft.com';      Port = 443; Protocol = 'Https'; Wildcard = $false; Note = 'Licensing' }
    [pscustomobject]@{ Category = 'MicrosoftUpdate'; HostName = 'activation.sls.microsoft.com';    Port = 443; Protocol = 'Https'; Wildcard = $false; Note = 'Activation' }
    [pscustomobject]@{ Category = 'MicrosoftUpdate'; HostName = 'crl.microsoft.com';               Port = 80;  Protocol = 'Http';  Wildcard = $false; Note = 'CRL (cert revocation)' }

    # ---- Diagnostics / settings / telemetry ----
    [pscustomobject]@{ Category = 'Diagnostics'; HostName = 'settings-win.data.microsoft.com';  Port = 443; Protocol = 'Https'; Wildcard = $false; Note = 'Settings / config' }
    [pscustomobject]@{ Category = 'Diagnostics'; HostName = 'v10.events.data.microsoft.com';    Port = 443; Protocol = 'Https'; Wildcard = $false; Note = 'Diagnostic events' }
    [pscustomobject]@{ Category = 'Diagnostics'; HostName = 'watson.events.data.microsoft.com'; Port = 443; Protocol = 'Https'; Wildcard = $false; Note = 'Error reporting (Watson)' }
)

# Documented but ancillary hosts. A DNS / connect failure on one of these is reported
# as a WARNING rather than failing the whole run, because the core scan/content path
# does not depend on it. Core endpoints still hard-FAIL on failure.
$OptionalHosts = @(
    'emdl.ws.microsoft.com'   # DO content metadata; other DO endpoints cover the function
)

# -------------------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------------------

function Get-ProxyConfiguration {
    <#
        Returns the effective proxy picture: the verbatim WinHTTP config (locale-safe
        display), a regex-parsed WinHTTP host:port for the test path, and the .NET
        system (WinINET) proxy for a sample WU URL.
    #>
    [CmdletBinding()]
    param()

    $winhttpRaw      = $null
    $winhttpProxyUrl = $null
    try {
        $winhttpRaw = (netsh winhttp show proxy) 2>$null
        # Parse host:port without depending on localized labels.
        $match = [regex]::Match(($winhttpRaw -join ' '), '(?<h>[A-Za-z0-9\.\-]+):(?<p>\d{1,5})')
        if ($match.Success) {
            $winhttpProxyUrl = ('http://{0}:{1}' -f $match.Groups['h'].Value, $match.Groups['p'].Value)
        }
    }
    catch {
        Write-Verbose ("Could not read WinHTTP proxy: {0}" -f $_.Exception.Message)
    }

    $systemProxyForWu = $null
    try {
        $sys      = [System.Net.WebRequest]::GetSystemWebProxy()
        $sample   = [Uri]'https://fe3.delivery.mp.microsoft.com'
        $resolved = $sys.GetProxy($sample)
        if ($resolved -and ($resolved.AbsoluteUri -ne $sample.AbsoluteUri)) {
            $systemProxyForWu = $resolved.AbsoluteUri
        }
    }
    catch {
        Write-Verbose ("Could not read system (WinINET) proxy: {0}" -f $_.Exception.Message)
    }

    [pscustomobject]@{
        WinHttpRaw       = ($winhttpRaw -join [Environment]::NewLine)
        WinHttpProxyUrl  = $winhttpProxyUrl
        SystemProxyForWu = $systemProxyForWu
    }
}

function Resolve-EndpointDns {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$HostName)

    try {
        $records = Resolve-DnsName -Name $HostName -Type A -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress } |
            Select-Object -ExpandProperty IPAddress -Unique
        if ($records) { return , @($records) }
    }
    catch {
        Write-Verbose ("Resolve-DnsName failed for {0}: {1}" -f $HostName, $_.Exception.Message)
    }

    # Fallback for environments where Resolve-DnsName behaves oddly.
    try {
        $addr = [System.Net.Dns]::GetHostAddresses($HostName) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
            ForEach-Object { $_.IPAddressToString }
        if ($addr) { return , @($addr) }
    }
    catch {
        Write-Verbose ("System.Net.Dns failed for {0}: {1}" -f $HostName, $_.Exception.Message)
    }

    return $null
}

function Test-DirectConnection {
    <#
        Raw TCP connect (bypasses proxy). For HTTPS endpoints it also performs an
        SslStream handshake on the same socket and captures the server certificate so
        SSL inspection can be detected. The validation callback always returns $true
        on purpose - we inspect the cert ourselves rather than relying on chain trust.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][ValidateSet('Http', 'Https')][string]$Protocol,
        [Parameter(Mandatory)][int]$TimeoutMs
    )

    $result = [pscustomobject]@{
        TcpOk             = $false
        LatencyMs         = $null
        TlsOk             = $null      # $null = not applicable (HTTP endpoint)
        TlsProtocol       = $null
        CertSubject       = $null
        CertIssuer        = $null
        CertNotAfter      = $null
        IssuerIsMicrosoft = $null
        Error             = $null
    }

    $client    = $null
    $sslStream = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $sw     = [System.Diagnostics.Stopwatch]::StartNew()
        $async  = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            throw "TCP connect timed out after $TimeoutMs ms"
        }
        $client.EndConnect($async)
        $sw.Stop()
        $result.TcpOk     = $client.Connected
        $result.LatencyMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 0)

        if ($Protocol -eq 'Https' -and $client.Connected) {
            $client.ReceiveTimeout = $TimeoutMs
            $client.SendTimeout    = $TimeoutMs
            $netStream = $client.GetStream()
            $callback  = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $cert, $chain, $errors) $true }
            $sslStream = New-Object System.Net.Security.SslStream($netStream, $false, $callback)
            # Pin to TLS 1.2 for the raw handshake. On Windows PowerShell 5.1 (.NET
            # Framework) the system-default selection can attempt TLS 1.3 and fail the
            # SslStream handshake even when the endpoint is perfectly reachable over
            # HTTPS; 1.2 is accepted by every WU endpoint and is enough for the issuer
            # inspection this test exists to perform.
            $sslStream.AuthenticateAsClient($HostName, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)

            $result.TlsOk       = $true
            $result.TlsProtocol = $sslStream.SslProtocol.ToString()

            if ($sslStream.RemoteCertificate) {
                $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 ($sslStream.RemoteCertificate)
                $result.CertSubject       = $x509.Subject
                $result.CertIssuer        = $x509.Issuer
                $result.CertNotAfter      = $x509.NotAfter
                $result.IssuerIsMicrosoft = ($x509.Issuer -match 'Microsoft')
            }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
        if ($Protocol -eq 'Https' -and $result.TcpOk) { $result.TlsOk = $false }
    }
    finally {
        if ($sslStream) { $sslStream.Dispose() }
        if ($client)    { $client.Close() }
    }

    return $result
}

function Test-HttpPath {
    <#
        Application-layer test honoring the configured proxy. Any HTTP response,
        including 4xx, means the path is reachable - only connection-level failures
        count as unreachable.

        Uses a raw HttpWebRequest rather than Invoke-WebRequest: a 4xx/5xx response
        raises a .NET WebException that is caught here, whereas the Invoke-WebRequest
        cmdlet equivalent gets echoed to the transcript as a "TerminatingError" line by
        some hosts (notably the ISE). The raw request keeps the transcript clean.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter()][System.Net.WebProxy]$Proxy,
        [Parameter(Mandatory)][int]$TimeoutSec
    )

    $r = [pscustomobject]@{ Ok = $false; StatusCode = $null; UsedProxy = [bool]$Proxy; Error = $null }
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method            = 'HEAD'
        $req.Timeout           = $TimeoutSec * 1000
        $req.AllowAutoRedirect = $true
        # Honor the configured proxy; otherwise force direct (empty proxy) rather than
        # falling back to the per-user WinINET proxy.
        if ($Proxy) { $req.Proxy = $Proxy } else { $req.Proxy = New-Object System.Net.WebProxy }

        $resp         = $req.GetResponse()
        $r.Ok         = $true
        $r.StatusCode = [int]([System.Net.HttpWebResponse]$resp).StatusCode
        $resp.Close()
    }
    catch [System.Net.WebException] {
        $we = $_.Exception
        if ($we.Response) {
            # Server answered (e.g. 403/404/405) -> path is reachable.
            try { $r.StatusCode = [int]([System.Net.HttpWebResponse]$we.Response).StatusCode } catch { }
            try { $we.Response.Close() } catch { }
            $r.Ok    = $true
            $r.Error = ('HTTP {0}' -f $r.StatusCode)
        }
        else {
            $r.Error = $we.Message
        }
    }
    catch {
        $r.Error = $_.Exception.Message
    }
    return $r
}

function Write-ResultLine {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Result)

    switch ($Result.Result) {
        'PASS'  { $color = 'Green' }
        'WARN'  { $color = 'Yellow' }
        'FAIL'  { $color = 'Red' }
        default { $color = 'Gray' }
    }
    $line = ('  [{0}] {1,-44} {2}/{3,-5} {4}' -f `
            $Result.Result, $Result.Endpoint, $Result.Protocol, $Result.Port, $Result.Detail)
    Write-Host $line -ForegroundColor $color
}

# -------------------------------------------------------------------------
# Main logic
# -------------------------------------------------------------------------

try {
    # --- -ListEndpoints short-circuit --------------------------------------
    if ($ListEndpoints) {
        $Endpoints |
            Where-Object { ($Category -contains 'All') -or ($Category -contains $_.Category) } |
            Sort-Object Category, HostName |
            Format-Table Category, HostName, Protocol, Port, Wildcard, Note -AutoSize
        return
    }

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

    # --- Ensure modern TLS for the HttpWebRequest path (PS 5.1) -------------
    try {
        [Net.ServicePointManager]::SecurityProtocol = `
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch {
        Write-Verbose "Could not adjust ServicePointManager.SecurityProtocol."
    }

    Write-Host ''
    Write-Host '=== Windows Update ONLINE connectivity test ===' -ForegroundColor Cyan
    Write-Host ("Host: {0}    Date: {1}" -f $env:COMPUTERNAME, (Get-Date)) -ForegroundColor Cyan
    Write-Host ("Categories: {0}    Timeout: {1}s    Proxy path: {2}" -f `
        ($Category -join ','), $TimeoutSeconds, (-not $SkipProxyPath)) -ForegroundColor Cyan

    # --- Optional DNS cache flush (only state-changing action) --------------
    if ($FlushDnsFirst) {
        if ($PSCmdlet.ShouldProcess('DNS client resolver cache', 'Clear-DnsClientCache')) {
            try {
                Clear-DnsClientCache
                Write-Host 'DNS client cache cleared.' -ForegroundColor DarkCyan
            }
            catch {
                Write-Warning ("Failed to clear DNS cache: {0}" -f $_.Exception.Message)
            }
        }
    }

    # --- Proxy picture ------------------------------------------------------
    $proxyConfig = Get-ProxyConfiguration
    Write-Host ''
    Write-Host '--- Proxy configuration ---' -ForegroundColor Cyan
    Write-Host 'WinHTTP (netsh):'
    Write-Host ($proxyConfig.WinHttpRaw)
    Write-Host ('Parsed WinHTTP proxy  : {0}' -f ($(if ($proxyConfig.WinHttpProxyUrl)  { $proxyConfig.WinHttpProxyUrl }  else { '(direct / none)' })))
    Write-Host ('System (WinINET) proxy: {0}' -f ($(if ($proxyConfig.SystemProxyForWu) { $proxyConfig.SystemProxyForWu } else { '(direct / none)' })))

    $webProxy = $null
    if (-not $SkipProxyPath -and $proxyConfig.WinHttpProxyUrl) {
        try {
            $webProxy = New-Object System.Net.WebProxy($proxyConfig.WinHttpProxyUrl, $true)
            $webProxy.UseDefaultCredentials = $true
        }
        catch { Write-Verbose ("Could not build WebProxy: {0}" -f $_.Exception.Message) }
    }

    # --- Test loop ----------------------------------------------------------
    $targets = $Endpoints |
        Where-Object { ($Category -contains 'All') -or ($Category -contains $_.Category) }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($group in ($targets | Group-Object Category)) {
        Write-Host ''
        Write-Host ('--- {0} ---' -f $group.Name) -ForegroundColor Cyan

        foreach ($ep in ($group.Group | Sort-Object HostName)) {
            Write-Verbose ("Testing {0}:{1} ({2})" -f $ep.HostName, $ep.Port, $ep.Protocol)

            # 1) DNS
            $ips   = Resolve-EndpointDns -HostName $ep.HostName
            $dnsOk = [bool]$ips

            # 2/3) Direct TCP (+TLS for HTTPS) - only if DNS resolved
            $direct = $null
            if ($dnsOk) {
                $direct = Test-DirectConnection -HostName $ep.HostName -Port $ep.Port -Protocol $ep.Protocol -TimeoutMs $TimeoutMs
            }

            # 4) Proxy/application path - only if DNS resolved and not skipped
            $http = $null
            if ($dnsOk -and -not $SkipProxyPath) {
                $scheme = if ($ep.Protocol -eq 'Https') { 'https' } else { 'http' }
                $url    = ('{0}://{1}' -f $scheme, $ep.HostName)
                $http   = Test-HttpPath -Url $url -Proxy $webProxy -TimeoutSec $TimeoutSeconds
            }

            # ----- Verdict -----
            $directOk = $false
            if ($direct) {
                $directOk = $direct.TcpOk -and ($ep.Protocol -eq 'Http' -or $direct.TlsOk)
            }
            $proxyOk       = [bool]($http -and $http.Ok)
            $sslInspection = ($direct -and $direct.IssuerIsMicrosoft -eq $false)

            $verdict     = 'FAIL'
            $detailParts = New-Object System.Collections.Generic.List[string]

            if (-not $dnsOk) {
                if ($ep.Wildcard) {
                    $verdict = 'WARN'
                    $detailParts.Add('DNS no-resolve (wildcard rep host - may be expected)')
                }
                elseif ($OptionalHosts -contains $ep.HostName) {
                    $verdict = 'WARN'
                    $detailParts.Add('DNS no-resolve (optional host - not blocking core WU)')
                }
                else {
                    $verdict = 'FAIL'
                    $detailParts.Add('DNS resolution FAILED')
                }
            }
            else {
                $detailParts.Add(('DNS ok ({0})' -f ($ips -join ',')))

                # Direct path detail
                if ($direct) {
                    if ($direct.TcpOk) {
                        $detailParts.Add(('TCP ok {0}ms' -f $direct.LatencyMs))
                        if ($ep.Protocol -eq 'Https') {
                            if ($direct.TlsOk) {
                                $issuerTag = if ($direct.IssuerIsMicrosoft) { 'MS-issuer' } else { 'NON-MS issuer!' }
                                $detailParts.Add(('TLS ok [{0} | {1}]' -f $direct.TlsProtocol, $issuerTag))
                            }
                            else {
                                $detailParts.Add('TLS FAILED')
                            }
                        }
                    }
                    else {
                        $detailParts.Add('TCP direct failed')
                    }
                }

                # Proxy path detail
                if (-not $SkipProxyPath) {
                    if ($proxyOk) {
                        $detailParts.Add(('HTTP via {0}: {1}' -f ($(if ($http.UsedProxy) { 'proxy' } else { 'direct' }), $http.StatusCode)))
                    }
                    elseif ($http) {
                        $detailParts.Add(('HTTP path failed: {0}' -f $http.Error))
                    }
                }

                # Verdict logic
                if ($directOk -or $proxyOk) {
                    if ($sslInspection) {
                        $verdict = 'WARN'
                        $detailParts.Add('possible SSL inspection - breaks WU cert pinning')
                    }
                    elseif ((-not $SkipProxyPath) -and ($directOk -xor $proxyOk)) {
                        $verdict = 'WARN'
                        $detailParts.Add('only one path works')
                    }
                    else {
                        $verdict = 'PASS'
                    }
                }
                else {
                    $verdict = if ($OptionalHosts -contains $ep.HostName) { 'WARN' } else { 'FAIL' }
                    $detailParts.Add('no path reached endpoint')
                }
            }

            $row = [pscustomobject]@{
                Category    = $ep.Category
                Endpoint    = $ep.HostName
                Protocol    = $ep.Protocol
                Port        = $ep.Port
                Wildcard    = $ep.Wildcard
                Result      = $verdict
                DnsResolved = $dnsOk
                IPs         = ($ips -join ',')
                TcpDirect   = if ($direct) { $direct.TcpOk } else { $null }
                LatencyMs   = if ($direct) { $direct.LatencyMs } else { $null }
                TlsDirect   = if ($direct) { $direct.TlsOk } else { $null }
                TlsProtocol = if ($direct) { $direct.TlsProtocol } else { $null }
                CertIssuer  = if ($direct) { $direct.CertIssuer } else { $null }
                IssuerIsMS  = if ($direct) { $direct.IssuerIsMicrosoft } else { $null }
                HttpProxyOk = if ($http)   { $http.Ok } else { $null }
                HttpStatus  = if ($http)   { $http.StatusCode } else { $null }
                Note        = $ep.Note
                Detail      = ($detailParts -join ' | ')
            }

            $results.Add($row)
            Write-ResultLine -Result $row
        }
    }

    # --- Summary ------------------------------------------------------------
    Write-Host ''
    Write-Host '=== Summary ===' -ForegroundColor Cyan
    $pass = ($results | Where-Object Result -eq 'PASS').Count
    $warn = ($results | Where-Object Result -eq 'WARN').Count
    $fail = ($results | Where-Object Result -eq 'FAIL').Count
    Write-Host ("PASS: {0}   WARN: {1}   FAIL: {2}   (of {3} endpoints)" -f $pass, $warn, $fail, $results.Count) `
        -ForegroundColor $(if ($fail) { 'Red' } elseif ($warn) { 'Yellow' } else { 'Green' })

    if ($results | Where-Object { $_.IssuerIsMS -eq $false }) {
        Write-Host ''
        Write-Host 'NOTE: One or more HTTPS endpoints presented a non-Microsoft certificate issuer.' -ForegroundColor Yellow
        Write-Host '      Windows Update connections are certificate-pinned; SSL/TLS inspection on these' -ForegroundColor Yellow
        Write-Host '      endpoints will break updates. Exclude WU endpoints from SSL inspection.' -ForegroundColor Yellow
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
