function Test-CippWordPressTarget {
    <#
    .SYNOPSIS
    Validates and normalizes a URL before the WordPress scanner is pointed at it.

    .DESCRIPTION
    The scanner takes a URL from the caller and makes the function app fetch it, which is a
    server-side request forgery primitive unless the target is pinned to the public internet.
    Every address behind the hostname is resolved and checked here: loopback, link-local
    (which includes the 169.254.169.254 instance metadata endpoint), private, carrier-grade
    NAT, multicast and reserved ranges are all rejected, as are schemes other than http/https,
    non-default ports, credentials embedded in the URL, and internal-only suffixes.

    A host that resolves to a mix of public and private addresses is rejected as well: DNS
    rebinding aside, one private answer is enough to reach something that is not the client's
    website.

    .PARAMETER Url
    The URL or bare hostname to validate. A missing scheme is treated as https.

    .PARAMETER SkipDnsResolution
    Skips the DNS lookup and the address checks that depend on it. Literal IP addresses in the
    URL are still checked. Only for callers that have already resolved the host, and for tests.

    .EXAMPLE
    Test-CippWordPressTarget -Url 'example.com'

    .EXAMPLE
    Test-CippWordPressTarget -Url 'http://192.168.1.10/'
    # IsValid = $false, Reason names the private address
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [switch]$SkipDnsResolution
    )

    $Result = [PSCustomObject]@{
        IsValid   = $false
        Reason    = ''
        Uri       = $null
        Hostname  = ''
        Addresses = @()
    }

    if ([string]::IsNullOrWhiteSpace($Url)) {
        $Result.Reason = 'No URL was supplied.'
        return $Result
    }

    $Candidate = $Url.Trim()
    # A bare hostname is the common case from the UI. Anything with '://' keeps its own scheme
    # so that an unsupported one (file, ftp, gopher) is rejected below instead of silently fixed.
    if ($Candidate -notmatch '^[A-Za-z][A-Za-z0-9+.\-]*://') {
        $Candidate = 'https://{0}' -f $Candidate
    }

    $Uri = $null
    if (-not [System.Uri]::TryCreate($Candidate, [System.UriKind]::Absolute, [ref]$Uri)) {
        $Result.Reason = "'$Url' is not a valid URL."
        return $Result
    }

    if ($Uri.Scheme -notin @('http', 'https')) {
        $Result.Reason = "Scheme '$($Uri.Scheme)' is not supported. Use http or https."
        return $Result
    }

    # user:password@host would be forwarded as an Authorization header on every probe.
    if (-not [string]::IsNullOrEmpty($Uri.UserInfo)) {
        $Result.Reason = 'Credentials in the URL are not supported.'
        return $Result
    }

    if (-not $Uri.IsDefaultPort) {
        $Result.Reason = "Port $($Uri.Port) is not supported. Only the default http (80) and https (443) ports are scanned."
        return $Result
    }

    $Hostname = $Uri.Host
    $Result.Hostname = $Hostname

    if ([string]::IsNullOrWhiteSpace($Hostname)) {
        $Result.Reason = 'The URL has no hostname.'
        return $Result
    }

    # Names that never belong to a customer website on the public internet. '.local' and
    # '.home.arpa' are mDNS/home networks, the rest are reserved by RFC 6761/6762 or are
    # conventional internal suffixes.
    $InternalSuffixes = @('.local', '.localhost', '.localdomain', '.internal', '.intranet', '.lan', '.home.arpa', '.corp', '.private', '.test', '.example', '.invalid')
    if ($Hostname -eq 'localhost' -or ($InternalSuffixes | Where-Object { $Hostname.EndsWith($_, [System.StringComparison]::OrdinalIgnoreCase) })) {
        $Result.Reason = "'$Hostname' is an internal-only hostname."
        return $Result
    }

    $Addresses = [System.Collections.Generic.List[System.Net.IPAddress]]::new()
    $Literal = $null
    if ([System.Net.IPAddress]::TryParse($Hostname.Trim('[', ']'), [ref]$Literal)) {
        $Addresses.Add($Literal)
    } elseif (-not $SkipDnsResolution) {
        # A hostname that does not resolve cannot be scanned, and reporting that up front is
        # more useful than a connection error on every one of the ~20 probes that follow.
        if ($Hostname -notmatch '^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$') {
            $Result.Reason = "'$Hostname' is not a valid hostname."
            return $Result
        }
        try {
            foreach ($Address in (Resolve-CippHostAddress -HostName $Hostname -ErrorAction Stop)) {
                $Addresses.Add($Address)
            }
        } catch {
            $Result.Reason = "'$Hostname' could not be resolved. $($_.Exception.Message)"
            return $Result
        }
        if ($Addresses.Count -eq 0) {
            $Result.Reason = "'$Hostname' did not resolve to any address."
            return $Result
        }
    }

    $Result.Addresses = @($Addresses | ForEach-Object { $_.ToString() })

    foreach ($Address in $Addresses) {
        $Private = Get-CippPrivateAddressReason -Address $Address
        if ($Private) {
            $Result.Reason = "'$Hostname' resolves to $($Address.ToString()), which is $Private. Only public internet targets can be scanned."
            return $Result
        }
    }

    $Result.IsValid = $true
    $Result.Uri = $Uri
    return $Result
}
