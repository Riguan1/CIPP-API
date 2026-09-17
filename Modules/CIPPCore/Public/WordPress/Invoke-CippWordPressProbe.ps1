function Invoke-CippWordPressProbe {
    <#
    .SYNOPSIS
    Performs a single read-only HTTP request against a scan target.

    .DESCRIPTION
    Every request the WordPress scanner makes goes through here, which is what keeps the scan
    passive: the method is fixed to GET or HEAD, no body is ever sent, and nothing is retried.
    The scanner only ever looks at what an anonymous visitor would already receive.

    The function does not throw. A refused connection, a TLS failure, a timeout and a 404 are all
    ordinary results for a scan, so they come back on the returned object and the caller decides
    what they mean. A certificate that fails validation is recorded and, with
    -AllowInsecureCertificate, the request is repeated with validation disabled so that the
    remaining checks still have a page to read.

    Redirects are followed, and the host they land on is re-checked against the same SSRF guard
    the scan started with - a public hostname that redirects to 127.0.0.1 would otherwise walk
    straight past it. FinalUri is where the request came to rest, which is what the HTTP-to-HTTPS
    and author enumeration checks read instead of a Location header: PowerShell 7.4 raises
    InvalidOperationException rather than returning the 3xx when -MaximumRedirection is 0, so the
    redirect itself is not observable.

    .PARAMETER Uri
    The absolute URL to request.

    .PARAMETER Method
    GET or HEAD. Defaults to GET.

    .PARAMETER TimeoutSeconds
    Per-request timeout. Defaults to 15.

    .PARAMETER MaximumRedirection
    Redirects to follow before the request is abandoned.

    .PARAMETER MaximumContentBytes
    Response body is truncated to this many characters. Defaults to 512 KB, which is well past the
    point where any of the checks are still reading.

    .PARAMETER AllowInsecureCertificate
    Repeat the request with certificate validation disabled when validation is what failed.

    .PARAMETER UserAgent
    Sent so that site owners can identify the scan in their access logs.

    .EXAMPLE
    Invoke-CippWordPressProbe -Uri 'https://example.com/readme.html'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [uri]$Uri,
        [ValidateSet('GET', 'HEAD')]
        [string]$Method = 'GET',
        [int]$TimeoutSeconds = 15,
        [ValidateRange(1, 10)]
        [int]$MaximumRedirection = 5,
        [int]$MaximumContentBytes = 524288,
        [switch]$AllowInsecureCertificate,
        [string]$UserAgent = 'Mozilla/5.0 (compatible; CIPP-WordPressSecurityScan/1.0; +https://cipp.app)'
    )

    $Result = [PSCustomObject]@{
        Uri              = $Uri.AbsoluteUri
        FinalUri         = $null
        Method           = $Method
        StatusCode       = 0
        Headers          = [ordered]@{}
        Content          = ''
        ContentType      = ''
        ContentLength    = 0
        Truncated        = $false
        Redirected       = $false
        Success          = $false
        CertificateError = $false
        Insecure         = $false
        Error            = ''
    }

    $Parameters = @{
        Uri                = $Uri
        Method             = $Method
        TimeoutSec         = $TimeoutSeconds
        MaximumRedirection = $MaximumRedirection
        UserAgent          = $UserAgent
        SkipHttpErrorCheck = $true
        ErrorAction        = 'Stop'
    }

    $Response = $null
    try {
        $Response = Invoke-WebRequest @Parameters
    } catch {
        $Exception = $_.Exception
        $Message = $Exception.Message
        $Inner = $Exception
        while ($Inner.InnerException) {
            $Inner = $Inner.InnerException
            $Message = '{0} {1}' -f $Message, $Inner.Message
        }

        # AuthenticationException is the .NET handshake failure; the message match covers the
        # HttpRequestException wrapper, whose text differs between platforms.
        $IsCertificateError = $Inner -is [System.Security.Authentication.AuthenticationException] -or
            $Message -match 'SSL|TLS|certificate|SecureChannelFailure|trust'

        if ($IsCertificateError) {
            $Result.CertificateError = $true
            if ($AllowInsecureCertificate) {
                try {
                    $Response = Invoke-WebRequest @Parameters -SkipCertificateCheck
                    $Result.Insecure = $true
                } catch {
                    $Result.Error = $_.Exception.Message
                    return $Result
                }
            } else {
                $Result.Error = $Message
                return $Result
            }
        } else {
            $Result.Error = $Message
            return $Result
        }
    }

    if (-not $Response) {
        if (-not $Result.Error) { $Result.Error = 'No response was returned.' }
        return $Result
    }

    $Result.StatusCode = [int]$Response.StatusCode
    $Result.Success = $true

    # PS7 hands back a header dictionary of string arrays. Flattening once here keeps every check
    # from having to know that Set-Cookie is the one that routinely has several values.
    $Headers = [ordered]@{}
    foreach ($Header in $Response.Headers.GetEnumerator()) {
        $Headers[$Header.Key] = ($Header.Value -join ', ')
    }
    $Result.Headers = $Headers
    $Result.ContentType = [string]$Headers['Content-Type']

    $FinalUri = $Response.BaseResponse.RequestMessage.RequestUri
    if ($FinalUri) {
        $Result.FinalUri = $FinalUri.AbsoluteUri
        $Result.Redirected = $FinalUri.AbsoluteUri -ne $Uri.AbsoluteUri
        # The guard that cleared the original hostname says nothing about where a redirect went.
        if ($FinalUri.Host -ne $Uri.Host) {
            $Redirected = Test-CippWordPressTarget -Url $FinalUri.AbsoluteUri
            if (-not $Redirected.IsValid) {
                $Result.Success = $false
                $Result.Content = ''
                $Result.Error = "Redirected to a target that cannot be scanned. $($Redirected.Reason)"
                return $Result
            }
        }
    } else {
        $Result.FinalUri = $Uri.AbsoluteUri
    }

    $Content = [string]$Response.Content
    if ($null -ne $Response.Content -and $Response.Content -isnot [string]) {
        # A non-text response comes back as a byte array; only the leading bytes are ever needed
        # (a signature match), so decode what fits and leave the rest.
        try {
            $Bytes = [byte[]]$Response.Content
            $Take = [Math]::Min($Bytes.Length, $MaximumContentBytes)
            $Content = [System.Text.Encoding]::UTF8.GetString($Bytes, 0, $Take)
        } catch {
            $Content = ''
        }
    }

    $Result.ContentLength = $Content.Length
    if ($Content.Length -gt $MaximumContentBytes) {
        $Content = $Content.Substring(0, $MaximumContentBytes)
        $Result.Truncated = $true
    }
    $Result.Content = $Content

    return $Result
}
