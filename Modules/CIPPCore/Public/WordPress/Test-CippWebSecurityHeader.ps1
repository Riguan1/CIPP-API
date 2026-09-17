function Test-CippWebSecurityHeader {
    <#
    .SYNOPSIS
    Checks the response headers of a page for the protections a browser relies on.

    .DESCRIPTION
    Pure inspection of one response: no request is made here, so the same headers produce the same
    findings every time and the checks can be tested against captured responses.

    The header checks are deliberately conservative about what counts as a failure. A header that
    is present but weak is a warning rather than a failure, and Content-Security-Policy is a
    warning even when absent, because a CSP that breaks a customer's site is worse than no CSP and
    retrofitting one to an existing WordPress theme is real work rather than a switch to flip.

    Session cookie flags are only judged on an HTTPS page. On plaintext HTTP the missing transport
    is the finding, and marking cookies Secure there would break the site without fixing anything.

    .PARAMETER Headers
    The response headers, as an ordered dictionary of header name to value.

    .PARAMETER Uri
    The URL the response came from. Determines whether HTTPS-only checks apply.

    .EXAMPLE
    Test-CippWebSecurityHeader -Headers $Response.Headers -Uri 'https://example.com'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Headers,
        [Parameter(Mandatory = $true)]
        [uri]$Uri
    )

    $Findings = [System.Collections.Generic.List[object]]::new()

    # Header names are case-insensitive per RFC 9110, and servers disagree about casing.
    $Lookup = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($Headers) {
        foreach ($Header in $Headers.GetEnumerator()) {
            $Lookup[[string]$Header.Key] = [string]$Header.Value
        }
    }

    $IsHttps = $Uri.Scheme -eq 'https'

    # --- Strict-Transport-Security -------------------------------------------------------
    if ($IsHttps) {
        $Hsts = $Lookup['Strict-Transport-Security']
        if ([string]::IsNullOrWhiteSpace($Hsts)) {
            $Findings.Add((New-CippWordPressFinding -Id 'WEB-HSTS-MISSING' -Category 'Headers' -Title 'HSTS is not enabled' -Severity Medium -Status Fail `
                        -Evidence 'No Strict-Transport-Security response header.' `
                        -Recommendation 'Send Strict-Transport-Security with a max-age of at least 15552000 (180 days). Without it a visitor''s first request can still be intercepted over plain HTTP.' `
                        -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security'))
        } else {
            $MaxAge = 0
            $MaxAgeMatch = [regex]::Match($Hsts, 'max-age\s*=\s*"?(\d+)', 'IgnoreCase')
            if ($MaxAgeMatch.Success) { $MaxAge = [int64]$MaxAgeMatch.Groups[1].Value }
            if ($MaxAge -lt 15552000) {
                $Findings.Add((New-CippWordPressFinding -Id 'WEB-HSTS-SHORT' -Category 'Headers' -Title 'HSTS max-age is short' -Severity Low -Status Warn `
                            -Evidence "Strict-Transport-Security: $Hsts" `
                            -Recommendation 'Raise max-age to at least 15552000 (180 days) once you are confident every hostname serves HTTPS.'))
            } else {
                $Findings.Add((New-CippWordPressFinding -Id 'WEB-HSTS-MISSING' -Category 'Headers' -Title 'HSTS is enabled' -Severity Medium -Status Pass `
                            -Evidence "Strict-Transport-Security: $Hsts"))
            }
        }
    }

    # --- Clickjacking --------------------------------------------------------------------
    $FrameOptions = $Lookup['X-Frame-Options']
    $Csp = $Lookup['Content-Security-Policy']
    $HasFrameAncestors = $Csp -and $Csp -match 'frame-ancestors'
    if ([string]::IsNullOrWhiteSpace($FrameOptions) -and -not $HasFrameAncestors) {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-CLICKJACKING' -Category 'Headers' -Title 'The site can be framed by any other site' -Severity Medium -Status Fail `
                    -Evidence 'Neither X-Frame-Options nor a CSP frame-ancestors directive was sent.' `
                    -Recommendation 'Send X-Frame-Options: SAMEORIGIN, or a Content-Security-Policy with frame-ancestors ''self''. This is what stops an attacker overlaying your admin pages inside their own page.' `
                    -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options'))
    } else {
        $Evidence = if ($FrameOptions) { "X-Frame-Options: $FrameOptions" } else { 'CSP frame-ancestors directive present.' }
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-CLICKJACKING' -Category 'Headers' -Title 'Framing is restricted' -Severity Medium -Status Pass -Evidence $Evidence))
    }

    # --- MIME sniffing -------------------------------------------------------------------
    $ContentTypeOptions = $Lookup['X-Content-Type-Options']
    if ($ContentTypeOptions -match 'nosniff') {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-NOSNIFF' -Category 'Headers' -Title 'MIME sniffing is disabled' -Severity Low -Status Pass -Evidence "X-Content-Type-Options: $ContentTypeOptions"))
    } else {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-NOSNIFF' -Category 'Headers' -Title 'MIME sniffing is not disabled' -Severity Low -Status Fail `
                    -Evidence 'No X-Content-Type-Options: nosniff header.' `
                    -Recommendation 'Send X-Content-Type-Options: nosniff so an uploaded file cannot be re-interpreted by the browser as script.'))
    }

    # --- Referrer-Policy -----------------------------------------------------------------
    $ReferrerPolicy = $Lookup['Referrer-Policy']
    if ([string]::IsNullOrWhiteSpace($ReferrerPolicy)) {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-REFERRER-POLICY' -Category 'Headers' -Title 'No Referrer-Policy is set' -Severity Low -Status Fail `
                    -Evidence 'No Referrer-Policy response header.' `
                    -Recommendation 'Send Referrer-Policy: strict-origin-when-cross-origin so query strings and admin paths are not leaked to third-party sites.'))
    } else {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-REFERRER-POLICY' -Category 'Headers' -Title 'A Referrer-Policy is set' -Severity Low -Status Pass -Evidence "Referrer-Policy: $ReferrerPolicy"))
    }

    # --- Content-Security-Policy ---------------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($Csp)) {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-CSP-MISSING' -Category 'Headers' -Title 'No Content-Security-Policy' -Severity Medium -Status Warn `
                    -Evidence 'No Content-Security-Policy response header.' `
                    -Recommendation 'Consider a Content-Security-Policy. It is the strongest defence against cross-site scripting, but it needs testing against the theme and plugins first - start in report-only mode.' `
                    -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy'))
    } elseif ($Csp -match "unsafe-inline|unsafe-eval") {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-CSP-WEAK' -Category 'Headers' -Title 'The Content-Security-Policy allows inline script' -Severity Low -Status Warn `
                    -Evidence "Content-Security-Policy: $Csp" `
                    -Recommendation 'unsafe-inline and unsafe-eval remove most of the XSS protection a CSP provides. Move to nonces or hashes for the scripts that need it.'))
    } else {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-CSP-MISSING' -Category 'Headers' -Title 'A Content-Security-Policy is set' -Severity Medium -Status Pass -Evidence "Content-Security-Policy: $Csp"))
    }

    # --- Software version disclosure -----------------------------------------------------
    foreach ($Name in @('Server', 'X-Powered-By')) {
        $Value = $Lookup[$Name]
        if ([string]::IsNullOrWhiteSpace($Value)) { continue }
        if ($Value -notmatch '\d+\.\d+') { continue }
        $Findings.Add((New-CippWordPressFinding -Id "WEB-BANNER-$($Name.ToUpperInvariant())" -Category 'Headers' -Title "The $Name header discloses software versions" -Severity Low -Status Fail `
                    -Evidence "${Name}: $Value" `
                    -Recommendation "Trim the $Name header to the product name. Exact versions let an attacker match your server against a list of known vulnerabilities without touching the site."))
    }

    $PhpFinding = Test-CippPhpVersionHeader -Headers $Lookup
    if ($PhpFinding) { $Findings.Add($PhpFinding) }

    # --- Cookie flags --------------------------------------------------------------------
    if ($IsHttps -and $Lookup.ContainsKey('Set-Cookie')) {
        $Cookies = @($Lookup['Set-Cookie'] -split ',(?=\s*[^;,\s]+=)')
        $Insecure = [System.Collections.Generic.List[string]]::new()
        $NoHttpOnly = [System.Collections.Generic.List[string]]::new()
        foreach ($Cookie in $Cookies) {
            $CookieName = ($Cookie -split '=', 2)[0].Trim()
            if ([string]::IsNullOrWhiteSpace($CookieName)) { continue }
            if ($Cookie -notmatch '(^|;)\s*Secure\s*(;|$)') { $Insecure.Add($CookieName) }
            if ($Cookie -notmatch '(^|;)\s*HttpOnly\s*(;|$)') { $NoHttpOnly.Add($CookieName) }
        }

        if ($Insecure.Count -gt 0) {
            $Findings.Add((New-CippWordPressFinding -Id 'WEB-COOKIE-SECURE' -Category 'Headers' -Title 'Cookies are set without the Secure flag' -Severity Medium -Status Fail `
                        -Evidence "Set without Secure: $($Insecure -join ', ')" `
                        -Recommendation 'Set the Secure flag on every cookie on an HTTPS site, so the browser never sends it over a plaintext connection.'))
        }
        if ($NoHttpOnly.Count -gt 0) {
            $Findings.Add((New-CippWordPressFinding -Id 'WEB-COOKIE-HTTPONLY' -Category 'Headers' -Title 'Cookies are readable by JavaScript' -Severity Low -Status Warn `
                        -Evidence "Set without HttpOnly: $($NoHttpOnly -join ', ')" `
                        -Recommendation 'Set HttpOnly on session cookies so a cross-site scripting bug cannot read them. Cookies a theme or plugin reads in the browser on purpose are the exception.'))
        }
        if ($Insecure.Count -eq 0 -and $NoHttpOnly.Count -eq 0) {
            $Findings.Add((New-CippWordPressFinding -Id 'WEB-COOKIE-SECURE' -Category 'Headers' -Title 'Cookies carry the Secure and HttpOnly flags' -Severity Medium -Status Pass -Evidence "$($Cookies.Count) cookie(s) checked."))
        }
    }

    return @($Findings)
}
