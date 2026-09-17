function Test-CippWordPressSecurity {
    <#
    .SYNOPSIS
    Runs a passive, non-intrusive security assessment of a WordPress website.

    .DESCRIPTION
    Produces a scored report of what a WordPress site tells the internet about itself: how it
    handles transport security, which protective headers it sends, which version of core, plugins
    and themes it is running, and which paths it leaves reachable that it should not.

    Every check is read-only. The scan issues ordinary GET requests for pages an anonymous visitor
    could already request, and never submits a form, tries a password, uploads anything or crafts
    input to provoke an error. Nothing it does can change or damage the site, which is what makes
    it safe to run against a live customer site - and also what limits it: this finds
    misconfiguration and missing patches, not logic flaws, and a clean report is evidence of good
    hygiene rather than proof that a site cannot be compromised.

    Scan only sites you own or are engaged to assess. Pointing it at a third party's site without
    permission is unauthorised scanning in most jurisdictions regardless of how gentle the requests
    are. The endpoint that fronts this function records who scanned what for exactly that reason.

    Targets are pinned to the public internet before any request is made, and again on every
    redirect, so a scan cannot be steered at the hosting network or at cloud instance metadata.

    .PARAMETER Url
    The site to scan. A bare hostname is treated as https.

    .PARAMETER TimeoutSeconds
    Per-request timeout. Defaults to 15.

    .PARAMETER MaxRequests
    Hard ceiling on the requests made against the target. Defaults to 30, which covers the full
    check set with room to spare. Checks that do not fit are reported as Unknown.

    .PARAMETER SkipVersionLookup
    Do not contact WordPress.org, and report version comparisons as Unknown. Everything else still
    runs.

    .PARAMETER SkipExposureProbes
    Run only the checks that read the home page - transport, headers, fingerprinting. Reduces the
    scan to two requests.

    .EXAMPLE
    Test-CippWordPressSecurity -Url 'https://example.com'

    .EXAMPLE
    Test-CippWordPressSecurity -Url 'example.com' -SkipVersionLookup
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [int]$TimeoutSeconds = 15,
        [ValidateRange(2, 100)]
        [int]$MaxRequests = 30,
        [switch]$SkipVersionLookup,
        [switch]$SkipExposureProbes
    )

    $Report = [PSCustomObject]@{
        Url                    = $Url
        FinalUrl               = $null
        ScannedAt              = [DateTimeOffset]::UtcNow.ToString('o')
        Completed              = $false
        IsWordPress            = $false
        WordPressVersion       = $null
        LatestWordPressVersion = $null
        Score                  = 0
        Grade                  = 'F'
        Summary                = $null
        Findings               = @()
        Components             = @()
        Certificate            = $null
        RequestsMade           = 0
        ValidationFails        = @()
        ValidationWarns        = @()
        ValidationPasses       = @()
        Error                  = ''
    }

    $Target = Test-CippWordPressTarget -Url $Url
    if (-not $Target.IsValid) {
        $Report.Error = $Target.Reason
        return $Report
    }

    $Findings = [System.Collections.Generic.List[object]]::new()
    $Requests = 0

    # --- Home page -----------------------------------------------------------------------
    $HomeResponse = Invoke-CippWordPressProbe -Uri $Target.Uri -TimeoutSeconds $TimeoutSeconds -AllowInsecureCertificate
    $Requests++

    if ($HomeResponse.CertificateError) {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-TLS-INVALID' -Category 'Transport' -Title 'The TLS certificate is not trusted' -Severity High -Status Fail `
                    -Evidence "The certificate presented by $($Target.Uri.Host) failed validation: $($HomeResponse.Error)" `
                    -Recommendation 'Fix or replace the certificate. Visitors are seeing a browser warning, and a site people are trained to click through on is a site they will click through on when the warning is real.'))
    }

    if (-not $HomeResponse.Success) {
        $Report.Error = "The site could not be reached. $($HomeResponse.Error)"
        $Report.RequestsMade = $Requests
        $Report.Findings = @($Findings)
        return $Report
    }

    # Where the request came to rest is the site: it accounts for http to https upgrades and for
    # www redirects, and scanning the pre-redirect URL would check a host nobody visits.
    #
    # Tested for emptiness rather than for $null: [uri]'' is a scheme-less relative URI that reads
    # as "not served over HTTPS", so an absent FinalUri would be reported to the customer as a
    # critical transport failure on a site that is served over HTTPS perfectly well.
    $FinalUrl = if ([string]::IsNullOrWhiteSpace($HomeResponse.FinalUri)) { $Target.Uri.AbsoluteUri } else { [string]$HomeResponse.FinalUri }
    $EffectiveUri = [uri]$FinalUrl
    $Report.FinalUrl = $EffectiveUri.AbsoluteUri
    $BaseUri = [uri]('{0}://{1}/' -f $EffectiveUri.Scheme, $EffectiveUri.Authority)

    # --- Transport -----------------------------------------------------------------------
    if ($EffectiveUri.Scheme -eq 'https') {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-HTTPS' -Category 'Transport' -Title 'The site is served over HTTPS' -Severity High -Status Pass -Evidence $EffectiveUri.AbsoluteUri))

        if ($Requests -lt $MaxRequests) {
            $PlainUri = [uri]('http://{0}/' -f $EffectiveUri.Authority)
            $Plain = Invoke-CippWordPressProbe -Uri $PlainUri -TimeoutSeconds $TimeoutSeconds -AllowInsecureCertificate
            $Requests++
            if ($Plain.Success -and $Plain.FinalUri -and ([uri]$Plain.FinalUri).Scheme -eq 'https') {
                $Findings.Add((New-CippWordPressFinding -Id 'WEB-HTTPS-REDIRECT' -Category 'Transport' -Title 'Plain HTTP redirects to HTTPS' -Severity Medium -Status Pass `
                            -Evidence "$($PlainUri.AbsoluteUri) redirects to $($Plain.FinalUri)."))
            } elseif ($Plain.Success) {
                $Findings.Add((New-CippWordPressFinding -Id 'WEB-HTTPS-REDIRECT' -Category 'Transport' -Title 'The site is also served over plain HTTP' -Severity Medium -Status Fail `
                            -Evidence "$($PlainUri.AbsoluteUri) returned $($Plain.StatusCode) without redirecting to HTTPS." `
                            -Recommendation 'Redirect every HTTP request to HTTPS permanently. Until you do, a login submitted over the plaintext URL travels in the clear.'))
            }
        }

        $Certificate = Get-CippTlsCertificateInfo -HostName $EffectiveUri.Host -TimeoutSeconds $TimeoutSeconds
        $Report.Certificate = $Certificate
        $Findings.AddRange([object[]]@(Get-CippCertificateFinding -Certificate $Certificate))
    } else {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-HTTPS' -Category 'Transport' -Title 'The site is not served over HTTPS' -Severity Critical -Status Fail `
                    -Evidence "$($EffectiveUri.AbsoluteUri) was served over plain HTTP." `
                    -Recommendation 'Install a certificate and force HTTPS. Every password and session cookie on this site currently crosses the network readable by anyone on the path, and browsers mark it as insecure.'))
    }

    # --- Headers -------------------------------------------------------------------------
    $Findings.AddRange([object[]]@(Test-CippWebSecurityHeader -Headers $HomeResponse.Headers -Uri $EffectiveUri))

    # --- Mixed content and visible errors -------------------------------------------------
    if ($EffectiveUri.Scheme -eq 'https') {
        # The w3.org namespace URLs in SVG and XHTML markup are identifiers, not fetches.
        $MixedMatches = @([regex]::Matches($HomeResponse.Content, '(?:src|href)\s*=\s*["'']http://(?!www\.w3\.org)([^"''\s]+)', 'IgnoreCase'))
        if ($MixedMatches.Count -gt 0) {
            $Sample = @($MixedMatches | Select-Object -First 3 | ForEach-Object { 'http://{0}' -f $_.Groups[1].Value })
            $Findings.Add((New-CippWordPressFinding -Id 'WEB-MIXED-CONTENT' -Category 'Transport' -Title 'The page loads resources over plain HTTP' -Severity Low -Status Warn `
                        -Evidence "$($MixedMatches.Count) HTTP reference(s) on an HTTPS page, including: $($Sample -join ', ')" `
                        -Recommendation 'Point these at their HTTPS equivalents. Browsers block or downgrade mixed content, so this breaks parts of the page as well as weakening it.'))
        }
    }

    # PHP's own error format: "<level>: <message> in <file> on line <n>". With html_errors on -
    # the default - each part is wrapped in tags, so the level and the colon are separated by
    # markup and a pattern anchored on 'Warning:' matches nothing on a real site. Requiring the
    # 'in ... on line N' tail as well is what keeps ordinary prose from matching.
    $PhpErrorPattern = '(?s)\b(Fatal error|Parse error|Warning|Notice|Deprecated)\b\s*(?:</[a-z]+>)?\s*:.{0,300}?\bin\b.{0,200}?\bon line\b\s*(?:<[a-z]+>)?\s*\d+'
    if ($HomeResponse.Content -match $PhpErrorPattern) {
        $Findings.Add((New-CippWordPressFinding -Id 'WP-PHP-ERRORS' -Category 'Exposure' -Title 'PHP errors are displayed to visitors' -Severity Medium -Status Fail `
                    -Evidence 'The home page contains a PHP error message naming a file and line number.' `
                    -Recommendation 'Set WP_DEBUG_DISPLAY to false and display_errors to Off. Error output discloses absolute server paths and plugin internals, and it tells an attacker exactly which code path they just broke.'))
    }

    # --- Fingerprint ---------------------------------------------------------------------
    $Fingerprint = Get-CippWordPressFingerprint -Content $HomeResponse.Content -Headers $HomeResponse.Headers -BaseUri $BaseUri
    $Report.IsWordPress = $Fingerprint.IsWordPress
    $Report.WordPressVersion = $Fingerprint.Version

    if (-not $Fingerprint.IsWordPress) {
        $Findings.Add((New-CippWordPressFinding -Id 'WP-NOT-DETECTED' -Category 'WordPress' -Title 'This does not look like a WordPress site' -Severity Info -Status Info `
                    -Evidence 'No WordPress markers were found in the home page or its headers.' `
                    -Recommendation 'The transport and header findings above still apply. If you expected WordPress here, check whether the site is behind a cache or a page builder that rewrites its markup, or whether WordPress lives on a different path.'))
    } else {
        if (-not $SkipExposureProbes) {
            $Remaining = $MaxRequests - $Requests
            if ($Remaining -gt 0) {
                $Exposure = Test-CippWordPressExposure -BaseUri $BaseUri -TimeoutSeconds $TimeoutSeconds -MaxRequests $Remaining
                $Requests += $Exposure.RequestsMade
                $Findings.AddRange([object[]]@($Exposure.Findings))
            }
        }

        $Components = Test-CippWordPressComponent -Fingerprint $Fingerprint -SkipVersionLookup:$SkipVersionLookup
        $Findings.AddRange([object[]]@($Components.Findings))
        $Report.Components = @($Components.Inventory)

        if (-not $SkipVersionLookup) {
            $Latest = Get-CippWordPressLatestVersion -Type Core
            if ($Latest.Status -eq 'Found') { $Report.LatestWordPressVersion = $Latest.Version }
        }
    }

    # --- Score ---------------------------------------------------------------------------
    $SeverityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $StatusOrder = @{ Fail = 0; Warn = 1; Unknown = 2; Info = 3; Pass = 4 }
    $Ordered = @($Findings | Sort-Object @{ Expression = { $StatusOrder[[string]$_.Status] } }, @{ Expression = { $SeverityOrder[[string]$_.Severity] } }, Id)

    $Risk = Get-CippWordPressRiskScore -Findings $Ordered
    $Report.Findings = $Ordered
    $Report.Score = $Risk.Score
    $Report.Grade = $Risk.Grade
    $Report.Summary = $Risk.Summary
    $Report.RequestsMade = $Requests
    $Report.Completed = $true

    # Flat lists in the shape the other CIPP health reports use, so the same UI can render this.
    $Report.ValidationFails = @($Ordered | Where-Object { $_.Status -eq 'Fail' } | ForEach-Object { '{0}: {1}' -f $_.Severity, $_.Title })
    $Report.ValidationWarns = @($Ordered | Where-Object { $_.Status -in @('Warn', 'Unknown') } | ForEach-Object { '{0}: {1}' -f $_.Severity, $_.Title })
    $Report.ValidationPasses = @($Ordered | Where-Object { $_.Status -eq 'Pass' } | ForEach-Object { $_.Title })

    return $Report
}
