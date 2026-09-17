function Get-CippCertificateFinding {
    <#
    .SYNOPSIS
    Turns the result of a TLS handshake into scan findings.

    .DESCRIPTION
    Separates the three things a site owner has to act on differently: a certificate that expires
    soon is a diary entry, one that has already expired is an outage in progress, and one that
    fails validation for any other reason is a configuration error a visitor sees as a warning
    page. A handshake that did not complete at all is reported as Unknown rather than as a failure,
    because a firewall between the scanner and the site looks the same from here as a broken TLS
    stack.

    .PARAMETER Certificate
    Output of Get-CippTlsCertificateInfo.

    .PARAMETER ExpiryWarningDays
    Days of remaining validity below which the certificate is flagged. Defaults to 21, a little
    over the point where a stalled Let's Encrypt renewal has stopped being self-correcting.

    .EXAMPLE
    Get-CippCertificateFinding -Certificate (Get-CippTlsCertificateInfo -HostName 'example.com')
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Certificate,
        [int]$ExpiryWarningDays = 21
    )

    $Findings = [System.Collections.Generic.List[object]]::new()

    if (-not $Certificate -or -not $Certificate.Succeeded) {
        $Reason = if ($Certificate) { $Certificate.Error } else { 'No handshake was attempted.' }
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-TLS-CERT' -Category 'Transport' -Title 'The TLS certificate could not be inspected' -Severity Medium -Status Unknown `
                    -Evidence $Reason `
                    -Recommendation 'Check the certificate directly. A blocked or filtered connection from the scanner produces this result as well, so it does not necessarily mean anything is wrong.'))
        return @($Findings)
    }

    $Expiry = $Certificate.NotAfter
    $DaysRemaining = $Certificate.DaysRemaining

    if ($DaysRemaining -lt 0) {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-TLS-EXPIRED' -Category 'Transport' -Title 'The TLS certificate has expired' -Severity Critical -Status Fail `
                    -Evidence "Expired on $($Expiry.ToString('yyyy-MM-dd')), $([Math]::Abs($DaysRemaining)) day(s) ago." `
                    -Recommendation 'Renew it now. Every visitor is currently being shown a full-page browser warning, and any integration calling this site over HTTPS has already stopped working.'))
    } elseif ($DaysRemaining -le $ExpiryWarningDays) {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-TLS-EXPIRING' -Category 'Transport' -Title 'The TLS certificate expires soon' -Severity Medium -Status Warn `
                    -Evidence "Expires on $($Expiry.ToString('yyyy-MM-dd')), in $DaysRemaining day(s)." `
                    -Recommendation 'Confirm that automatic renewal is working. A certificate this close to expiry usually means renewal has been failing quietly for weeks.'))
    } else {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-TLS-EXPIRING' -Category 'Transport' -Title 'The TLS certificate is valid' -Severity Medium -Status Pass `
                    -Evidence "Issued by $($Certificate.Issuer). Expires on $($Expiry.ToString('yyyy-MM-dd')), in $DaysRemaining day(s)."))
    }

    $PolicyErrors = @($Certificate.PolicyErrors | Where-Object { $_ -and $_ -ne 'None' })
    if ($PolicyErrors.Count -gt 0) {
        $Title = 'The TLS certificate fails validation'
        $Recommendation = 'Reissue the certificate for the names the site is actually served on, and install the full chain the issuer supplies.'
        if ($PolicyErrors -contains 'RemoteCertificateNameMismatch') {
            $Title = 'The TLS certificate does not cover this hostname'
            $Recommendation = "Reissue the certificate including $($Certificate.HostName), or serve the site on a name the certificate does cover."
        } elseif ($PolicyErrors -contains 'RemoteCertificateChainErrors' -and $Certificate.IsSelfSigned) {
            $Title = 'The TLS certificate is self-signed'
            $Recommendation = 'Replace it with a certificate from a trusted authority. A free Let''s Encrypt certificate takes minutes and removes the browser warning entirely.'
        }
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-TLS-VALIDATION' -Category 'Transport' -Title $Title -Severity High -Status Fail `
                    -Evidence "Subject $($Certificate.Subject); validation reported: $($PolicyErrors -join ', ')." `
                    -Recommendation $Recommendation))
    }

    if ($Certificate.Protocol -and $Certificate.Protocol -match 'Tls11|Tls10|^Tls$|Ssl') {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-TLS-PROTOCOL' -Category 'Transport' -Title 'The connection negotiated an obsolete TLS version' -Severity High -Status Fail `
                    -Evidence "The handshake settled on $($Certificate.Protocol)." `
                    -Recommendation 'Enable TLS 1.2 and 1.3 and disable everything below. Browsers have shown errors for TLS 1.0 and 1.1 since 2020, and card payment compliance rules out both.'))
    } elseif ($Certificate.Protocol) {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-TLS-PROTOCOL' -Category 'Transport' -Title 'The connection negotiated a current TLS version' -Severity High -Status Pass `
                    -Evidence "The handshake settled on $($Certificate.Protocol). This does not prove that older versions are switched off."))
    }

    if ($Certificate.KeySize -and $Certificate.KeySize -lt 2048 -and $Certificate.SignatureAlgorithm -notmatch 'ecdsa|sha\d+ECDSA') {
        $Findings.Add((New-CippWordPressFinding -Id 'WEB-TLS-KEYSIZE' -Category 'Transport' -Title 'The certificate key is too small' -Severity High -Status Fail `
                    -Evidence "RSA key size $($Certificate.KeySize) bits." `
                    -Recommendation 'Reissue with at least a 2048-bit RSA key, or an ECDSA P-256 key.'))
    }

    return @($Findings)
}
