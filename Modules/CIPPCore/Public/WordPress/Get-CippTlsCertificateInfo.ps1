function Get-CippTlsCertificateInfo {
    <#
    .SYNOPSIS
    Opens one TLS handshake against a host and reports the certificate and protocol it presented.

    .DESCRIPTION
    Invoke-WebRequest either accepts a certificate or throws, which is not enough to tell a site
    owner what is wrong: an expired certificate, a hostname mismatch and an untrusted issuer all
    need different work. This performs the handshake directly so the certificate can be inspected
    even when it fails validation, and reports each validation error separately.

    The negotiated protocol is the best one both ends support, so TLS 1.2 here means the server
    offered at least that. It does not prove that TLS 1.0 and 1.1 are switched off - establishing that
    needs deliberately downgraded handshakes, which many platform TLS stacks now refuse to attempt
    at all, so the result would be inconclusive rather than clean. Verifying legacy protocol
    support is left to a dedicated TLS tool.

    .PARAMETER HostName
    The host to connect to.

    .PARAMETER Port
    Defaults to 443.

    .PARAMETER TimeoutSeconds
    Applies to both the TCP connect and the handshake. Defaults to 10.

    .EXAMPLE
    Get-CippTlsCertificateInfo -HostName 'example.com'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,
        [int]$Port = 443,
        [int]$TimeoutSeconds = 10
    )

    $Info = [PSCustomObject]@{
        HostName         = $HostName
        Port             = $Port
        Succeeded        = $false
        Subject          = ''
        Issuer           = ''
        NotBefore        = $null
        NotAfter         = $null
        DaysRemaining    = $null
        Protocol         = ''
        SignatureAlgorithm = ''
        KeySize          = $null
        IsSelfSigned     = $false
        PolicyErrors     = @()
        Error            = ''
    }

    $TcpClient = $null
    $SslStream = $null
    # The validation callback runs on another scope, so results come back through a shared
    # reference rather than a captured variable.
    $Observed = @{ Errors = 'None' }

    try {
        $TcpClient = [System.Net.Sockets.TcpClient]::new()
        $Connect = $TcpClient.ConnectAsync($HostName, $Port)
        if (-not $Connect.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            $Info.Error = "Timed out connecting to ${HostName}:${Port}."
            return $Info
        }
        if ($Connect.IsFaulted) {
            $Info.Error = $Connect.Exception.GetBaseException().Message
            return $Info
        }

        $Callback = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($Sender, $Certificate, $Chain, $SslPolicyErrors)
            $Observed.Errors = $SslPolicyErrors.ToString()
            # Always true: the point is to inspect what the server presented, including a
            # certificate a browser would reject. Nothing is sent over this stream afterwards.
            return $true
        }.GetNewClosure()

        $SslStream = [System.Net.Security.SslStream]::new($TcpClient.GetStream(), $false, $Callback)
        $Authenticate = $SslStream.AuthenticateAsClientAsync($HostName)
        if (-not $Authenticate.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            $Info.Error = 'Timed out during the TLS handshake.'
            return $Info
        }
        if ($Authenticate.IsFaulted) {
            $Info.Error = $Authenticate.Exception.GetBaseException().Message
            return $Info
        }

        $Remote = $SslStream.RemoteCertificate
        if (-not $Remote) {
            $Info.Error = 'The server presented no certificate.'
            return $Info
        }

        $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Remote)
        $Info.Succeeded = $true
        $Info.Subject = $Certificate.Subject
        $Info.Issuer = $Certificate.Issuer
        $Info.NotBefore = $Certificate.NotBefore.ToUniversalTime()
        $Info.NotAfter = $Certificate.NotAfter.ToUniversalTime()
        $Info.DaysRemaining = [int][Math]::Floor(($Certificate.NotAfter.ToUniversalTime() - [DateTime]::UtcNow).TotalDays)
        $Info.Protocol = $SslStream.SslProtocol.ToString()
        $Info.SignatureAlgorithm = $Certificate.SignatureAlgorithm.FriendlyName
        $Info.IsSelfSigned = $Certificate.Subject -eq $Certificate.Issuer
        try { $Info.KeySize = $Certificate.PublicKey.Key.KeySize } catch { $Info.KeySize = $null }

        if ($Observed.Errors -and $Observed.Errors -ne 'None') {
            $Info.PolicyErrors = @($Observed.Errors -split ',\s*')
        }
    } catch {
        $Info.Error = $_.Exception.Message
    } finally {
        if ($SslStream) { $SslStream.Dispose() }
        if ($TcpClient) { $TcpClient.Dispose() }
    }

    return $Info
}
