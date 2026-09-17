# Pester tests for the WordPress scan as a whole.
#
# These drive the orchestrator against a fake site so the parts that only appear when the pieces
# are wired together are covered: that the guard runs before any request is made, that a redirect
# decides which host the rest of the scan reads, that a component check never happens on a site
# that is not WordPress, and that a failure anywhere degrades the report instead of throwing.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $WordPressRoot = Join-Path $RepoRoot 'Modules/CIPPCore/Public/WordPress'
    foreach ($Leaf in 'Compare-CippWordPressVersion.ps1', 'Get-CippCertificateFinding.ps1', 'Get-CippPrivateAddressReason.ps1',
        'Get-CippWordPressAsset.ps1', 'Get-CippWordPressFingerprint.ps1', 'Get-CippWordPressRiskScore.ps1',
        'New-CippWordPressFinding.ps1', 'Resolve-CippHostAddress.ps1', 'Test-CippPhpVersionHeader.ps1',
        'Test-CippWebSecurityHeader.ps1', 'Test-CippWordPressComponent.ps1', 'Test-CippWordPressExposure.ps1',
        'Test-CippWordPressTarget.ps1', 'Test-CippWordPressSecurity.ps1') {
        . (Join-Path $WordPressRoot $Leaf)
    }

    # The two functions that touch the network, stubbed so Pester can replace them.
    function Invoke-CippWordPressProbe {
        param([uri]$Uri, [string]$Method, [int]$TimeoutSeconds, [int]$MaximumRedirection, [int]$MaximumContentBytes, [switch]$AllowInsecureCertificate, [string]$UserAgent)
    }
    function Get-CippTlsCertificateInfo { param([string]$HostName, [int]$Port, [int]$TimeoutSeconds) }
    function Get-CippWordPressLatestVersion { param([string]$Type, [string]$Slug, [int]$TimeoutSeconds, [int]$CacheMinutes) }

    $script:HomePage = @'
<!DOCTYPE html><html><head>
<meta name="generator" content="WordPress 6.3.1" />
<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/styles.css?ver=5.7.0" />
<link rel="stylesheet" href="/wp-content/themes/twentytwentythree/style.css?ver=1.1" />
</head><body>Welcome</body></html>
'@

    function New-ProbeResponse {
        # No '= $null' default on FinalUri: PowerShell coerces that to '' on a [string] parameter,
        # and '' is not what ?? falls back from.
        param([string]$Uri, [int]$StatusCode = 200, [string]$Content = '', $Headers = $null, [bool]$Success = $true, [string]$FinalUri)
        [PSCustomObject]@{
            Uri = $Uri; FinalUri = $(if ([string]::IsNullOrEmpty($FinalUri)) { $Uri } else { $FinalUri }); Method = 'GET'; StatusCode = $StatusCode
            Headers = ($Headers ?? [ordered]@{}); Content = $Content; ContentType = 'text/html'
            ContentLength = $Content.Length; Truncated = $false; Redirected = $false
            Success = $Success; CertificateError = $false; Insecure = $false; Error = ''
        }
    }

    function Get-Finding {
        param($Report, [string]$Id)
        return @($Report.Findings | Where-Object { $_.Id -eq $Id })
    }
}

Describe 'Test-CippWordPressSecurity' {

    # Declared here rather than in a helper: Mock registers against the scope it is called from,
    # so wrapping it in a function does not reliably reach the nested blocks. Contexts and
    # individual tests override these where they need different behaviour.
    BeforeAll {
        Mock Resolve-CippHostAddress { @([System.Net.IPAddress]'93.184.216.34') }
        Mock Get-CippTlsCertificateInfo {
            [PSCustomObject]@{
                HostName = $HostName; Port = 443; Succeeded = $true
                Subject = "CN=$HostName"; Issuer = 'CN=Test CA'
                NotBefore = [datetime]::UtcNow.AddDays(-30); NotAfter = [datetime]::UtcNow.AddDays(60)
                DaysRemaining = 60; Protocol = 'Tls13'; SignatureAlgorithm = 'sha256RSA'; KeySize = 2048
                IsSelfSigned = $false; PolicyErrors = @(); Error = ''
            }
        }
        Mock Get-CippWordPressLatestVersion {
            if ($Type -eq 'Core') { return [PSCustomObject]@{ Type = 'Core'; Slug = ''; Version = '6.4.2'; Status = 'Found'; Error = '' } }
            return [PSCustomObject]@{ Type = $Type; Slug = $Slug; Version = '5.9.0'; Status = 'Found'; Error = '' }
        }
        Mock Invoke-CippWordPressProbe {
            if ($Uri.AbsolutePath -eq '/' -or $Uri.AbsolutePath -eq '') {
                return New-ProbeResponse -Uri $Uri.AbsoluteUri -Content $script:HomePage
            }
            return New-ProbeResponse -Uri $Uri.AbsoluteUri -StatusCode 404 -Content 'Not Found'
        }
    }

    Context 'Refusing a target it must not scan' {

        It 'refuses a private address' {
            $Report = Test-CippWordPressSecurity -Url 'http://192.168.1.10/'
            $Report.Completed | Should -BeFalse
            $Report.Error | Should -Match 'public internet'
        }

        It 'makes no request at all when the target is refused' {
            # The guard is only a guard if it runs first.
            Test-CippWordPressSecurity -Url 'http://169.254.169.254/' | Out-Null
            Should -Not -Invoke Invoke-CippWordPressProbe -Scope It
        }

        It 'refuses a hostname that resolves into private space' {
            Mock Resolve-CippHostAddress { @([System.Net.IPAddress]'10.1.1.1') }
            (Test-CippWordPressSecurity -Url 'https://customer.com/').Completed | Should -BeFalse
        }
    }

    Context 'A healthy WordPress site' {
        BeforeAll {
            $script:Report = Test-CippWordPressSecurity -Url 'https://example.com/'
        }

        It 'completes and identifies WordPress' {
            $script:Report.Completed | Should -BeTrue
            $script:Report.IsWordPress | Should -BeTrue
        }

        It 'reports the detected and current core versions' {
            $script:Report.WordPressVersion | Should -Be '6.3.1'
            $script:Report.LatestWordPressVersion | Should -Be '6.4.2'
        }

        It 'flags core as out of date' {
            (Get-Finding $script:Report 'WP-CORE-OUTDATED').Status | Should -Be 'Fail'
        }

        It 'flags the outdated plugin it found in the markup' {
            $Finding = Get-Finding $script:Report 'WP-COMPONENT-OUTDATED-CONTACT-FORM-7'
            $Finding.Status | Should -Be 'Fail'
            $Finding.Evidence | Should -Match '5\.7\.0'
        }

        It 'lists the components it inventoried' {
            $script:Report.Components.Slug | Should -Contain 'contact-form-7'
            $script:Report.Components.Slug | Should -Contain 'twentytwentythree'
        }

        It 'scores the scan and grades it' {
            $script:Report.Score | Should -BeGreaterOrEqual 0
            $script:Report.Score | Should -BeLessOrEqual 100
            $script:Report.Grade | Should -BeIn @('A', 'B', 'C', 'D', 'F')
        }

        It 'sorts findings so failures come first' {
            # The report is read top-down by someone deciding what to do this afternoon.
            @($script:Report.Findings)[0].Status | Should -Be 'Fail'
        }

        It 'fills the flat validation lists the other CIPP health reports use' {
            $script:Report.ValidationFails | Should -Not -BeNullOrEmpty
            $script:Report.ValidationPasses | Should -Not -BeNullOrEmpty
        }

        It 'stays within the request budget it was given' {
            $script:Report.RequestsMade | Should -BeLessOrEqual 30
        }
    }

    Context 'Transport problems' {
        It 'treats a site with no HTTPS as critical' {
            Mock Invoke-CippWordPressProbe {
                if ($Uri.AbsolutePath -eq '/') { return New-ProbeResponse -Uri 'http://example.com/' -Content $script:HomePage }
                return New-ProbeResponse -Uri $Uri.AbsoluteUri -StatusCode 404
            }
            $Report = Test-CippWordPressSecurity -Url 'http://example.com/'
            $Finding = Get-Finding $Report 'WEB-HTTPS'
            $Finding.Status | Should -Be 'Fail'
            $Finding.Severity | Should -Be 'Critical'
        }

        It 'follows a redirect and scans where the site actually lives' {
            # http://example.com -> https://www.example.com. Scanning the pre-redirect host would
            # check a name nobody visits and report its headers as the site's.
            Mock Invoke-CippWordPressProbe {
                if ($Uri.Host -eq 'example.com' -and $Uri.Scheme -eq 'http') {
                    return New-ProbeResponse -Uri $Uri.AbsoluteUri -Content $script:HomePage -FinalUri 'https://www.example.com/'
                }
                return New-ProbeResponse -Uri $Uri.AbsoluteUri -StatusCode 404
            }
            $Report = Test-CippWordPressSecurity -Url 'http://example.com/'
            $Report.FinalUrl | Should -Be 'https://www.example.com/'
            (Get-Finding $Report 'WEB-HTTPS').Status | Should -Be 'Pass'
        }

        It 'reports an expired certificate as critical' {
            Mock Get-CippTlsCertificateInfo {
                [PSCustomObject]@{
                    HostName = $HostName; Port = 443; Succeeded = $true; Subject = "CN=$HostName"; Issuer = 'CN=Test CA'
                    NotBefore = [datetime]::UtcNow.AddDays(-400); NotAfter = [datetime]::UtcNow.AddDays(-5)
                    DaysRemaining = -5; Protocol = 'Tls12'; SignatureAlgorithm = 'sha256RSA'; KeySize = 2048
                    IsSelfSigned = $false; PolicyErrors = @(); Error = ''
                }
            }
            $Finding = Get-Finding (Test-CippWordPressSecurity -Url 'https://example.com/') 'WEB-TLS-EXPIRED'
            $Finding.Status | Should -Be 'Fail'
            $Finding.Severity | Should -Be 'Critical'
        }

        It 'reports a certificate that does not cover the hostname' {
            Mock Get-CippTlsCertificateInfo {
                [PSCustomObject]@{
                    HostName = $HostName; Port = 443; Succeeded = $true; Subject = 'CN=other.example'; Issuer = 'CN=Test CA'
                    NotBefore = [datetime]::UtcNow.AddDays(-10); NotAfter = [datetime]::UtcNow.AddDays(80)
                    DaysRemaining = 80; Protocol = 'Tls13'; SignatureAlgorithm = 'sha256RSA'; KeySize = 2048
                    IsSelfSigned = $false; PolicyErrors = @('RemoteCertificateNameMismatch'); Error = ''
                }
            }
            (Get-Finding (Test-CippWordPressSecurity -Url 'https://example.com/') 'WEB-TLS-VALIDATION').Title | Should -Match 'hostname'
        }

        It 'does not claim a certificate is fine when it could not be inspected' {
            Mock Get-CippTlsCertificateInfo {
                [PSCustomObject]@{ HostName = $HostName; Port = 443; Succeeded = $false; PolicyErrors = @(); Error = 'Timed out' }
            }
            (Get-Finding (Test-CippWordPressSecurity -Url 'https://example.com/') 'WEB-TLS-CERT').Status | Should -Be 'Unknown'
        }
    }

    Context 'A site that is not WordPress' {
        BeforeAll {
            Mock Invoke-CippWordPressProbe {
                if ($Uri.AbsolutePath -eq '/') {
                    return New-ProbeResponse -Uri $Uri.AbsoluteUri -Content '<html><body><h1>A static site</h1></body></html>'
                }
                return New-ProbeResponse -Uri $Uri.AbsoluteUri -StatusCode 404
            }
            $script:Static = Test-CippWordPressSecurity -Url 'https://example.com/'
        }

        It 'says so instead of reporting WordPress findings' {
            $script:Static.IsWordPress | Should -BeFalse
            (Get-Finding $script:Static 'WP-NOT-DETECTED').Status | Should -Be 'Info'
        }

        It 'skips the WordPress.org lookups entirely' {
            Should -Not -Invoke Get-CippWordPressLatestVersion -Scope Context
        }

        It 'still reports on transport and headers' {
            Get-Finding $script:Static 'WEB-HTTPS' | Should -Not -BeNullOrEmpty
            Get-Finding $script:Static 'WEB-HSTS-MISSING' | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Degrading instead of failing' {
        It 'returns an error report when the site cannot be reached' {
            Mock Invoke-CippWordPressProbe {
                [PSCustomObject]@{
                    Uri = $Uri.AbsoluteUri; FinalUri = $null; Method = 'GET'; StatusCode = 0
                    Headers = [ordered]@{}; Content = ''; ContentType = ''; ContentLength = 0
                    Truncated = $false; Redirected = $false; Success = $false; CertificateError = $false
                    Insecure = $false; Error = 'Connection refused'
                }
            }
            $Report = Test-CippWordPressSecurity -Url 'https://example.com/'
            $Report.Completed | Should -BeFalse
            $Report.Error | Should -Match 'Connection refused'
        }

        It 'reports version checks as unknown when WordPress.org cannot be reached' {
            # A third party being down must not turn into a clean bill of health.
            Mock Get-CippWordPressLatestVersion {
                [PSCustomObject]@{ Type = $Type; Slug = $Slug; Version = $null; Status = 'Unknown'; Error = 'Timed out' }
            }
            (Get-Finding (Test-CippWordPressSecurity -Url 'https://example.com/') 'WP-CORE-OUTDATED').Status | Should -Be 'Unknown'
        }

        It 'reports an unlisted plugin as unknown rather than as current' {
            Mock Get-CippWordPressLatestVersion {
                if ($Type -eq 'Core') { return [PSCustomObject]@{ Type = 'Core'; Version = '6.4.2'; Status = 'Found'; Error = '' } }
                return [PSCustomObject]@{ Type = $Type; Slug = $Slug; Version = $null; Status = 'NotFound'; Error = 'Plugin not found.' }
            }
            $Finding = Get-Finding (Test-CippWordPressSecurity -Url 'https://example.com/') 'WP-COMPONENT-UNLISTED-CONTACT-FORM-7'
            $Finding.Status | Should -Be 'Unknown'
            $Finding.Recommendation | Should -Match 'closes it|unpatched|premium'
        }

        It 'honours SkipVersionLookup without contacting WordPress.org' {
            $Report = Test-CippWordPressSecurity -Url 'https://example.com/' -SkipVersionLookup
            Should -Not -Invoke Get-CippWordPressLatestVersion -Scope It
            (Get-Finding $Report 'WP-CORE-OUTDATED').Status | Should -Be 'Unknown'
        }

        It 'honours SkipExposureProbes by staying on the home page' {
            $Report = Test-CippWordPressSecurity -Url 'https://example.com/' -SkipExposureProbes
            $Report.RequestsMade | Should -BeLessOrEqual 2
            Get-Finding $Report 'WP-XMLRPC' | Should -BeNullOrEmpty
        }
    }

    Context 'Content read from the home page' {
        It 'reports PHP errors printed on the page' {
            # Exactly what PHP emits with html_errors on, tags and all - not the tidied-up form.
            $ErrorOutput = '<br />' + "`n" + '<b>Warning</b>:  include(): Failed opening ''parts/header.php'' for inclusion in <b>/var/www/html/wp-content/themes/acme/index.php</b> on line <b>42</b><br />'
            Mock Invoke-CippWordPressProbe {
                if ($Uri.AbsolutePath -eq '/') {
                    return New-ProbeResponse -Uri $Uri.AbsoluteUri -Content ($script:HomePage + $ErrorOutput)
                }
                return New-ProbeResponse -Uri $Uri.AbsoluteUri -StatusCode 404
            }
            (Get-Finding (Test-CippWordPressSecurity -Url 'https://example.com/') 'WP-PHP-ERRORS').Status | Should -Be 'Fail'
        }

        It 'reports PHP errors in their plain-text form too' {
            Mock Invoke-CippWordPressProbe {
                if ($Uri.AbsolutePath -eq '/') {
                    return New-ProbeResponse -Uri $Uri.AbsoluteUri -Content ($script:HomePage + 'Warning: mysqli_connect(): Access denied in /var/www/html/wp-includes/wp-db.php on line 1653')
                }
                return New-ProbeResponse -Uri $Uri.AbsoluteUri -StatusCode 404
            }
            (Get-Finding (Test-CippWordPressSecurity -Url 'https://example.com/') 'WP-PHP-ERRORS').Status | Should -Be 'Fail'
        }

        It 'does not read ordinary prose as a PHP error' {
            # A page can legitimately contain the word Warning; the finding needs the whole
            # "<level>: ... in <file> on line <n>" shape before it accuses the site of leaking.
            Mock Invoke-CippWordPressProbe {
                if ($Uri.AbsolutePath -eq '/') {
                    return New-ProbeResponse -Uri $Uri.AbsoluteUri -Content ($script:HomePage + '<p>Warning: our office is closed. Read more in the notice on line two of the letter.</p>')
                }
                return New-ProbeResponse -Uri $Uri.AbsoluteUri -StatusCode 404
            }
            Get-Finding (Test-CippWordPressSecurity -Url 'https://example.com/') 'WP-PHP-ERRORS' | Should -BeNullOrEmpty
        }

        It 'reports mixed content on an HTTPS page' {
            Mock Invoke-CippWordPressProbe {
                if ($Uri.AbsolutePath -eq '/') {
                    return New-ProbeResponse -Uri $Uri.AbsoluteUri -Content ($script:HomePage + '<img src="http://cdn.example.net/logo.png">')
                }
                return New-ProbeResponse -Uri $Uri.AbsoluteUri -StatusCode 404
            }
            (Get-Finding (Test-CippWordPressSecurity -Url 'https://example.com/') 'WEB-MIXED-CONTENT').Status | Should -Be 'Warn'
        }

        It 'does not mistake an XML namespace for mixed content' {
            # Every SVG in a theme carries http://www.w3.org/2000/svg, which is an identifier and
            # not something the browser fetches.
            Mock Invoke-CippWordPressProbe {
                if ($Uri.AbsolutePath -eq '/') {
                    return New-ProbeResponse -Uri $Uri.AbsoluteUri -Content ($script:HomePage + '<svg xmlns="http://www.w3.org/2000/svg"><use href="http://www.w3.org/1999/xlink"/></svg>')
                }
                return New-ProbeResponse -Uri $Uri.AbsoluteUri -StatusCode 404
            }
            Get-Finding (Test-CippWordPressSecurity -Url 'https://example.com/') 'WEB-MIXED-CONTENT' | Should -BeNullOrEmpty
        }
    }
}
