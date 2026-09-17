# Pester tests for the response header checks and the risk score.
#
# Two properties matter more than any individual check here. First, header names are
# case-insensitive on the wire and servers genuinely disagree about casing, so a check that only
# matches the spelling in the fixture silently passes every site that spells it differently.
# Second, the score has to keep tracking the worst problem: a site with a dozen missing headers and
# nothing else must not grade below a site serving its database credentials.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $WordPressRoot = Join-Path $RepoRoot 'Modules/CIPPCore/Public/WordPress'
    foreach ($Leaf in 'Compare-CippWordPressVersion.ps1', 'New-CippWordPressFinding.ps1', 'Test-CippPhpVersionHeader.ps1',
        'Test-CippWebSecurityHeader.ps1', 'Get-CippWordPressRiskScore.ps1') {
        . (Join-Path $WordPressRoot $Leaf)
    }

    function Get-Finding {
        param($Findings, [string]$Id)
        return @($Findings | Where-Object { $_.Id -eq $Id })
    }

    $script:HardenedHeaders = [ordered]@{
        'Strict-Transport-Security' = 'max-age=31536000; includeSubDomains'
        'X-Frame-Options'           = 'SAMEORIGIN'
        'X-Content-Type-Options'    = 'nosniff'
        'Referrer-Policy'           = 'strict-origin-when-cross-origin'
        'Content-Security-Policy'   = "default-src 'self'"
        'Server'                    = 'nginx'
    }
}

Describe 'Test-CippWebSecurityHeader' {

    Context 'A hardened response' {
        BeforeAll {
            $script:Hardened = Test-CippWebSecurityHeader -Headers $script:HardenedHeaders -Uri ([uri]'https://example.com/')
        }

        It 'reports no failures' {
            @($script:Hardened | Where-Object { $_.Status -eq 'Fail' }) | Should -BeNullOrEmpty
        }

        It 'still records the checks it passed, so the report shows what was verified' {
            @($script:Hardened | Where-Object { $_.Status -eq 'Pass' }).Count | Should -BeGreaterThan 3
        }
    }

    Context 'A bare response' {
        BeforeAll {
            $script:Bare = Test-CippWebSecurityHeader -Headers ([ordered]@{}) -Uri ([uri]'https://example.com/')
        }

        It 'reports missing HSTS' {
            (Get-Finding $script:Bare 'WEB-HSTS-MISSING').Status | Should -Be 'Fail'
        }

        It 'reports that the site can be framed' {
            (Get-Finding $script:Bare 'WEB-CLICKJACKING').Status | Should -Be 'Fail'
        }

        It 'reports missing nosniff' {
            (Get-Finding $script:Bare 'WEB-NOSNIFF').Status | Should -Be 'Fail'
        }

        It 'warns rather than fails on a missing CSP' {
            # A CSP that breaks a customer's theme is worse than no CSP; this is advice, not a bug.
            (Get-Finding $script:Bare 'WEB-CSP-MISSING').Status | Should -Be 'Warn'
        }

        It 'gives every finding an actionable recommendation' {
            foreach ($Finding in @($script:Bare | Where-Object { $_.Status -in @('Fail', 'Warn') })) {
                $Finding.Recommendation | Should -Not -BeNullOrEmpty -Because "$($Finding.Id) is asking someone to do something"
            }
        }
    }

    Context 'Header name casing' {
        It 'recognises headers whatever case the server sends them in' {
            # RFC 9110: field names are case-insensitive. Real servers send strict-transport-security,
            # X-Frame-Options and x-content-type-options in whatever mix they like.
            $Headers = [ordered]@{
                'strict-transport-security' = 'max-age=63072000'
                'x-frame-options'           = 'DENY'
                'X-CONTENT-TYPE-OPTIONS'    = 'nosniff'
                'referrer-policy'           = 'no-referrer'
                'content-security-policy'   = "default-src 'self'"
            }
            $Findings = Test-CippWebSecurityHeader -Headers $Headers -Uri ([uri]'https://example.com/')
            @($Findings | Where-Object { $_.Status -eq 'Fail' }) | Should -BeNullOrEmpty
        }
    }

    Context 'Partial configuration' {
        It 'warns when HSTS is set but short-lived' {
            $Headers = [ordered]@{ 'Strict-Transport-Security' = 'max-age=300' }
            (Get-Finding (Test-CippWebSecurityHeader -Headers $Headers -Uri ([uri]'https://example.com/')) 'WEB-HSTS-SHORT').Status | Should -Be 'Warn'
        }

        It 'accepts a CSP frame-ancestors directive in place of X-Frame-Options' {
            $Headers = [ordered]@{ 'Content-Security-Policy' = "default-src 'self'; frame-ancestors 'self'" }
            (Get-Finding (Test-CippWebSecurityHeader -Headers $Headers -Uri ([uri]'https://example.com/')) 'WEB-CLICKJACKING').Status | Should -Be 'Pass'
        }

        It 'warns about a CSP that allows inline script' {
            $Headers = [ordered]@{ 'Content-Security-Policy' = "default-src 'self' 'unsafe-inline'" }
            (Get-Finding (Test-CippWebSecurityHeader -Headers $Headers -Uri ([uri]'https://example.com/')) 'WEB-CSP-WEAK').Status | Should -Be 'Warn'
        }

        It 'skips HSTS entirely on a plain HTTP page' {
            # HSTS is ignored by browsers over HTTP; the missing transport is the finding.
            $Findings = Test-CippWebSecurityHeader -Headers ([ordered]@{}) -Uri ([uri]'http://example.com/')
            Get-Finding $Findings 'WEB-HSTS-MISSING' | Should -BeNullOrEmpty
        }
    }

    Context 'Version disclosure' {
        It 'reports a Server header carrying a version' {
            $Headers = [ordered]@{ 'Server' = 'Apache/2.4.41 (Ubuntu)' }
            (Get-Finding (Test-CippWebSecurityHeader -Headers $Headers -Uri ([uri]'https://example.com/')) 'WEB-BANNER-SERVER').Status | Should -Be 'Fail'
        }

        It 'accepts a Server header with no version in it' {
            $Headers = [ordered]@{ 'Server' = 'nginx' }
            Get-Finding (Test-CippWebSecurityHeader -Headers $Headers -Uri ([uri]'https://example.com/')) 'WEB-BANNER-SERVER' | Should -BeNullOrEmpty
        }
    }

    Context 'Cookie flags' {
        It 'reports cookies set without Secure on an HTTPS page' {
            $Headers = [ordered]@{ 'Set-Cookie' = 'wordpress_logged_in_abc=value; path=/; HttpOnly' }
            (Get-Finding (Test-CippWebSecurityHeader -Headers $Headers -Uri ([uri]'https://example.com/')) 'WEB-COOKIE-SECURE').Status | Should -Be 'Fail'
        }

        It 'reports cookies readable by JavaScript' {
            $Headers = [ordered]@{ 'Set-Cookie' = 'session=value; path=/; Secure' }
            (Get-Finding (Test-CippWebSecurityHeader -Headers $Headers -Uri ([uri]'https://example.com/')) 'WEB-COOKIE-HTTPONLY').Status | Should -Be 'Warn'
        }

        It 'splits several cookies folded into one header value' {
            # PowerShell joins repeated Set-Cookie headers with a comma; the expiry date inside a
            # cookie contains commas too, so a naive split reports cookies that do not exist.
            $Headers = [ordered]@{ 'Set-Cookie' = 'a=1; expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; HttpOnly, b=2; path=/' }
            $Finding = Get-Finding (Test-CippWebSecurityHeader -Headers $Headers -Uri ([uri]'https://example.com/')) 'WEB-COOKIE-SECURE'
            $Finding.Status | Should -Be 'Fail'
            $Finding.Evidence | Should -Match '\bb\b'
            $Finding.Evidence | Should -Not -Match 'expires'
        }

        It 'does not judge cookie flags on a plain HTTP page' {
            $Headers = [ordered]@{ 'Set-Cookie' = 'a=1; path=/' }
            Get-Finding (Test-CippWebSecurityHeader -Headers $Headers -Uri ([uri]'http://example.com/')) 'WEB-COOKIE-SECURE' | Should -BeNullOrEmpty
        }
    }
}

Describe 'Test-CippPhpVersionHeader' {

    It 'reports a PHP branch that is past end of support' {
        $Headers = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $Headers['X-Powered-By'] = 'PHP/7.4.33'
        $Finding = Test-CippPhpVersionHeader -Headers $Headers
        $Finding.Status | Should -Be 'Fail'
        $Finding.Severity | Should -Be 'High'
    }

    It 'reads the version out of a Server header too' {
        $Headers = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $Headers['Server'] = 'Apache/2.4.41 (Unix) PHP/5.6.40'
        (Test-CippPhpVersionHeader -Headers $Headers).Status | Should -Be 'Fail'
    }

    It 'returns nothing when no PHP version is disclosed' {
        $Headers = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $Headers['Server'] = 'nginx'
        Test-CippPhpVersionHeader -Headers $Headers | Should -BeNullOrEmpty
    }

    It 'judges the branch against the current date rather than a frozen verdict' {
        # The table holds end-of-support dates, so a branch supported today stops passing on its own
        # once that date goes by - without anyone having to remember to edit this check.
        $Headers = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $Headers['X-Powered-By'] = 'PHP/8.4.1'
        $Finding = Test-CippPhpVersionHeader -Headers $Headers
        $Expected = if ([datetime]::UtcNow -gt [datetime]'2028-12-31') { 'Fail' } else { @('Pass', 'Warn') }
        $Finding.Status | Should -BeIn @($Expected)
    }
}

Describe 'Get-CippWordPressRiskScore' {

    It 'scores a clean scan at 100' {
        $Findings = @(
            New-CippWordPressFinding -Id 'A' -Category 'Headers' -Title 'ok' -Severity High -Status Pass
            New-CippWordPressFinding -Id 'B' -Category 'Headers' -Title 'ok' -Severity Medium -Status Pass
        )
        $Risk = Get-CippWordPressRiskScore -Findings $Findings
        $Risk.Score | Should -Be 100
        $Risk.Grade | Should -Be 'A'
    }

    It 'deducts nothing for a check that could not be run' {
        # An Unknown is the scan admitting it did not look. Guessing in either direction is worse.
        $Findings = @(New-CippWordPressFinding -Id 'A' -Category 'Headers' -Title 'x' -Severity Critical -Status Unknown)
        (Get-CippWordPressRiskScore -Findings $Findings).Score | Should -Be 100
    }

    It 'deducts half for a warning' {
        $Fail = Get-CippWordPressRiskScore -Findings @(New-CippWordPressFinding -Id 'A' -Category 'H' -Title 'x' -Severity Medium -Status Fail)
        $Warn = Get-CippWordPressRiskScore -Findings @(New-CippWordPressFinding -Id 'A' -Category 'H' -Title 'x' -Severity Medium -Status Warn)
        (100 - $Warn.Score) | Should -Be ((100 - $Fail.Score) / 2)
    }

    It 'keeps one critical finding worse than a pile of small ones' {
        # The property that makes the grade mean something: many missing headers must not outrank
        # an exposed wp-config backup.
        $Small = @(1..12 | ForEach-Object { New-CippWordPressFinding -Id "L$_" -Category 'Headers' -Title 'x' -Severity Low -Status Fail })
        $Critical = @(New-CippWordPressFinding -Id 'C' -Category 'Exposure' -Title 'x' -Severity Critical -Status Fail)
        (Get-CippWordPressRiskScore -Findings $Critical).Score |
            Should -BeLessThan (Get-CippWordPressRiskScore -Findings $Small).Score
    }

    It 'never returns a negative score' {
        $Findings = @(1..10 | ForEach-Object { New-CippWordPressFinding -Id "C$_" -Category 'Exposure' -Title 'x' -Severity Critical -Status Fail })
        $Risk = Get-CippWordPressRiskScore -Findings $Findings
        $Risk.Score | Should -Be 0
        $Risk.Grade | Should -Be 'F'
    }

    It 'counts findings by severity for the report summary' {
        $Findings = @(
            New-CippWordPressFinding -Id 'A' -Category 'X' -Title 'x' -Severity Critical -Status Fail
            New-CippWordPressFinding -Id 'B' -Category 'X' -Title 'x' -Severity High -Status Fail
            New-CippWordPressFinding -Id 'C' -Category 'X' -Title 'x' -Severity High -Status Warn
            New-CippWordPressFinding -Id 'D' -Category 'X' -Title 'x' -Severity Low -Status Pass
            New-CippWordPressFinding -Id 'E' -Category 'X' -Title 'x' -Severity Low -Status Unknown
        )
        $Summary = (Get-CippWordPressRiskScore -Findings $Findings).Summary
        $Summary.Critical | Should -Be 1
        $Summary.High | Should -Be 2
        $Summary.Passed | Should -Be 1
        $Summary.Unknown | Should -Be 1
    }

    It 'handles an empty finding set' {
        (Get-CippWordPressRiskScore -Findings @()).Score | Should -Be 100
    }

    It 'grades <Expected> for <Case>' -ForEach @(
        @{ Case = 'nothing found'; Severities = @(); Score = 100; Expected = 'A' }
        @{ Case = 'four minor issues'; Severities = @('Low', 'Low', 'Low', 'Low'); Score = 88; Expected = 'B' }
        @{ Case = 'one of each'; Severities = @('High', 'Medium', 'Low'); Score = 71; Expected = 'C' }
        @{ Case = 'a single critical'; Severities = @('Critical'); Score = 60; Expected = 'D' }
        @{ Case = 'two criticals'; Severities = @('Critical', 'Critical'); Score = 20; Expected = 'F' }
    ) {
        $Index = 0
        $Findings = @(foreach ($Severity in $Severities) {
                $Index++
                New-CippWordPressFinding -Id "F$Index" -Category 'X' -Title 'x' -Severity $Severity -Status Fail
            })
        $Risk = Get-CippWordPressRiskScore -Findings @($Findings)
        $Risk.Score | Should -Be $Score
        $Risk.Grade | Should -Be $Expected
    }
}
