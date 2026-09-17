# Pester tests for the exposure probes.
#
# The property under test is restraint. A scanner that reports an exposed wp-config because the
# site returned its themed 404 page with status 200 is worse than no scanner: an MSP acts on a
# critical finding, rotates a customer's database credentials, and finds nothing was ever wrong.
# So every probe here is driven through a fake site that answers the way real ones do, including
# the soft-404 behaviour that makes status codes useless on their own.
#
# The other property is that the scan stays passive: only GET requests, and only for paths an
# anonymous visitor could already ask for.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $WordPressRoot = Join-Path $RepoRoot 'Modules/CIPPCore/Public/WordPress'
    foreach ($Leaf in 'New-CippWordPressFinding.ps1', 'Test-CippWordPressExposure.ps1') {
        . (Join-Path $WordPressRoot $Leaf)
    }

    # Stand-in for the real prober so Pester has a command to replace.
    function Invoke-CippWordPressProbe {
        param([uri]$Uri, [string]$Method, [int]$TimeoutSeconds, [int]$MaximumRedirection, [int]$MaximumContentBytes, [switch]$AllowInsecureCertificate, [string]$UserAgent)
    }

    function New-ProbeResponse {
        param([string]$Uri, [int]$StatusCode = 404, [string]$Content = '', [bool]$Success = $true)
        [PSCustomObject]@{
            Uri = $Uri; FinalUri = $Uri; Method = 'GET'; StatusCode = $StatusCode
            Headers = [ordered]@{}; Content = $Content; ContentType = 'text/html'
            ContentLength = $Content.Length; Truncated = $false; Redirected = $false
            Success = $Success; CertificateError = $false; Insecure = $false; Error = ''
        }
    }

    # A site that answers 404 to everything unless a case below says otherwise.
    function Set-FakeSite {
        param([hashtable]$Responses = @{}, [switch]$SoftNotFound)
        $script:RequestedPaths = [System.Collections.Generic.List[string]]::new()
        $script:FakeResponses = $Responses
        $script:FakeSoft404 = [bool]$SoftNotFound
        Mock Invoke-CippWordPressProbe {
            $Path = $Uri.PathAndQuery.TrimStart('/')
            $script:RequestedPaths.Add($Path)
            if ($script:FakeResponses.ContainsKey($Path)) {
                $Canned = $script:FakeResponses[$Path]
                return New-ProbeResponse -Uri $Uri.AbsoluteUri -StatusCode $Canned.Status -Content $Canned.Body
            }
            if ($script:FakeSoft404) {
                return New-ProbeResponse -Uri $Uri.AbsoluteUri -StatusCode 200 -Content '<html><body>Oops, that page cannot be found.</body></html>'
            }
            return New-ProbeResponse -Uri $Uri.AbsoluteUri -StatusCode 404 -Content 'Not Found'
        }
    }

    function Get-Finding {
        param($Result, [string]$Id)
        return @($Result.Findings | Where-Object { $_.Id -eq $Id })
    }
}

Describe 'Test-CippWordPressExposure' {

    Context 'A site with nothing exposed' {
        BeforeAll {
            Set-FakeSite
            $script:Clean = Test-CippWordPressExposure -BaseUri ([uri]'https://example.com/')
        }

        It 'reports no failures' {
            @($script:Clean.Findings | Where-Object { $_.Status -eq 'Fail' }) | Should -BeNullOrEmpty
        }

        It 'only ever issues GET requests' {
            # The scan is read-only by construction, not by convention. Scope Context because the
            # probes ran in BeforeAll, where the whole check set is exercised once.
            Should -Invoke Invoke-CippWordPressProbe -Scope Context -ParameterFilter { -not $Method -or $Method -eq 'GET' }
            Should -Not -Invoke Invoke-CippWordPressProbe -Scope Context -ParameterFilter { $Method -and $Method -ne 'GET' }
        }

        It 'stays within its request budget' {
            $script:Clean.RequestsMade | Should -BeLessOrEqual 30
        }
    }

    Context 'A site with real exposures' {
        BeforeAll {
            Set-FakeSite -Responses @{
                'wp-config.php.bak'    = @{ Status = 200; Body = "<?php`ndefine('DB_NAME', 'wp_live');`ndefine('DB_PASSWORD', 'hunter2');" }
                '.env'                 = @{ Status = 200; Body = "DB_HOST=localhost`nAPP_KEY=base64:abcdef" }
                '.git/config'          = @{ Status = 200; Body = "[core]`n`trepositoryformatversion = 0" }
                'wp-content/debug.log' = @{ Status = 200; Body = 'PHP Warning:  include(): failed opening /var/www/x.php on line 12' }
                'wp-content/uploads/'  = @{ Status = 200; Body = '<html><head><title>Index of /wp-content/uploads</title></head><body><h1>Index of /wp-content/uploads</h1></body></html>' }
                'xmlrpc.php'           = @{ Status = 405; Body = 'XML-RPC server accepts POST requests only.' }
                'wp-json/wp/v2/users'  = @{ Status = 200; Body = '[{"id":1,"name":"Admin","slug":"administrator"},{"id":2,"name":"Editor","slug":"jane"}]' }
                'wp-login.php'         = @{ Status = 200; Body = '<form name="loginform"><input name="user_login"><input id="wp-submit"></form>' }
            }
            $script:Exposed = Test-CippWordPressExposure -BaseUri ([uri]'https://example.com/')
        }

        It 'reports the wp-config backup as critical' {
            $Finding = Get-Finding $script:Exposed 'WP-CONFIG-BACKUP'
            @($Finding)[0].Status | Should -Be 'Fail'
            @($Finding)[0].Severity | Should -Be 'Critical'
        }

        It 'tells the owner to rotate the credentials, not just delete the file' {
            # Deleting it does not un-leak what has already been fetched.
            @(Get-Finding $script:Exposed 'WP-CONFIG-BACKUP')[0].Recommendation | Should -Match 'rotate'
        }

        It 'reports the exposed .env file' {
            (Get-Finding $script:Exposed 'WP-ENV-FILE').Status | Should -Be 'Fail'
        }

        It 'reports the exposed git repository' {
            (Get-Finding $script:Exposed 'WP-GIT-EXPOSED').Status | Should -Be 'Fail'
        }

        It 'reports the readable debug log' {
            (Get-Finding $script:Exposed 'WP-DEBUG-LOG').Status | Should -Be 'Fail'
        }

        It 'reports the directory listing' {
            (Get-Finding $script:Exposed 'WP-DIRECTORY-LISTING').Status | Should -Be 'Fail'
        }

        It 'reports XML-RPC as enabled and explains why that matters' {
            $Finding = Get-Finding $script:Exposed 'WP-XMLRPC'
            $Finding.Status | Should -Be 'Fail'
            $Finding.Recommendation | Should -Match 'multicall|pingback'
        }

        It 'reports REST user enumeration and names what leaked' {
            $Finding = Get-Finding $script:Exposed 'WP-REST-USERS'
            $Finding.Status | Should -Be 'Fail'
            $Finding.Evidence | Should -Match 'administrator'
        }

        It 'records the login page as context rather than as a fault' {
            # Having a login page is not a vulnerability; it should not cost the customer a grade.
            (Get-Finding $script:Exposed 'WP-LOGIN-EXPOSED').Status | Should -Be 'Info'
        }
    }

    Context 'A site that answers everything with 200' {
        BeforeAll {
            Set-FakeSite -SoftNotFound
            $script:Soft = Test-CippWordPressExposure -BaseUri ([uri]'https://example.com/')
        }

        It 'does not report a wp-config backup that is really a themed 404 page' {
            # The whole point of the content signatures. Status 200 proves nothing here.
            Get-Finding $script:Soft 'WP-CONFIG-BACKUP' | Should -BeNullOrEmpty
        }

        It 'does not report an exposed .env' {
            Get-Finding $script:Soft '.env' | Should -BeNullOrEmpty
            Get-Finding $script:Soft 'WP-ENV-FILE' | Should -BeNullOrEmpty
        }

        It 'says so in the report, so the findings can be read in context' {
            (Get-Finding $script:Soft 'WP-SOFT-404').Status | Should -Be 'Info'
            $script:Soft.SoftNotFound | Should -BeTrue
        }

        It 'requests a path that cannot exist to establish the behaviour' {
            @($script:RequestedPaths | Where-Object { $_ -match '^cipp-scan-' }) | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Ambiguous answers' {
        It 'flags a 200 on a critical path for a human to look at rather than guessing' {
            # No soft-404 behaviour, yet a path that should not exist answered 200 with content
            # that is not the file. Silence would be the wrong call for a database credential file.
            Set-FakeSite -Responses @{ 'wp-config.php.bak' = @{ Status = 200; Body = '<html>Access denied by security plugin</html>' } }
            $Result = Test-CippWordPressExposure -BaseUri ([uri]'https://example.com/')
            @(Get-Finding $Result 'WP-CONFIG-BACKUP')[0].Status | Should -Be 'Unknown'
        }

        It 'does not flag an ambiguous 200 on a low severity path' {
            Set-FakeSite -Responses @{ 'readme.html' = @{ Status = 200; Body = '<html>our news page</html>' } }
            $Result = Test-CippWordPressExposure -BaseUri ([uri]'https://example.com/')
            Get-Finding $Result 'WP-README' | Should -BeNullOrEmpty
        }
    }

    Context 'Request budget' {
        It 'stops probing at the limit and reports the rest as unchecked' {
            Set-FakeSite
            $Result = Test-CippWordPressExposure -BaseUri ([uri]'https://example.com/') -MaxRequests 3
            $Result.RequestsMade | Should -BeLessOrEqual 3
            @($Result.Findings | Where-Object { $_.Status -eq 'Unknown' }) | Should -Not -BeNullOrEmpty
        }

        It 'never reports an unchecked item as a pass' {
            Set-FakeSite
            $Result = Test-CippWordPressExposure -BaseUri ([uri]'https://example.com/') -MaxRequests 2
            foreach ($Finding in @($Result.Findings | Where-Object { $_.Evidence -match 'Not checked' })) {
                $Finding.Status | Should -Be 'Unknown'
            }
        }
    }

    Context 'An unreachable site' {
        It 'reports nothing rather than inventing passes' {
            Mock Invoke-CippWordPressProbe {
                New-ProbeResponse -Uri $Uri.AbsoluteUri -StatusCode 0 -Success $false
            }
            $Result = Test-CippWordPressExposure -BaseUri ([uri]'https://example.com/')
            @($Result.Findings | Where-Object { $_.Status -eq 'Pass' }) | Should -BeNullOrEmpty
        }
    }
}
