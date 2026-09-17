# Pester tests for the single request the WordPress scanner is built on.
#
# Invoke-WebRequest is mocked rather than a real site being contacted, so these run anywhere and
# assert the parts that are easy to get wrong and invisible when they are: that a refused
# connection comes back as a result instead of an exception, that a TLS failure is distinguished
# from every other failure, that header values are flattened the way the checks expect to read
# them, and - the one that matters for security - that a redirect landing on a private host is
# discarded rather than reported.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $WordPressRoot = Join-Path $RepoRoot 'Modules/CIPPCore/Public/WordPress'
    foreach ($Leaf in 'Get-CippPrivateAddressReason.ps1', 'Resolve-CippHostAddress.ps1',
        'Test-CippWordPressTarget.ps1', 'Invoke-CippWordPressProbe.ps1') {
        . (Join-Path $WordPressRoot $Leaf)
    }

    # Shape of what Invoke-WebRequest returns in PowerShell 7: header values are string arrays and
    # the final URL is only reachable through the underlying request message.
    function New-WebResponse {
        param([int]$StatusCode = 200, $Headers = @{}, [string]$Content = '', [string]$RequestUri = 'https://example.com/')
        $Typed = @{}
        foreach ($Key in $Headers.Keys) { $Typed[$Key] = [string[]]@($Headers[$Key]) }
        [PSCustomObject]@{
            StatusCode   = $StatusCode
            Headers      = $Typed
            Content      = $Content
            BaseResponse = [PSCustomObject]@{
                RequestMessage = [PSCustomObject]@{ RequestUri = [uri]$RequestUri }
            }
        }
    }
}

Describe 'Invoke-CippWordPressProbe' {

    BeforeAll {
        Mock Resolve-CippHostAddress { @([System.Net.IPAddress]'93.184.216.34') }
    }

    Context 'A normal response' {
        BeforeAll {
            Mock Invoke-WebRequest {
                New-WebResponse -StatusCode 200 -Content '<html>hello</html>' -Headers @{
                    'Content-Type' = 'text/html; charset=UTF-8'
                    'Set-Cookie'   = @('a=1; Path=/', 'b=2; Path=/; Secure')
                }
            }
            $script:Result = Invoke-CippWordPressProbe -Uri ([uri]'https://example.com/')
        }

        It 'reports success and the status code' {
            $script:Result.Success | Should -BeTrue
            $script:Result.StatusCode | Should -Be 200
        }

        It 'flattens repeated header values into one string' {
            # Set-Cookie routinely arrives several times; the cookie check reads one value.
            $script:Result.Headers['Set-Cookie'] | Should -Match 'a=1'
            $script:Result.Headers['Set-Cookie'] | Should -Match 'b=2'
        }

        It 'returns the body' {
            $script:Result.Content | Should -Be '<html>hello</html>'
        }

        It 'requests the page without following anything the caller did not ask for' {
            Should -Invoke Invoke-WebRequest -Scope Context -Times 1 -Exactly
        }
    }

    Context 'Error responses' {
        It 'treats a 404 as a result, not a failure' {
            # Most of what a scan asks for does not exist. A 404 is an answer.
            Mock Invoke-WebRequest { New-WebResponse -StatusCode 404 -Content 'Not Found' }
            $Result = Invoke-CippWordPressProbe -Uri ([uri]'https://example.com/missing')
            $Result.Success | Should -BeTrue
            $Result.StatusCode | Should -Be 404
        }

        It 'returns a refused connection instead of throwing' {
            Mock Invoke-WebRequest { throw [System.Net.Http.HttpRequestException]::new('Connection refused') }
            $Result = Invoke-CippWordPressProbe -Uri ([uri]'https://example.com/')
            $Result.Success | Should -BeFalse
            $Result.Error | Should -Match 'Connection refused'
        }
    }

    Context 'Certificate failures' {
        It 'marks a TLS failure as such rather than as a generic error' {
            Mock Invoke-WebRequest { throw [System.Security.Authentication.AuthenticationException]::new('The remote certificate is invalid.') }
            $Result = Invoke-CippWordPressProbe -Uri ([uri]'https://example.com/')
            $Result.CertificateError | Should -BeTrue
            $Result.Success | Should -BeFalse
        }

        It 'retries insecurely when asked, so the rest of the scan still has a page to read' {
            # A site with a broken certificate has everything else wrong with it too, and the
            # report is more useful for saying so than for stopping at the handshake.
            $script:Attempt = 0
            Mock Invoke-WebRequest {
                $script:Attempt++
                if (-not $SkipCertificateCheck) { throw [System.Security.Authentication.AuthenticationException]::new('The remote certificate is invalid.') }
                New-WebResponse -StatusCode 200 -Content '<html>still here</html>'
            }
            $Result = Invoke-CippWordPressProbe -Uri ([uri]'https://example.com/') -AllowInsecureCertificate
            $Result.CertificateError | Should -BeTrue
            $Result.Insecure | Should -BeTrue
            $Result.Success | Should -BeTrue
            $Result.Content | Should -Be '<html>still here</html>'
        }

        It 'does not retry insecurely unless it was asked to' {
            Mock Invoke-WebRequest { throw [System.Security.Authentication.AuthenticationException]::new('The remote certificate is invalid.') }
            Invoke-CippWordPressProbe -Uri ([uri]'https://example.com/') | Out-Null
            Should -Not -Invoke Invoke-WebRequest -Scope It -ParameterFilter { $SkipCertificateCheck -eq $true }
        }
    }

    Context 'Redirects' {
        It 'records where the request came to rest' {
            Mock Invoke-WebRequest { New-WebResponse -RequestUri 'https://www.example.com/' -Content 'ok' }
            $Result = Invoke-CippWordPressProbe -Uri ([uri]'https://example.com/')
            $Result.FinalUri | Should -Be 'https://www.example.com/'
            $Result.Redirected | Should -BeTrue
        }

        It 'discards a response that redirected onto a private host' {
            # The guard that cleared the original hostname says nothing about where a redirect
            # went. Without this the scan is an open redirect away from reading the metadata API.
            Mock Invoke-WebRequest { New-WebResponse -RequestUri 'http://169.254.169.254/latest/meta-data/' -Content 'iam-credentials' }
            $Result = Invoke-CippWordPressProbe -Uri ([uri]'https://example.com/')
            $Result.Success | Should -BeFalse
            $Result.Content | Should -BeNullOrEmpty
            $Result.Error | Should -Match 'cannot be scanned'
        }

        It 'allows a redirect to another public host' {
            Mock Resolve-CippHostAddress { @([System.Net.IPAddress]'93.184.216.34') }
            Mock Invoke-WebRequest { New-WebResponse -RequestUri 'https://cdn.example.net/' -Content 'ok' }
            (Invoke-CippWordPressProbe -Uri ([uri]'https://example.com/')).Success | Should -BeTrue
        }
    }

    Context 'Large responses' {
        It 'truncates a body past the limit and says that it did' {
            Mock Invoke-WebRequest { New-WebResponse -Content ('x' * 5000) }
            $Result = Invoke-CippWordPressProbe -Uri ([uri]'https://example.com/') -MaximumContentBytes 1000
            $Result.Content.Length | Should -Be 1000
            $Result.Truncated | Should -BeTrue
        }

        It 'leaves a body within the limit alone' {
            Mock Invoke-WebRequest { New-WebResponse -Content ('x' * 100) }
            $Result = Invoke-CippWordPressProbe -Uri ([uri]'https://example.com/') -MaximumContentBytes 1000
            $Result.Truncated | Should -BeFalse
        }
    }

    Context 'Request shape' {
        It 'identifies itself in the User-Agent so site owners can see the scan in their logs' {
            Mock Invoke-WebRequest { New-WebResponse }
            Invoke-CippWordPressProbe -Uri ([uri]'https://example.com/') | Out-Null
            Should -Invoke Invoke-WebRequest -Scope It -ParameterFilter { $UserAgent -match 'CIPP' }
        }

        It 'never sends a body' {
            Mock Invoke-WebRequest { New-WebResponse }
            Invoke-CippWordPressProbe -Uri ([uri]'https://example.com/') | Out-Null
            Should -Not -Invoke Invoke-WebRequest -Scope It -ParameterFilter { $null -ne $Body }
        }

        It 'refuses a method other than GET or HEAD' {
            { Invoke-CippWordPressProbe -Uri ([uri]'https://example.com/') -Method 'POST' } | Should -Throw
        }
    }
}
