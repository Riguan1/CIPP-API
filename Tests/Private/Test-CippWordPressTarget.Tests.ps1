# Pester tests for the WordPress scanner's target guard.
#
# This is the security boundary of the whole feature, not a convenience validator. The endpoint
# takes a URL from an authenticated caller and makes the function app fetch it, so every range that
# is not rejected here is a request the caller gets to aim at the hosting network - and
# 169.254.169.254 is a request for the instance's own credentials. The cases below are the ways
# that guard has historically been walked past: decimal and IPv6 spellings of loopback, a hostname
# that resolves to RFC1918 space, and a scheme or port that was never meant to be reachable.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $WordPressRoot = Join-Path $RepoRoot 'Modules/CIPPCore/Public/WordPress'
    . (Join-Path $WordPressRoot 'Get-CippPrivateAddressReason.ps1')
    . (Join-Path $WordPressRoot 'Resolve-CippHostAddress.ps1')
    . (Join-Path $WordPressRoot 'Test-CippWordPressTarget.ps1')
}

Describe 'Get-CippPrivateAddressReason' {

    Context 'Addresses that must never be reachable' {
        It 'rejects <Address>' -ForEach @(
            @{ Address = '127.0.0.1'; Because = 'loopback' }
            @{ Address = '127.255.255.254'; Because = 'the whole 127/8 block is loopback, not just .0.1' }
            @{ Address = '0.0.0.0'; Because = '"this network"' }
            @{ Address = '10.1.2.3'; Because = 'RFC1918' }
            @{ Address = '172.16.0.1'; Because = 'RFC1918 lower bound' }
            @{ Address = '172.31.255.255'; Because = 'RFC1918 upper bound' }
            @{ Address = '192.168.1.1'; Because = 'RFC1918' }
            @{ Address = '169.254.169.254'; Because = 'cloud instance metadata' }
            @{ Address = '169.254.1.1'; Because = 'link-local' }
            @{ Address = '100.64.0.1'; Because = 'carrier-grade NAT' }
            @{ Address = '224.0.0.1'; Because = 'multicast' }
            @{ Address = '255.255.255.255'; Because = 'broadcast, inside 240/4' }
            @{ Address = '::1'; Because = 'IPv6 loopback' }
            @{ Address = 'fe80::1'; Because = 'IPv6 link-local' }
            @{ Address = 'fd00::1'; Because = 'IPv6 unique local' }
            @{ Address = 'fc00::1'; Because = 'IPv6 unique local lower bound' }
        ) {
            Get-CippPrivateAddressReason -Address ([System.Net.IPAddress]$Address) |
                Should -Not -BeNullOrEmpty -Because $Because
        }

        It 'names the metadata endpoint specifically' {
            # The operator reading a rejected scan needs to know this was not an ordinary typo.
            Get-CippPrivateAddressReason -Address ([System.Net.IPAddress]'169.254.169.254') |
                Should -Match 'metadata'
        }

        It 'unwraps IPv4-mapped IPv6 addresses' {
            # ::ffff:127.0.0.1 reaches loopback; a v6-only check would wave it through.
            Get-CippPrivateAddressReason -Address ([System.Net.IPAddress]'::ffff:10.0.0.1') |
                Should -Not -BeNullOrEmpty
        }

        It 'unwraps 6to4 addresses carrying a private v4 address' {
            # 2002:c0a8:0101:: embeds 192.168.1.1.
            Get-CippPrivateAddressReason -Address ([System.Net.IPAddress]'2002:c0a8:0101::') |
                Should -Not -BeNullOrEmpty
        }
    }

    Context 'Addresses that are ordinary public hosts' {
        It 'accepts <Address>' -ForEach @(
            @{ Address = '93.184.216.34' }
            @{ Address = '1.1.1.1' }
            @{ Address = '8.8.8.8' }
            @{ Address = '172.15.255.255' }   # just below 172.16/12
            @{ Address = '172.32.0.1' }       # just above 172.16/12
            @{ Address = '100.63.255.255' }   # just below 100.64/10
            @{ Address = '11.0.0.1' }         # just above 10/8
            @{ Address = '2606:4700:4700::1111' }
        ) {
            Get-CippPrivateAddressReason -Address ([System.Net.IPAddress]$Address) | Should -BeNullOrEmpty
        }
    }
}

Describe 'Test-CippWordPressTarget' {

    Context 'Input handling' {
        It 'treats a bare hostname as https' {
            $Result = Test-CippWordPressTarget -Url 'example.com' -SkipDnsResolution
            $Result.IsValid | Should -BeTrue
            $Result.Uri.Scheme | Should -Be 'https'
        }

        It 'keeps an explicit http scheme rather than upgrading it' {
            # The scan has to be able to observe a site that is only served over HTTP.
            $Result = Test-CippWordPressTarget -Url 'http://example.com/' -SkipDnsResolution
            $Result.IsValid | Should -BeTrue
            $Result.Uri.Scheme | Should -Be 'http'
        }

        It 'rejects an empty URL' {
            (Test-CippWordPressTarget -Url '  ').IsValid | Should -BeFalse
        }

        It 'rejects <Scheme> URLs' -ForEach @(
            @{ Scheme = 'file:///etc/passwd' }
            @{ Scheme = 'ftp://example.com/' }
            @{ Scheme = 'gopher://example.com/' }
        ) {
            (Test-CippWordPressTarget -Url $Scheme -SkipDnsResolution).IsValid | Should -BeFalse
        }

        It 'rejects credentials embedded in the URL' {
            # They would be replayed as an Authorization header on every probe.
            (Test-CippWordPressTarget -Url 'https://user:pass@example.com/' -SkipDnsResolution).IsValid | Should -BeFalse
        }

        It 'rejects a non-default port' {
            $Result = Test-CippWordPressTarget -Url 'https://example.com:8443/' -SkipDnsResolution
            $Result.IsValid | Should -BeFalse
            $Result.Reason | Should -Match '8443'
        }

        It 'rejects a malformed hostname' {
            (Test-CippWordPressTarget -Url 'https://not a host/').IsValid | Should -BeFalse
        }
    }

    Context 'Internal targets' {
        It 'rejects <Target>' -ForEach @(
            @{ Target = 'http://localhost/' }
            @{ Target = 'https://intranet.local/' }
            @{ Target = 'https://wordpress.internal/' }
            @{ Target = 'https://site.lan/' }
            @{ Target = 'https://box.home.arpa/' }
        ) {
            (Test-CippWordPressTarget -Url $Target).IsValid | Should -BeFalse
        }

        It 'rejects a literal private address without needing DNS' {
            $Result = Test-CippWordPressTarget -Url 'http://192.168.1.10/'
            $Result.IsValid | Should -BeFalse
            $Result.Reason | Should -Match 'private'
        }

        It 'rejects the cloud metadata endpoint' {
            $Result = Test-CippWordPressTarget -Url 'http://169.254.169.254/latest/meta-data/'
            $Result.IsValid | Should -BeFalse
            $Result.Reason | Should -Match 'metadata'
        }

        It 'rejects IPv6 loopback in bracket notation' {
            (Test-CippWordPressTarget -Url 'http://[::1]/').IsValid | Should -BeFalse
        }

        It 'rejects a public hostname that resolves into private space' {
            # The DNS rebinding shape, and the reason the guard checks addresses rather than names:
            # the hostname is a perfectly ordinary public one, the answer is not.
            Mock Resolve-CippHostAddress { @([System.Net.IPAddress]'10.0.0.5') }
            $Result = Test-CippWordPressTarget -Url 'https://customer-site.com/'
            $Result.IsValid | Should -BeFalse
            $Result.Reason | Should -Match '10\.0\.0\.5'
        }

        It 'rejects a host whose answers are only partly public' {
            # One private answer is enough: which address the request lands on is not ours to pick.
            Mock Resolve-CippHostAddress { @([System.Net.IPAddress]'93.184.216.34', [System.Net.IPAddress]'127.0.0.1') }
            (Test-CippWordPressTarget -Url 'https://customer-site.com/').IsValid | Should -BeFalse
        }

        It 'accepts a host that resolves entirely into public space' {
            Mock Resolve-CippHostAddress { @([System.Net.IPAddress]'93.184.216.34') }
            $Result = Test-CippWordPressTarget -Url 'https://customer-site.com/'
            $Result.IsValid | Should -BeTrue
            $Result.Addresses | Should -Contain '93.184.216.34'
        }

        It 'reports a name that does not resolve rather than probing it' {
            Mock Resolve-CippHostAddress { throw [System.Net.Sockets.SocketException]::new(11001) }
            $Result = Test-CippWordPressTarget -Url 'https://does-not-exist-hopefully.com/'
            $Result.IsValid | Should -BeFalse
        }

        It 'reports the address it rejected so the result is diagnosable' {
            $Result = Test-CippWordPressTarget -Url 'http://10.20.30.40/'
            $Result.Reason | Should -Match '10\.20\.30\.40'
            $Result.Addresses | Should -Contain '10.20.30.40'
        }
    }
}
