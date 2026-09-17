# Pester tests for WordPress fingerprinting and version comparison.
#
# The fingerprint decides what the rest of the scan asks about, so its failure modes are quiet: a
# missed plugin is a component that is never version-checked and a report that looks clean. The
# markup fixtures below are the shapes real sites serve - minified output with no spaces around
# attributes, protocol-relative asset URLs, a child theme loading its parent, and a plugin that
# enqueues several assets at different versions.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $WordPressRoot = Join-Path $RepoRoot 'Modules/CIPPCore/Public/WordPress'
    foreach ($Leaf in 'Compare-CippWordPressVersion.ps1', 'Get-CippWordPressAsset.ps1', 'Get-CippWordPressFingerprint.ps1') {
        . (Join-Path $WordPressRoot $Leaf)
    }

    $script:WordPressPage = @'
<!DOCTYPE html><html><head>
<meta name="generator" content="WordPress 6.4.2" />
<link rel="https://api.w.org/" href="https://example.com/wp-json/" />
<link rel="stylesheet" href="https://example.com/wp-includes/css/dist/block-library/style.min.css?ver=6.4.2" />
<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.8.4" />
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.8.4"></script>
<link rel="stylesheet" href="/wp-content/plugins/woocommerce/assets/css/woocommerce.css?ver=8.2.1" />
<link rel="stylesheet" href="/wp-content/themes/storefront/style.css?ver=4.5.1" />
<link rel="stylesheet" href="/wp-content/themes/storefront-child/style.css?ver=1.0.0" />
</head><body>content</body></html>
'@
}

Describe 'Compare-CippWordPressVersion' {

    It 'orders <Left> against <Right> as <Expected>' -ForEach @(
        @{ Left = '6.4.2'; Right = '6.4.3'; Expected = -1 }
        @{ Left = '6.4.3'; Right = '6.4.2'; Expected = 1 }
        @{ Left = '6.4.2'; Right = '6.4.2'; Expected = 0 }
        @{ Left = '6.5'; Right = '6.4.9'; Expected = 1 }
        @{ Left = '5.9'; Right = '6.0'; Expected = -1 }
        @{ Left = '1.2.3.4'; Right = '1.2.3.5'; Expected = -1 }
        @{ Left = '10.0'; Right = '9.9'; Expected = 1 }
    ) {
        Compare-CippWordPressVersion -Left $Left -Right $Right | Should -Be $Expected
    }

    It 'treats a missing component as zero' {
        # The reason [version] cannot be used: it reads 6.4 as 6.4.-1 and calls it older than 6.4.0.
        Compare-CippWordPressVersion -Left '6.4' -Right '6.4.0' | Should -Be 0
        Compare-CippWordPressVersion -Left '6.4.0.0' -Right '6.4' | Should -Be 0
    }

    It 'compares numerically rather than as text' {
        # '10' sorts before '9' as a string, which would report a current version as outdated.
        Compare-CippWordPressVersion -Left '1.10.0' -Right '1.9.0' | Should -Be 1
    }

    It 'ignores a pre-release suffix instead of guessing its order' {
        Compare-CippWordPressVersion -Left '6.4-beta1' -Right '6.4' | Should -Be 0
        Compare-CippWordPressVersion -Left '6.4.0-RC1' -Right '6.4.1' | Should -Be -1
    }

    It 'reports no difference for a version it cannot parse' {
        # Returning 0 keeps a garbage version string from being reported as a vulnerability.
        Compare-CippWordPressVersion -Left 'trunk' -Right '6.4' | Should -Be 0
        Compare-CippWordPressVersion -Left '' -Right '6.4' | Should -Be 0
        Compare-CippWordPressVersion -Left $null -Right $null | Should -Be 0
    }
}

Describe 'Get-CippWordPressAsset' {

    It 'extracts plugin slugs with their versions' {
        $Plugins = Get-CippWordPressAsset -Content $script:WordPressPage -Kind 'plugins'
        $Plugins.Slug | Should -Contain 'contact-form-7'
        $Plugins.Slug | Should -Contain 'woocommerce'
        ($Plugins | Where-Object { $_.Slug -eq 'woocommerce' }).Version | Should -Be '8.2.1'
    }

    It 'extracts theme slugs, parent and child alike' {
        $Themes = Get-CippWordPressAsset -Content $script:WordPressPage -Kind 'themes'
        $Themes.Slug | Should -Contain 'storefront'
        $Themes.Slug | Should -Contain 'storefront-child'
    }

    It 'collapses repeated references to one entry and counts them' {
        $Plugin = Get-CippWordPressAsset -Content $script:WordPressPage -Kind 'plugins' |
            Where-Object { $_.Slug -eq 'contact-form-7' }
        @($Plugin).Count | Should -Be 1
        $Plugin.References | Should -Be 2
    }

    It 'keeps the highest version when one plugin serves several' {
        # A plugin cannot be older than the newest version it serves, and taking the lowest would
        # report a vulnerability that was already patched.
        $Content = '<link href="/wp-content/plugins/demo/a.css?ver=1.2.0"><script src="/wp-content/plugins/demo/b.js?ver=1.10.0"></script>'
        $Plugin = Get-CippWordPressAsset -Content $Content -Kind 'plugins'
        $Plugin.Version | Should -Be '1.10.0'
        $Plugin.AllVersions | Should -Contain '1.2.0'
    }

    It 'records a plugin that serves no version at all' {
        # Asset optimisers strip ?ver=. The plugin is still installed and still worth listing.
        $Content = '<script src="/wp-content/plugins/some-plugin/app.js"></script>'
        $Plugin = Get-CippWordPressAsset -Content $Content -Kind 'plugins'
        $Plugin.Slug | Should -Be 'some-plugin'
        $Plugin.Version | Should -BeNullOrEmpty
    }

    It 'resolves evidence to an absolute URL when a base is given' {
        $Plugin = Get-CippWordPressAsset -Content $script:WordPressPage -Kind 'plugins' -BaseUri ([uri]'https://example.com/') |
            Where-Object { $_.Slug -eq 'woocommerce' }
        $Plugin.Evidence | Should -BeLike 'https://example.com/wp-content/plugins/woocommerce/*'
    }

    It 'returns nothing for a page with no components' {
        Get-CippWordPressAsset -Content '<html><body>plain</body></html>' -Kind 'plugins' | Should -BeNullOrEmpty
    }

    It 'handles minified markup with no whitespace' {
        $Content = '<link rel=stylesheet href=/wp-content/plugins/elementor/assets/css/frontend.min.css?ver=3.18.0>'
        $Plugin = Get-CippWordPressAsset -Content $Content -Kind 'plugins'
        $Plugin.Slug | Should -Be 'elementor'
        $Plugin.Version | Should -Be '3.18.0'
    }
}

Describe 'Get-CippWordPressFingerprint' {

    Context 'Detection' {
        It 'identifies a WordPress page' {
            $Fingerprint = Get-CippWordPressFingerprint -Content $script:WordPressPage -BaseUri ([uri]'https://example.com/')
            $Fingerprint.IsWordPress | Should -BeTrue
            $Fingerprint.Signals.Count | Should -BeGreaterThan 1
        }

        It 'does not claim a plain HTML page is WordPress' {
            $Fingerprint = Get-CippWordPressFingerprint -Content '<html><body><h1>Hello</h1></body></html>'
            $Fingerprint.IsWordPress | Should -BeFalse
        }

        It 'identifies WordPress from headers when the markup is rewritten' {
            # A cache or page builder can strip every marker out of the HTML; the headers remain.
            $Headers = [ordered]@{ 'X-Pingback' = 'https://example.com/xmlrpc.php' }
            $Fingerprint = Get-CippWordPressFingerprint -Content '<html><body>cached</body></html>' -Headers $Headers
            $Fingerprint.IsWordPress | Should -BeTrue
        }

        It 'returns an empty result for empty input rather than failing' {
            $Fingerprint = Get-CippWordPressFingerprint -Content '' -Headers $null
            $Fingerprint.IsWordPress | Should -BeFalse
            $Fingerprint.Version | Should -BeNullOrEmpty
        }
    }

    Context 'Version detection' {
        It 'prefers the generator meta tag' {
            $Fingerprint = Get-CippWordPressFingerprint -Content $script:WordPressPage
            $Fingerprint.Version | Should -Be '6.4.2'
            $Fingerprint.VersionSource | Should -Be 'generator meta tag'
        }

        It 'falls back to a core asset version when the meta tag is removed' {
            $Content = '<link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.3.1" />'
            $Fingerprint = Get-CippWordPressFingerprint -Content $Content
            $Fingerprint.Version | Should -Be '6.3.1'
            $Fingerprint.VersionSource | Should -Be 'core asset version query string'
        }

        It 'falls back to the feed generator link' {
            $Content = '<generator>https://wordpress.org/?v=6.2</generator><link href="/wp-content/x.css">'
            $Fingerprint = Get-CippWordPressFingerprint -Content $Content
            $Fingerprint.Version | Should -Be '6.2'
        }

        It 'reports no version when the site publishes none' {
            $Content = '<html><head><link href="/wp-content/themes/x/style.css"></head></html>'
            $Fingerprint = Get-CippWordPressFingerprint -Content $Content
            $Fingerprint.IsWordPress | Should -BeTrue
            $Fingerprint.Version | Should -BeNullOrEmpty
        }
    }
}
