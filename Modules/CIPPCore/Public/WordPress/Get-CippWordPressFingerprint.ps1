function Get-CippWordPressFingerprint {
    <#
    .SYNOPSIS
    Identifies WordPress, its version, and the plugins and themes a page loads.

    .DESCRIPTION
    Reads only what the site already published: the HTML of a single page plus its response
    headers. No request is made from here, which is what makes the detection testable against
    captured markup and keeps the request budget in the caller's hands.

    Plugin and theme versions come from the ?ver= query string WordPress appends to enqueued
    assets. That is the version the site is running in the overwhelming majority of cases, but a
    plugin can enqueue an asset with any version string it likes, and a site behind an asset
    optimiser may strip or rewrite ?ver= entirely. Versions are therefore reported with the URL
    they were read from, so a finding can always be traced back to its evidence.

    A site that moves wp-content elsewhere (WP_CONTENT_DIR) hides its plugins from this and from
    every other passive scanner; that shows up as an empty plugin list, not as a clean result.

    .PARAMETER Content
    The HTML body to read.

    .PARAMETER Headers
    Response headers for the same page. Link headers and X-Powered-By are read from here.

    .PARAMETER BaseUri
    The URL the content came from, used to resolve relative asset paths.

    .EXAMPLE
    Get-CippWordPressFingerprint -Content $Response.Content -Headers $Response.Headers -BaseUri 'https://example.com'
    #>
    [CmdletBinding()]
    param(
        [string]$Content = '',
        $Headers,
        [uri]$BaseUri
    )

    $Fingerprint = [PSCustomObject]@{
        IsWordPress   = $false
        Signals       = [System.Collections.Generic.List[string]]::new()
        Version       = $null
        VersionSource = $null
        Plugins       = [System.Collections.Generic.List[object]]::new()
        Themes        = [System.Collections.Generic.List[object]]::new()
    }

    $HeaderText = ''
    if ($Headers) {
        $HeaderText = ($Headers.GetEnumerator() | ForEach-Object { '{0}: {1}' -f $_.Key, $_.Value }) -join "`n"
    }

    if ([string]::IsNullOrEmpty($Content) -and [string]::IsNullOrEmpty($HeaderText)) {
        return $Fingerprint
    }

    if ($Content -match '/wp-content/') { $Fingerprint.Signals.Add('wp-content asset paths') }
    if ($Content -match '/wp-includes/') { $Fingerprint.Signals.Add('wp-includes asset paths') }
    if ($Content -match 'api\.w\.org') { $Fingerprint.Signals.Add('WordPress REST API link tag') }
    if ($Content -match '<meta[^>]+name=["'']generator["''][^>]+content=["'']WordPress') { $Fingerprint.Signals.Add('generator meta tag') }
    if ($Content -match 'wp-json') { $Fingerprint.Signals.Add('wp-json endpoint reference') }
    if ($Content -match 'wp-emoji-release\.min\.js|wp-block-library') { $Fingerprint.Signals.Add('core script/style handles') }
    if ($HeaderText -match 'X-Pingback:.*xmlrpc\.php') { $Fingerprint.Signals.Add('X-Pingback header') }
    if ($HeaderText -match 'Link:.*api\.w\.org') { $Fingerprint.Signals.Add('REST API Link header') }

    $Fingerprint.IsWordPress = $Fingerprint.Signals.Count -gt 0

    # Most precise source first: the generator tag states the version outright, a core asset's
    # ?ver= carries it as a side effect, and the RSS generator link is the fallback for sites that
    # removed the meta tag but left the feed alone.
    $VersionPatterns = [ordered]@{
        'generator meta tag'             = '<meta[^>]+name=["'']generator["''][^>]+content=["'']WordPress\s+([0-9]+(?:\.[0-9]+){0,2})'
        'core asset version query string' = '/wp-includes/[^"''\s>]*[?&]ver=([0-9]+(?:\.[0-9]+){1,2})'
        'feed generator link'            = 'wordpress\.org/\?v=([0-9]+(?:\.[0-9]+){0,2})'
    }
    foreach ($Pattern in $VersionPatterns.GetEnumerator()) {
        $Match = [regex]::Match($Content, $Pattern.Value, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($Match.Success) {
            $Fingerprint.Version = $Match.Groups[1].Value
            $Fingerprint.VersionSource = $Pattern.Key
            break
        }
    }

    $Fingerprint.Plugins = @(Get-CippWordPressAsset -Content $Content -Kind 'plugins' -BaseUri $BaseUri)
    $Fingerprint.Themes = @(Get-CippWordPressAsset -Content $Content -Kind 'themes' -BaseUri $BaseUri)

    return $Fingerprint
}
