function Get-CippWordPressAsset {
    <#
    .SYNOPSIS
    Extracts the plugin or theme slugs, and their versions, referenced by a page.

    .DESCRIPTION
    WordPress serves plugin and theme assets from /wp-content/plugins/<slug>/ and
    /wp-content/themes/<slug>/, and appends ?ver=<version> to everything it enqueues. That pair is
    the whole fingerprint: the slug identifies the component in the WordPress.org directory and the
    version is what an outdated-version check compares.

    One slug can appear many times on a page with different versions - a plugin that enqueues
    several assets, or a child theme loading a parent's stylesheet. The highest version wins and
    the rest are counted, because a plugin cannot be older than the newest version string it serves
    and taking the lowest would report vulnerabilities that were already patched.

    .PARAMETER Content
    The HTML body to read.

    .PARAMETER Kind
    'plugins' or 'themes'.

    .PARAMETER BaseUri
    Used to record an absolute evidence URL for each slug.

    .EXAMPLE
    Get-CippWordPressAsset -Content $Html -Kind 'plugins'
    #>
    [CmdletBinding()]
    param(
        [string]$Content = '',
        [Parameter(Mandatory = $true)]
        [ValidateSet('plugins', 'themes')]
        [string]$Kind,
        [uri]$BaseUri
    )

    if ([string]::IsNullOrEmpty($Content)) { return @() }

    # Slugs are lowercase alphanumeric with dashes and underscores by WordPress.org convention;
    # anything else is a path segment this is not meant to match.
    $Pattern = '/wp-content/{0}/([A-Za-z0-9][A-Za-z0-9_\-]{{0,62}})/([^"''\s>)]*)' -f $Kind
    # Not $Matches: that is the automatic variable the -match operator writes to.
    $AssetMatches = [regex]::Matches($Content, $Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($AssetMatches.Count -eq 0) { return @() }

    $BySlug = [ordered]@{}
    foreach ($Match in $AssetMatches) {
        $Slug = $Match.Groups[1].Value.ToLowerInvariant()
        $Path = $Match.Groups[2].Value

        $Version = $null
        $VersionMatch = [regex]::Match($Path, '[?&]ver=([0-9]+(?:\.[0-9]+){0,3})(?:[&"'']|$)')
        if ($VersionMatch.Success) { $Version = $VersionMatch.Groups[1].Value }

        if (-not $BySlug.Contains($Slug)) {
            $BySlug[$Slug] = [PSCustomObject]@{
                Slug         = $Slug
                Version      = $Version
                AssetPath    = '/wp-content/{0}/{1}/{2}' -f $Kind, $Slug, $Path
                References   = 1
                AllVersions  = [System.Collections.Generic.List[string]]::new()
            }
            if ($Version) { $BySlug[$Slug].AllVersions.Add($Version) }
            continue
        }

        $Existing = $BySlug[$Slug]
        $Existing.References++
        if (-not $Version) { continue }
        if (-not $Existing.AllVersions.Contains($Version)) { $Existing.AllVersions.Add($Version) }

        if (-not $Existing.Version -or (Compare-CippWordPressVersion -Left $Version -Right $Existing.Version) -gt 0) {
            $Existing.Version = $Version
            $Existing.AssetPath = '/wp-content/{0}/{1}/{2}' -f $Kind, $Slug, $Path
        }
    }

    foreach ($Entry in $BySlug.Values) {
        $Evidence = $Entry.AssetPath
        if ($BaseUri) {
            $Absolute = $null
            if ([System.Uri]::TryCreate($BaseUri, $Entry.AssetPath, [ref]$Absolute)) { $Evidence = $Absolute.AbsoluteUri }
        }
        $Entry | Add-Member -NotePropertyName 'Evidence' -NotePropertyValue $Evidence -Force
        $Entry.AllVersions = @($Entry.AllVersions)
    }

    return @($BySlug.Values)
}
