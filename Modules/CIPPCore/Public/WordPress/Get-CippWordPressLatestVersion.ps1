function Get-CippWordPressLatestVersion {
    <#
    .SYNOPSIS
    Looks up the current release of WordPress core, a plugin or a theme on WordPress.org.

    .DESCRIPTION
    Queries the public WordPress.org APIs - the same ones a WordPress site calls to check for its
    own updates - and caches each answer in the worker for twelve hours. The data is identical for
    every caller and every tenant, so the cache is a plain script-scoped table with no tenant key;
    nothing customer-specific passes through this function.

    A plugin or theme that is not in the directory comes back as Status 'NotFound'. That is not the
    same as an error: a premium or bespoke plugin was never listed, while a plugin that WordPress
    closed for an unpatched vulnerability also disappears from it. The caller reports the
    ambiguity rather than resolving it, because the API does not distinguish the two.

    A failed lookup returns Status 'Unknown' and never throws. Losing the version comparison must
    degrade the scan, not fail it.

    .PARAMETER Type
    Core, Plugin or Theme.

    .PARAMETER Slug
    The WordPress.org slug. Required for Plugin and Theme.

    .PARAMETER TimeoutSeconds
    Per-request timeout. Defaults to 10.

    .PARAMETER CacheMinutes
    How long an answer stays cached in this worker. Defaults to 720.

    .EXAMPLE
    Get-CippWordPressLatestVersion -Type Core

    .EXAMPLE
    Get-CippWordPressLatestVersion -Type Plugin -Slug 'contact-form-7'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Core', 'Plugin', 'Theme')]
        [string]$Type,
        [string]$Slug,
        [int]$TimeoutSeconds = 10,
        [int]$CacheMinutes = 720
    )

    if ($Type -ne 'Core' -and [string]::IsNullOrWhiteSpace($Slug)) {
        return [PSCustomObject]@{ Type = $Type; Slug = $Slug; Version = $null; Status = 'Unknown'; Error = 'A slug is required.' }
    }

    if (-not $script:CippWordPressVersionCache) {
        $script:CippWordPressVersionCache = @{}
    }

    $CacheKey = '{0}|{1}' -f $Type, $Slug.ToLowerInvariant()
    $Cached = $script:CippWordPressVersionCache[$CacheKey]
    if ($Cached -and ([DateTimeOffset]::UtcNow - $Cached.Retrieved).TotalMinutes -lt $CacheMinutes) {
        return $Cached.Result
    }

    $Result = [PSCustomObject]@{
        Type    = $Type
        Slug    = $Slug
        Version = $null
        Status  = 'Unknown'
        Error   = ''
    }

    $EncodedSlug = [uri]::EscapeDataString(([string]$Slug))
    $Uri = switch ($Type) {
        'Core' { 'https://api.wordpress.org/core/version-check/1.7/' }
        'Plugin' { 'https://api.wordpress.org/plugins/info/1.0/{0}.json' -f $EncodedSlug }
        'Theme' { 'https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]={0}' -f $EncodedSlug }
    }

    try {
        $Response = Invoke-RestMethod -Uri $Uri -Method Get -TimeoutSec $TimeoutSeconds -ErrorAction Stop -UserAgent 'CIPP-WordPressSecurityScan/1.0'

        switch ($Type) {
            'Core' {
                # Offers are ordered newest first and include upgrade offers for older branches;
                # the 'upgrade' response type is the current release.
                $Offer = $Response.offers | Where-Object { $_.response -eq 'upgrade' -or $_.response -eq 'latest' } | Select-Object -First 1
                if (-not $Offer) { $Offer = $Response.offers | Select-Object -First 1 }
                if ($Offer.current) {
                    $Result.Version = [string]$Offer.current
                    $Result.Status = 'Found'
                } else {
                    $Result.Error = 'The core version-check API returned no offers.'
                }
            }
            default {
                # Both APIs answer a missing slug with 200 and an error body rather than a 404.
                if ($Response.error) {
                    $Result.Status = 'NotFound'
                    $Result.Error = [string]$Response.error
                } elseif ($Response.version) {
                    $Result.Version = [string]$Response.version
                    $Result.Status = 'Found'
                } else {
                    $Result.Error = 'The API response carried no version.'
                }
            }
        }
    } catch {
        $Result.Error = $_.Exception.Message
    }

    $script:CippWordPressVersionCache[$CacheKey] = @{
        Retrieved = [DateTimeOffset]::UtcNow
        Result    = $Result
    }

    return $Result
}
