function Test-CippWordPressComponent {
    <#
    .SYNOPSIS
    Compares the detected WordPress core, plugin and theme versions against WordPress.org.

    .DESCRIPTION
    Out-of-date components are what actually gets WordPress sites compromised: the overwhelming
    majority of incidents trace back to a known vulnerability in a plugin that had a patch
    available. This compares what the site is serving against the current release of each
    component and reports the gap.

    It does not consult a vulnerability database, so a component that is current is reported as
    current rather than as safe - a vulnerability with no patch yet is invisible here. Pairing the
    inventory this produces with a CVE feed is the natural next step, and is deliberately not
    implied by the wording of any finding.

    A plugin missing from the WordPress.org directory is reported as its own finding rather than
    ignored. It usually means a premium or bespoke plugin, which simply cannot be checked this way,
    but it is also what a plugin looks like after WordPress closes it for an unfixed vulnerability,
    and that case is worth a person's attention.

    .PARAMETER Fingerprint
    Output of Get-CippWordPressFingerprint.

    .PARAMETER SkipVersionLookup
    Skip the WordPress.org lookups and report every version check as Unknown. Used when the scan
    must not make third-party requests.

    .PARAMETER MaxComponents
    Most plugins and themes to look up, newest detection order. Defaults to 25.

    .EXAMPLE
    Test-CippWordPressComponent -Fingerprint $Fingerprint
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Fingerprint,
        [switch]$SkipVersionLookup,
        [int]$MaxComponents = 25
    )

    $Findings = [System.Collections.Generic.List[object]]::new()
    $Inventory = [System.Collections.Generic.List[object]]::new()

    # --- Core ----------------------------------------------------------------------------
    if ($Fingerprint.Version) {
        $Findings.Add((New-CippWordPressFinding -Id 'WP-VERSION-DISCLOSED' -Category 'WordPress' -Title 'The WordPress version is published' -Severity Low -Status Warn `
                    -Evidence "Version $($Fingerprint.Version), read from the $($Fingerprint.VersionSource)." `
                    -Recommendation 'Remove the generator meta tag and the version query string from asset URLs. Hiding the version does not fix anything by itself, but it stops your site matching a search for that exact version.'))

        if ($SkipVersionLookup) {
            $Findings.Add((New-CippWordPressFinding -Id 'WP-CORE-OUTDATED' -Category 'WordPress' -Title 'WordPress core version was not compared' -Severity High -Status Unknown `
                        -Evidence "Detected version $($Fingerprint.Version). The WordPress.org lookup was skipped." `
                        -Recommendation 'Compare the version against the current WordPress release manually.'))
        } else {
            $Latest = Get-CippWordPressLatestVersion -Type Core
            if ($Latest.Status -eq 'Found') {
                $Comparison = Compare-CippWordPressVersion -Left $Fingerprint.Version -Right $Latest.Version
                if ($Comparison -lt 0) {
                    # A whole major behind means missed security releases for a year or more, which
                    # is a different conversation from being one patch release late.
                    $DetectedMajor = ($Fingerprint.Version -split '\.')[0]
                    $LatestMajor = ($Latest.Version -split '\.')[0]
                    $Severity = if ($DetectedMajor -ne $LatestMajor) { 'Critical' } else { 'High' }
                    $Findings.Add((New-CippWordPressFinding -Id 'WP-CORE-OUTDATED' -Category 'WordPress' -Title 'WordPress core is out of date' -Severity $Severity -Status Fail `
                                -Evidence "The site reports WordPress $($Fingerprint.Version); the current release is $($Latest.Version)." `
                                -Recommendation 'Update WordPress core. Take a backup first, then update on a staging copy if the site is business-critical. Turn on automatic updates for minor releases so security fixes land without waiting for a maintenance window.' `
                                -Reference 'https://wordpress.org/download/releases/'))
                } else {
                    $Findings.Add((New-CippWordPressFinding -Id 'WP-CORE-OUTDATED' -Category 'WordPress' -Title 'WordPress core is current' -Severity High -Status Pass `
                                -Evidence "The site reports WordPress $($Fingerprint.Version); the current release is $($Latest.Version)."))
                }
            } else {
                $Findings.Add((New-CippWordPressFinding -Id 'WP-CORE-OUTDATED' -Category 'WordPress' -Title 'WordPress core version could not be compared' -Severity High -Status Unknown `
                            -Evidence "Detected version $($Fingerprint.Version). The WordPress.org lookup failed: $($Latest.Error)" `
                            -Recommendation 'Check the version against the current WordPress release manually.'))
            }
        }
    } else {
        $Findings.Add((New-CippWordPressFinding -Id 'WP-CORE-OUTDATED' -Category 'WordPress' -Title 'The WordPress version could not be determined' -Severity High -Status Unknown `
                    -Evidence 'No version was disclosed in the page markup, headers or asset URLs.' `
                    -Recommendation 'Good practice in itself - but it also means this scan cannot tell you whether core is up to date. Confirm from the admin dashboard.'))
    }

    # --- Plugins and themes ---------------------------------------------------------------
    $Components = @()
    foreach ($Plugin in @($Fingerprint.Plugins)) { $Components += [PSCustomObject]@{ Kind = 'Plugin'; Item = $Plugin } }
    foreach ($Theme in @($Fingerprint.Themes)) { $Components += [PSCustomObject]@{ Kind = 'Theme'; Item = $Theme } }

    $Checked = 0
    foreach ($Component in $Components) {
        $Item = $Component.Item
        $Record = [PSCustomObject]@{
            Kind          = $Component.Kind
            Slug          = $Item.Slug
            Version       = $Item.Version
            LatestVersion = $null
            Status        = 'Unknown'
            Evidence      = $Item.Evidence
        }

        if ($SkipVersionLookup -or $Checked -ge $MaxComponents) {
            $Inventory.Add($Record)
            continue
        }
        $Checked++

        $Latest = Get-CippWordPressLatestVersion -Type $Component.Kind -Slug $Item.Slug
        $Record.LatestVersion = $Latest.Version
        $Record.Status = $Latest.Status

        if ($Latest.Status -eq 'NotFound') {
            $Record.Status = 'NotInDirectory'
            $Findings.Add((New-CippWordPressFinding -Id "WP-COMPONENT-UNLISTED-$($Item.Slug.ToUpperInvariant())" -Category 'Components' -Title "$($Component.Kind) '$($Item.Slug)' is not in the WordPress.org directory" -Severity Medium -Status Unknown `
                        -Evidence "$($Item.Evidence) - WordPress.org has no entry for '$($Item.Slug)'." `
                        -Recommendation 'Usually a premium or custom component, which this scan cannot version-check. Confirm that it is still supported and receiving updates - a plugin also disappears from the directory when WordPress closes it for an unpatched vulnerability.'))
            $Inventory.Add($Record)
            continue
        }

        if ($Latest.Status -ne 'Found' -or -not $Item.Version) {
            $Inventory.Add($Record)
            continue
        }

        if ((Compare-CippWordPressVersion -Left $Item.Version -Right $Latest.Version) -lt 0) {
            $DetectedMajor = ($Item.Version -split '\.')[0]
            $LatestMajor = ($Latest.Version -split '\.')[0]
            $Severity = if ($DetectedMajor -ne $LatestMajor) { 'High' } else { 'Medium' }
            $Record.Status = 'Outdated'
            $Findings.Add((New-CippWordPressFinding -Id "WP-COMPONENT-OUTDATED-$($Item.Slug.ToUpperInvariant())" -Category 'Components' -Title "$($Component.Kind) '$($Item.Slug)' is out of date" -Severity $Severity -Status Fail `
                        -Evidence "Version $($Item.Version) is in use; $($Latest.Version) is current. Detected from $($Item.Evidence)." `
                        -Recommendation "Update $($Item.Slug) to $($Latest.Version). Outdated plugins are the single most common way WordPress sites are compromised, because the fix being public is what tells attackers what to look for." `
                        -Reference "https://wordpress.org/plugins/$($Item.Slug)/"))
        } else {
            $Record.Status = 'Current'
        }

        $Inventory.Add($Record)
    }

    $Outdated = @($Inventory | Where-Object { $_.Status -eq 'Outdated' })
    if ($Components.Count -gt 0 -and $Outdated.Count -eq 0 -and -not $SkipVersionLookup) {
        $Findings.Add((New-CippWordPressFinding -Id 'WP-COMPONENTS-CURRENT' -Category 'Components' -Title 'Every detected plugin and theme is current' -Severity Medium -Status Pass `
                    -Evidence "$($Components.Count) component(s) detected, none behind their published release."))
    }

    return [PSCustomObject]@{
        Findings  = @($Findings)
        Inventory = @($Inventory)
    }
}
