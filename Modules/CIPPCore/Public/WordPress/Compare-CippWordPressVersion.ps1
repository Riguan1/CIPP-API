function Compare-CippWordPressVersion {
    <#
    .SYNOPSIS
    Compares two version strings as WordPress writes them. Returns -1, 0 or 1.

    .DESCRIPTION
    [version] cannot be used directly here. WordPress and its plugins ship versions like '6.4',
    '1.2.3.4', '2.0-beta1' and '5.9.0-RC1', and a cast either throws or silently treats '6.4' as
    6.4.-1.-1, which then compares as older than '6.4.0'. This compares the numeric components
    left to right, treating a missing component as 0 so that 6.4 and 6.4.0 are equal, and ignores
    any pre-release suffix rather than guessing at its ordering.

    Returning 0 for versions that differ only by suffix is the safe direction: an outdated-version
    finding is raised on a strict numeric difference, so a beta of the current release is not
    reported as vulnerable on the strength of its label alone.

    .PARAMETER Left
    First version.

    .PARAMETER Right
    Second version.

    .EXAMPLE
    Compare-CippWordPressVersion -Left '6.4' -Right '6.4.0'
    # 0

    .EXAMPLE
    Compare-CippWordPressVersion -Left '6.3.2' -Right '6.4'
    # -1
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [string]$Left,
        [string]$Right
    )

    $Parse = {
        param([string]$Value)
        if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
        $Numeric = ([regex]::Match($Value.Trim(), '^[vV]?([0-9]+(?:\.[0-9]+)*)')).Groups[1].Value
        if ([string]::IsNullOrEmpty($Numeric)) { return @() }
        return @($Numeric -split '\.' | ForEach-Object { [int]$_ })
    }

    $LeftParts = & $Parse $Left
    $RightParts = & $Parse $Right

    # An unparseable version cannot be ordered. Callers treat 0 as "no difference to report",
    # which keeps a garbage version string from becoming a finding.
    if ($LeftParts.Count -eq 0 -or $RightParts.Count -eq 0) { return 0 }

    $Length = [Math]::Max($LeftParts.Count, $RightParts.Count)
    for ($Index = 0; $Index -lt $Length; $Index++) {
        $LeftPart = if ($Index -lt $LeftParts.Count) { $LeftParts[$Index] } else { 0 }
        $RightPart = if ($Index -lt $RightParts.Count) { $RightParts[$Index] } else { 0 }
        if ($LeftPart -gt $RightPart) { return 1 }
        if ($LeftPart -lt $RightPart) { return -1 }
    }

    return 0
}
