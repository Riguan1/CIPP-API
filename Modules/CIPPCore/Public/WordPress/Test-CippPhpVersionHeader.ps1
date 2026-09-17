function Test-CippPhpVersionHeader {
    <#
    .SYNOPSIS
    Reports a PHP version disclosed in response headers against the PHP support calendar.

    .DESCRIPTION
    A PHP branch that has passed its end of security support stops receiving fixes for
    vulnerabilities that are still being found in it, so the version banner a server volunteers is
    worth reading rather than only telling the owner to hide it.

    The branch end-of-life dates are compared against the current date rather than hard-coded into
    a verdict, so this keeps giving the right answer as branches age. A branch newer than anything
    in the table is treated as supported.

    .PARAMETER Headers
    Case-insensitive header lookup for the response.

    .EXAMPLE
    Test-CippPhpVersionHeader -Headers $Lookup
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Headers
    )

    $Candidates = @()
    foreach ($Name in @('X-Powered-By', 'Server')) {
        $Value = $null
        if ($Headers -is [System.Collections.Generic.Dictionary[string, string]]) {
            if ($Headers.ContainsKey($Name)) { $Value = $Headers[$Name] }
        } elseif ($Headers) {
            $Value = $Headers[$Name]
        }
        if ($Value) { $Candidates += [string]$Value }
    }

    $Version = $null
    foreach ($Candidate in $Candidates) {
        $Match = [regex]::Match($Candidate, 'PHP/(\d+\.\d+(?:\.\d+)?)', 'IgnoreCase')
        if ($Match.Success) { $Version = $Match.Groups[1].Value; break }
    }
    if (-not $Version) { return $null }

    # End of security support per php.net. A branch absent from the table is newer than the table.
    $EndOfLife = @{
        '5.6' = '2018-12-31'
        '7.0' = '2019-01-10'
        '7.1' = '2019-12-01'
        '7.2' = '2020-11-30'
        '7.3' = '2021-12-06'
        '7.4' = '2022-11-28'
        '8.0' = '2023-11-26'
        '8.1' = '2025-12-31'
        '8.2' = '2026-12-31'
        '8.3' = '2027-12-31'
        '8.4' = '2028-12-31'
    }

    $Branch = ($Version -split '\.')[0..1] -join '.'
    if (-not $EndOfLife.ContainsKey($Branch)) {
        # Older than every branch in the table (PHP 5.5 and down) rather than newer.
        if ((Compare-CippWordPressVersion -Left $Branch -Right '5.6') -lt 0) {
            return New-CippWordPressFinding -Id 'WEB-PHP-EOL' -Category 'Headers' -Title "PHP $Version is long out of support" -Severity High -Status Fail `
                -Evidence "The server reports PHP $Version." `
                -Recommendation 'Move the site to a supported PHP branch. This version stopped receiving security fixes years ago.' `
                -Reference 'https://www.php.net/supported-versions.php'
        }
        return $null
    }

    $EolDate = [datetime]::Parse($EndOfLife[$Branch], [cultureinfo]::InvariantCulture)
    $Now = [datetime]::UtcNow

    if ($Now -gt $EolDate) {
        return New-CippWordPressFinding -Id 'WEB-PHP-EOL' -Category 'Headers' -Title "PHP $Version no longer receives security fixes" -Severity High -Status Fail `
            -Evidence "The server reports PHP $Version; security support for the $Branch branch ended on $($EolDate.ToString('yyyy-MM-dd'))." `
            -Recommendation 'Ask the hosting provider to move the site to a supported PHP branch, after testing the theme and plugins against it.' `
            -Reference 'https://www.php.net/supported-versions.php'
    }

    if (($EolDate - $Now).TotalDays -le 120) {
        return New-CippWordPressFinding -Id 'WEB-PHP-EOL' -Category 'Headers' -Title "PHP $Version reaches end of support soon" -Severity Medium -Status Warn `
            -Evidence "The server reports PHP $Version; security support for the $Branch branch ends on $($EolDate.ToString('yyyy-MM-dd'))." `
            -Recommendation 'Plan the PHP upgrade now, while it is still routine maintenance rather than an emergency.' `
            -Reference 'https://www.php.net/supported-versions.php'
    }

    return New-CippWordPressFinding -Id 'WEB-PHP-EOL' -Category 'Headers' -Title "PHP $Version is supported" -Severity High -Status Pass `
        -Evidence "The server reports PHP $Version; the $Branch branch is supported until $($EolDate.ToString('yyyy-MM-dd'))."
}
