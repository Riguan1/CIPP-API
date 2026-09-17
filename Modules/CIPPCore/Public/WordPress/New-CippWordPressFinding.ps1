function New-CippWordPressFinding {
    <#
    .SYNOPSIS
    Builds one finding for a WordPress security scan.

    .DESCRIPTION
    Every check returns the same shape so the report can be sorted, scored and handed to a customer
    without each check inventing its own vocabulary. Severity states how bad the issue is; Status
    states what the check actually observed, and the two are independent - a High severity check
    that passed contributes nothing to the score.

    Status 'Unknown' exists because a scan from the outside genuinely cannot see everything. A
    check that could not reach the site, or whose answer was ambiguous, says so instead of
    reporting a pass that was never verified.

    .PARAMETER Id
    Stable identifier, e.g. WP-CORE-OUTDATED. Reports are compared between scans on this.

    .PARAMETER Category
    Grouping for the report: Transport, Headers, WordPress, Exposure, Enumeration, Components.

    .PARAMETER Title
    One line naming the issue, written for the site owner rather than for an engineer.

    .PARAMETER Severity
    Critical, High, Medium, Low or Info.

    .PARAMETER Status
    Fail, Warn, Pass, Info or Unknown.

    .PARAMETER Evidence
    What the scan saw: the URL, header value or version that produced this result.

    .PARAMETER Recommendation
    The fix, phrased as an action.

    .PARAMETER Reference
    Optional documentation URL.

    .EXAMPLE
    New-CippWordPressFinding -Id 'WP-HSTS' -Category 'Headers' -Title 'HSTS is not enabled' -Severity Medium -Status Fail -Evidence 'No Strict-Transport-Security header' -Recommendation 'Send Strict-Transport-Security with a max-age of at least 180 days.'
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingVerbs', '', Justification = 'Builds an in-memory object and changes no state.')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [string]$Category,
        [Parameter(Mandatory = $true)]
        [string]$Title,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Fail', 'Warn', 'Pass', 'Info', 'Unknown')]
        [string]$Status,
        [string]$Evidence = '',
        [string]$Recommendation = '',
        [string]$Reference = ''
    )

    return [PSCustomObject]@{
        Id             = $Id
        Category       = $Category
        Title          = $Title
        Severity       = $Severity
        Status         = $Status
        Evidence       = $Evidence
        Recommendation = $Recommendation
        Reference      = $Reference
    }
}
