function Get-CippWordPressRiskScore {
    <#
    .SYNOPSIS
    Turns a set of findings into a score out of 100 and a letter grade.

    .DESCRIPTION
    The score exists so a scan can be put in front of a customer and compared to last month's. It
    is a weighted deduction, not a measurement: a site with no findings scores 100, and each failed
    check subtracts by severity. A warned check subtracts half, because a warning is something that
    is configured but weakly.

    Deductions are capped per severity band so that ten missing headers cannot outweigh one exposed
    wp-config backup. Without the cap a site with many small issues and no serious ones grades
    worse than a site that is actually compromised.

    An 'Unknown' status subtracts nothing. The scan could not see it, and a guess in either
    direction would be worse than saying so in the report.

    .PARAMETER Findings
    The findings to score.

    .EXAMPLE
    Get-CippWordPressRiskScore -Findings $Findings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Findings
    )

    $Weights = @{
        Critical = 40
        High     = 18
        Medium   = 8
        Low      = 3
        Info     = 0
    }
    # Most a single severity band can take off, so the grade keeps tracking the worst problem
    # rather than the number of problems.
    $Caps = @{
        Critical = 100
        High     = 54
        Medium   = 32
        Low      = 15
        Info     = 0
    }

    # Critical..Low count issues that were actually observed (Fail or Warn). Informational covers
    # both a finding reported for context and one whose severity is Info, since neither is work.
    $Summary = [ordered]@{
        Critical      = 0
        High          = 0
        Medium        = 0
        Low           = 0
        Informational = 0
        Passed        = 0
        Unknown       = 0
    }

    $Deductions = @{}
    foreach ($Severity in $Weights.Keys) { $Deductions[$Severity] = 0 }

    foreach ($Finding in $Findings) {
        $Status = [string]$Finding.Status
        if ($Status -eq 'Pass') { $Summary.Passed++; continue }
        if ($Status -eq 'Unknown') { $Summary.Unknown++; continue }
        if ($Status -eq 'Info') { $Summary.Informational++; continue }
        if ($Status -notin @('Fail', 'Warn')) { continue }

        $Severity = [string]$Finding.Severity
        if (-not $Weights.ContainsKey($Severity)) { continue }
        if ($Severity -eq 'Info') { $Summary.Informational++ } else { $Summary[$Severity]++ }

        $Deduction = $Weights[$Severity]
        if ($Finding.Status -eq 'Warn') { $Deduction = $Deduction / 2 }
        $Deductions[$Severity] += $Deduction
    }

    $Total = 0
    foreach ($Severity in $Weights.Keys) {
        $Total += [Math]::Min($Deductions[$Severity], $Caps[$Severity])
    }

    $Score = [int][Math]::Round([Math]::Max(0, 100 - $Total))
    $Grade = switch ($Score) {
        { $_ -ge 90 } { 'A'; break }
        { $_ -ge 80 } { 'B'; break }
        { $_ -ge 70 } { 'C'; break }
        { $_ -ge 50 } { 'D'; break }
        default { 'F' }
    }

    return [PSCustomObject]@{
        Score   = $Score
        Grade   = $Grade
        Summary = [PSCustomObject]$Summary
    }
}
