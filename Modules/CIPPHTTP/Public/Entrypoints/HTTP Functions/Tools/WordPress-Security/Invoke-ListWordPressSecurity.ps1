function Invoke-ListWordPressSecurity {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        CIPP.Core.Read
    .DESCRIPTION
        Runs a passive, read-only security assessment of a WordPress website and returns scored findings covering transport security, response headers, version currency of core, plugins and themes, and files the site exposes.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Url = $Request.Query.Url ?? $Request.Body.Url

    if ([string]::IsNullOrWhiteSpace($Url)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ 'Results' = "The 'Url' parameter is required." }
            })
    }

    # Skip the WordPress.org version lookups, for scans that must not reach a third party.
    $SkipVersionLookup = ($Request.Query.SkipVersionLookup ?? $Request.Body.SkipVersionLookup) -eq $true
    # Home page only: transport, headers and fingerprinting, in two requests.
    $SkipExposureProbes = ($Request.Query.SkipExposureProbes ?? $Request.Body.SkipExposureProbes) -eq $true

    $Parameters = @{
        Url                = $Url
        SkipVersionLookup  = $SkipVersionLookup
        SkipExposureProbes = $SkipExposureProbes
    }

    $MaxRequests = $Request.Query.MaxRequests ?? $Request.Body.MaxRequests
    if ($MaxRequests) {
        $Parsed = 0
        if (-not [int]::TryParse([string]$MaxRequests, [ref]$Parsed) -or $Parsed -lt 2 -or $Parsed -gt 100) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = [pscustomobject]@{ 'Results' = "The 'MaxRequests' parameter must be a number between 2 and 100." }
                })
        }
        $Parameters.MaxRequests = $Parsed
    }

    try {
        # Logged before the scan rather than after it: this endpoint makes the function app send
        # traffic to a third-party site on a caller's say-so, and the record of who asked for it
        # has to exist even if the scan then fails or times out.
        Write-LogMessage -API $APIName -headers $Request.Headers -message "Started a WordPress security scan of $Url" -Sev 'Info'

        $Results = Test-CippWordPressSecurity @Parameters

        if ($Results.Error -and -not $Results.Completed) {
            # A target that cannot be scanned - unresolvable, not public, or unreachable - is the
            # caller's input being wrong, not the API failing.
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = [pscustomobject]@{ 'Results' = $Results.Error; 'Scan' = $Results }
                })
        }

        $StatusCode = [HttpStatusCode]::OK
        $Body = $Results
    } catch {
        Write-LogMessage -API $APIName -headers $Request.Headers -message "WordPress security scan of $Url failed. $($_.Exception.Message)" -Sev 'Error' -LogData (Get-CippException -Exception $_)
        $StatusCode = [HttpStatusCode]::InternalServerError
        $Body = [pscustomobject]@{ 'Results' = "Failed. $($_.Exception.Message)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
