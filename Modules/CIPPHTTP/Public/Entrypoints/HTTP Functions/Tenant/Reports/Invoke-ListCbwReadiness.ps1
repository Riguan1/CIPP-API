function Invoke-ListCbwReadiness {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.Reports.Read
    .DESCRIPTION
        Returns what a tenant can actually prove against the duty of care of the Dutch Cyberbeveiligingswet
        (the NIS2 implementation, in force since 15 August 2026).

        Each result maps a live signal from Microsoft 365 onto a control of NIS2 art. 21(2), using the control
        identifiers of the Cbw-wegwijzer in Tools/CbwWegwijzer. The wegwijzer imports this response to pre-fill
        its self-assessment, so a customer sees what is already in place instead of answering from memory.

        Controls that Microsoft 365 cannot prove - backups outside the tenant, supplier contracts, board
        training - are returned under NotDetectable with the reason. They stay a manual answer by design: a
        missing signal must never read as a passing one.

        Query parameters:
          - tenantFilter: The tenant to inspect. Required. AllTenants is rejected; this report is too
                          Graph-heavy to fan out in a single request.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $TriggerMetadata.FunctionName
    $TenantFilter = $Request.Query.tenantFilter

    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Error = 'tenantFilter is verplicht.' }
            })
    }

    if ($TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Error = 'Dit rapport werkt op één tenant tegelijk. Geef een specifieke tenantFilter op.' }
            })
    }

    try {
        $Readiness = Get-CIPPCbwReadiness -TenantFilter $TenantFilter -Headers $Request.Headers
        $StatusCode = [HttpStatusCode]::OK
        $Body = $Readiness
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API $APIName -tenant $TenantFilter -message "Failed to build Cbw readiness report: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::BadRequest
        $Body = @{ Error = $ErrorMessage.NormalizedError }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
