# Pester tests for Invoke-ListWordPressSecurity.
#
# This endpoint is unusual for CIPP: it makes the function app send traffic to a third-party
# website chosen by the caller. Two things follow from that and are asserted here. The scan is
# logged before it runs, so the record of who pointed the platform at whose site exists even when
# the scan then fails - that log is what turns an unauthorised scan from deniable into traceable.
# And a target the scanner refuses comes back as 400 with the reason, not 500, because a refused
# target is the caller's input being wrong rather than the API breaking.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-ListWordPressSecurity.ps1' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $FunctionPath) { throw 'Could not locate Invoke-ListWordPressSecurity.ps1 under Modules/' }

    # Azure Functions binding types do not exist outside the Functions host - fake them.
    class HttpResponseContext {
        [object]$StatusCode
        [object]$Body
    }

    $Accelerators = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
    if (-not $Accelerators::Get.ContainsKey('HttpStatusCode')) {
        $Accelerators::Add('HttpStatusCode', [System.Net.HttpStatusCode])
    }

    # Stub every CIPP helper the function calls so Pester's Mock has a command to replace.
    function Write-LogMessage { param($headers, $API, $tenant, $message, $sev, $LogData) }
    function Get-CippException { param($Exception) }
    function Test-CippWordPressSecurity { param($Url, $TimeoutSeconds, $MaxRequests, [switch]$SkipVersionLookup, [switch]$SkipExposureProbes) }

    . $FunctionPath

    function New-ScanRequest {
        param($Url = 'https://example.com', $SkipVersionLookup, $SkipExposureProbes, $MaxRequests, $Body)
        [pscustomobject]@{
            Params  = @{ CIPPEndpoint = 'ListWordPressSecurity' }
            Headers = @{ Authorization = 'token' }
            Query   = [pscustomobject]@{
                Url                = $Url
                SkipVersionLookup  = $SkipVersionLookup
                SkipExposureProbes = $SkipExposureProbes
                MaxRequests        = $MaxRequests
            }
            Body    = $Body
        }
    }

    function New-ScanResult {
        param([bool]$Completed = $true, [string]$ScanError = '')
        [pscustomobject]@{
            Url = 'https://example.com'; FinalUrl = 'https://example.com/'; Completed = $Completed
            IsWordPress = $true; Score = 72; Grade = 'C'; Findings = @(); Components = @()
            RequestsMade = 18; Error = $ScanError
        }
    }
}

Describe 'Invoke-ListWordPressSecurity' {

    BeforeAll {
        Mock Write-LogMessage {}
        Mock Get-CippException { @{} }
    }

    Context 'Input validation' {
        It 'rejects a request with no URL' {
            Mock Test-CippWordPressSecurity { New-ScanResult }
            $Response = Invoke-ListWordPressSecurity -Request (New-ScanRequest -Url $null)
            $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
            $Response.Body.Results | Should -Match 'Url'
        }

        It 'does not start a scan when the URL is missing' {
            Mock Test-CippWordPressSecurity { New-ScanResult }
            Invoke-ListWordPressSecurity -Request (New-ScanRequest -Url '   ') | Out-Null
            Should -Not -Invoke Test-CippWordPressSecurity -Scope It
        }

        It 'rejects a MaxRequests value outside the allowed range' {
            Mock Test-CippWordPressSecurity { New-ScanResult }
            $Response = Invoke-ListWordPressSecurity -Request (New-ScanRequest -MaxRequests '5000')
            $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        }

        It 'rejects a MaxRequests value that is not a number' {
            Mock Test-CippWordPressSecurity { New-ScanResult }
            $Response = Invoke-ListWordPressSecurity -Request (New-ScanRequest -MaxRequests 'lots')
            $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        }

        It 'passes a valid MaxRequests through to the scan' {
            Mock Test-CippWordPressSecurity { New-ScanResult }
            Invoke-ListWordPressSecurity -Request (New-ScanRequest -MaxRequests '12') | Out-Null
            Should -Invoke Test-CippWordPressSecurity -Scope It -ParameterFilter { $MaxRequests -eq 12 }
        }

        It 'reads the URL from the body when the query has none' {
            Mock Test-CippWordPressSecurity { New-ScanResult }
            $Request = New-ScanRequest -Url $null -Body ([pscustomobject]@{ Url = 'https://body.example' })
            Invoke-ListWordPressSecurity -Request $Request | Out-Null
            Should -Invoke Test-CippWordPressSecurity -Scope It -ParameterFilter { $Url -eq 'https://body.example' }
        }
    }

    Context 'Running a scan' {
        It 'returns the scan on success' {
            Mock Test-CippWordPressSecurity { New-ScanResult }
            $Response = Invoke-ListWordPressSecurity -Request (New-ScanRequest)
            $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
            $Response.Body.Grade | Should -Be 'C'
        }

        It 'records who scanned what before the scan runs' {
            # The audit trail is the point: it has to exist even for a scan that then fails.
            Mock Test-CippWordPressSecurity { throw 'boom' }
            Invoke-ListWordPressSecurity -Request (New-ScanRequest -Url 'https://customer.example') | Out-Null
            Should -Invoke Write-LogMessage -Scope It -ParameterFilter { $message -match 'customer\.example' }
        }

        It 'forwards the skip flags as real switches' {
            Mock Test-CippWordPressSecurity { New-ScanResult }
            Invoke-ListWordPressSecurity -Request (New-ScanRequest -SkipVersionLookup $true -SkipExposureProbes $true) | Out-Null
            Should -Invoke Test-CippWordPressSecurity -Scope It -ParameterFilter {
                $SkipVersionLookup -eq $true -and $SkipExposureProbes -eq $true
            }
        }

        It 'leaves the skip flags off when they were not requested' {
            Mock Test-CippWordPressSecurity { New-ScanResult }
            Invoke-ListWordPressSecurity -Request (New-ScanRequest) | Out-Null
            Should -Invoke Test-CippWordPressSecurity -Scope It -ParameterFilter {
                $SkipVersionLookup -eq $false -and $SkipExposureProbes -eq $false
            }
        }
    }

    Context 'Failure handling' {
        It 'answers 400 when the target was refused' {
            # An unscannable target is bad input, not a broken API - a 500 would send an MSP
            # looking for a platform fault that is not there.
            Mock Test-CippWordPressSecurity { New-ScanResult -Completed $false -ScanError "'10.0.0.1' is a private address." }
            $Response = Invoke-ListWordPressSecurity -Request (New-ScanRequest -Url 'http://10.0.0.1/')
            $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
            $Response.Body.Results | Should -Match 'private address'
        }

        It 'answers 500 when the scan itself throws' {
            Mock Test-CippWordPressSecurity { throw 'unexpected' }
            $Response = Invoke-ListWordPressSecurity -Request (New-ScanRequest)
            $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::InternalServerError)
            $Response.Body.Results | Should -Match 'unexpected'
        }

        It 'logs a failed scan as an error' {
            Mock Test-CippWordPressSecurity { throw 'unexpected' }
            Invoke-ListWordPressSecurity -Request (New-ScanRequest) | Out-Null
            Should -Invoke Write-LogMessage -Scope It -ParameterFilter { $Sev -eq 'Error' }
        }
    }
}
