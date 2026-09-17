function Resolve-CippHostAddress {
    <#
    .SYNOPSIS
    Resolves a hostname to its IP addresses.

    .DESCRIPTION
    A one-line wrapper over System.Net.Dns that exists so the resolution step of the scanner's SSRF
    guard is a seam rather than a static call. The case that matters most there - a perfectly valid
    public hostname whose DNS answer points into private address space - cannot be exercised
    against real DNS, and a guard whose most important branch is untestable is a guard nobody can
    be confident in.

    Returns an empty array when the name does not resolve rather than throwing, so callers treat a
    missing answer the same way they treat an empty one.

    .PARAMETER HostName
    The hostname to resolve.

    .EXAMPLE
    Resolve-CippHostAddress -HostName 'example.com'
    #>
    [CmdletBinding()]
    [OutputType([System.Net.IPAddress[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName
    )

    return [System.Net.IPAddress[]]@([System.Net.Dns]::GetHostAddresses($HostName))
}
