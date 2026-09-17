function Get-CippPrivateAddressReason {
    <#
    .SYNOPSIS
    Returns why an IP address is not routable on the public internet, or $null when it is.

    .DESCRIPTION
    Backs the SSRF guard in Test-CippWordPressTarget. Split out because the ranges are the part
    that has to be exactly right: every gap here is a path from a caller-supplied URL to something
    inside the hosting network, and the instance metadata endpoint (169.254.169.254) is the one
    that hands out tokens.

    IPv4-mapped and 6to4 IPv6 addresses are unwrapped before the v4 ranges are applied, because
    ::ffff:127.0.0.1 and 2002:7f00:1::  reach the same place as 127.0.0.1 does.

    .PARAMETER Address
    The address to classify.

    .EXAMPLE
    Get-CippPrivateAddressReason -Address ([System.Net.IPAddress]'169.254.169.254')
    # 'a link-local address (cloud instance metadata)'

    .EXAMPLE
    Get-CippPrivateAddressReason -Address ([System.Net.IPAddress]'93.184.216.34')
    # $null
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.IPAddress]$Address
    )

    if ([System.Net.IPAddress]::IsLoopback($Address)) {
        return 'a loopback address'
    }

    $Target = $Address
    if ($Target.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        $Bytes = $Target.GetAddressBytes()

        if ($Target.IsIPv4MappedToIPv6) {
            $Target = $Target.MapToIPv4()
        } elseif ($Bytes[0] -eq 0x20 -and $Bytes[1] -eq 0x02) {
            # 6to4 (2002::/16) embeds the v4 address in bytes 2-5.
            $Target = [System.Net.IPAddress]::new($Bytes[2..5])
        } else {
            if ($Target.IsIPv6LinkLocal) { return 'an IPv6 link-local address' }
            if ($Target.IsIPv6SiteLocal) { return 'an IPv6 site-local address' }
            if ($Target.IsIPv6Multicast) { return 'an IPv6 multicast address' }
            # fc00::/7, unique local addresses - the IPv6 equivalent of 10/8.
            if (($Bytes[0] -band 0xFE) -eq 0xFC) { return 'an IPv6 unique local address' }
            if ($Target.Equals([System.Net.IPAddress]::IPv6Any)) { return 'the unspecified address' }
            return $null
        }
    }

    if ($Target.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $null
    }

    $Octets = $Target.GetAddressBytes()
    $Value = ([uint32]$Octets[0] -shl 24) -bor ([uint32]$Octets[1] -shl 16) -bor ([uint32]$Octets[2] -shl 8) -bor [uint32]$Octets[3]

    # Ordered so the most specific range wins the description: 169.254.169.254 is link-local,
    # but naming the metadata endpoint is what makes a rejected scan understandable.
    $Ranges = @(
        @{ Cidr = '169.254.169.254/32'; Reason = 'a link-local address (cloud instance metadata)' }
        @{ Cidr = '0.0.0.0/8'; Reason = 'in the "this network" range' }
        @{ Cidr = '10.0.0.0/8'; Reason = 'a private address' }
        @{ Cidr = '100.64.0.0/10'; Reason = 'a carrier-grade NAT address' }
        @{ Cidr = '127.0.0.0/8'; Reason = 'a loopback address' }
        @{ Cidr = '169.254.0.0/16'; Reason = 'a link-local address' }
        @{ Cidr = '172.16.0.0/12'; Reason = 'a private address' }
        @{ Cidr = '192.0.0.0/24'; Reason = 'in the IETF protocol assignments range' }
        @{ Cidr = '192.0.2.0/24'; Reason = 'a documentation address' }
        @{ Cidr = '192.168.0.0/16'; Reason = 'a private address' }
        @{ Cidr = '198.18.0.0/15'; Reason = 'a benchmarking address' }
        @{ Cidr = '198.51.100.0/24'; Reason = 'a documentation address' }
        @{ Cidr = '203.0.113.0/24'; Reason = 'a documentation address' }
        @{ Cidr = '224.0.0.0/4'; Reason = 'a multicast address' }
        @{ Cidr = '240.0.0.0/4'; Reason = 'a reserved address' }
    )

    foreach ($Range in $Ranges) {
        $Parts = $Range.Cidr -split '/'
        $NetworkOctets = ([System.Net.IPAddress]$Parts[0]).GetAddressBytes()
        $Network = ([uint32]$NetworkOctets[0] -shl 24) -bor ([uint32]$NetworkOctets[1] -shl 16) -bor ([uint32]$NetworkOctets[2] -shl 8) -bor [uint32]$NetworkOctets[3]
        $Prefix = [int]$Parts[1]
        # A /0 mask cannot be expressed by shifting a 32-bit value 32 places, and no range here
        # needs one, so the prefix is trusted to be 1-32.
        $Mask = [uint32]::MaxValue -shl (32 - $Prefix)
        if (($Value -band $Mask) -eq ($Network -band $Mask)) {
            return $Range.Reason
        }
    }

    return $null
}
