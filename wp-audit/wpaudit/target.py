"""Deciding whether a URL may be scanned at all.

This is the security boundary of the tool, not a convenience validator. The scanner fetches a URL
somebody hands it, so every address range that is not rejected here is a request an operator (or
anything that can influence the target list) gets to aim at the local network -- and
`169.254.169.254` is a request for the host's cloud credentials.

Python's `ipaddress` module classifies most of this correctly, but the exact membership of
`is_private` has changed between Python versions, so the ranges that matter are also listed
explicitly rather than trusted to the standard library of whichever interpreter this runs on.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

#: Hostnames and suffixes that never belong to a customer website on the public internet.
INTERNAL_SUFFIXES = (
    ".local",
    ".localhost",
    ".localdomain",
    ".internal",
    ".intranet",
    ".lan",
    ".home.arpa",
    ".corp",
    ".private",
    ".test",
    ".example",
    ".invalid",
)

#: Ranges checked by hand, with the description an operator needs to understand a refusal.
#: Ordered most specific first so the metadata endpoint is named rather than called link-local.
_BLOCKED_V4 = (
    (ipaddress.ip_network("169.254.169.254/32"), "a link-local address (cloud instance metadata)"),
    (ipaddress.ip_network("0.0.0.0/8"), 'in the "this network" range'),
    (ipaddress.ip_network("10.0.0.0/8"), "a private address"),
    (ipaddress.ip_network("100.64.0.0/10"), "a carrier-grade NAT address"),
    (ipaddress.ip_network("127.0.0.0/8"), "a loopback address"),
    (ipaddress.ip_network("169.254.0.0/16"), "a link-local address"),
    (ipaddress.ip_network("172.16.0.0/12"), "a private address"),
    (ipaddress.ip_network("192.0.0.0/24"), "in the IETF protocol assignments range"),
    (ipaddress.ip_network("192.0.2.0/24"), "a documentation address"),
    (ipaddress.ip_network("192.168.0.0/16"), "a private address"),
    (ipaddress.ip_network("198.18.0.0/15"), "a benchmarking address"),
    (ipaddress.ip_network("198.51.100.0/24"), "a documentation address"),
    (ipaddress.ip_network("203.0.113.0/24"), "a documentation address"),
    (ipaddress.ip_network("224.0.0.0/4"), "a multicast address"),
    (ipaddress.ip_network("240.0.0.0/4"), "a reserved address"),
)

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


@dataclass
class TargetResult:
    valid: bool
    reason: str = ""
    url: str = ""
    host: str = ""
    scheme: str = ""
    addresses: list[str] = field(default_factory=list)


def private_address_reason(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Why this address is not routable on the public internet, or None when it is.

    IPv4-mapped and 6to4 IPv6 addresses are unwrapped first, because `::ffff:127.0.0.1` and
    `2002:7f00:1::` reach exactly where `127.0.0.1` does.
    """
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        elif address.sixtofour is not None:
            address = address.sixtofour
        else:
            if address.is_loopback:
                return "an IPv6 loopback address"
            if address.is_link_local:
                return "an IPv6 link-local address"
            if address.is_site_local:
                return "an IPv6 site-local address"
            if address.is_multicast:
                return "an IPv6 multicast address"
            if address.is_unspecified:
                return "the unspecified address"
            # fc00::/7, unique local addresses -- the IPv6 equivalent of 10/8.
            if address in ipaddress.ip_network("fc00::/7"):
                return "an IPv6 unique local address"
            if address.is_reserved:
                return "an IPv6 reserved address"
            return None

    for network, reason in _BLOCKED_V4:
        if address in network:
            return reason

    # Anything the standard library still objects to, whatever this Python version calls it.
    if address.is_private or address.is_reserved or address.is_multicast or address.is_unspecified:
        return "a non-public address"
    return None


def resolve_host(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve a hostname to every address behind it.

    Split out so the case that matters most -- a perfectly ordinary public hostname whose DNS
    answer points into private space -- can be exercised in tests, which is impossible against
    real DNS.
    """
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    addresses = []
    for info in infos:
        candidate = ipaddress.ip_address(info[4][0])
        if candidate not in addresses:
            addresses.append(candidate)
    return addresses


def validate_target(url: str, *, resolver=resolve_host, skip_dns: bool = False) -> TargetResult:
    """Normalise a URL and decide whether it may be scanned.

    A host that resolves to a mix of public and private addresses is refused too: which address the
    request actually lands on is not ours to choose, so one private answer is enough.
    """
    if not url or not url.strip():
        return TargetResult(False, "No URL was supplied.")

    candidate = url.strip()
    # A bare hostname is the common case from a site list. Anything carrying its own scheme keeps
    # it, so an unsupported one is refused below instead of silently repaired.
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*://", candidate):
        candidate = "https://" + candidate

    parts = urlsplit(candidate)

    if parts.scheme not in ("http", "https"):
        return TargetResult(False, f"Scheme '{parts.scheme}' is not supported. Use http or https.")

    if parts.username or parts.password:
        # They would be replayed as an Authorization header on every probe.
        return TargetResult(False, "Credentials in the URL are not supported.")

    try:
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        return TargetResult(False, f"'{url}' is not a valid URL. {exc}")

    if not host:
        return TargetResult(False, "The URL has no hostname.")

    default_port = 443 if parts.scheme == "https" else 80
    if port is not None and port != default_port:
        return TargetResult(
            False,
            f"Port {port} is not supported. Only the default http (80) and https (443) ports are scanned.",
        )

    lowered = host.lower()
    if lowered == "localhost" or lowered.endswith(INTERNAL_SUFFIXES):
        return TargetResult(False, f"'{host}' is an internal-only hostname.")

    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        addresses.append(ipaddress.ip_address(host))
    except ValueError:
        if not skip_dns:
            if not _HOSTNAME.match(host):
                return TargetResult(False, f"'{host}' is not a valid hostname.")
            try:
                addresses = resolver(host)
            except OSError as exc:
                return TargetResult(False, f"'{host}' could not be resolved. {exc}")
            if not addresses:
                return TargetResult(False, f"'{host}' did not resolve to any address.")

    for address in addresses:
        reason = private_address_reason(address)
        if reason:
            return TargetResult(
                False,
                f"'{host}' resolves to {address}, which is {reason}. "
                "Only public internet targets can be scanned.",
                addresses=[str(a) for a in addresses],
                host=host,
            )

    normalised = f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"
    if parts.query:
        normalised += "?" + parts.query

    return TargetResult(
        True,
        url=normalised,
        host=host,
        scheme=parts.scheme,
        addresses=[str(a) for a in addresses],
    )
