"""The target guard.

This is the security boundary of the tool, not a convenience validator: the scanner fetches URLs it
is handed, so every range not rejected here is a request someone gets to aim at the local network,
and 169.254.169.254 is a request for the host's cloud credentials. The cases below are the ways
this class of guard is usually walked past.
"""

from __future__ import annotations

import ipaddress

import pytest

from wpaudit.target import private_address_reason, validate_target


@pytest.mark.parametrize(
    "address,because",
    [
        ("127.0.0.1", "loopback"),
        ("127.255.255.254", "the whole 127/8 block is loopback, not just .0.1"),
        ("0.0.0.0", "this network"),
        ("10.1.2.3", "RFC1918"),
        ("172.16.0.1", "RFC1918 lower bound"),
        ("172.31.255.255", "RFC1918 upper bound"),
        ("192.168.1.1", "RFC1918"),
        ("169.254.169.254", "cloud instance metadata"),
        ("169.254.1.1", "link-local"),
        ("100.64.0.1", "carrier-grade NAT"),
        ("224.0.0.1", "multicast"),
        ("255.255.255.255", "broadcast, inside 240/4"),
        ("::1", "IPv6 loopback"),
        ("fe80::1", "IPv6 link-local"),
        ("fd00::1", "IPv6 unique local"),
        ("fc00::1", "IPv6 unique local lower bound"),
        ("::ffff:10.0.0.1", "IPv4-mapped private address"),
        ("2002:c0a8:0101::", "6to4 wrapping 192.168.1.1"),
    ],
)
def test_rejects_non_public_addresses(address, because):
    assert private_address_reason(ipaddress.ip_address(address)), because


@pytest.mark.parametrize(
    "address",
    [
        "93.184.216.34",
        "1.1.1.1",
        "8.8.8.8",
        "172.15.255.255",  # just below 172.16/12
        "172.32.0.1",  # just above 172.16/12
        "100.63.255.255",  # just below 100.64/10
        "11.0.0.1",  # just above 10/8
        "2606:4700:4700::1111",
    ],
)
def test_accepts_ordinary_public_addresses(address):
    assert private_address_reason(ipaddress.ip_address(address)) is None


def test_names_the_metadata_endpoint_specifically():
    # Whoever reads a refused scan needs to know this was not an ordinary typo.
    assert "metadata" in private_address_reason(ipaddress.ip_address("169.254.169.254"))


class TestUrlHandling:
    def test_treats_a_bare_hostname_as_https(self):
        result = validate_target("example.com", skip_dns=True)
        assert result.valid
        assert result.url == "https://example.com/"

    def test_keeps_an_explicit_http_scheme(self):
        # The scan has to be able to observe a site that is only served over HTTP.
        result = validate_target("http://example.com/", skip_dns=True)
        assert result.valid
        assert result.scheme == "http"

    @pytest.mark.parametrize(
        "url",
        ["", "   ", "file:///etc/passwd", "ftp://example.com/", "gopher://example.com/"],
    )
    def test_rejects_unusable_urls(self, url):
        assert validate_target(url, skip_dns=True).valid is False

    def test_rejects_credentials_in_the_url(self):
        # They would be replayed as an Authorization header on every probe.
        assert validate_target("https://user:pass@example.com/", skip_dns=True).valid is False

    def test_rejects_a_non_default_port(self):
        result = validate_target("https://example.com:8443/", skip_dns=True)
        assert result.valid is False
        assert "8443" in result.reason

    def test_rejects_a_malformed_hostname(self):
        assert validate_target("https://not a host/").valid is False


class TestInternalTargets:
    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost/",
            "https://intranet.local/",
            "https://wordpress.internal/",
            "https://site.lan/",
            "https://box.home.arpa/",
        ],
    )
    def test_rejects_internal_hostnames(self, url):
        assert validate_target(url).valid is False

    def test_rejects_a_literal_private_address_without_dns(self):
        result = validate_target("http://192.168.1.10/")
        assert result.valid is False
        assert "private" in result.reason

    def test_rejects_the_metadata_endpoint(self):
        result = validate_target("http://169.254.169.254/latest/meta-data/")
        assert result.valid is False
        assert "metadata" in result.reason

    def test_rejects_ipv6_loopback_in_brackets(self):
        assert validate_target("http://[::1]/").valid is False

    def test_rejects_a_public_hostname_resolving_into_private_space(self):
        # The DNS rebinding shape, and the reason the guard checks addresses rather than names.
        resolver = lambda host: [ipaddress.ip_address("10.0.0.5")]
        result = validate_target("https://customer-site.com/", resolver=resolver)
        assert result.valid is False
        assert "10.0.0.5" in result.reason

    def test_rejects_a_host_that_is_only_partly_public(self):
        # Which address the request lands on is not ours to choose, so one private answer is enough.
        resolver = lambda host: [
            ipaddress.ip_address("93.184.216.34"),
            ipaddress.ip_address("127.0.0.1"),
        ]
        assert validate_target("https://customer-site.com/", resolver=resolver).valid is False

    def test_accepts_a_fully_public_host(self):
        resolver = lambda host: [ipaddress.ip_address("93.184.216.34")]
        result = validate_target("https://customer-site.com/", resolver=resolver)
        assert result.valid
        assert result.addresses == ["93.184.216.34"]

    def test_reports_a_name_that_does_not_resolve(self):
        def resolver(host):
            raise OSError("Name or service not known")

        assert validate_target("https://nope.example.com/", resolver=resolver).valid is False
