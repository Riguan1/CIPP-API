"""The single read-only request every check goes through.

Keeping all network access behind one class is what makes the scan passive by construction rather
than by convention: the method is fixed to GET or HEAD, no body is ever sent, and nothing is
retried. The scanner only ever looks at what an anonymous visitor would already receive.

Redirects are followed one hop at a time and each hop is re-validated against the same guard the
scan started with. Handing `allow_redirects=True` to requests would be shorter, but then an open
redirect on a customer's site -- or a compromised one -- is enough to walk the scanner into the
hosting network, and the guard would only ever see where it ended up.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests
from urllib3.exceptions import InsecureRequestWarning

from .target import validate_target

USER_AGENT = (
    "Mozilla/5.0 (compatible; wp-audit/1.0; +https://github.com/wp-audit) "
    "passive-security-scanner"
)

#: Response bodies are cut off here. Every signature the checks look for is in the first few KB;
#: this only stops a hostile or broken server from feeding the scanner unbounded memory.
MAX_CONTENT_BYTES = 512 * 1024


@dataclass
class ProbeResponse:
    url: str
    final_url: str = ""
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    set_cookie: list[str] = field(default_factory=list)
    text: str = ""
    content_length: int = 0
    truncated: bool = False
    redirected: bool = False
    ok: bool = False
    certificate_error: bool = False
    insecure: bool = False
    error: str = ""

    def header(self, name: str) -> str | None:
        """Case-insensitive header lookup; field names are case-insensitive per RFC 9110."""
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return None


class Prober:
    """Issues the scan's requests and counts them.

    The budget is enforced here rather than in each check, so no check can spend another's
    allowance and a scan can be capped no matter how many components a page turns out to load.
    """

    def __init__(
        self,
        *,
        timeout: float = 15.0,
        max_requests: int = 30,
        max_redirects: int = 5,
        allow_insecure: bool = True,
        user_agent: str = USER_AGENT,
        verify_targets: bool = True,
    ) -> None:
        self.timeout = timeout
        self.max_requests = max_requests
        self.max_redirects = max_redirects
        self.allow_insecure = allow_insecure
        self.verify_targets = verify_targets
        self.requests_made = 0
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "en;q=0.9",
            }
        )
        # requests keeps cookies across a session by default. A scanner that starts carrying a
        # site's session cookie stops seeing what an anonymous visitor sees.
        self.session.cookies.set_policy(_RejectAllCookies())

    @property
    def budget_left(self) -> int:
        return max(0, self.max_requests - self.requests_made)

    def get(self, url: str, *, method: str = "GET") -> ProbeResponse:
        """Fetch a URL. Never raises: a refused connection, a TLS failure and a 404 are all
        ordinary results for a scan, and the caller decides what each one means."""
        if method not in ("GET", "HEAD"):
            raise ValueError(f"Refusing method {method}: this scanner is read-only.")

        result = ProbeResponse(url=url)
        if self.budget_left <= 0:
            result.error = f"Request budget of {self.max_requests} exhausted."
            return result

        current = url
        for hop in range(self.max_redirects + 1):
            if self.verify_targets:
                target = validate_target(current)
                if not target.valid:
                    result.ok = False
                    result.text = ""
                    result.error = f"Target cannot be scanned. {target.reason}"
                    return result

            self.requests_made += 1
            response, error, certificate_error, insecure = self._request_once(current, method)
            if response is None:
                result.error = error
                result.certificate_error = certificate_error
                return result

            result.certificate_error = result.certificate_error or certificate_error
            result.insecure = result.insecure or insecure

            location = response.headers.get("Location", "") if response.is_redirect else ""
            if location:
                if hop >= self.max_redirects:
                    # Returning the 3xx as though it were the page would hand every check a
                    # redirect body to read and call it the site's home page.
                    response.close()
                    result.ok = False
                    result.error = f"Too many redirects (more than {self.max_redirects})."
                    return result

                # stream=True leaves the connection open until the body is read or closed, and a
                # redirect body is never read.
                response.close()
                current = urljoin(current, location)
                result.redirected = True
                if self.budget_left <= 0:
                    result.error = "Request budget exhausted while following redirects."
                    return result
                continue

            # A 3xx with no Location is not a redirect anyone can follow; report what was sent.
            return self._finish(result, response, current)

        result.error = f"Too many redirects (more than {self.max_redirects})."
        return result

    def _request_once(self, url: str, method: str):
        """One HTTP request. Returns (response, error, certificate_error, insecure)."""
        try:
            response = self.session.request(
                method, url, timeout=self.timeout, allow_redirects=False, stream=True
            )
            return response, "", False, False
        except requests.exceptions.SSLError as exc:
            if not self.allow_insecure:
                return None, str(exc), True, False
            # A site with a broken certificate usually has everything else wrong with it too, and
            # the report is more useful for saying so than for stopping at the handshake. The
            # certificate failure itself is recorded and reported either way.
            try:
                # The certificate failure is already a finding; urllib3's warning about it on
                # every subsequent request would only bury the report it appears alongside.
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", InsecureRequestWarning)
                    response = self.session.request(
                        method,
                        url,
                        timeout=self.timeout,
                        allow_redirects=False,
                        stream=True,
                        verify=False,
                    )
                return response, "", True, True
            except requests.exceptions.RequestException as retry_exc:
                return None, str(retry_exc), True, False
        except requests.exceptions.RequestException as exc:
            return None, str(exc), False, False

    def _finish(self, result: ProbeResponse, response, final_url: str) -> ProbeResponse:
        result.status_code = response.status_code
        result.final_url = final_url
        result.ok = True
        result.headers = {key: value for key, value in response.headers.items()}
        # requests folds repeated headers into one comma-joined value, which is wrong for
        # Set-Cookie: an Expires attribute contains a comma, so the cookie checks would see
        # cookies that do not exist. urllib3 keeps the originals.
        try:
            result.set_cookie = list(response.raw.headers.getlist("Set-Cookie"))
        except Exception:  # pragma: no cover - depends on the transport adapter in use
            single = response.headers.get("Set-Cookie")
            result.set_cookie = [single] if single else []

        body = b""
        try:
            for chunk in response.iter_content(8192):
                body += chunk
                if len(body) >= MAX_CONTENT_BYTES:
                    result.truncated = True
                    break
        except requests.exceptions.RequestException as exc:
            result.error = str(exc)
        finally:
            response.close()

        encoding = response.encoding or "utf-8"
        try:
            result.text = body.decode(encoding, errors="replace")
        except LookupError:
            result.text = body.decode("utf-8", errors="replace")
        result.content_length = len(body)
        return result

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> Prober:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


class _RejectAllCookies:
    """Cookie policy that stores nothing, so the scanner keeps seeing the anonymous view."""

    def set_ok(self, cookie, request) -> bool:
        return False

    def return_ok(self, cookie, request) -> bool:
        return False

    def domain_return_ok(self, domain, request) -> bool:
        return False

    def path_return_ok(self, path, request) -> bool:
        return False

    # http.cookiejar reads these attributes directly.
    netscape = True
    rfc2965 = False
    hide_cookie2 = False
