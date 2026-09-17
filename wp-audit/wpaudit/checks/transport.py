"""Transport security: HTTPS, the redirect to it, and the certificate behind it.

`requests` either accepts a certificate or raises, which is not enough to tell a site owner what to
do: an expired certificate, a hostname mismatch and an untrusted issuer need different work. So the
handshake is performed directly here -- once with validation to learn whether a browser would
accept it, and if not, once without so the certificate can still be described.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..models import Finding, Severity, Status

try:  # pragma: no cover - exercised by whichever branch the environment supports
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTOGRAPHY = False

EXPIRY_WARNING_DAYS = 21


@dataclass
class CertificateInfo:
    host: str
    port: int = 443
    ok: bool = False
    trusted: bool = False
    subject: str = ""
    issuer: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_remaining: int | None = None
    protocol: str = ""
    key_type: str = ""
    key_size: int | None = None
    self_signed: bool = False
    validation_error: str = ""
    error: str = ""
    names: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "ok": self.ok,
            "trusted": self.trusted,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "days_remaining": self.days_remaining,
            "protocol": self.protocol,
            "key_type": self.key_type,
            "key_size": self.key_size,
            "self_signed": self.self_signed,
            "validation_error": self.validation_error,
            "error": self.error,
            "names": self.names,
        }


def inspect_certificate(host: str, port: int = 443, timeout: float = 10.0) -> CertificateInfo:
    """Open one TLS handshake and describe what the server presented.

    The negotiated protocol is the best one both ends support, so TLS 1.3 here means the server
    offered at least that. It does not prove that TLS 1.0 and 1.1 are switched off: establishing
    that needs deliberately downgraded handshakes, which many platform TLS stacks now refuse to
    attempt at all, so the answer would be inconclusive rather than clean.
    """
    info = CertificateInfo(host=host, port=port)

    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            context.wrap_socket(raw, server_hostname=host) as tls,
        ):
            info.ok = True
            info.trusted = True
            info.protocol = tls.version() or ""
            _fill_from_dict(info, tls.getpeercert())
            der = tls.getpeercert(binary_form=True)
            if der:
                _fill_from_der(info, der)
        return info
    except ssl.SSLCertVerificationError as exc:
        info.validation_error = exc.verify_message or str(exc.reason or exc)
    except ssl.SSLError as exc:
        info.validation_error = str(exc)
    except (TimeoutError, OSError) as exc:
        info.error = str(exc)
        return info

    # The certificate failed validation. Reconnect without checking so it can still be described:
    # "expired three days ago" is actionable, "handshake failed" is not.
    insecure = ssl.create_default_context()
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            insecure.wrap_socket(raw, server_hostname=host) as tls,
        ):
            info.ok = True
            info.protocol = tls.version() or ""
            der = tls.getpeercert(binary_form=True)
            if der:
                _fill_from_der(info, der)
    except (TimeoutError, OSError, ssl.SSLError) as exc:
        if not info.error:
            info.error = str(exc)
    return info


def _fill_from_dict(info: CertificateInfo, cert: dict | None) -> None:
    if not cert:
        return
    info.subject = _format_name(cert.get("subject"))
    info.issuer = _format_name(cert.get("issuer"))
    info.names = [value for key, value in cert.get("subjectAltName", ()) if key == "DNS"]
    for field_name, target in (("notBefore", "not_before"), ("notAfter", "not_after")):
        raw = cert.get(field_name)
        if not raw:
            continue
        try:
            parsed = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            setattr(info, target, parsed)
        except ValueError:
            pass
    _set_days_remaining(info)


def _fill_from_der(info: CertificateInfo, der: bytes) -> None:
    if not HAVE_CRYPTOGRAPHY:
        return
    try:
        certificate = x509.load_der_x509_certificate(der)
    except Exception:  # pragma: no cover - malformed certificate
        return

    info.subject = certificate.subject.rfc4514_string()
    info.issuer = certificate.issuer.rfc4514_string()
    info.self_signed = certificate.subject == certificate.issuer
    info.not_before = certificate.not_valid_before_utc
    info.not_after = certificate.not_valid_after_utc
    _set_days_remaining(info)

    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        info.names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        info.key_type, info.key_size = "RSA", public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        info.key_type, info.key_size = "ECDSA", public_key.curve.key_size


def _set_days_remaining(info: CertificateInfo) -> None:
    if info.not_after:
        info.days_remaining = (info.not_after - datetime.now(timezone.utc)).days


def _format_name(name) -> str:
    if not name:
        return ""
    parts = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def certificate_findings(info: CertificateInfo | None) -> list[Finding]:
    """Turn a handshake result into findings a site owner can act on."""
    if info is None or not info.ok:
        reason = info.error if info else "No handshake was attempted."
        return [
            Finding(
                id="WEB-TLS-CERT",
                category="Transport",
                title="The TLS certificate could not be inspected",
                severity=Severity.MEDIUM,
                status=Status.UNKNOWN,
                evidence=reason or "The handshake did not complete.",
                recommendation=(
                    "Check the certificate directly. A blocked or filtered connection from the "
                    "scanner produces this result too, so it does not necessarily mean anything "
                    "is wrong."
                ),
            )
        ]

    findings: list[Finding] = []
    days = info.days_remaining

    if days is not None and days < 0:
        findings.append(
            Finding(
                id="WEB-TLS-EXPIRED",
                category="Transport",
                title="The TLS certificate has expired",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                evidence=f"Expired on {info.not_after.date()}, {abs(days)} day(s) ago.",
                recommendation=(
                    "Renew it now. Every visitor is being shown a full-page browser warning, and "
                    "any integration calling this site over HTTPS has already stopped working."
                ),
            )
        )
    elif days is not None and days <= EXPIRY_WARNING_DAYS:
        findings.append(
            Finding(
                id="WEB-TLS-EXPIRING",
                category="Transport",
                title="The TLS certificate expires soon",
                severity=Severity.MEDIUM,
                status=Status.WARN,
                evidence=f"Expires on {info.not_after.date()}, in {days} day(s).",
                recommendation=(
                    "Confirm that automatic renewal is working. A certificate this close to expiry "
                    "usually means renewal has been failing quietly for weeks."
                ),
            )
        )
    elif days is not None:
        findings.append(
            Finding(
                id="WEB-TLS-EXPIRING",
                category="Transport",
                title="The TLS certificate is valid",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                evidence=f"Issued by {info.issuer or 'an unnamed issuer'}. "
                f"Expires on {info.not_after.date()}, in {days} day(s).",
            )
        )

    if not info.trusted:
        title = "The TLS certificate fails validation"
        recommendation = (
            "Reissue the certificate for the names the site is actually served on, and install the "
            "full chain the issuer supplies."
        )
        lowered = (info.validation_error or "").lower()
        if "hostname mismatch" in lowered or "doesn't match" in lowered:
            title = "The TLS certificate does not cover this hostname"
            recommendation = (
                f"Reissue the certificate including {info.host}, or serve the site on a name the "
                "certificate does cover."
            )
        elif info.self_signed or "self signed" in lowered or "self-signed" in lowered:
            title = "The TLS certificate is self-signed"
            recommendation = (
                "Replace it with a certificate from a trusted authority. A free Let's Encrypt "
                "certificate takes minutes and removes the browser warning entirely."
            )
        findings.append(
            Finding(
                id="WEB-TLS-VALIDATION",
                category="Transport",
                title=title,
                severity=Severity.HIGH,
                status=Status.FAIL,
                evidence=f"Subject {info.subject or 'unknown'}; validation reported: "
                f"{info.validation_error or 'the certificate is not trusted'}.",
                recommendation=recommendation,
            )
        )

    if info.protocol:
        obsolete = info.protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")
        findings.append(
            Finding(
                id="WEB-TLS-PROTOCOL",
                category="Transport",
                title=(
                    "The connection negotiated an obsolete TLS version"
                    if obsolete
                    else "The connection negotiated a current TLS version"
                ),
                severity=Severity.HIGH,
                status=Status.FAIL if obsolete else Status.PASS,
                evidence=(
                    f"The handshake settled on {info.protocol}."
                    + ("" if obsolete else " This does not prove that older versions are switched off.")
                ),
                recommendation=(
                    "Enable TLS 1.2 and 1.3 and disable everything below. Browsers have shown "
                    "errors for TLS 1.0 and 1.1 since 2020, and card payment compliance rules out "
                    "both."
                )
                if obsolete
                else "",
            )
        )

    if info.key_type == "RSA" and info.key_size and info.key_size < 2048:
        findings.append(
            Finding(
                id="WEB-TLS-KEYSIZE",
                category="Transport",
                title="The certificate key is too small",
                severity=Severity.HIGH,
                status=Status.FAIL,
                evidence=f"RSA key size {info.key_size} bits.",
                recommendation="Reissue with at least a 2048-bit RSA key, or an ECDSA P-256 key.",
            )
        )

    return findings
