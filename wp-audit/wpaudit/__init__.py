"""wp-audit: a passive security scanner for WordPress websites."""

__version__ = "1.0.0"

from .models import Finding, ScanReport, Severity, Status  # noqa: F401
