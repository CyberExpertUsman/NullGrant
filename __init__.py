"""
NullGrant - configuration auditing for OAuth 2.0 / OpenID Connect authorization servers.

Runs read-only, standards-based compliance checks against an authorization server you own
or are authorised to test, and reports whether it enforces the controls described in
RFC 9700 (OAuth 2.0 Security BCP), RFC 6749, RFC 7636 (PKCE), RFC 7662 and RFC 8414.

Command line::

    nullgrant --issuer https://as.lab.example.com \\
               --client-id lab-client \\
               --redirect-uri https://app.lab.example.com/callback \\
               --i-authorize-target --out ./report

Or as a module::

    python -m nullgrant --help

Library use::

    import nullgrant
    rc = nullgrant.main(["--issuer", ..., "--i-authorize-target"])

The tool sends only requests an OAuth client would legitimately send, using the single
registered test client you name. It does not brute force, does not enumerate other clients
or accounts, and does not attempt to exploit anything it reports.
"""

from __future__ import annotations

from ._version import TOOL_NAME, TOOL_VERSION, USER_AGENT, __version__
from .checks import CHECKS, CHECK_IDS, DEFAULT_CHECKS
from .context import AuditContext
from .discovery import discover
from .http import HttpClient
from .model import (
    SEVERITY_ORDER,
    STATUS_FAIL,
    STATUS_INDETERMINATE,
    STATUS_INFO,
    STATUS_LABEL,
    STATUS_PASS,
    STATUS_WARN,
    Finding,
    HttpResponse,
    Target,
)
from .report import (
    print_console,
    summarise,
    write_html_report,
    write_json_report,
)
from .util import (
    build_url_with_params,
    normalize_uri,
    random_verifier,
    redact_url,
    redact_value,
    s256_challenge,
    same_uri,
    scan_for_internal_detail,
)
from .variants import (
    IMPLICIT_TYPES,
    RESPONSE_TYPES_TO_ENUMERATE,
    build_redirect_variants,
)

__all__ = [
    "__version__",
    "TOOL_NAME",
    "TOOL_VERSION",
    "USER_AGENT",
    # entry point
    "main",
    "build_parser",
    # model
    "Finding",
    "HttpResponse",
    "Target",
    "AuditContext",
    "HttpClient",
    "SEVERITY_ORDER",
    "STATUS_PASS",
    "STATUS_FAIL",
    "STATUS_WARN",
    "STATUS_INFO",
    "STATUS_INDETERMINATE",
    "STATUS_LABEL",
    # checks
    "CHECKS",
    "CHECK_IDS",
    "DEFAULT_CHECKS",
    "discover",
    # test inputs
    "build_redirect_variants",
    "RESPONSE_TYPES_TO_ENUMERATE",
    "IMPLICIT_TYPES",
    # reporting
    "summarise",
    "print_console",
    "write_json_report",
    "write_html_report",
    # helpers
    "random_verifier",
    "s256_challenge",
    "build_url_with_params",
    "normalize_uri",
    "same_uri",
    "redact_value",
    "redact_url",
    "scan_for_internal_detail",
]


def __getattr__(name: str):
    """Import the CLI lazily so `import nullgrant` stays cheap."""
    if name in ("main", "build_parser"):
        from . import cli

        return getattr(cli, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(__all__)
