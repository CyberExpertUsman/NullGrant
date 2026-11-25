"""Core data model: findings, captured HTTP responses, and the audit target."""

from __future__ import annotations

import dataclasses
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

STATUS_PASS = "PASS"

STATUS_FAIL = "FAIL"

STATUS_WARN = "WARN"

STATUS_INFO = "INFO"

STATUS_INDETERMINATE = "INDETERMINATE"

STATUS_LABEL = {
    STATUS_PASS: "pass",
    STATUS_FAIL: "FAIL",
    STATUS_WARN: "warn",
    STATUS_INFO: "info",
    STATUS_INDETERMINATE: "indeterminate",
}

@dataclass
class Finding:
    """A single audited control and its verdict."""

    check_id: str
    title: str
    status: str
    check: str = ""          # the --checks CLI id that produced this finding
    severity: str = "INFO"
    summary: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    recommendation: str = ""
    references: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

@dataclass
class HttpResponse:
    """A captured HTTP response. Redirects are NOT followed."""

    url: str
    status: int
    headers: Dict[str, str]
    body: bytes
    transport_error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.transport_error is None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def location(self) -> Optional[str]:
        return self.headers.get("location")

    @property
    def location_parts(self) -> Optional[Dict[str, Any]]:
        """Parsed Location header, if present."""
        if not self.location:
            return None
        p = urllib.parse.urlsplit(self.location)
        return {
            "raw": self.location,
            "scheme": p.scheme,
            "netloc": p.netloc,
            "host": p.hostname,
            "port": p.port,
            "path": p.path,
            "query": dict(urllib.parse.parse_qsl(p.query, keep_blank_values=True)),
            "fragment": dict(urllib.parse.parse_qsl(p.fragment, keep_blank_values=True)),
            "fragment_raw": p.fragment,
        }

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

@dataclass
class Target:
    """The authorization server under audit and the test client used to reach it."""

    issuer: str
    client_id: str
    redirect_uri: str
    client_type: str  # "public" | "confidential"
    client_secret: Optional[str] = None
    auth_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    jwks_uri: Optional[str] = None
    registration_endpoint: Optional[str] = None
    scopes: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    metadata_source: Optional[str] = None
    metadata_error: Optional[str] = None
    metadata_reachable: bool = False
