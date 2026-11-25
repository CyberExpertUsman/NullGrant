"""Small pure helpers: encoding, URI normalisation, redaction, detail scanning."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def random_verifier(length: int = 64) -> str:
    """RFC 7636 compliant code_verifier (43-128 chars, unreserved charset)."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def s256_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())

def _host_of(url: str) -> Optional[str]:
    try:
        return urllib.parse.urlsplit(url).hostname
    except Exception:
        return None

def _origin_of(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    netloc = p.netloc
    if not netloc:
        return ""
    try:
        if p.port is None:
            netloc = p.hostname or ""
    except ValueError:
        pass
    return f"{p.scheme}://{netloc}".lower()

def normalize_uri(url: str) -> Optional[Tuple[str, str, Optional[int], str]]:
    """(scheme, host, effective_port, path) with RFC 3986 case/scheme-default normalisation."""
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    host = (p.hostname or "").lower()
    scheme = (p.scheme or "").lower()
    try:
        port = p.port
    except ValueError:
        port = None
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme)
    return scheme, host, port, p.path

def same_uri(a: str, b: str) -> bool:
    """True if a and b are the same URI after scheme/host case and default-port normalisation.

    The path is compared exactly - RFC 6749 s3.1.2.3 requires exact string matching, and
    case-folding the path would hide genuine matching bugs.
    """
    na, nb = normalize_uri(a), normalize_uri(b)
    if na is None or nb is None:
        return False
    return na == nb

def base_url(url: str) -> str:
    """Strip query and fragment."""
    return url.split("#", 1)[0].split("?", 1)[0]

def parse_json_maybe(text: str) -> Optional[Any]:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None

TRACE_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"java\.lang\.[A-Za-z]*Exception", "Java exception class name"),
    (r"at [\w.$]+\([\w.]+\.java:\d+\)", "Java stack frame"),
    (r"System\.(NullReference|Argument)Exception", ".NET exception"),
    (r"org\.springframework\.[\w.]+", "Spring framework internals"),
    (r"/var/www/|/home/\w+/|C:\\\\", "Server filesystem path"),
    (r"\bSELECT\b.+\bFROM\b.+\bWHERE\b", "Raw SQL fragment"),
    (r"sqlstate|ORA-\d{5}|pg_query", "Database driver error"),
]

def scan_for_internal_detail(text: str) -> List[str]:
    hits = []
    for pattern, label in TRACE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            hits.append(label)
    # de-duplicate, keep order
    seen = set()
    out = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out

SENSITIVE_KEYS = {"access_token", "id_token", "refresh_token", "code", "code_verifier",
                  "client_secret", "client_assertion", "password", "token"}

def redact_value(key: str, value: str) -> str:
    """Keep enough of a credential-like value to prove presence, hide the rest."""
    if key.lower() in SENSITIVE_KEYS and isinstance(value, str) and value:
        if len(value) <= 8:
            return "<redacted>"
        return f"<redacted len={len(value)} {value[:4]}...>"
    return value

def redact_url(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    if not p.query:
        return url
    q = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    red = urllib.parse.urlencode([(k, redact_value(k, v)) for k, v in q])
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, red, p.fragment))

def redact_body_snippet(text: str, limit: int = 400) -> str:
    t = re.sub(r"\s+", " ", text).strip()
    return t[:limit] + ("..." if len(t) > limit else "")

def build_url_with_params(url: str, params: Dict[str, Any]) -> str:
    clean = {k: v for k, v in params.items() if v is not None}
    sep = "&" if urllib.parse.urlsplit(url).query else "?"
    return url + sep + urllib.parse.urlencode(clean, quote_via=urllib.parse.quote)
