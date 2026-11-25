"""Authorization server metadata discovery (RFC 8414 / OpenID Connect Discovery)."""

from __future__ import annotations

import sys
import urllib.parse
from typing import Any, Dict

from .http import HttpClient
from .model import Target
from .util import parse_json_maybe

WELL_KNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

def discover(target: Target, http: HttpClient, verbose: bool = False) -> Dict[str, Any]:
    info: Dict[str, Any] = {"source": None, "error": None, "metadata": {}, "reachable": False}
    issuer = target.issuer.rstrip("/")
    candidates = []
    for wk in WELL_KNOWN_PATHS:
        candidates.append(issuer + wk)
    # RFC 8414 path-inserted form, for issuers with a path component
    p = urllib.parse.urlsplit(issuer)
    if p.path and p.path != "/":
        candidates.append(f"{p.scheme}://{p.netloc}/.well-known/oauth-authorization-server{p.path}")
        candidates.append(f"{p.scheme}://{p.netloc}/.well-known/openid-configuration{p.path}")

    errors = []
    got_any_http_response = False
    for url in candidates:
        resp = http.get(url)
        if not resp.ok:
            errors.append(f"{url}: {resp.transport_error}")
            continue
        got_any_http_response = True
        if resp.status != 200:
            errors.append(f"{url}: HTTP {resp.status}")
            continue
        data = parse_json_maybe(resp.text)
        if not isinstance(data, dict):
            errors.append(f"{url}: not JSON")
            continue
        info["source"] = url
        info["metadata"] = data
        info["reachable"] = True
        if verbose:
            print(f"    discovery: using {url}", file=sys.stderr)
        return info

    info["error"] = "; ".join(errors) if errors else "no discovery document found"
    info["reachable"] = got_any_http_response
    return info
