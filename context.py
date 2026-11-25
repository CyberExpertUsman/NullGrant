"""Shared audit state: the target, the HTTP client, and the probe/classify helper."""

from __future__ import annotations

import argparse
import re
import secrets
import sys
import time
from typing import Any, Dict, List, Optional

from .http import HttpClient
from .model import Finding, Target
from .util import (
    _host_of,
    _origin_of,
    base_url,
    build_url_with_params,
    parse_json_maybe,
    random_verifier,
    redact_body_snippet,
    redact_url,
    redact_value,
    s256_challenge,
    same_uri,
)

class AuditContext:
    """Shared state passed to every check."""

    def __init__(self, target: Target, http: HttpClient, args: argparse.Namespace) -> None:
        self.target = target
        self.http = http
        self.args = args
        self.findings: List[Finding] = []
        self.log_lines: List[str] = []
        self.started_at = time.time()

    def log(self, msg: str) -> None:
        self.log_lines.append(msg)
        if self.args.verbose:
            print(f"    {msg}", file=sys.stderr)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def build_authorize_params(self, response_type: str = "code",
                               redirect_uri: Optional[str] = None,
                               with_pkce: bool = True,
                               challenge_method: str = "S256",
                               verifier: Optional[str] = None,
                               challenge_raw: Optional[str] = None,
                               state: Optional[str] = None,
                               nonce: Optional[str] = None,
                               scope: Optional[str] = None,
                               extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        t = self.target
        params: Dict[str, Any] = {
            "client_id": t.client_id,
            "response_type": response_type,
            "redirect_uri": redirect_uri if redirect_uri is not None else t.redirect_uri,
            "scope": scope if scope is not None else t.scopes,
            "state": state if state is not None else f"oa-{secrets.token_urlsafe(12)}",
        }
        if nonce is not None:
            params["nonce"] = nonce
        if with_pkce:
            v = verifier or random_verifier()
            if challenge_raw is not None:
                # Send the challenge string verbatim, for malformed-input probes.
                params["code_challenge"] = challenge_raw
            elif challenge_method == "S256":
                params["code_challenge"] = s256_challenge(v)
            elif challenge_method == "plain":
                params["code_challenge"] = v
            else:
                params["code_challenge"] = challenge_method  # raw invalid value
            params["code_challenge_method"] = challenge_method
        if extra:
            params.update(extra)
        return params

    def probe_authorize(self, params: Dict[str, Any],
                        label: str) -> Dict[str, Any]:
        """GET the authorization endpoint and classify the response."""
        ep = self.target.auth_endpoint
        rec: Dict[str, Any] = {"probe": label}
        if not ep:
            rec.update({"outcome": "no-endpoint", "detail": "authorization_endpoint unknown"})
            return rec
        resp = self.http.get(ep, params=params)
        rec["request"] = redact_url(build_url_with_params(ep, params))
        if not resp.ok:
            rec.update({"outcome": "transport-error", "detail": resp.transport_error})
            self.log(f"{label}: transport error - {resp.transport_error}")
            return rec

        rec["status"] = resp.status
        rec["state_sent"] = params.get("state")
        loc = resp.location_parts
        as_origin = _origin_of(self.target.issuer)
        as_host = _host_of(self.target.issuer)

        if loc:
            rec["location"] = redact_url(loc["raw"])
            loc_origin = _origin_of(loc["raw"])
            registered_host = _host_of(self.target.redirect_uri)
            loc_host = (loc["host"] or "").lower()

            if loc_host == (registered_host or "").lower():
                # Same host as the registered client URI: not an off-site redirect.
                equivalent = same_uri(base_url(loc["raw"]), self.target.redirect_uri)
                rec.update({
                    "outcome": "redirect-to-client",
                    "to_client": True,
                    "equivalent_to_registered": equivalent,
                })
                rec["query"] = {k: redact_value(k, v) for k, v in loc["query"].items()}
                rec["fragment"] = {k: redact_value(k, v) for k, v in loc["fragment"].items()}
                rec["error"] = loc["query"].get("error") or loc["fragment"].get("error")
                rec["has_code"] = bool(loc["query"].get("code") or loc["fragment"].get("code"))
                rec["tokens_in_query"] = sorted(
                    k for k in loc["query"] if k.lower() in
                    ("access_token", "id_token", "refresh_token", "code"))
                rec["tokens_in_fragment"] = sorted(
                    k for k in loc["fragment"] if k.lower() in
                    ("access_token", "id_token", "refresh_token", "code"))
                rec["state_echo"] = (loc["query"].get("state")
                                     or loc["fragment"].get("state"))
            elif loc_origin == as_origin or loc_host == (as_host or "").lower():
                rec.update({"outcome": "redirect-to-as", "to_client": False})
                rec["query"] = {k: redact_value(k, v) for k, v in loc["query"].items()}
                rec["error"] = loc["query"].get("error")
                rec["state_echo"] = (loc["query"].get("state")
                                     or loc["fragment"].get("state"))
            else:
                rec.update({"outcome": "redirect-off-site", "to_client": False,
                            "off_site_host": loc_host})
        elif resp.status in (400, 401, 403):
            rec.update({"outcome": "http-error"})
            body_json = parse_json_maybe(resp.text)
            if isinstance(body_json, dict):
                rec["error"] = body_json.get("error")
                rec["error_description"] = redact_value(
                    "error_description", str(body_json.get("error_description", "")))
                # RFC 6749 s4.1.2.1: state MUST be returned on error responses too.
                rec["state_echo"] = body_json.get("state")
            rec["body_snippet"] = redact_body_snippet(resp.text)
        elif resp.status == 200:
            rec.update({"outcome": "html-200"})
            rec["body_snippet"] = redact_body_snippet(resp.text)
            rec["looks_like_login"] = bool(re.search(
                r"<input[^>]+type=[\"']?password|name=[\"']?(login|username|j_username)"
                r"|sign\s*in|log\s*in",
                resp.text, re.IGNORECASE))
        else:
            rec.update({"outcome": f"status-{resp.status}"})
            rec["body_snippet"] = redact_body_snippet(resp.text)

        self.log(f"{label}: HTTP {resp.status} -> {rec.get('outcome')}")
        return rec
