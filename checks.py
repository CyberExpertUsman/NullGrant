"""The audit checks. Each takes an AuditContext and appends exactly one Finding.

Every check treats an unreachable endpoint as INDETERMINATE. A false PASS is the most
damaging thing an audit tool can emit, so no check reports a pass it did not earn.
"""

from __future__ import annotations

import base64
import binascii
import secrets
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Tuple

from .context import AuditContext
from .model import (
    STATUS_FAIL,
    STATUS_INDETERMINATE,
    STATUS_PASS,
    STATUS_WARN,
    Finding,
)
from .util import (
    _host_of,
    parse_json_maybe,
    random_verifier,
    redact_body_snippet,
    redact_url,
    redact_value,
    scan_for_internal_detail,
)
from .variants import (
    IMPLICIT_TYPES,
    RESPONSE_TYPES_TO_ENUMERATE,
    build_redirect_variants,
)

def check_discovery(ctx: AuditContext) -> None:
    t = ctx.target
    md = t.metadata
    ev: List[Dict[str, Any]] = []
    problems: List[str] = []

    issuer_url = urllib.parse.urlsplit(t.issuer)
    if issuer_url.scheme != "https":
        problems.append(f"Issuer URL uses '{issuer_url.scheme}://' rather than https://")
    if t.auth_endpoint and not t.auth_endpoint.startswith("https://"):
        problems.append("authorization_endpoint is not HTTPS")
    if t.token_endpoint and not t.token_endpoint.startswith("https://"):
        problems.append("token_endpoint is not HTTPS")
    if t.redirect_uri and not t.redirect_uri.startswith("https://"):
        if urllib.parse.urlsplit(t.redirect_uri).hostname not in ("localhost", "127.0.0.1", "::1"):
            problems.append("Registered redirect_uri is not HTTPS (localhost is exempt per RFC 8252)")

    ev.append({
        "issuer": t.issuer,
        "metadata_source": t.metadata_source,
        "metadata_error": t.metadata_error,
        "authorization_endpoint": t.auth_endpoint,
        "token_endpoint": t.token_endpoint,
        "jwks_uri": t.jwks_uri,
        "client_type": t.client_type,
    })

    if t.metadata_source:
        # issuer identity must match
        declared = md.get("issuer")
        if declared and declared.rstrip("/") != t.issuer.rstrip("/"):
            problems.append(
                f"Discovery 'issuer' ({declared}) does not match the URL it was fetched from ({t.issuer})")
        rts = md.get("response_types_supported")
        ev.append({"response_types_supported": rts})
        if isinstance(rts, list):
            implicit = [r for r in rts if r in IMPLICIT_TYPES]
            if implicit:
                problems.append(
                    "Metadata advertises implicit/hybrid response types: " + ", ".join(map(str, implicit)))
        methods = md.get("code_challenge_methods_supported")
        ev.append({"code_challenge_methods_supported": methods})
        if methods is None:
            problems.append("Metadata does not advertise code_challenge_methods_supported (PKCE support unclear)")
        elif "S256" not in methods:
            problems.append("S256 is not among code_challenge_methods_supported")
        if isinstance(methods, list) and "plain" in methods:
            problems.append("'plain' code_challenge_method is supported - RFC 7636 s4.2 says it MUST NOT be used unless S256 is unsupported")
        grants = md.get("grant_types_supported")
        ev.append({"grant_types_supported": grants})
        tam = md.get("token_endpoint_auth_methods_supported")
        ev.append({"token_endpoint_auth_methods_supported": tam})
        if isinstance(tam, list) and "none" in tam and t.client_type == "confidential":
            problems.append("Confidential client, but token endpoint advertises 'none' client authentication")
        ev.append({
            "tls_client_certificate_bound_access_tokens": md.get("tls_client_certificate_bound_access_tokens"),
            "mtls_endpoint_aliases": md.get("mtls_endpoint_aliases"),
            "authorization_signing_alg_values_supported": md.get("authorization_signing_alg_values_supported"),
        })
    else:
        problems.append(f"No discovery document could be retrieved: {t.metadata_error}")

    # Problems derivable from the URLs alone remain valid even if the host is unreachable.
    url_only_problems = [p for p in problems
                         if "not HTTPS" in p or p.startswith("Issuer URL uses")
                         or p.startswith("Registered redirect_uri")]

    if not t.metadata_source and not t.metadata_reachable and not url_only_problems:
        # Nothing answered. Report uncertainty, never a pass.
        status, severity = STATUS_INDETERMINATE, "INFO"
        summary = (f"The authorization server did not answer any request "
                   f"({t.metadata_error or 'unreachable'}). No conclusion is drawn.")
        rec = ("Confirm the issuer URL, network reachability, firewall rules and TLS trust "
               "(use --insecure-tls only for a lab CA), then re-run.")
    elif problems:
        status = STATUS_FAIL
        severity = "HIGH" if url_only_problems else "MEDIUM"
        summary = f"{len(problems)} configuration problem(s) found in transport/discovery."
        rec = ("Serve all OAuth endpoints over TLS only, publish a valid discovery document whose "
               "'issuer' matches its own URL, advertise S256 (not plain), and do not advertise "
               "implicit or hybrid response types.")
    else:
        status = STATUS_PASS
        severity = "INFO"
        summary = "Endpoints are HTTPS and the discovery document is internally consistent."
        rec = "No action required."

    ev.append({"problems": problems})
    ctx.add(Finding(
        check_id="discovery-transport",
        title="TLS, discovery document and advertised capabilities",
        status=status,
        severity=severity,
        summary=summary,
        evidence=ev,
        recommendation=rec,
        references=["RFC 8414", "RFC 9700 s2.1", "OpenID Connect Discovery 1.0"],
    ))

def check_redirect_uri_strictness(ctx: AuditContext) -> None:
    t = ctx.target
    variants = build_redirect_variants(t.redirect_uri)
    registered_host = _host_of(t.redirect_uri)
    # Origin comparison happens once, centrally, in AuditContext.probe_authorize, which
    # classifies each response as redirect-to-client / redirect-to-as / redirect-off-site.
    # Recomputing origins here would duplicate that policy in a second place.

    open_redirects: List[Dict[str, Any]] = []
    loose_accepts: List[Dict[str, Any]] = []
    equivalent_accepts: List[Dict[str, Any]] = []
    rejects: List[Dict[str, Any]] = []
    indeterminates: List[Dict[str, Any]] = []
    control_seen = False

    for v in variants:
        params = ctx.build_authorize_params(redirect_uri=v["uri"])
        rec = ctx.probe_authorize(params, f"redirect-variant[{v['id']}]")
        entry = {
            "variant": v["id"],
            "description": v["description"],
            "redirect_uri_sent": v["uri"],
            "expected": "accept" if v["expect"] == "accept" else "reject",
            "outcome": rec.get("outcome"),
            "http_status": rec.get("status"),
            "state": rec.get("state_sent"),
        }
        if rec.get("location"):
            entry["location"] = rec["location"]
        if rec.get("error"):
            entry["error"] = rec["error"]
        if rec.get("off_site_host"):
            entry["off_site_host"] = rec["off_site_host"]
        if rec.get("detail"):
            entry["detail"] = rec["detail"]

        outcome = rec.get("outcome")

        if outcome in ("transport-error", "no-endpoint"):
            indeterminates.append(entry)
            continue

        if outcome == "redirect-off-site":
            # Redirected to a host that is neither the registered client nor the AS itself.
            entry["verdict"] = "OPEN REDIRECT"
            open_redirects.append(entry)
            continue

        if outcome == "redirect-to-client":
            if rec.get("equivalent_to_registered"):
                entry["verdict"] = "accepted (RFC 3986-equivalent to the registered URI)"
                equivalent_accepts.append(entry)
                if v["id"] == "control-exact":
                    control_seen = True
            else:
                entry["verdict"] = "accepted a non-identical URI"
                loose_accepts.append(entry)
            continue

        if outcome == "http-error":
            entry["verdict"] = f"rejected with HTTP {rec.get('status')}"
            rejects.append(entry)
            continue

        if outcome == "redirect-to-as":
            err = (rec.get("error") or "").lower()
            entry["error"] = rec.get("error")
            if err in ("invalid_request", "invalid_redirect_uri", "access_denied",
                       "unauthorized_client", "unsupported_response_type"):
                entry["verdict"] = f"rejected with error={err}"
                rejects.append(entry)
            else:
                # Sent to the AS's own login/consent page: validation has not happened yet.
                entry["verdict"] = "AS-hosted page reached before redirect_uri validation"
                indeterminates.append(entry)
            continue

        if outcome == "html-200":
            entry["looks_like_login"] = rec.get("looks_like_login")
            entry["verdict"] = "AS-hosted HTML page; validation outcome unknown"
            indeterminates.append(entry)
            continue

        entry["verdict"] = "inconclusive"
        indeterminates.append(entry)

    # An "accept"-expected variant that was rejected is over-strict but harmless; note it only.
    over_strict = [x for x in rejects + indeterminates
                   if x.get("expected") == "accept" and x["variant"] != "control-exact"]

    ev = [
        {"registered_redirect_uri": t.redirect_uri, "registered_host": registered_host,
         "authorization_endpoint": t.auth_endpoint, "variants_tested": len(variants)},
        {"rejected": rejects},
        {"accepted_equivalent": equivalent_accepts},
        {"accepted_loosely": loose_accepts},
        {"open_redirect_confirmed": open_redirects},
        {"indeterminate": indeterminates},
        {"over_strict_but_harmless": over_strict},
    ]

    if open_redirects:
        status, severity = STATUS_FAIL, "CRITICAL"
        summary = (f"{len(open_redirects)} redirect_uri variant(s) caused a redirect to a host "
                   f"other than the registered client and the authorization server.")
        rec = ("Validate redirect_uri by exact string comparison against the registered value "
               "(RFC 6749 s3.1.2.3 / RFC 9700 s2.1.3). Reject the request with "
               "error=invalid_request on an AS-hosted page and never redirect to a non-registered URI.")
    elif loose_accepts:
        status, severity = STATUS_FAIL, "HIGH"
        summary = (f"{len(loose_accepts)} non-identical redirect_uri variant(s) were accepted, "
                   f"indicating prefix or substring matching rather than exact matching.")
        rec = ("Switch to exact string matching for redirect_uri. Prefix, wildcard and "
               "substring matching enable authorization-code and token theft (RFC 9700 s2.1.3).")
    elif rejects and not indeterminates:
        status, severity = STATUS_PASS, "INFO"
        summary = (f"{len(rejects)} of {len(variants)} redirect_uri variant(s) were rejected and "
                   f"{len(equivalent_accepts)} resolved to the exact registered URI. No non-identical "
                   f"URI was accepted.")
        if over_strict:
            summary += (f" Note: {len(over_strict)} benign-equivalent variant(s) "
                        f"({', '.join(x['variant'] for x in over_strict)}) were also refused; that is "
                        f"stricter than required but not a weakness.")
        rec = "No action required."
    elif rejects:
        status, severity = STATUS_WARN, "LOW"
        summary = (f"{len(rejects)} variant(s) rejected, {len(indeterminates)} inconclusive "
                   f"(server returned a login page before validating redirect_uri).")
        rec = ("Re-run with an authenticated session (--session-cookie) to complete the "
               "inconclusive cases, or confirm in configuration that redirect_uri matching is exact.")
    else:
        status, severity = STATUS_INDETERMINATE, "INFO"
        summary = ("Could not determine redirect_uri validation behaviour - every probe stopped "
                   "at a login page or failed at the transport layer.")
        rec = ("Supply an authenticated session with --session-cookie, or verify "
               "redirect_uri matching in the AS configuration directly.")

    if not control_seen and rejects:
        ev.append({"note": "The exact registered URI was not observed completing a redirect to the "
                           "client during this unauthenticated run; classification relies on the AS's "
                           "error responses."})

    ctx.add(Finding(
        check_id="redirect-uri-strictness",
        title="Strict redirect_uri validation (open redirection)",
        status=status,
        severity=severity,
        summary=summary,
        evidence=ev,
        recommendation=rec,
        references=["RFC 6749 s3.1.2.3, s4.1.3", "RFC 9700 s2.1.3", "RFC 8252 s7.3"],
    ))

def check_pkce(ctx: AuditContext) -> None:
    t = ctx.target
    ev: List[Dict[str, Any]] = [{"client_type": t.client_type,
                                 "authorization_endpoint": t.auth_endpoint}]
    problems: List[str] = []
    notes: List[str] = []
    rejected: Dict[str, bool] = {}
    confirmed_missing_pkce = False
    confirmed_weak_pkce = False

    REJECT_ERRORS = ("invalid_request", "invalid_grant", "unauthorized_client",
                     "invalid_client", "access_denied")

    def classify(rec: Dict[str, Any]) -> str:
        """'issued' | 'rejected' | 'unverified'"""
        if rec.get("has_code") or rec.get("tokens_in_query") or rec.get("tokens_in_fragment"):
            return "issued"
        if (rec.get("error") or "").lower() in REJECT_ERRORS:
            return "rejected"
        return "unverified"

    # 2a. metadata
    methods = t.metadata.get("code_challenge_methods_supported")
    ev.append({"code_challenge_methods_supported": methods})
    plain_advertised = False
    if isinstance(methods, list):
        if "plain" in methods:
            plain_advertised = True
            problems.append("Discovery advertises the 'plain' code_challenge_method")
        if "S256" not in methods:
            problems.append("Discovery does not advertise 'S256'")
    elif methods is None:
        notes.append("Discovery does not list code_challenge_methods_supported")

    # 2b. live probe: no PKCE at all
    rec = ctx.probe_authorize(ctx.build_authorize_params(with_pkce=False), "pkce-absent")
    ev.append({"probe": "authorization request with no code_challenge", **rec})
    v_absent = classify(rec)
    rejected["absent"] = v_absent == "rejected"
    if v_absent == "issued":
        confirmed_missing_pkce = True
        problems.append("Server issued an authorization code to a request with no code_challenge")
    elif v_absent == "rejected":
        notes.append(f"Server rejected the PKCE-less request with error={rec.get('error')}")
    else:
        notes.append("PKCE-less request reached a login/consent page; enforcement could not be "
                     "confirmed without an authenticated session")

    # 2c. live probe: plain method
    v = random_verifier()
    rec = ctx.probe_authorize(
        ctx.build_authorize_params(challenge_method="plain", verifier=v), "pkce-plain")
    ev.append({"probe": "authorization request with code_challenge_method=plain", **rec})
    v_plain = classify(rec)
    rejected["plain"] = v_plain == "rejected"
    if v_plain == "issued":
        confirmed_weak_pkce = True
        problems.append("Server issued an authorization code for a 'plain' PKCE challenge")
    elif v_plain == "rejected":
        notes.append(f"Server rejected 'plain' with error={rec.get('error')}")
    else:
        notes.append("Response to the 'plain' challenge was not conclusive")

    # 2d. live probe: undersized challenge (RFC 7636 requires 43-128 characters)
    rec = ctx.probe_authorize(
        ctx.build_authorize_params(challenge_method="S256", challenge_raw="short"),
        "pkce-short-challenge")
    ev.append({"probe": "authorization request with a 5-character code_challenge", **rec})
    v_short = classify(rec)
    rejected["short"] = v_short == "rejected"
    if v_short == "issued":
        confirmed_weak_pkce = True
        problems.append("Server accepted a code_challenge shorter than the 43-character RFC 7636 minimum")
    elif v_short == "rejected":
        notes.append("Server rejected the undersized code_challenge")

    # 2e. live probe: challenge that is not base64url at all
    rec = ctx.probe_authorize(
        ctx.build_authorize_params(challenge_method="S256", challenge_raw="!!!not-base64url!!!"),
        "pkce-invalid-encoding")
    ev.append({"probe": "authorization request with a non-base64url code_challenge", **rec})
    v_enc = classify(rec)
    rejected["encoding"] = v_enc == "rejected"
    if v_enc == "issued":
        problems.append("Server accepted a code_challenge that is not valid base64url")
    elif v_enc == "rejected":
        notes.append("Server rejected a malformed code_challenge")

    # 2f. bogus challenge method
    rec = ctx.probe_authorize(
        ctx.build_authorize_params(challenge_method="bogus-method", verifier="bogus"),
        "pkce-bogus-method")
    ev.append({"probe": "authorization request with code_challenge_method=bogus-method", **rec})
    v_method = classify(rec)
    rejected["method"] = v_method == "rejected"
    if v_method == "issued":
        problems.append("Server accepted an unrecognised code_challenge_method")
    elif v_method == "rejected":
        notes.append("Server rejected an unknown code_challenge_method")

    # 2g. token endpoint: exchange a real code without the verifier
    token_result = None
    if ctx.args.auth_code and t.token_endpoint:
        params = {
            "grant_type": "authorization_code",
            "code": ctx.args.auth_code,
            "redirect_uri": t.redirect_uri,
            "client_id": t.client_id,
        }
        if t.client_secret:
            params["client_secret"] = t.client_secret
        resp = ctx.http.post_form(t.token_endpoint, params)
        body = parse_json_maybe(resp.text) or {}
        token_result = {
            "probe": "token exchange of a real code with NO code_verifier",
            "status": resp.status,
            "error": body.get("error") if isinstance(body, dict) else None,
            "issued_token": isinstance(body, dict) and "access_token" in body,
        }
        ev.append(token_result)
        if isinstance(body, dict) and "access_token" in body:
            confirmed_missing_pkce = True
            problems.append("Token endpoint issued tokens for a code redeemed without a code_verifier")
    elif t.client_type == "public" and not ctx.args.auth_code:
        notes.append("Skipped token-endpoint PKCE check; pass a single-use lab authorization code "
                     "with --auth-code to enable it")

    ev.append({
        "problems": problems,
        "notes": notes,
        "live_probe_results": {
            "pkce_absent": v_absent,
            "plain_method": v_plain,
            "short_challenge": v_short,
            "non_base64url_challenge": v_enc,
            "unknown_method": v_method,
        },
        "token_endpoint_probe": token_result,
    })

    if confirmed_missing_pkce:
        status, severity = STATUS_FAIL, "CRITICAL"
        summary = "PKCE is not enforced - an authorization code was issued or redeemed without a code_verifier."
        rec = ("Require code_challenge on every authorization request and require a matching "
               "code_verifier at the token endpoint for all clients, especially public clients "
               "(RFC 9700 s2.1.2). Reject requests without PKCE with error=invalid_request.")
    elif confirmed_weak_pkce:
        status, severity = STATUS_FAIL, "HIGH"
        summary = "PKCE is present but weak - a 'plain' or malformed challenge was accepted."
        rec = ("Support only the S256 code_challenge_method, remove 'plain' from advertised and "
               "accepted values, and enforce the 43-128 character challenge length and base64url "
               "encoding (RFC 7636 s4.1, s4.2).")
    elif plain_advertised and not rejected["plain"]:
        status, severity = STATUS_FAIL, "MEDIUM"
        summary = ("Discovery advertises the 'plain' code_challenge_method and the live probe "
                   "could not confirm that it is refused.")
        rec = ("Remove 'plain' from code_challenge_methods_supported and reject it at the "
               "authorization endpoint. 'plain' gives no protection against code interception.")
    elif plain_advertised:
        status, severity = STATUS_WARN, "LOW"
        summary = ("'plain' is advertised in discovery metadata, although the live probe with "
                   "code_challenge_method=plain was rejected.")
        rec = "Remove 'plain' from code_challenge_methods_supported so it cannot be requested."
    elif problems:
        status, severity = STATUS_WARN, "MEDIUM"
        summary = "PKCE configuration problems detected in discovery metadata: " + "; ".join(problems)
        rec = "Advertise and enforce S256 only."
    elif rejected["absent"] and rejected["plain"]:
        status, severity = STATUS_PASS, "INFO"
        summary = ("PKCE is enforced: a request with no code_challenge was rejected, and 'plain', "
                   "undersized, non-base64url and unknown-method challenges were all refused.")
        rec = "No action required."
    elif rejected["absent"]:
        status, severity = STATUS_WARN, "LOW"
        summary = ("Requests without code_challenge are rejected, but some malformed-challenge "
                   "probes were inconclusive.")
        rec = ("Confirm that S256 is the only accepted method and that challenge length and "
               "encoding are validated.")
    else:
        status, severity = STATUS_INDETERMINATE, "INFO"
        summary = ("No PKCE weakness confirmed, but enforcement could not be proven from an "
                   "unauthenticated position.")
        rec = ("Confirm in AS configuration that PKCE is mandatory for this client type, or re-run "
               "with --session-cookie (and --auth-code for the token-endpoint half of the check).")

    ctx.add(Finding(
        check_id="pkce-enforcement",
        title="Proof Key for Code Exchange (PKCE) enforcement",
        status=status,
        severity=severity,
        summary=summary,
        evidence=ev,
        recommendation=rec,
        references=["RFC 7636", "RFC 9700 s2.1.2", "RFC 8252 s8.3"],
    ))

def check_response_types(ctx: AuditContext) -> None:
    t = ctx.target
    declared = t.metadata.get("response_types_supported")
    ev: List[Dict[str, Any]] = [{"declared_in_metadata": declared}]

    served: List[str] = []
    rejected: List[str] = []
    unknown: List[str] = []
    rows: List[Dict[str, Any]] = []

    for rt, description in RESPONSE_TYPES_TO_ENUMERATE:
        rec = ctx.probe_authorize(ctx.build_authorize_params(response_type=rt),
                                  f"response-type[{rt}]")
        row = {
            "response_type": rt,
            "description": description,
            "declared": bool(isinstance(declared, list) and rt in declared),
            "http_status": rec.get("status"),
            "outcome": rec.get("outcome"),
            "state": rec.get("state_sent"),
            "state_echo": rec.get("state_echo"),
            "tokens_in_query": rec.get("tokens_in_query"),
            "tokens_in_fragment": rec.get("tokens_in_fragment"),
            "has_code": rec.get("has_code"),
        }
        err = (rec.get("error") or "").lower()
        if rec.get("error"):
            row["error"] = rec.get("error")
        if rec.get("location"):
            row["location"] = rec["location"]

        delivered_tokens = bool(rec.get("tokens_in_query") or rec.get("tokens_in_fragment"))
        if err in ("unsupported_response_type", "invalid_request", "unauthorized_client"):
            row["verdict"] = "rejected"
            rejected.append(rt)
        elif rec.get("has_code") or delivered_tokens:
            row["verdict"] = "served"
            row["credentials_delivered"] = (rec.get("tokens_in_query") or []) + \
                                           (rec.get("tokens_in_fragment") or [])
            served.append(rt)
        elif rec.get("outcome") in ("redirect-to-as", "html-200") and not err:
            # Reached a login page: the server did not reject the response_type up front.
            row["verdict"] = "not-rejected-up-front"
            if row["declared"]:
                served.append(rt)
            else:
                unknown.append(rt)
        else:
            row["verdict"] = "inconclusive"
            if row["declared"]:
                served.append(rt)
            else:
                unknown.append(rt)
        rows.append(row)

    implicit_served = sorted({r for r in served if r in IMPLICIT_TYPES})
    ev.append({"probes": rows})
    ev.append({"served_or_advertised": sorted(set(served)),
               "explicitly_rejected": rejected,
               "inconclusive": unknown,
               "implicit_or_hybrid_available": implicit_served})

    problems = []
    if implicit_served:
        problems.append("Implicit/hybrid response types are available: " + ", ".join(implicit_served))
    if "code" not in served and isinstance(declared, list) and "code" not in declared:
        problems.append("The authorization code response_type does not appear to be supported")
    if served and "none" in served:
        problems.append("response_type=none is served")

    if implicit_served:
        status, severity = STATUS_FAIL, "HIGH"
        summary = f"Server answers {len(implicit_served)} implicit/hybrid response type(s)."
        rec = ("Disable the implicit and hybrid flows. Remove token, id_token and any combination "
               "response types from response_types_supported and reject them at the authorization "
               "endpoint with error=unsupported_response_type (RFC 9700 s2.1.1). Use authorization "
               "code + PKCE for all clients.")
    elif problems:
        status, severity = STATUS_WARN, "MEDIUM"
        summary = "; ".join(problems)
        rec = "Restrict supported response types to 'code' only."
    elif rejected and not unknown:
        status, severity = STATUS_PASS, "INFO"
        summary = (f"Only the authorization code flow is served; {len(rejected)} other response "
                   f"type(s) were explicitly rejected.")
        rec = "No action required."
    elif unknown:
        status, severity = STATUS_INDETERMINATE, "INFO"
        summary = (f"No implicit flow confirmed. {len(unknown)} response type(s) could not be "
                   f"conclusively rejected without an authenticated session.")
        rec = ("Re-run with --session-cookie to force the server past the login page, or check "
               "response_types_supported in the AS configuration.")
    else:
        status, severity = STATUS_PASS, "INFO"
        summary = "No implicit or hybrid response type is available."
        rec = "No action required."

    ev.append({"problems": problems})
    ctx.add(Finding(
        check_id="response-type-enumeration",
        title="Supported response types (implicit/hybrid flow exposure)",
        status=status,
        severity=severity,
        summary=summary,
        evidence=ev,
        recommendation=rec,
        references=["RFC 9700 s2.1.1", "RFC 6749 s3.1.1", "OAuth 2.0 Security BCP"],
    ))

def check_token_leakage(ctx: AuditContext) -> None:
    """Inspect every captured client-bound redirect for credentials in the wrong place."""
    query_tokens: List[Dict[str, Any]] = []
    fragment_tokens: List[Dict[str, Any]] = []
    state_issues: List[Dict[str, Any]] = []
    inspected = 0
    seen_locations = set()

    def walk(obj: Any):
        """Yield every dict in the evidence tree that describes a redirect we captured."""
        if isinstance(obj, dict):
            if isinstance(obj.get("location"), str):
                yield obj
            for v in obj.values():
                yield from walk(v)
        elif isinstance(obj, list):
            for v in obj:
                yield from walk(v)

    for f in ctx.findings:
        for entry in walk(f.evidence):
            loc = entry.get("location")
            if not isinstance(loc, str) or not loc or loc in seen_locations:
                continue
            seen_locations.add(loc)
            if _host_of(loc) != _host_of(ctx.target.redirect_uri):
                continue  # not a client-bound redirect
            inspected += 1
            context = (entry.get("probe") or entry.get("variant")
                       or entry.get("response_type") or f.check_id)

            tq = entry.get("tokens_in_query")
            tf = entry.get("tokens_in_fragment")
            if tq is None or tf is None:
                p = urllib.parse.urlsplit(loc)
                q = dict(urllib.parse.parse_qsl(p.query, keep_blank_values=True))
                fr = dict(urllib.parse.parse_qsl(p.fragment, keep_blank_values=True))
                keys = ("access_token", "id_token", "refresh_token", "code")
                tq = tq if tq is not None else sorted(k for k in q if k.lower() in keys)
                tf = tf if tf is not None else sorted(k for k in fr if k.lower() in keys)

            for k in tq:
                if k.lower() in ("access_token", "id_token", "refresh_token"):
                    query_tokens.append({"parameter": k, "component": "query",
                                         "context": context, "redirect_url": redact_url(loc)})
                # an authorization code belongs in the query component; that is correct
            for k in tf:
                rec = {"parameter": k, "component": "fragment", "context": context,
                       "redirect_url": redact_url(loc)}
                if k.lower() in ("access_token", "id_token", "refresh_token"):
                    fragment_tokens.append(rec)
                elif k.lower() == "code":
                    rec["note"] = "authorization code delivered in the fragment"
                    fragment_tokens.append(rec)

            # state reflection
            sent = entry.get("state") or entry.get("state_sent")
            returned = entry.get("state_echo")
            if returned is None and isinstance(loc, str):
                p = urllib.parse.urlsplit(loc)
                q = dict(urllib.parse.parse_qsl(p.query, keep_blank_values=True))
                fr = dict(urllib.parse.parse_qsl(p.fragment, keep_blank_values=True))
                returned = q.get("state") or fr.get("state")
            if sent and returned and returned != sent:
                state_issues.append({"issue": "state value altered in transit",
                                     "sent": sent, "returned": returned, "context": context})
            elif sent and not returned:
                state_issues.append({"issue": "state not echoed back",
                                     "sent": redact_value("state", str(sent)),
                                     "context": context})

    ev: List[Dict[str, Any]] = [
        {"client_bound_redirects_inspected": inspected},
        {"credentials_in_query_component": query_tokens},
        {"credentials_in_fragment_component": fragment_tokens},
        {"state_handling_issues": state_issues},
    ]

    if query_tokens:
        status, severity = STATUS_FAIL, "CRITICAL"
        summary = (f"{len(query_tokens)} token(s) appeared in the QUERY component of a "
                   f"client-bound redirect URL. Query strings leak through Referer headers, "
                   f"browser history, proxies and web server access logs.")
        rec = ("Never return access_token, id_token or refresh_token in a query string. Disable the "
               "implicit and hybrid flows so no credential transits the front channel at all "
               "(RFC 9700 s2.1.1) and use authorization code + PKCE instead.")
    elif fragment_tokens:
        status, severity = STATUS_FAIL, "HIGH"
        summary = (f"{len(fragment_tokens)} credential parameter(s) observed in the fragment of a "
                   f"client-bound redirect URL.")
        rec = ("Prefer authorization code + PKCE so no token is delivered through the browser. "
               "Ensure authorization codes are single-use, bound to the client and the "
               "code_challenge, and expire within a minute (RFC 9700 s2.1.4).")
    elif state_issues:
        status, severity = STATUS_WARN, "MEDIUM"
        summary = f"State parameter handling anomalies observed ({len(state_issues)})."
        rec = ("Echo the client's 'state' value verbatim on every response, including error "
               "responses, so clients can perform CSRF protection (RFC 6749 s10.12).")
    elif inspected == 0:
        status, severity = STATUS_INDETERMINATE, "INFO"
        summary = ("No client-bound redirect was observed during this run, so there were no "
                   "redirect URLs to inspect for leaked credentials.")
        rec = ("Re-run with --session-cookie so the audit reaches the redirect stage, or supply a "
               "single-use lab authorization code with --auth-code to exercise the token endpoint.")
    else:
        status, severity = STATUS_PASS, "INFO"
        summary = (f"Inspected {inspected} client-bound redirect URL(s); no credential appeared "
                   f"where it should not, and state was echoed correctly.")
        rec = "No action required."

    ctx.add(Finding(
        check_id="token-leakage-in-redirect",
        title="Credentials exposed in redirect URLs",
        status=status,
        severity=severity,
        summary=summary,
        evidence=ev,
        recommendation=rec,
        references=["RFC 9700 s2.1.1, s2.1.4", "RFC 6749 s4.2.2, s10.3", "RFC 6819 s5.2.3.4"],
    ))

def check_token_endpoint_auth(ctx: AuditContext) -> None:
    t = ctx.target
    if not t.token_endpoint:
        ctx.add(Finding(
            check_id="token-endpoint-auth",
            title="Token endpoint client authentication",
            status=STATUS_INDETERMINATE,
            severity="INFO",
            summary="Token endpoint unknown (no discovery document); check skipped.",
            evidence=[{"token_endpoint": None}],
            recommendation="Supply --token-endpoint explicitly to enable this check.",
            references=["RFC 9700 s2.1.1"],
        ))
        return

    ev: List[Dict[str, Any]] = [{"token_endpoint": t.token_endpoint, "client_type": t.client_type}]
    problems: List[str] = []
    advisories: List[str] = []   # things that cannot be verified from outside the AS

    # Probe with an unusable code and NO client credentials. We expect invalid_client for a
    # confidential client, and invalid_grant/invalid_request for a public client using PKCE.
    resp = ctx.http.post_form(t.token_endpoint, {
        "grant_type": "authorization_code",
        "code": "nullgrant-invalid-code-" + secrets.token_urlsafe(8),
        "redirect_uri": t.redirect_uri,
        "client_id": t.client_id,
    })
    if not resp.ok:
        # Never report PASS for a probe that never reached the server.
        ctx.add(Finding(
            check_id="token-endpoint-auth",
            title="Token endpoint client authentication and error hygiene",
            status=STATUS_INDETERMINATE,
            severity="INFO",
            summary=f"Token endpoint could not be reached: {resp.transport_error}",
            evidence=[{"token_endpoint": t.token_endpoint,
                       "transport_error": resp.transport_error}],
            recommendation=("Confirm the token endpoint URL, network reachability and TLS "
                            "trust, then re-run. No conclusion is drawn from an unreachable "
                            "endpoint."),
            references=["RFC 9700 s2.1.1", "RFC 6749 s2.3"],
        ))
        return

    body = parse_json_maybe(resp.text) or {}
    err = body.get("error") if isinstance(body, dict) else None
    entry = {
        "probe": "POST token endpoint, no client authentication, deliberately invalid code",
        "http_status": resp.status,
        "error": err,
        "error_description": redact_value("error_description",
                                          str(body.get("error_description", ""))) if isinstance(body, dict) else None,
        "issued_access_token": isinstance(body, dict) and "access_token" in body,
        "internal_detail": scan_for_internal_detail(resp.text),
    }
    ev.append(entry)

    if isinstance(body, dict) and "access_token" in body:
        problems.append("Token endpoint issued a token in response to an unauthenticated request "
                        "carrying an invalid authorization code")
    if t.client_type == "confidential" and err != "invalid_client":
        problems.append(f"Confidential client: expected error=invalid_client, got error={err!r} "
                        f"- client authentication may not be required")
    if entry["internal_detail"]:
        problems.append("Token endpoint error response leaks implementation detail: "
                        + ", ".join(entry["internal_detail"]))

    # TLS check
    if not t.token_endpoint.startswith("https://"):
        problems.append("Token endpoint is not served over HTTPS")

    # refresh token behaviour for public clients. Whether rotation/reuse-detection is
    # enabled cannot be observed from outside without a real refresh token, so this is
    # an advisory to verify, not a failure.
    rt_supported = t.metadata.get("grant_types_supported")
    ev.append({"grant_types_supported": rt_supported})
    if t.client_type == "public" and isinstance(rt_supported, list) and "refresh_token" in rt_supported:
        advisories.append(
            "The refresh_token grant is advertised and this is a public client. Verify that "
            "refresh tokens are sender-constrained, or rotated on every use with reuse "
            "detection (RFC 9700 s2.2.2). This cannot be confirmed by external probing.")

    ev.append({"problems": problems, "advisories": advisories})

    if any("issued a token" in p for p in problems):
        status, severity = STATUS_FAIL, "CRITICAL"
    elif problems:
        status, severity = STATUS_FAIL, "HIGH"
    elif advisories:
        status, severity = STATUS_WARN, "MEDIUM"
    else:
        status, severity = STATUS_PASS, "INFO"

    parts = list(problems)
    if advisories:
        parts.append("To verify (not observable externally): " + " ".join(advisories))
    summary = ("; ".join(parts) if parts
               else "Token endpoint requires client authentication and returns clean error responses.")
    rec = ("Authenticate every client at the token endpoint, return error=invalid_client for failed "
           "authentication, and keep error responses free of stack traces."
           + (" For public clients, use rotating sender-constrained refresh tokens."
              if advisories else "")) if parts else "No action required."

    ctx.add(Finding(
        check_id="token-endpoint-auth",
        title="Token endpoint client authentication and error hygiene",
        status=status,
        severity=severity,
        summary=summary,
        evidence=ev,
        recommendation=rec,
        references=["RFC 9700 s2.1.1, s2.2.2", "RFC 6749 s2.3", "RFC 6819 s5.1.4"],
    ))

def check_jwks(ctx: AuditContext) -> None:
    t = ctx.target
    if not t.jwks_uri:
        ctx.add(Finding(
            check_id="jwks-hygiene",
            title="JWK Set hygiene",
            status=STATUS_INDETERMINATE,
            severity="INFO",
            summary="No jwks_uri published in discovery; check skipped.",
            evidence=[{"jwks_uri": None}],
            recommendation="Publish a JWKS URI if the AS signs ID tokens or access tokens.",
            references=["RFC 7517"],
        ))
        return

    resp = ctx.http.get(t.jwks_uri)
    ev: List[Dict[str, Any]] = [{"jwks_uri": t.jwks_uri, "http_status": resp.status}]
    problems: List[str] = []

    if not resp.ok:
        # An unreachable JWKS is not a clean JWKS. Report uncertainty, never a pass.
        ctx.add(Finding(
            check_id="jwks-hygiene",
            title="JWK Set hygiene",
            status=STATUS_INDETERMINATE,
            severity="INFO",
            summary=f"The JWKS endpoint could not be reached: {resp.transport_error}",
            evidence=ev + [{"transport_error": resp.transport_error}],
            recommendation=("Confirm the jwks_uri, network reachability and TLS trust, then "
                            "re-run. No conclusion is drawn from an unreachable endpoint."),
            references=["RFC 7517"],
        ))
        return

    if resp.status != 200:
        problems.append(f"JWKS endpoint returned HTTP {resp.status}")
        keys = []
    else:
        data = parse_json_maybe(resp.text)
        if not isinstance(data, dict) or "keys" not in data:
            problems.append("JWKS response is not a valid JWK Set")
            keys = []
        else:
            keys = data.get("keys") or []

    if not t.jwks_uri.startswith("https://"):
        problems.append("JWKS is not served over HTTPS")

    safe_keys = []
    for k in keys if isinstance(keys, list) else []:
        if not isinstance(k, dict):
            continue
        summary = {"kty": k.get("kty"), "kid": k.get("kid"), "alg": k.get("alg"),
                   "use": k.get("use"), "crv": k.get("crv")}
        safe_keys.append(summary)
        if k.get("kty") == "oct":
            problems.append("A symmetric (kty=oct) key is published in the public JWKS")
        if not k.get("kid"):
            problems.append("A key has no 'kid', which prevents key rotation")
        if k.get("kty") == "RSA" and k.get("n"):
            try:
                n_bytes = base64.urlsafe_b64decode(k["n"] + "=" * (-len(k["n"]) % 4))
                bits = len(n_bytes) * 8
                summary["rsa_modulus_bits"] = bits
                if bits < 2048:
                    problems.append(f"RSA key with a {bits}-bit modulus (minimum 2048)")
            except (binascii.Error, ValueError):
                problems.append("RSA modulus is not valid base64url")
        if k.get("kty") == "EC" and k.get("crv") in ("P-192", "secp192r1"):
            problems.append("Weak elliptic curve published")
        if k.get("alg") in ("none", "None", "NONE"):
            problems.append("A key advertises alg=none")
        for secret_field in ("d", "p", "q", "dp", "dq", "qi", "k"):
            if k.get(secret_field) and k.get("kty") != "oct":
                problems.append(f"Key material exposes private parameter '{secret_field}'")

    ev.append({"published_keys": safe_keys, "key_count": len(safe_keys)})
    ev.append({"internal_detail": scan_for_internal_detail(resp.text) if resp.ok else []})
    ev.append({"problems": problems})

    if problems:
        status = STATUS_FAIL
        severity = "CRITICAL" if any("private parameter" in p or "symmetric" in p for p in problems) else "MEDIUM"
        summary = f"{len(problems)} problem(s) in the published JWK Set."
        rec = ("Publish only public key material, give every key a 'kid', use RSA >= 2048 bits or "
               "P-256+, never publish symmetric or private keys, and rotate on a defined schedule.")
    else:
        status, severity = STATUS_PASS, "INFO"
        summary = f"JWKS published {len(safe_keys)} key(s), all public and adequately sized."
        rec = "No action required."

    ctx.add(Finding(
        check_id="jwks-hygiene",
        title="JWK Set hygiene",
        status=status,
        severity=severity,
        summary=summary,
        evidence=ev,
        recommendation=rec,
        references=["RFC 7517", "RFC 7518 s3.3", "RFC 9700 s2.1"],
    ))

def check_error_hygiene(ctx: AuditContext) -> None:
    t = ctx.target
    problems: List[str] = []
    samples: List[Dict[str, Any]] = []

    probes = []
    if t.auth_endpoint:
        probes.append(("authorization endpoint, unknown client_id",
                       lambda: ctx.http.get(t.auth_endpoint, params={
                           "client_id": "nullgrant-nonexistent-" + secrets.token_urlsafe(6),
                           "response_type": "code",
                           "redirect_uri": t.redirect_uri,
                       })))
        probes.append(("authorization endpoint, missing required parameters",
                       lambda: ctx.http.get(t.auth_endpoint, params={})))
        probes.append(("authorization endpoint, unknown parameter pollution",
                       lambda: ctx.http.get(t.auth_endpoint, params={
                           "client_id": t.client_id,
                           "response_type": "code",
                           "redirect_uri": t.redirect_uri,
                           "nonce": "x", "claims": "{}", "acr_values": "x",
                       })))
    if t.token_endpoint:
        probes.append(("token endpoint, unsupported grant_type",
                       lambda: ctx.http.post_form(t.token_endpoint, {
                           "grant_type": "urn:nullgrant:unsupported",
                           "client_id": t.client_id,
                       })))

    reachable = 0
    unreachable: List[str] = []
    for label, fn in probes:
        resp = fn()
        if not resp.ok:
            samples.append({"probe": label, "transport_error": resp.transport_error})
            unreachable.append(label)
            continue
        reachable += 1
        detail = scan_for_internal_detail(resp.text)
        samples.append({
            "probe": label,
            "http_status": resp.status,
            "body_snippet": redact_body_snippet(resp.text, 300),
            "internal_detail": detail,
            "server_header": resp.header("server"),
            "security_headers": {
                "strict-transport-security": resp.header("strict-transport-security"),
                "x-content-type-options": resp.header("x-content-type-options"),
                "x-frame-options": resp.header("x-frame-options"),
                "content-security-policy": (resp.header("content-security-policy") or "")[:120] or None,
            },
        })
        if detail:
            problems.append(f"{label}: leaks {', '.join(detail)}")
        if resp.status >= 500:
            problems.append(f"{label}: returned HTTP {resp.status}")

    if problems:
        status, severity = STATUS_FAIL, "MEDIUM"
        summary = f"{len(problems)} error response(s) disclose implementation detail."
        rec = ("Return only the standard OAuth error codes, suppress stack traces and internal "
               "paths, and never return HTTP 5xx for malformed client input.")
    elif reachable == 0:
        # No probe reached the server: there is nothing to conclude.
        status, severity = STATUS_INDETERMINATE, "INFO"
        summary = (f"None of the {len(probes)} error-handling probe(s) reached the server "
                   f"({unreachable[0] if unreachable else 'unknown'}: "
                   f"{samples[0].get('transport_error') if samples else 'no response'}).")
        rec = ("Confirm endpoint reachability and TLS trust, then re-run. An unreachable "
               "endpoint is not evidence of clean error handling.")
    elif unreachable:
        status, severity = STATUS_WARN, "LOW"
        summary = (f"{reachable} probe(s) produced clean error responses; {len(unreachable)} "
                   f"could not be reached and were not assessed.")
        rec = ("Re-run once all endpoints are reachable before treating this control as passing.")
    else:
        status, severity = STATUS_PASS, "INFO"
        summary = (f"All {reachable} malformed-request probe(s) produced clean, standard error "
                   f"responses with no implementation detail.")
        rec = "No action required."

    ctx.add(Finding(
        check_id="error-hygiene",
        title="Error response hygiene and information disclosure",
        status=status,
        severity=severity,
        summary=summary,
        evidence=[{"probes": samples}, {"problems": problems,
                                        "reachable_probes": reachable,
                                        "unreachable_probes": unreachable}],
        recommendation=rec,
        references=["RFC 6749 s5.2", "RFC 6819 s5.1.4"],
    ))

def check_state(ctx: AuditContext) -> None:
    """RFC 6749 s4.1.2 / s4.1.2.1 - the AS must return 'state' unchanged when sent.

    Note on scope: 'state' is the CLIENT's CSRF defence (RFC 6749 s10.12). The AS is not
    required to reject a request that omits it, and cannot detect a reused value because it
    does not track state. So probes B and C below are recorded as observations, not failures.
    Dropping or altering a state value the client DID send is a genuine failure, because it
    makes client-side CSRF protection impossible.
    """
    ev: List[Dict[str, Any]] = []
    problems: List[str] = []
    observations: List[str] = []
    definitive = 0
    inconclusive = 0

    DEFINITIVE = ("redirect-to-client", "http-error")

    # A. state sent -> must come back verbatim, including on error responses
    state_val = f"oa-state-{secrets.token_urlsafe(16)}"
    rec = ctx.probe_authorize(ctx.build_authorize_params(state=state_val), "state-echo")
    ev.append({"probe": "authorization request carrying a unique state value",
               "state_sent": state_val, **rec})
    outcome = rec.get("outcome")
    echoed = rec.get("state_echo")
    if outcome in DEFINITIVE or (outcome == "redirect-to-as" and rec.get("error")):
        definitive += 1
        if echoed is None:
            problems.append("The server produced an OAuth response but did not return 'state', "
                            "so the client cannot perform CSRF validation (RFC 6749 s4.1.2)")
        elif echoed != state_val:
            problems.append(f"'state' was altered in transit: sent {state_val!r}, "
                            f"received {echoed!r}")
        else:
            observations.append("state was echoed back verbatim")
    else:
        inconclusive += 1
        observations.append("request stopped at an AS-hosted login/consent page; "
                            "state echo not observable")

    # B. state omitted -> observation only
    params = ctx.build_authorize_params()
    params.pop("state", None)
    rec = ctx.probe_authorize(params, "state-absent")
    ev.append({"probe": "authorization request with NO state parameter", **rec})
    if rec.get("outcome") in DEFINITIVE:
        definitive += 1
        if rec.get("has_code") or rec.get("tokens_in_query") or rec.get("tokens_in_fragment"):
            observations.append(
                "Server issued a credential to a request with no state. This is permitted - "
                "state is the client's responsibility - but it means the client must not rely "
                "on the AS to enforce it.")
        elif rec.get("error"):
            observations.append(f"Server rejected a stateless request with error={rec.get('error')} "
                                f"(stricter than the RFC requires)")
    else:
        inconclusive += 1

    # C. same state value reused -> observation only
    dup = f"oa-dup-{secrets.token_urlsafe(12)}"
    r1 = ctx.probe_authorize(ctx.build_authorize_params(state=dup), "state-reuse-first")
    r2 = ctx.probe_authorize(ctx.build_authorize_params(state=dup), "state-reuse-second")
    ev.append({"probe": "the SAME state value sent twice",
               "state_sent": dup,
               "first": r1, "second": r2})
    both_definitive = (r1.get("outcome") in DEFINITIVE and r2.get("outcome") in DEFINITIVE)
    if both_definitive:
        definitive += 1
        if r1.get("error") == r2.get("error") and not r1.get("has_code"):
            observations.append("Both requests with the duplicated state produced the same "
                                "outcome; the AS does not bind anything to state (expected).")
        else:
            observations.append("Both requests with the duplicated state were processed "
                                "independently; the AS does not track state reuse (expected - "
                                "replay protection is the client's job via nonce/state).")
    else:
        inconclusive += 1

    ev.append({"problems": problems, "observations": observations,
               "definitive_responses": definitive, "inconclusive_probes": inconclusive})

    if problems:
        status, severity = STATUS_FAIL, "HIGH"
        summary = "; ".join(problems)
        rec_txt = ("Return the client's 'state' value verbatim on every response, including error "
                   "responses (RFC 6749 s4.1.2, s4.1.2.1). Without it the client cannot detect "
                   "CSRF or cross-site request forgery of the authorization response.")
    elif definitive and not inconclusive:
        status, severity = STATUS_PASS, "INFO"
        summary = ("'state' is returned unchanged when supplied. " + " ".join(observations))
        rec_txt = "No action required."
    elif definitive:
        status, severity = STATUS_WARN, "LOW"
        summary = (f"{definitive} probe(s) conclusive and correct, {inconclusive} inconclusive "
                   f"because the server stopped at a login page.")
        rec_txt = "Re-run with --session-cookie to make the remaining probes conclusive."
    else:
        status, severity = STATUS_INDETERMINATE, "INFO"
        summary = ("No probe reached an OAuth response, so state handling could not be observed.")
        rec_txt = ("Re-run with --session-cookie, or verify in the AS configuration that 'state' "
                   "is echoed on both success and error responses.")

    ctx.add(Finding(
        check_id="state-handling",
        title="State parameter handling (CSRF support)",
        status=status,
        severity=severity,
        summary=summary,
        evidence=ev,
        recommendation=rec_txt,
        references=["RFC 6749 s4.1.2, s4.1.2.1, s10.12", "RFC 9700 s2.1"],
    ))

def check_refresh_reuse(ctx: AuditContext) -> None:
    """RFC 9700 s2.2.2 - replay a used refresh token and record the server's answer.

    DESTRUCTIVE: a correctly configured server revokes the whole token family when it
    detects reuse, which invalidates the lab session that produced the token. Gated behind
    --allow-refresh-replay for that reason.
    """
    t = ctx.target
    ck = "refresh-reuse"
    title = "Refresh token rotation and reuse detection"
    refs = ["RFC 9700 s2.2.2", "RFC 6749 s6", "RFC 6819 s5.2.2.3"]

    def skip(reason: str, extra: Optional[Dict[str, Any]] = None) -> None:
        ctx.add(Finding(
            check_id=ck, title=title, status=STATUS_INDETERMINATE, severity="INFO",
            summary=reason,
            evidence=[{"reason": reason, **(extra or {})}],
            recommendation=("Supply a single-use lab refresh token with --refresh-token and "
                            "confirm the destructive replay with --allow-refresh-replay. "
                            "Use a throwaway session: a correct server will revoke the token "
                            "family when it sees the replay."),
            references=refs,
        ))

    if not ctx.args.refresh_token:
        return skip("Not run: no refresh token supplied (--refresh-token).")
    if not ctx.args.allow_refresh_replay:
        return skip("Not run: --allow-refresh-replay was not given. This check consumes the "
                    "refresh token and a correct server will revoke the whole token family.")
    if not t.token_endpoint:
        return skip("Not run: token endpoint unknown.")

    rt = ctx.args.refresh_token
    ev: List[Dict[str, Any]] = [{"token_endpoint": t.token_endpoint,
                                 "refresh_token_supplied": redact_value("refresh_token", rt),
                                 "client_type": t.client_type}]
    problems: List[str] = []

    def grant() -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "grant_type": "refresh_token",
            "refresh_token": rt,
            "client_id": t.client_id,
        }
        if t.client_secret:
            params["client_secret"] = t.client_secret
        resp = ctx.http.post_form(t.token_endpoint, params)
        body = parse_json_maybe(resp.text)
        body = body if isinstance(body, dict) else {}
        return {
            "http_status": resp.status,
            "transport_error": resp.transport_error,
            "error": body.get("error"),
            "error_description": redact_value("error_description",
                                              str(body.get("error_description", ""))) or None,
            "issued_access_token": "access_token" in body,
            "issued_refresh_token": "refresh_token" in body,
            "rotated": bool(body.get("refresh_token")) and body.get("refresh_token") != rt,
            "fields_returned": sorted(body.keys()),
            "internal_detail": scan_for_internal_detail(resp.text),
        }

    # Step 1 - legitimate use of the supplied token
    first = grant()
    ev.append({"step": "1. legitimate refresh with the supplied token", **first})

    if first["transport_error"]:
        return skip(f"Token endpoint unreachable: {first['transport_error']}",
                    {"token_endpoint": t.token_endpoint})

    if first["error"]:
        # The token was already invalid/expired, so nothing can be concluded about reuse.
        ev.append({"problems": problems})
        ctx.add(Finding(
            check_id=ck, title=title, status=STATUS_INDETERMINATE, severity="INFO",
            summary=(f"The supplied refresh token was rejected on first use "
                     f"(error={first['error']}), so reuse detection could not be tested."),
            evidence=ev,
            recommendation="Supply a freshly issued, unused refresh token and re-run.",
            references=refs,
        ))
        return

    if not first["issued_access_token"]:
        ev.append({"problems": problems})
        ctx.add(Finding(
            check_id=ck, title=title, status=STATUS_INDETERMINATE, severity="INFO",
            summary="The refresh request returned no access token and no error.",
            evidence=ev,
            recommendation="Inspect the token endpoint response manually.",
            references=refs,
        ))
        return

    if not first["rotated"]:
        problems.append("The server did not issue a new refresh_token on use - refresh tokens "
                        "are not being rotated")

    # Step 2 - replay the ORIGINAL token, which a correct server has now invalidated
    second = grant()
    ev.append({"step": "2. REPLAY of the same original refresh token", **second})

    if second["issued_access_token"]:
        problems.append("The server accepted a replayed refresh token and issued new tokens - "
                        "there is no reuse detection")
    elif (second["error"] or "").lower() in ("invalid_grant", "invalid_request", "invalid_client"):
        ev.append({"reuse_detected": True, "error": second["error"]})
    else:
        ev.append({"reuse_outcome_unclear": True})

    if first["internal_detail"] or second["internal_detail"]:
        problems.append("Token endpoint leaked implementation detail: "
                        + ", ".join(sorted(set(first["internal_detail"] + second["internal_detail"]))))

    ev.append({"problems": problems})

    if any("replayed refresh token" in p for p in problems):
        status, severity = STATUS_FAIL, "CRITICAL"
    elif problems:
        status, severity = STATUS_FAIL, "HIGH"
    else:
        status, severity = STATUS_PASS, "INFO"

    summary = ("; ".join(problems) if problems else
               "Refresh token was rotated on use and the replayed original token was rejected "
               "with error=%s - reuse detection is working." % (second.get("error") or "n/a"))
    rec_txt = ("Rotate refresh tokens on every use and revoke the entire token family when a "
               "previously used token is replayed (RFC 9700 s2.2.2). For public clients prefer "
               "sender-constrained tokens.") if problems else "No action required."

    ctx.add(Finding(check_id=ck, title=title, status=status, severity=severity,
                    summary=summary, evidence=ev, recommendation=rec_txt, references=refs))

def check_introspection(ctx: AuditContext) -> None:
    """RFC 7662 - record what the introspection endpoint reveals, and to whom."""
    t = ctx.target
    ck = "introspection"
    title = "Token introspection endpoint behaviour"
    refs = ["RFC 7662 s2.1, s2.2, s4"]

    ep = ctx.args.introspection_endpoint or t.metadata.get("introspection_endpoint")
    token = ctx.args.access_token

    def skip(reason: str, extra: Optional[Dict[str, Any]] = None) -> None:
        ctx.add(Finding(
            check_id=ck, title=title, status=STATUS_INDETERMINATE, severity="INFO",
            summary=reason, evidence=[{"reason": reason, **(extra or {})}],
            recommendation=("Publish introspection_endpoint in discovery and supply a lab access "
                            "token with --access-token to record what the endpoint reveals."),
            references=refs,
        ))

    if not ep:
        return skip("Not run: no introspection_endpoint published in discovery "
                    "(and --introspection-endpoint was not given).")
    if not token:
        return skip("Not run: no access token supplied (--access-token).")

    ev: List[Dict[str, Any]] = [{"introspection_endpoint": ep,
                                 "token_supplied": redact_value("access_token", token),
                                 "client_type": t.client_type}]
    problems: List[str] = []

    def introspect(authenticated: bool) -> Dict[str, Any]:
        params = {"token": token, "token_type_hint": "access_token"}
        headers = {}
        if authenticated and t.client_id:
            if t.client_secret:
                creds = base64.b64encode(
                    f"{t.client_id}:{t.client_secret}".encode()).decode()
                headers["Authorization"] = f"Basic {creds}"
            else:
                params["client_id"] = t.client_id
        resp = ctx.http.post_form(ep, params, headers=headers or None)
        body = parse_json_maybe(resp.text)
        body = body if isinstance(body, dict) else {}
        return {
            "http_status": resp.status,
            "transport_error": resp.transport_error,
            "authenticated": authenticated,
            "error": body.get("error"),
            "active": body.get("active"),
            "fields_returned": sorted(body.keys()),
            "body": {k: (redact_value(k, str(v)) if k not in ("active", "scope", "client_id",
                                                              "token_type", "exp", "iat")
                         else v) for k, v in body.items()},
            "internal_detail": scan_for_internal_detail(resp.text),
        }

    # A. unauthenticated - RFC 7662 s2.1 requires the endpoint to be protected
    unauth = introspect(authenticated=False)
    ev.append({"step": "A. POST with token and NO client authentication", **unauth})

    if unauth["transport_error"]:
        return skip(f"Introspection endpoint unreachable: {unauth['transport_error']}",
                    {"introspection_endpoint": ep})

    if unauth["error"] is None and unauth["http_status"] == 200 and unauth["body"]:
        problems.append("The introspection endpoint answered an unauthenticated request with "
                        "token metadata (RFC 7662 s2.1 requires client authentication)")

    # B. authenticated - record what is disclosed
    auth = introspect(authenticated=True)
    ev.append({"step": "B. POST with token and client authentication", **auth})

    SENSITIVE_FIELDS = {"sub", "username", "email", "phone_number", "address", "birthdate",
                        "jti", "scope", "client_id", "aud", "iss", "exp", "iat", "nbf",
                        "cnf", "active", "token_type"}
    revealed = set(auth["fields_returned"])
    unusual = sorted(revealed - SENSITIVE_FIELDS - {"error", "error_description"})
    if unusual:
        ev.append({"non_standard_fields_returned": unusual})
        problems.append("Introspection response carries non-standard fields that may disclose "
                        "more than necessary: " + ", ".join(unusual))

    if auth["active"] is False and unauth.get("active") is not False:
        ev.append({"note": "token reported inactive when authenticated"})

    if unauth["internal_detail"] or auth["internal_detail"]:
        problems.append("Introspection endpoint leaked implementation detail: "
                        + ", ".join(sorted(set(unauth["internal_detail"] + auth["internal_detail"]))))

    if not ep.startswith("https://"):
        problems.append("Introspection endpoint is not served over HTTPS")

    ev.append({"problems": problems,
               "disclosed_when_authenticated": auth["fields_returned"]})

    if any("unauthenticated request" in p for p in problems):
        status, severity = STATUS_FAIL, "HIGH"
    elif problems:
        status, severity = STATUS_WARN, "MEDIUM"
    else:
        status, severity = STATUS_PASS, "INFO"

    summary = ("; ".join(problems) if problems else
               f"Introspection requires client authentication and disclosed only standard "
               f"fields: {', '.join(auth['fields_returned']) or 'none'}.")
    rec_txt = ("Require client authentication on the introspection endpoint, return "
               '{\"active\": false} rather than an error for unknown tokens so it cannot be used '
               "as an oracle, and disclose only the claims the relying party needs."
               ) if problems else "No action required."

    ctx.add(Finding(check_id=ck, title=title, status=status, severity=severity,
                    summary=summary, evidence=ev, recommendation=rec_txt, references=refs))

CHECKS: List[Tuple[str, str, Callable[[AuditContext], None]]] = [
    ("discovery", "TLS, discovery document and advertised capabilities", check_discovery),
    ("redirect", "Strict redirect_uri validation (open redirection)", check_redirect_uri_strictness),
    ("pkce", "PKCE enforcement", check_pkce),
    ("response-types", "Supported response types", check_response_types),
    ("token-auth", "Token endpoint client authentication", check_token_endpoint_auth),
    ("state", "State parameter handling", check_state),
    ("refresh-reuse", "Refresh token rotation and reuse detection", check_refresh_reuse),
    ("introspection", "Token introspection endpoint behaviour", check_introspection),
    ("jwks", "JWK Set hygiene", check_jwks),
    ("error-hygiene", "Error response hygiene", check_error_hygiene),
    ("token-leakage", "Credentials exposed in redirect URLs", check_token_leakage),
]

CHECK_IDS = [c[0] for c in CHECKS]

DEFAULT_CHECKS = CHECK_IDS
