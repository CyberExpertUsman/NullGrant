"""Test inputs: redirect_uri mutations and the response types to enumerate.

The attacker-controlled domains below all use the .invalid TLD, which RFC 2606 reserves
specifically for tests that must fail. It is guaranteed never to resolve. Do not replace it
with an unreserved name such as .valid - that would lose the guarantee.
"""

from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List

def build_redirect_variants(registered: str) -> List[Dict[str, Any]]:
    p = urllib.parse.urlsplit(registered)
    host = p.hostname or ""
    path = p.path or "/"
    scheme = p.scheme or "https"
    port_part = "" if p.port in (None, 80, 443) else f":{p.port}"

    variants: List[Dict[str, Any]] = [
        {
            "id": "control-exact",
            "uri": registered,
            "description": "Registered redirect_uri, unmodified (control case)",
            "expect": "accept",
        },
        {
            "id": "trailing-slash",
            "uri": registered.rstrip("/") + "/" if path != "/" else registered + "/",
            "description": "Trailing slash appended",
            "expect": "reject",
        },
        {
            "id": "path-suffix",
            "uri": registered + "/attacker",
            "description": "Extra path segment appended (prefix matching flaw)",
            "expect": "reject",
        },
        {
            "id": "dot-segment-escape",
            "uri": registered + "/../attacker",
            "description": "Dot-segment path traversal past the registered path",
            "expect": "reject",
        },
        {
            "id": "encoded-traversal",
            "uri": registered + "%2f..%2f..%2fattacker",
            "description": "Percent-encoded traversal (parser-differential flaw)",
            "expect": "reject",
        },
        {
            "id": "subdomain-confusion",
            "uri": f"{scheme}://{host}.evil-audit.invalid{port_part}{path}",
            "description": "Registered host used as a label of an attacker domain",
            "expect": "reject",
        },
        {
            "id": "host-swap",
            "uri": f"{scheme}://evil-audit.invalid{port_part}{path}",
            "description": "Completely different host",
            "expect": "reject",
        },
        {
            "id": "userinfo-override",
            "uri": f"{scheme}://{host}@evil-audit.invalid{port_part}{path}",
            "description": "Userinfo component to confuse host parsing",
            "expect": "reject",
        },
        {
            "id": "backslash-override",
            "uri": f"{scheme}://{host}\\@evil-audit.invalid{port_part}{path}",
            "description": "Backslash separator (browser/URllib parsing differential)",
            "expect": "reject",
        },
        {
            "id": "scheme-downgrade",
            "uri": f"http://{host}{port_part}{path}",
            "description": "HTTPS downgraded to plaintext HTTP",
            "expect": "reject",
        },
        {
            "id": "port-change",
            "uri": f"{scheme}://{host}:8443{path}",
            "description": "Different port on the same host",
            "expect": "reject",
        },
        {
            "id": "case-change",
            "uri": f"{scheme.upper()}://{host.upper()}{port_part}{path}",
            "description": "Scheme and host upper-cased",
            "expect": "accept",
        },
        {
            "id": "protocol-relative",
            "uri": f"//evil-audit.invalid{path}",
            "description": "Protocol-relative URL",
            "expect": "reject",
        },
        {
            "id": "javascript-scheme",
            "uri": "javascript:alert(document.domain)",
            "description": "Non-HTTP scheme (script execution in the redirect target)",
            "expect": "reject",
        },
        {
            "id": "data-scheme",
            "uri": "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "description": "data: URI as redirect target",
            "expect": "reject",
        },
        {
            "id": "fragment-append",
            "uri": registered + "#attacker",
            "description": "Fragment appended to the registered URI",
            "expect": "accept",
        },
        {
            "id": "query-append",
            "uri": registered + ("&" if p.query else "?") + "next=https://evil-audit.invalid",
            "description": "Extra query parameter carrying an off-site URL",
            "expect": "accept",
        },
    ]
    if scheme == "http":
        variants.append({
            "id": "scheme-upgrade",
            "uri": f"https://{host}{port_part}{path}",
            "description": "HTTP upgraded to HTTPS (still a non-identical string)",
            "expect": "reject",
        })

    # Drop variants that normalise to the registered URI itself (no information value).
    unique, seen = [], set()
    for v in variants:
        if v["uri"] in seen or v["uri"] == registered and v["id"] != "control-exact":
            continue
        seen.add(v["uri"])
        unique.append(v)
    return unique

RESPONSE_TYPES_TO_ENUMERATE = [
    ("code", "Authorization Code flow (expected, correct)"),
    ("token", "Implicit flow - access token in front channel"),
    ("id_token", "Implicit flow - ID token only"),
    ("id_token token", "Implicit flow - hybrid implicit"),
    ("code id_token", "Hybrid flow"),
    ("code token", "Hybrid flow - access token in front channel"),
    ("code id_token token", "Hybrid flow - all tokens in front channel"),
    ("none", "RFC 8628 device flow marker / unusual"),
]

IMPLICIT_TYPES = {"token", "id_token", "id_token token", "code token",
                  "code id_token", "code id_token token"}
