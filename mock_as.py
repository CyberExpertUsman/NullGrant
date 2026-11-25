#!/usr/bin/env python3
"""
mock_as.py - a deliberately MISCONFIGURED OAuth 2.0 authorization server, used only as a
test fixture for nullgrant.py.

It exists so the audit checks can be verified end-to-end without pointing the tool at a
real system. It is intentionally wrong in every way nullgrant looks for:

  * loose (prefix) redirect_uri matching  -> open redirection
  * no PKCE enforcement, accepts 'plain'  -> code theft
  * advertises and serves implicit flows  -> front-channel tokens
  * returns access_token in the QUERY string of the redirect
  * publishes a JWKS containing a private key parameter and a key with no kid
  * leaks a Python traceback from one error path

It binds to 127.0.0.1 only and accepts exactly one hard-coded test client.
There is no authentication, no user store and no data. Do not deploy this.

Usage:  python3 mock_as.py [--port 8765] [--flavour vulnerable|hardened]

--flavour hardened flips the same fixture to a correctly configured server, so you can
confirm nullgrant reports PASS rather than just always reporting FAIL.
"""

from __future__ import annotations

import argparse
import base64
import http.server
import json
import re
import secrets
import socketserver
import urllib.parse

CLIENT_ID = "lab-client"
CLIENT_SECRET = "lab-secret"
REDIRECT_URI = "http://localhost:9999/callback"
FAKE_JWK_PRIVATE_N = base64.urlsafe_b64encode(b"\x00" * 64).rstrip(b"=").decode()

# Lab credentials printed at startup so the tester can pass them to nullgrant.py.
LAB_REFRESH_TOKEN = "rt-lab-0123456789abcdef"
LAB_ACCESS_TOKEN = "at-lab-0123456789abcdef"
ISSUED_REFRESH_TOKENS = {LAB_REFRESH_TOKEN}
USED_REFRESH_TOKENS: set = set()

# Records headers from the most recent request, so tests can assert what actually
# went over the wire (e.g. that --session-cookie produced a Cookie header).
LAST_HEADERS: dict = {}


class MockAS(http.server.BaseHTTPRequestHandler):
    server_version = "MockAS/0.1"
    protocol_version = "HTTP/1.1"
    flavour = "vulnerable"
    scheme = "http"

    # ---- plumbing -------------------------------------------------------
    def log_message(self, fmt, *args):  # quieter test output
        if self.server.verbose:
            super().log_message(fmt, *args)

    def _send(self, code, body=b"", ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, code, obj, extra=None):
        self._send(code, json.dumps(obj).encode(), "application/json", extra)

    def _redirect(self, url, extra=None):
        self._send(302, b"", "text/plain", {"Location": url, **(extra or {})})

    # ---- routes ---------------------------------------------------------
    def do_GET(self):
        LAST_HEADERS.clear()
        for _k in ("cookie", "host", "user-agent", "authorization", "accept"):
            LAST_HEADERS[_k] = self.headers.get(_k.title() if _k != "user-agent"
                                                else "User-Agent")
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

        if path in ("/.well-known/openid-configuration",
                    "/.well-known/oauth-authorization-server"):
            return self._metadata()
        if path == "/authorize":
            return self._authorize(q)
        if path == "/jwks.json":
            return self._jwks()
        if path == "/boom":
            return self._traceback()
        self._json(404, {"error": "not_found"})

    def do_POST(self):
        LAST_HEADERS.clear()
        for _k in ("cookie", "host", "user-agent", "authorization", "accept"):
            LAST_HEADERS[_k] = self.headers.get(_k.title() if _k != "user-agent"
                                                else "User-Agent")
        parsed = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        q = dict(urllib.parse.parse_qsl(raw.decode("utf-8", "replace"), keep_blank_values=True))

        if parsed.path == "/token":
            return self._token(q)
        if parsed.path == "/introspect":
            return self._introspect(q)
        self._json(404, {"error": "not_found"})

    # ---- handlers -------------------------------------------------------
    def _metadata(self):
        base = f"{self.scheme}://{self.headers.get('Host', '127.0.0.1')}"
        if self.flavour == "hardened":
            doc = {
                "issuer": base,
                "authorization_endpoint": f"{base}/authorize",
                "token_endpoint": f"{base}/token",
                "jwks_uri": f"{base}/jwks.json",
                "introspection_endpoint": f"{base}/introspect",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
                "scopes_supported": ["openid", "profile"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            }
        else:
            doc = {
                "issuer": base + "/tenant-a",           # mismatch on purpose
                "authorization_endpoint": f"{base}/authorize",
                "token_endpoint": f"{base}/token",
                "jwks_uri": f"{base}/jwks.json",
                "introspection_endpoint": f"{base}/introspect",
                "response_types_supported": [
                    "code", "token", "id_token", "id_token token",
                    "code id_token", "code token", "code id_token token",
                ],
                "grant_types_supported": ["authorization_code", "implicit", "refresh_token"],
                "code_challenge_methods_supported": ["plain", "S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": ["openid", "profile"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256", "none"],
            }
        self._json(200, doc)

    def _authorize(self, q):
        redirect_uri = q.get("redirect_uri", "")
        response_type = q.get("response_type", "")
        state = q.get("state")
        client_id = q.get("client_id")

        if self.flavour == "hardened":
            if client_id != CLIENT_ID:
                return self._json(400, {"error": "unauthorized_client"})
            if not q.get("code_challenge"):
                return self._redirect_error(redirect_uri if redirect_uri == REDIRECT_URI else None,
                                            "invalid_request", "code_challenge is required", state)
            if q.get("code_challenge_method") != "S256":
                return self._redirect_error(REDIRECT_URI if redirect_uri == REDIRECT_URI else None,
                                            "invalid_request", "only S256 is supported", state)
            challenge = q.get("code_challenge") or ""
            if not (43 <= len(challenge) <= 128):
                return self._redirect_error(REDIRECT_URI if redirect_uri == REDIRECT_URI else None,
                                            "invalid_request",
                                            "code_challenge must be 43-128 characters", state)
            if not re.fullmatch(r"[A-Za-z0-9_-]+", challenge):
                return self._redirect_error(REDIRECT_URI if redirect_uri == REDIRECT_URI else None,
                                            "invalid_request",
                                            "code_challenge is not base64url", state)
            if redirect_uri != REDIRECT_URI:
                # Exact match failed: show an AS-hosted error, never redirect off-site.
                return self._json(400, {"error": "invalid_request",
                                        "error_description": "redirect_uri mismatch"})
            if response_type != "code":
                return self._redirect_error(REDIRECT_URI, "unsupported_response_type",
                                            "only 'code' is supported", state)
            return self._redirect_with(REDIRECT_URI,
                                       {"code": "hardened-" + secrets.token_urlsafe(12)},
                                       state, fragment=False)

        # ---- vulnerable path ----
        if client_id and client_id != CLIENT_ID:
            # deliberately leak internals for the unknown-client case
            body = ("Traceback (most recent call last):\n"
                    '  File "/var/www/oauth/as/views.py", line 142, in authorize\n'
                    "    client = Client.objects.get(client_id=client_id)\n"
                    "Client.DoesNotExist: Client matching query does not exist.\n"
                    "SELECT * FROM oauth_client WHERE client_id = '%s'" % client_id)
            return self._send(500, body.encode(), "text/plain")

        # loose prefix matching on the path component only -> open redirection
        registered_prefix = urllib.parse.urlsplit(REDIRECT_URI)
        got = urllib.parse.urlsplit(redirect_uri)
        loose = (got.path.startswith(registered_prefix.path.rstrip("/"))
                 if got.path else False)

        if loose and got.hostname == registered_prefix.hostname:
            target = redirect_uri
        elif self.flavour == "vulnerable" and got.scheme in ("http", "https"):
            # prefix-of-string matching: any URI beginning with "http://localhost" passes
            target = redirect_uri if redirect_uri.startswith("http://localhost") else None
        else:
            target = None

        if target is None:
            if redirect_uri.startswith("http"):
                target = redirect_uri          # accepts anything -> open redirect
            else:
                return self._json(400, {"error": "invalid_request",
                                        "error_description": "redirect_uri must be absolute"})

        if response_type in ("token", "id_token token", "code token", "code id_token token",
                             "id_token", "code id_token"):
            frag = {"access_token": "ya29.mock." + secrets.token_urlsafe(16),
                    "token_type": "Bearer", "expires_in": "3600",
                    "id_token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJtb2NrIn0."}
            if self.flavour == "vulnerable":
                # worst case: tokens in the QUERY string, which leaks via Referer
                return self._redirect_with(target, frag, state, fragment=False)
            return self._redirect_with(target, frag, state, fragment=True)

        code = "mock-" + secrets.token_urlsafe(12)
        return self._redirect_with(target, {"code": code}, state, fragment=False)

    def _redirect_with(self, target, payload, state, fragment=True):
        if state:
            payload = {**payload, "state": state}
        encoded = urllib.parse.urlencode(payload)
        base, _, existing_frag = target.partition("#")
        sep = "#" if fragment else "?"
        existing = "&" if (not fragment and "?" in base) else ""
        url = base + sep + existing + encoded
        if existing_frag and not fragment:
            url += "#" + existing_frag
        return self._redirect(url)

    def _redirect_error(self, redirect_uri, error, description, state):
        payload = {"error": error, "error_description": description}
        if state:
            payload["state"] = state
        if redirect_uri:
            return self._redirect(redirect_uri + "?" + urllib.parse.urlencode(payload))
        return self._json(400, payload)

    def _has_client_auth(self, q):
        auth = self.headers.get("Authorization", "")
        return bool(q.get("client_secret") or auth.startswith("Basic "))

    def _refresh(self, q):
        rt = q.get("refresh_token", "")
        if self.flavour == "hardened":
            if not self._has_client_auth(q):
                return self._json(401, {"error": "invalid_client"})
            if rt in USED_REFRESH_TOKENS:
                # Reuse detected: a correct server revokes the whole family.
                ISSUED_REFRESH_TOKENS.clear()
                USED_REFRESH_TOKENS.add(rt)
                return self._json(400, {"error": "invalid_grant",
                                        "error_description": "refresh token reuse detected; "
                                                             "token family revoked"})
            if rt not in ISSUED_REFRESH_TOKENS:
                return self._json(400, {"error": "invalid_grant"})
            USED_REFRESH_TOKENS.add(rt)
            ISSUED_REFRESH_TOKENS.discard(rt)
            new_rt = "rt-" + secrets.token_urlsafe(24)
            ISSUED_REFRESH_TOKENS.add(new_rt)
            return self._json(200, {"access_token": "at-" + secrets.token_urlsafe(20),
                                    "token_type": "Bearer", "expires_in": 300,
                                    "refresh_token": new_rt})
        # vulnerable: no client auth, no rotation, no reuse detection
        return self._json(200, {"access_token": "at-" + secrets.token_urlsafe(20),
                                "token_type": "Bearer", "expires_in": 3600})

    def _introspect(self, q):
        token = q.get("token", "")
        if self.flavour == "hardened":
            if not self._has_client_auth(q):
                return self._json(401, {"error": "invalid_client"})
            active = token == LAB_ACCESS_TOKEN
            body = {"active": active}
            if active:
                body.update({"scope": "openid profile", "client_id": CLIENT_ID,
                             "token_type": "Bearer", "sub": "lab-user-1",
                             "iat": 1700000000, "exp": 9999999999})
            return self._json(200, body)
        # vulnerable: answers unauthenticated and over-discloses
        return self._json(200, {
            "active": True, "scope": "openid profile email admin",
            "client_id": CLIENT_ID, "sub": "lab-user-1",
            "username": "lab-user-1", "email": "user@lab.example",
            "internal_user_id": 4217, "db_row": "oauth_token/4217",
            "amr": "pwd", "auth_time": 1700000000})

    def _token(self, q):
        grant = q.get("grant_type")
        if grant == "refresh_token":
            return self._refresh(q)
        if self.flavour == "hardened":
            if grant != "authorization_code":
                return self._json(400, {"error": "unsupported_grant_type"})
            # A public client authenticates with PKCE, not a secret, so client_id alone is
            # accepted here. Requiring a secret from a public client would itself be wrong.
            if not q.get("code_verifier"):
                return self._json(400, {"error": "invalid_request",
                                        "error_description": "code_verifier required"})
            return self._json(400, {"error": "invalid_grant"})

        if grant == "urn:nullgrant:unsupported":
            return self._json(500, {"error": "server_error",
                                    "error_description":
                                        "java.lang.NullPointerException at com.lab.as.TokenHandler.grant(TokenHandler.java:88)"})
        if grant != "authorization_code":
            return self._json(400, {"error": "unsupported_grant_type"})
        # vulnerable: no client authentication required, no code_verifier required
        return self._json(400, {"error": "invalid_grant",
                                "error_description": "code not found in oauth_code table"})

    def _jwks(self):
        if self.flavour == "hardened":
            keys = [{"kty": "RSA", "kid": "k-2026-01", "use": "sig", "alg": "RS256",
                     "n": base64.urlsafe_b64encode(b"\x01" * 256).rstrip(b"=").decode(),
                     "e": "AQAB"}]
        else:
            keys = [
                {"kty": "RSA", "use": "sig", "alg": "RS256",   # no kid
                 "n": FAKE_JWK_PRIVATE_N, "e": "AQAB",
                 "d": base64.urlsafe_b64encode(b"\x02" * 64).rstrip(b"=").decode()},
                {"kty": "oct", "kid": "shared-1", "k": "c3VwZXItc2VjcmV0LWhtYWMta2V5"},
            ]
        self._json(200, {"keys": keys})

    def _traceback(self):
        self._send(500, b"Traceback (most recent call last):\n  File \"/var/www/as.py\"\n", "text/plain")


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    verbose = False


def serve(port: int, flavour: str, verbose: bool = False,
          certfile: str = "", keyfile: str = "") -> Server:
    """Start a fixture.

    `flavour` and `scheme` are bound to a per-call subclass, NOT to MockAS itself. Setting
    them on the class would make a second fixture silently reconfigure the first, because
    every handler shares the class attribute.
    """
    scheme = "https" if certfile else "http"
    handler = type(f"MockAS_{flavour}_{scheme}", (MockAS,),
                   {"flavour": flavour, "scheme": scheme})
    srv = Server(("127.0.0.1", port), handler)
    srv.verbose = verbose
    if certfile:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile or certfile)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--flavour", choices=["vulnerable", "hardened"], default="vulnerable")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--certfile", default="")
    ap.add_argument("--keyfile", default="")
    a = ap.parse_args()
    srv = serve(a.port, a.flavour, a.verbose, a.certfile, a.keyfile)
    scheme = "https" if a.certfile else "http"
    print(f"mock {a.flavour} AS on {scheme}://127.0.0.1:{a.port}  (client_id={CLIENT_ID})")
    print(f"  lab refresh token : {LAB_REFRESH_TOKEN}")
    print(f"  lab access token  : {LAB_ACCESS_TOKEN}")
    if a.flavour == "hardened":
        print(f"  client secret     : {CLIENT_SECRET} (required at the token endpoint)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
