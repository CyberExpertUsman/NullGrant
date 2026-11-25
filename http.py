"""HTTP client. Redirects are never followed, so Location headers can be inspected.

Supports connecting to one address while presenting a different name for the Host header
and TLS SNI, which is what makes --target-ip work in labs without DNS.
"""

from __future__ import annotations

import functools
import http.client
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ._version import USER_AGENT
from .model import HttpResponse

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects so we can inspect Location headers directly."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None

class _SNIConnection(http.client.HTTPSConnection):
    """TLS connection to one address while presenting a different name for SNI/verification.

    Lets the audit reach a lab server by IP (no DNS configured) while still sending the
    correct Host header, the correct SNI server_name, and verifying the certificate
    against the real hostname rather than the IP.
    """

    def __init__(self, host, port=None, *, sni_host=None, **kwargs):
        kwargs.pop("check_hostname", None)
        super().__init__(host, port, **kwargs)
        self.sni_host = sni_host or host

    def connect(self):
        sock = socket.create_connection((self.host, self.port),
                                        self.timeout, self.source_address)
        if getattr(self, "_tunnel_host", None):
            self.sock = sock
            self._tunnel()
        self.sock = self._context.wrap_socket(sock, server_hostname=self.sni_host)

class _SNIHandler(urllib.request.HTTPSHandler):
    def __init__(self, sni_host: str, context: ssl.SSLContext):
        super().__init__(context=context)
        self.sni_host = sni_host

    def https_open(self, req):
        # The SSL context MUST be forwarded here. urllib's do_open only passes what we
        # hand it, and HTTPSConnection would otherwise build its own default context,
        # silently ignoring --ca-bundle and --insecure-tls.
        return self.do_open(functools.partial(_SNIConnection,
                                              sni_host=self.sni_host,
                                              context=self._context), req)

class HttpClient:
    def __init__(self, timeout: float = 20.0, insecure_tls: bool = False,
                 max_body: int = 256 * 1024,
                 connect_host: Optional[str] = None,
                 connect_port: Optional[int] = None,
                 ca_bundle: Optional[str] = None,
                 cookies: Optional[Sequence[str]] = None) -> None:
        self.timeout = timeout
        self.max_body = max_body
        self.insecure_tls = insecure_tls
        self.connect_host = connect_host
        self.connect_port = connect_port
        self.ca_bundle = ca_bundle
        self.cookies = list(cookies or [])
        self.request_count = 0
        self.redirect_overrides = 0
        self._opener_cache: Dict[Any, Any] = {}

    def _opener_for(self, sni_host: str):
        """Build (and cache) an opener whose TLS layer uses `sni_host` for SNI/verification."""
        key = (sni_host, self.insecure_tls, self.connect_host, self.connect_port,
               self.ca_bundle)
        if key in self._opener_cache:
            return self._opener_cache[key]

        handlers: List[urllib.request.BaseHandler] = [_NoRedirect()]
        ctx = ssl.create_default_context(cafile=self.ca_bundle) if self.ca_bundle \
            else ssl.create_default_context()
        if self.insecure_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if self.connect_host and sni_host:
            handlers.append(_SNIHandler(sni_host, ctx))
        else:
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        opener = urllib.request.build_opener(*handlers)
        self._opener_cache[key] = opener
        return opener

    def _rewrite(self, url: str) -> Tuple[str, Optional[str], Optional[str]]:
        """Apply --target-ip. Returns (url_to_fetch, host_header, sni_host)."""
        if not self.connect_host:
            return url, None, None
        p = urllib.parse.urlsplit(url)
        if not p.hostname:
            return url, None, None
        port = self.connect_port or p.port
        netloc = f"{self.connect_host}:{port}" if port else self.connect_host
        rewritten = urllib.parse.urlunsplit((p.scheme, netloc, p.path, p.query, p.fragment))
        self.redirect_overrides += 1
        # Preserve the logical name in both the Host header and TLS SNI.
        return rewritten, p.netloc, p.hostname

    def request(self, method: str, url: str,
                params: Optional[Dict[str, Any]] = None,
                data: Optional[bytes] = None,
                headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            sep = "&" if urllib.parse.urlsplit(url).query else "?"
            url = url + sep + urllib.parse.urlencode(clean, quote_via=urllib.parse.quote)

        fetch_url, host_header, sni_host = self._rewrite(url)

        hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if host_header:
            hdrs["Host"] = host_header
        if self.cookies:
            hdrs["Cookie"] = "; ".join(self.cookies)
        if headers:
            hdrs.update(headers)

        req = urllib.request.Request(fetch_url, data=data, headers=hdrs, method=method)
        opener = self._opener_for(sni_host or urllib.parse.urlsplit(url).hostname or "")
        self.request_count += 1
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(self.max_body)
                return HttpResponse(
                    url=url,
                    status=resp.status,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    body=raw,
                )
        except urllib.error.HTTPError as exc:
            # 3xx land here because _NoRedirect declines to follow them.
            raw = b""
            try:
                raw = exc.read(self.max_body)
            except Exception:
                pass
            return HttpResponse(
                url=url,
                status=exc.code,
                headers={k.lower(): v for k, v in (exc.headers or {}).items()},
                body=raw,
            )
        except urllib.error.URLError as exc:
            return HttpResponse(url=url, status=0, headers={}, body=b"",
                                transport_error=f"URLError: {exc.reason}")
        except ssl.SSLError as exc:
            return HttpResponse(url=url, status=0, headers={}, body=b"",
                                transport_error=f"TLS error: {exc}")
        except socket.gaierror as exc:
            return HttpResponse(url=url, status=0, headers={}, body=b"",
                                transport_error=f"DNS resolution failed: {exc}")
        except Exception as exc:  # pragma: no cover - defensive
            return HttpResponse(url=url, status=0, headers={}, body=b"",
                                transport_error=f"{type(exc).__name__}: {exc}")

    def get(self, url, params=None, headers=None) -> HttpResponse:
        return self.request("GET", url, params=params, headers=headers)

    def post_form(self, url, params, headers=None) -> HttpResponse:
        body = urllib.parse.urlencode(
            {k: v for k, v in params.items() if v is not None}
        ).encode()
        hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
        if headers:
            hdrs.update(headers)
        return self.request("POST", url, data=body, headers=hdrs)
