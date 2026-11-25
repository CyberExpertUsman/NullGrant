"""Report rendering: colourised console output, JSON, and self-contained HTML."""

from __future__ import annotations

import datetime as _dt
import html
import json
import platform
import textwrap
import time
from typing import Any, Dict, List, Sequence

from ._version import TOOL_NAME, TOOL_VERSION
from .context import AuditContext
from .model import (
    SEVERITY_ORDER,
    STATUS_FAIL,
    STATUS_INDETERMINATE,
    STATUS_INFO,
    STATUS_LABEL,
    STATUS_PASS,
    STATUS_WARN,
    Finding,
)
from .theme import c

# Severity -> theme role. A module constant rather than an inline dict literal because a
# multi-line expression inside a single-quoted f-string is a SyntaxError before Python 3.12
# (PEP 701 lifted that restriction); this project supports 3.8+.
_SEVERITY_ROLE = {
    "CRITICAL": "sev_critical",
    "HIGH": "sev_high",
    "MEDIUM": "sev_medium",
    "LOW": "sev_low",
}

def summarise(findings: Sequence[Finding]) -> Dict[str, int]:
    counts = {STATUS_PASS: 0, STATUS_FAIL: 0, STATUS_WARN: 0,
              STATUS_INDETERMINATE: 0, STATUS_INFO: 0}
    for f in findings:
        counts[f.status] = counts.get(f.status, 0) + 1
    return counts

def print_console(ctx: AuditContext, target_label: str) -> None:
    counts = summarise(ctx.findings)
    w = 78
    print()
    print("=" * w)
    print(c(f" {TOOL_NAME} {TOOL_VERSION}", "brand", "bold")
          + c(" - authorization server audit", "accent"))
    print(c("=" * w, "frame"))
    print(f" Target          : {target_label}")
    print(f" Issuer          : {ctx.target.issuer}")
    print(f" Client          : {ctx.target.client_id} ({ctx.target.client_type})")
    print(f" Redirect URI    : {ctx.target.redirect_uri}")
    print(f" Metadata source : {ctx.target.metadata_source or 'not found'}")
    print(f" HTTP requests   : {ctx.http.request_count}")
    print(f" Duration        : {time.time() - ctx.started_at:.1f}s")
    print(c("-" * w, "frame"))
    print(f" {c(f'FAIL {counts[STATUS_FAIL]}', 'fail', 'bold')}   "
          f"{c(f'WARN {counts[STATUS_WARN]}', 'warn')}   "
          f"{c(f'PASS {counts[STATUS_PASS]}', 'pass')}   "
          f"{c(f'INDETERMINATE {counts[STATUS_INDETERMINATE]}', 'unknown')}")
    print(c("=" * w, "frame"))

    ordered = sorted(ctx.findings,
                     key=lambda f: (SEVERITY_ORDER.get(f.severity, 9),
                                    0 if f.status == STATUS_FAIL else 1,
                                    f.check_id))
    for f in ordered:
        print()
        label, col = {
            STATUS_FAIL: ("FAIL", "fail"),
            STATUS_WARN: ("WARN", "warn"),
            STATUS_PASS: ("PASS", "pass"),
            STATUS_INDETERMINATE: ("????", "unknown"),
            STATUS_INFO: ("INFO", "info"),
        }.get(f.status, ("    ", "info"))
        print(f"[{c(label, col, 'bold')}] {c(f.title, 'bold')}")
        print(f"       {c('check:', 'dim')} {f.check_id}   "
              f"{c('--checks id:', 'dim')} {f.check or '-'}   "
              f"{c('severity:', 'dim')} "
              f"{c(f.severity, _SEVERITY_ROLE.get(f.severity, 'sev_info'))}")
        for line in textwrap.wrap(f.summary, w - 7):
            print(f"       {line}")
        if f.evidence and ctx.args.verbose:
            for line in textwrap.wrap("evidence: " + compact_json(f.evidence), w - 7):
                print(f"       {line}")
        if f.recommendation and f.status != STATUS_PASS:
            for line in textwrap.wrap("fix: " + f.recommendation, w - 7):
                print(f"       {line}")
        if f.references:
            print(f"       refs: {', '.join(f.references)}")
    print()
    print("=" * w)

def compact_json(obj: Any, limit: int = 1200) -> str:
    s = json.dumps(obj, default=str)
    return s[:limit] + ("..." if len(s) > limit else "")

def write_json_report(ctx: AuditContext, path: str) -> None:
    counts = summarise(ctx.findings)
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "target": {
            "issuer": ctx.target.issuer,
            "client_id": ctx.target.client_id,
            "client_type": ctx.target.client_type,
            "redirect_uri": ctx.target.redirect_uri,
            "authorization_endpoint": ctx.target.auth_endpoint,
            "token_endpoint": ctx.target.token_endpoint,
            "jwks_uri": ctx.target.jwks_uri,
            "metadata_source": ctx.target.metadata_source,
            "metadata_error": ctx.target.metadata_error,
            "metadata": ctx.target.metadata,
        },
        "run": {
            "http_requests": ctx.http.request_count,
            "duration_seconds": round(time.time() - ctx.started_at, 2),
            "checks_enabled": ctx.args.checks,
            "dry_run": False,
            # Provenance: what produced this report, so it can be reproduced.
            "platform": platform.platform(),
            "system": platform.system(),
            "python_version": platform.python_version(),
            "tool_version": TOOL_VERSION,
            "connection": {
                "target_ip": getattr(ctx.args, "target_ip", None),
                "ca_bundle": bool(getattr(ctx.args, "ca_bundle", None)),
                "insecure_tls": bool(getattr(ctx.args, "insecure_tls", False)),
                "authenticated_session": bool(getattr(ctx.args, "session_cookie", [])),
                "auth_code_supplied": bool(getattr(ctx.args, "auth_code", None)),
                "refresh_token_supplied": bool(getattr(ctx.args, "refresh_token", None)),
                "access_token_supplied": bool(getattr(ctx.args, "access_token", None)),
            },
        },
        "summary": counts,
        "findings": [f.as_dict() for f in ctx.findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)

HTML_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; padding: 32px 20px; background: #0f1115; color: #e6e8ee;
       font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
.wrap { max-width: 980px; margin: 0 auto; }
h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.02em; }
h2 { font-size: 18px; margin: 34px 0 12px; padding-bottom: 8px;
     border-bottom: 1px solid #262b36; letter-spacing: -0.01em; }
.sub { color: #98a2b3; font-size: 13px; margin-bottom: 24px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 18px 0; }
.stat { background: #171a21; border: 1px solid #262b36; border-radius: 10px; padding: 12px 14px; }
.stat .n { font-size: 24px; font-weight: 650; letter-spacing: -0.02em; }
.stat .l { font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em; color: #98a2b3; }
table { width: 100%; border-collapse: collapse; font-size: 13.5px; margin: 10px 0 4px; }
th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid #20242e; vertical-align: top; }
th { color: #98a2b3; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
tr:last-child td { border-bottom: none; }
.card { background: #171a21; border: 1px solid #262b36; border-radius: 12px;
        padding: 16px 18px; margin: 12px 0; }
.card.FAIL { border-left: 4px solid #f4525e; }
.card.WARN { border-left: 4px solid #f2a33c; }
.card.PASS { border-left: 4px solid #3ecf8e; }
.card.INDETERMINATE { border-left: 4px solid #7c8db5; }
.card.INFO { border-left: 4px solid #4b5568; }
.ct { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.badge { font-size: 10.5px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;
         padding: 3px 8px; border-radius: 999px; white-space: nowrap; }
.badge.FAIL { background: #3a1418; color: #ff8f99; }
.badge.WARN { background: #3a2a10; color: #ffc46b; }
.badge.PASS { background: #0f3327; color: #5fe0a8; }
.badge.INDETERMINATE { background: #1e2433; color: #9fb0d6; }
.badge.INFO { background: #1e2129; color: #9aa3b5; }
.sev { font-size: 10.5px; letter-spacing: 0.08em; color: #98a2b3; text-transform: uppercase; }
.title { font-size: 16px; font-weight: 620; }
.summary { color: #c3c9d6; margin: 8px 0 0; }
.fix { margin: 12px 0 0; padding: 10px 12px; background: #12161d;
       border-radius: 8px; font-size: 13.5px; color: #c3c9d6; }
.fix b { color: #e6e8ee; }
.refs { margin-top: 8px; font-size: 12px; color: #7c8db5; }
.cid { font-size: 11px; color: #7c8db5; margin-left: auto; }
.cid code { background: #12161d; padding: 1px 5px; border-radius: 4px; }
details { margin-top: 12px; }
summary { cursor: pointer; font-size: 12px; letter-spacing: 0.05em; text-transform: uppercase;
          color: #98a2b3; user-select: none; }
summary:hover { color: #e6e8ee; }
pre { margin: 8px 0 0; padding: 12px; background: #0b0d12; border: 1px solid #20242e;
      border-radius: 8px; overflow-x: auto; font-size: 12px; line-height: 1.5;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: #c3c9d6; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.banner { background: #171a21; border: 1px solid #262b36; border-radius: 12px; padding: 16px 18px; }
.banner table { margin: 0; }
.note { font-size: 12.5px; color: #7c8db5; margin-top: 22px; padding-top: 14px;
        border-top: 1px solid #20242e; }
"""

def write_html_report(ctx: AuditContext, path: str) -> None:
    counts = summarise(ctx.findings)
    ordered = sorted(ctx.findings,
                     key=lambda f: (0 if f.status == STATUS_FAIL else
                                    1 if f.status == STATUS_WARN else
                                    2 if f.status == STATUS_INDETERMINATE else 3,
                                    SEVERITY_ORDER.get(f.severity, 9), f.check_id))
    e = html.escape
    parts: List[str] = []
    parts.append(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(TOOL_NAME)} report - {e(ctx.target.issuer)}</title>
<style>{HTML_CSS}</style></head><body><div class="wrap">
<h1>{e(TOOL_NAME)} audit report</h1>
<div class="sub">Authorization server configuration audit &middot; generated
{e(_dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'))} &middot; {e(TOOL_NAME)} v{e(TOOL_VERSION)}</div>

<div class="grid">
  <div class="stat"><div class="n" style="color:#ff8f99">{counts[STATUS_FAIL]}</div><div class="l">Fail</div></div>
  <div class="stat"><div class="n" style="color:#ffc46b">{counts[STATUS_WARN]}</div><div class="l">Warn</div></div>
  <div class="stat"><div class="n" style="color:#5fe0a8">{counts[STATUS_PASS]}</div><div class="l">Pass</div></div>
  <div class="stat"><div class="n" style="color:#9fb0d6">{counts[STATUS_INDETERMINATE]}</div><div class="l">Indeterminate</div></div>
  <div class="stat"><div class="n">{ctx.http.request_count}</div><div class="l">Requests</div></div>
</div>

<h2>Target</h2>
<div class="banner"><table>
<tr><th>Issuer</th><td><code>{e(ctx.target.issuer)}</code></td></tr>
<tr><th>Client</th><td><code>{e(ctx.target.client_id)}</code> ({e(ctx.target.client_type)})</td></tr>
<tr><th>Registered redirect URI</th><td><code>{e(ctx.target.redirect_uri)}</code></td></tr>
<tr><th>Authorization endpoint</th><td><code>{e(str(ctx.target.auth_endpoint))}</code></td></tr>
<tr><th>Token endpoint</th><td><code>{e(str(ctx.target.token_endpoint))}</code></td></tr>
<tr><th>JWKS URI</th><td><code>{e(str(ctx.target.jwks_uri))}</code></td></tr>
<tr><th>Metadata source</th><td><code>{e(str(ctx.target.metadata_source or 'not found'))}</code></td></tr>
<tr><th>Metadata error</th><td><code>{e(str(ctx.target.metadata_error or '-'))}</code></td></tr>
</table></div>

<h2>Findings</h2>
""")

    for f in ordered:
        refs = ""
        if f.references:
            refs = f'<div class="refs">References: {e(", ".join(f.references))}</div>'
        fix = ""
        if f.recommendation and f.status != STATUS_PASS:
            fix = f'<div class="fix"><b>Remediation.</b> {e(f.recommendation)}</div>'
        parts.append(f"""
<div class="card {e(f.status)}">
  <div class="ct">
    <span class="badge {e(f.status)}">{e(STATUS_LABEL.get(f.status, f.status))}</span>
    <span class="title">{e(f.title)}</span>
    <span class="sev">{e(f.severity)}</span>
    <span class="cid"><code>--checks {e(f.check or '?')}</code> &middot; <code>{e(f.check_id)}</code></span>
  </div>
  <p class="summary">{e(f.summary)}</p>
  {fix}{refs}
  <details><summary>Evidence ({len(f.evidence)} block{"s" if len(f.evidence) != 1 else ""})</summary>
  <pre>{e(json.dumps(f.evidence, indent=2, default=str))}</pre></details>
</div>""")

    parts.append(f"""
<h2>Run details</h2>
<div class="banner"><table>
<tr><th>Checks enabled</th><td><code>{e(", ".join(ctx.args.checks))}</code></td></tr>
<tr><th>Duration</th><td>{time.time() - ctx.started_at:.1f}s</td></tr>
<tr><th>HTTP requests sent</th><td>{ctx.http.request_count}</td></tr>
<tr><th>Authenticated session used</th><td>{"yes" if ctx.args.session_cookie else "no"}</td></tr>
<tr><th>Connect via</th><td><code>{e(str(ctx.args.target_ip or 'issuer hostname (resolved normally)'))}</code></td></tr>
<tr><th>TLS trust</th><td>{'INSECURE - verification disabled' if ctx.args.insecure_tls
    else ('lab CA bundle' if ctx.args.ca_bundle else 'system trust store')}</td></tr>
<tr><th>Credentials supplied</th><td>{e(', '.join(
    [n for n, v in (('auth-code', ctx.args.auth_code),
                    ('refresh-token', ctx.args.refresh_token),
                    ('access-token', ctx.args.access_token)) if v]) or 'none')}</td></tr>
<tr><th>Run on</th><td>{e(platform.platform())} &middot; Python {e(platform.python_version())}</td></tr>
</table></div>

<div class="note">
{e(TOOL_NAME)} sends only the requests an OAuth client would legitimately send, using the single
registered test client named on the command line. It does not brute force, does not enumerate
other clients or user accounts, and does not attempt to exploit any condition it reports.
Credential-like values in this report are truncated. Every finding is a configuration
observation for you to verify and remediate on systems you own or are authorised to test.
</div>
</div></body></html>""")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(parts))
