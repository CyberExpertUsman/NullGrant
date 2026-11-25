#!/usr/bin/env python3
"""
selftest.py - reproducible verification of every build step in nullgrant.

Boots the mock authorization servers in-process, runs the real audit against them, and
asserts the expected verdicts. Nothing here touches the network beyond 127.0.0.1.

    python3 selftest.py            # run everything
    python3 selftest.py -v         # also show audit console output
    python3 selftest.py -k pkce    # only steps whose name matches 'pkce'

Exit code 0 = all assertions passed, 1 = something failed.

Covers:
    Step 1  request building and URL encoding
    Step 2  redirect-address variants (strict vs loose must differ)
    Step 3  PKCE enforcement (enforcing vs non-enforcing must both be correct)
    Step 4  response-type enumeration (reported flows must match enabled flows)
    Step 5  token-in-URL detection (token-carrying flagged, code-only not flagged)
    Step 6  CLI arguments and report completeness (two different runs)
    Step 7  full end-to-end run, every check has a verdict and evidence
    Extra   authorisation gate, dry-run, unreachable target, --target-ip + TLS
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)   # tests/mock_as.py
sys.path.insert(0, ROOT)   # the nullgrant package

import mock_as  # noqa: E402
import nullgrant as oa  # noqa: E402

LAB_REFRESH = mock_as.LAB_REFRESH_TOKEN
LAB_ACCESS = mock_as.LAB_ACCESS_TOKEN
REDIRECT_URI = mock_as.REDIRECT_URI

RESULTS = []
SERVERS = []


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------


def check(step: str, name: str, cond: bool, detail: str = "") -> bool:
    RESULTS.append({"step": step, "name": name, "ok": bool(cond), "detail": detail})
    return bool(cond)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_mock(flavour: str, port: int, certfile: str = "", keyfile: str = ""):
    srv = mock_as.serve(port, flavour, False, certfile, keyfile)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    SERVERS.append(srv)
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", port), 0.25).close()
            break
        except OSError:
            time.sleep(0.05)
    return srv


def reset_mock_state() -> None:
    """Refresh-token rotation state is module-level; reset it between scenarios."""
    mock_as.ISSUED_REFRESH_TOKENS.clear()
    mock_as.ISSUED_REFRESH_TOKENS.add(LAB_REFRESH)
    mock_as.USED_REFRESH_TOKENS.clear()


def run_audit(outdir: str, issuer: str, extra=None, show: bool = False):
    """Run the real CLI entry point and return (exit_code, report_dict)."""
    argv = [
        "--issuer", issuer,
        "--client-id", mock_as.CLIENT_ID,
        "--redirect-uri", REDIRECT_URI,
        "--client-type", "public",
        "--delay", "0",
        "--timeout", "10",
        "--out", outdir,
        "--format", "console,json,html",
        "--i-authorize-target",
    ] + (extra or [])
    buf = io.StringIO()
    if show:
        rc = oa.main(argv)
    else:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = oa.main(argv)
    path = os.path.join(outdir, "nullgrant-report.json")
    report = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else None
    return rc, report, buf.getvalue()


def by_id(report: dict) -> dict:
    return {f["check"]: f for f in report["findings"]}


def submod(name: str):
    """Import nullgrant.<name>, or fall back to the merged single-file namespace.

    `nullgrant.py` has no submodules - every name lives in one module - so `from nullgrant
    import tui` raises ImportError there. Aliasing the merged module works because the
    single-file build is verified to expose the same names (tools/build_singlefile.py).
    """
    import importlib
    try:
        return importlib.import_module(f"nullgrant.{name}")
    except ImportError:
        import nullgrant
        if hasattr(nullgrant, "main") and hasattr(nullgrant, "CHECKS"):
            return nullgrant
        raise


#: True when running against the merged single file rather than the package.
SINGLE_FILE = not os.path.isdir(os.path.join(ROOT, "nullgrant"))


def stdlib_names() -> set:
    """Names of the standard library. sys.stdlib_module_names is Python 3.10+, and the CI
    matrix also runs 3.8 and 3.9, so fall back to scanning the stdlib directory."""
    names = getattr(sys, "stdlib_module_names", None)
    if names:
        return set(names)
    import sysconfig
    root = sysconfig.get_paths()["stdlib"]
    import importlib.machinery
    suffixes = sorted(importlib.machinery.all_suffixes(), key=len, reverse=True)
    out = set(sys.builtin_module_names) | {"__future__"}
    # C extensions live in lib-dynload/, not in the stdlib root.
    dirs = [root]
    dynload = os.path.join(root, "lib-dynload")
    if os.path.isdir(dynload):
        dirs.append(dynload)
    for entry in [e for d in dirs for e in os.listdir(d)]:
        if entry == "__pycache__":
            continue
        # C extensions land here as e.g. unicodedata.cpython-313-x86_64-linux-gnu.so
        for suf in suffixes:
            if entry.endswith(suf):
                entry = entry[:-len(suf)]
                break
        out.add(entry)
    return out


def make_cert(tmpdir: str):
    """Self-signed cert valid for localhost, if openssl is available."""
    if not shutil.which("openssl"):
        return None, None
    crt = os.path.join(tmpdir, "selftest.crt")
    key = os.path.join(tmpdir, "selftest.key")
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
        capture_output=True)
    if r.returncode != 0:
        return None, None
    return crt, key


# ---------------------------------------------------------------------------
# Step 1 - request building and encoding
# ---------------------------------------------------------------------------


def step1_encoding() -> None:
    S = "step1-encoding"
    t = oa.Target(issuer="https://as.example.test", client_id="lab client+id",
                  redirect_uri="https://app.example.test/cb?x=1&y=two three#frag",
                  client_type="public", scopes="openid profile email")

    class A:
        verbose = False
        delay = 0

    ctx = oa.AuditContext(t, oa.HttpClient(), A())
    ctx.target.auth_endpoint = "https://as.example.test/authorize"

    params = ctx.build_authorize_params(
        response_type="id_token token",
        state="st/ate+va=lue&more",
        nonce="n0nce~with-_chars",
        scope="openid profile urn:example:scope+read/write",
    )
    params["code_challenge"] = "abc-DEF_123~xyz.456"
    url = oa.build_url_with_params(ctx.target.auth_endpoint, params)

    got = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True))
    sent = {k: v for k, v in params.items() if v is not None}

    check(S, "all required parameters present",
          set(sent) >= {"client_id", "response_type", "redirect_uri", "state",
                        "code_challenge", "code_challenge_method"},
          f"present={sorted(sent)}")
    check(S, "every parameter round-trips exactly",
          all(got.get(k) == v for k, v in sent.items()),
          f"mismatched={[k for k, v in sent.items() if got.get(k) != v]}")

    q = urllib.parse.urlsplit(url).query
    check(S, "space in response_type percent-encoded", "id_token%20token" in q)
    check(S, "'+' in scope encoded as %2B, not left literal",
          "scope%2Bread" in q, "a literal + would decode to a space server-side")
    check(S, "nested redirect_uri fully escaped",
          "redirect_uri=https%3A%2F%2F" in q and "%3Fx%3D1%26y%3D" in q)
    check(S, "'&' inside state escaped (no parameter split)",
          "state=st%2Fate%2Bva%3Dlue%26more" in q)
    check(S, "base64url challenge unreserved chars intact",
          "code_challenge=abc-DEF_123~xyz.456" in q)
    check(S, "exactly one '?' in the built URL", url.count("?") == 1)


def step1_end_to_end(vuln_port: int) -> None:
    """Prove the encoding survives server-side decoding."""
    S = "step1-encoding"
    t = oa.Target(issuer=f"http://127.0.0.1:{vuln_port}", client_id=mock_as.CLIENT_ID,
                  redirect_uri=REDIRECT_URI, client_type="public")

    class A:
        verbose = False
        delay = 0

    ctx = oa.AuditContext(t, oa.HttpClient(), A())
    info = oa.discover(t, ctx.http)
    t.metadata = info["metadata"]
    t.auth_endpoint = info["metadata"]["authorization_endpoint"]

    rec = ctx.probe_authorize(ctx.build_authorize_params(response_type="id_token token"),
                              "rt[id_token token]")
    check(S, "server decoded 'id_token token' (space survived both ways)",
          "access_token" in (rec.get("tokens_in_query") or []),
          f"tokens_in_query={rec.get('tokens_in_query')}")


# ---------------------------------------------------------------------------
# Steps 2-5 - differential fixture tests
# ---------------------------------------------------------------------------


def steps2to5(tmpdir: str, vuln_port: int, hard_port: int,
              clean_issuer: str = "", clean_extra=None) -> None:
    rc_v, rv, _ = run_audit(os.path.join(tmpdir, "v"), f"http://127.0.0.1:{vuln_port}")
    reset_mock_state()
    rc_h, rh, _ = run_audit(os.path.join(tmpdir, "h"), f"http://127.0.0.1:{hard_port}")

    # The plaintext hardened fixture legitimately FAILs its TLS checks, so exit code 1 is
    # correct there. The "clean" assertion needs the TLS fixture.
    check("step6-cli", "vulnerable run exits 1 (has failures)", rc_v == 1, f"rc={rc_v}")
    tls_fail = [f["check"] for f in rh["findings"] if f["status"] == "FAIL"]
    check("step6-cli", "plaintext hardened: only TLS-derived checks fail",
          set(tls_fail) <= {"discovery", "token-auth", "jwks"}, f"failed={tls_fail}")
    if clean_issuer:
        reset_mock_state()
        rc_c, rc_rep, _ = run_audit(os.path.join(tmpdir, "c"), clean_issuer, extra=clean_extra)
        check("step6-cli", "TLS hardened run exits 0 (no failures)", rc_c == 0, f"rc={rc_c}")
        check("step6-cli", "TLS hardened run has zero FAIL",
              rc_rep and rc_rep["summary"]["FAIL"] == 0, f"summary={(rc_rep or {}).get('summary')}")

    v, h = by_id(rv), by_id(rh)

    # Step 2 - redirect strictness must differ between loose and strict servers
    check("step2-redirect", "loose-matching server: open redirect CONFIRMED",
          v["redirect"]["status"] == "FAIL"
          and v["redirect"]["severity"] == "CRITICAL",
          v["redirect"]["summary"][:90])
    check("step2-redirect", "strict-matching server: PASS",
          h["redirect"]["status"] == "PASS", h["redirect"]["summary"][:90])
    check("step2-redirect", "the two reports DIFFER",
          v["redirect"]["status"] != h["redirect"]["status"])
    vopen = [b for b in v["redirect"]["evidence"] if "open_redirect_confirmed" in b]
    check("step2-redirect", "off-site redirects recorded as evidence",
          bool(vopen) and len(vopen[0]["open_redirect_confirmed"]) > 0,
          f"count={len(vopen[0]['open_redirect_confirmed']) if vopen else 0}")

    # Step 3 - PKCE
    check("step3-pkce", "non-enforcing server: CRITICAL FAIL",
          v["pkce"]["status"] == "FAIL" and v["pkce"]["severity"] == "CRITICAL",
          v["pkce"]["summary"][:90])
    check("step3-pkce", "enforcing server: PASS",
          h["pkce"]["status"] == "PASS", h["pkce"]["summary"][:90])
    check("step3-pkce", "both verdicts correct (they differ)",
          v["pkce"]["status"] != h["pkce"]["status"])

    # Step 4 - response types must match what the fixture enables
    vdecl = rv["target"]["metadata"].get("response_types_supported") or []
    hdecl = rh["target"]["metadata"].get("response_types_supported") or []
    vimp = [b for b in v["response-types"]["evidence"] if "implicit_or_hybrid_available" in b]
    himp = [b for b in h["response-types"]["evidence"] if "implicit_or_hybrid_available" in b]
    v_list = vimp[0]["implicit_or_hybrid_available"] if vimp else []
    h_list = himp[0]["implicit_or_hybrid_available"] if himp else []
    expected_v = sorted(r for r in vdecl if r in oa.IMPLICIT_TYPES)
    check("step4-response-types", "vulnerable: reported implicit flows == enabled implicit flows",
          sorted(v_list) == expected_v, f"reported={sorted(v_list)} enabled={expected_v}")
    check("step4-response-types", "hardened: no implicit flow reported",
          h_list == [] and h["response-types"]["status"] == "PASS",
          f"reported={h_list} declared={hdecl}")
    check("step4-response-types", "vulnerable FAILs and hardened PASSes",
          v["response-types"]["status"] == "FAIL" and h["response-types"]["status"] == "PASS")

    # Step 5 - token-in-URL: flagged with a token, not flagged without
    vq = [b for b in v["token-leakage"]["evidence"] if "credentials_in_query_component" in b]
    hq = [b for b in h["token-leakage"]["evidence"] if "credentials_in_query_component" in b]
    vlist = vq[0]["credentials_in_query_component"] if vq else []
    hlist = hq[0]["credentials_in_query_component"] if hq else []
    check("step5-token-in-url", "token-carrying redirect FLAGGED",
          len(vlist) > 0 and v["token-leakage"]["status"] == "FAIL",
          f"flagged={len(vlist)}")
    check("step5-token-in-url", "flagged parameters are tokens, not codes",
          all(x["parameter"] in ("access_token", "id_token", "refresh_token") for x in vlist),
          f"params={sorted({x['parameter'] for x in vlist})}")
    check("step5-token-in-url", "code-only redirects NOT flagged",
          h["token-leakage"]["status"] == "PASS" and hlist == [],
          f"flagged={len(hlist)}")
    inspected = [b for b in h["token-leakage"]["evidence"]
                 if "client_bound_redirects_inspected" in b]
    check("step5-token-in-url", "hardened run still inspected redirects (not vacuous)",
          bool(inspected) and inspected[0]["client_bound_redirects_inspected"] > 0,
          f"inspected={inspected[0]['client_bound_redirects_inspected'] if inspected else 0}")


# ---------------------------------------------------------------------------
# Step 6 - CLI arguments and report completeness across two different runs
# ---------------------------------------------------------------------------


def step6(tmpdir: str, vuln_port: int, clean_issuer: str = "", clean_extra=None) -> None:
    S = "step6-cli"
    # Run A: default checks
    rcA, rA, _ = run_audit(os.path.join(tmpdir, "6a"), f"http://127.0.0.1:{vuln_port}")
    # Run B: different settings - subset of checks, JSON only, different client type
    rcB, rB, outB = run_audit(
        os.path.join(tmpdir, "6b"), f"http://127.0.0.1:{vuln_port}",
        extra=["--checks", "redirect,pkce,jwks", "--format", "json",
               "--client-type", "confidential", "--client-secret", "s3cret"])

    check(S, "run A complete: all checks present",
          len(rA["findings"]) == len(oa.CHECKS), f"got {len(rA['findings'])}")
    check(S, "run B honours --checks subset",
          {f["check"] for f in rB["findings"]} == {"redirect", "pkce", "jwks"},
          f"got {sorted({f['check'] for f in rB['findings']})}")
    check(S, "run B wrote JSON but not HTML (--format json)",
          os.path.exists(os.path.join(tmpdir, "6b", "nullgrant-report.json"))
          and not os.path.exists(os.path.join(tmpdir, "6b", "nullgrant-report.html")))
    check(S, "the two reports differ (different settings)",
          len(rA["findings"]) != len(rB["findings"]))
    check(S, "both reports record their own run settings",
          rA["run"]["checks_enabled"] != rB["run"]["checks_enabled"])

    # argument validation
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc_bad = oa.main(["--issuer", "https://x.invalid", "--client-id", "c",
                          "--redirect-uri", "https://a.test/cb", "--checks", "nope",
                          "--dry-run"])
    check(S, "unknown --checks value rejected with exit 2", rc_bad == 2, f"rc={rc_bad}")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc_missing = oa.main(["--issuer", "https://x.invalid", "--dry-run"])
    check(S, "missing required args rejected with exit 2", rc_missing == 2, f"rc={rc_missing}")


# ---------------------------------------------------------------------------
# Step 7 - full run, every check has a verdict and evidence
# ---------------------------------------------------------------------------

VALID_STATUS = {"PASS", "FAIL", "WARN", "INFO", "INDETERMINATE"}
VALID_SEV = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def step7(tmpdir: str, vuln_port: int, hard_port: int,
          clean_issuer: str = "", clean_extra=None) -> None:
    S = "step7-full-run"
    reset_mock_state()
    rc_v, rv, _ = run_audit(
        os.path.join(tmpdir, "7v"), f"http://127.0.0.1:{vuln_port}",
        extra=["--refresh-token", LAB_REFRESH, "--allow-refresh-replay",
               "--access-token", LAB_ACCESS, "--scope", "openid profile"])
    reset_mock_state()
    rc_h, rh, _ = run_audit(
        os.path.join(tmpdir, "7h"), f"http://127.0.0.1:{hard_port}",
        extra=["--refresh-token", LAB_REFRESH, "--allow-refresh-replay",
               "--access-token", LAB_ACCESS, "--scope", "openid profile",
               "--client-secret", mock_as.CLIENT_SECRET])

    for label, rep, d in (("vulnerable", rv, "7v"), ("hardened", rh, "7h")):
        fs = rep["findings"]
        check(S, f"{label}: all {len(oa.CHECKS)} checks reported",
              len(fs) == len(oa.CHECKS), f"got {len(fs)}")
        check(S, f"{label}: check ids unique",
              len({f["check_id"] for f in fs}) == len(fs))

        empty_ev = [f["check_id"] for f in fs
                    if not f["evidence"]
                    or any(json.dumps(b) in ("{}", "[]", "null") for b in f["evidence"])]
        check(S, f"{label}: every check has non-empty evidence", not empty_ev,
              f"empty={empty_ev}")

        bad = [f["check_id"] for f in fs
               if f["status"] not in VALID_STATUS or f["severity"] not in VALID_SEV
               or len(f["summary"].strip()) <= 10
               or not f["recommendation"].strip() or not f["references"]
               or not f["check"].strip()]
        check(S, f"{label}: every check has verdict+severity+summary+fix+refs+cli-id",
              not bad, f"incomplete={bad}")

        mism = [k for k, n in rep["summary"].items()
                if sum(1 for f in fs if f["status"] == k) != n]
        check(S, f"{label}: summary counts agree with findings", not mism, f"mismatch={mism}")
        check(S, f"{label}: summary total equals finding count",
              sum(rep["summary"].values()) == len(fs))

        # HTML mirror
        hp = os.path.join(tmpdir, d, "nullgrant-report.html")
        htxt = open(hp, encoding="utf-8").read()
        check(S, f"{label}: HTML has one card per finding",
              htxt.count('<div class="card ') == len(fs))
        check(S, f"{label}: HTML has one evidence block per finding",
              htxt.count("<details>") == len(fs))
        missing = [f["check_id"] for f in fs if f["title"] not in htxt]
        check(S, f"{label}: every finding title present in HTML", not missing,
              f"missing={missing}")
        check(S, f"{label}: HTML is self-contained (no external refs)",
              not re.search(r'(src|href)="https?://', htxt))
        check(S, f"{label}: HTML not truncated", htxt.rstrip().endswith("</html>"))

        for k in ("issuer", "client_id", "redirect_uri", "authorization_endpoint",
                  "token_endpoint", "metadata_source", "platform"):
            check(S, f"{label}: report target/run block records {k}",
                  k in rep["target"] or k in rep["run"], f"missing {k}")

    v, h = by_id(rv), by_id(rh)
    check(S, "full run discriminates: vulnerable has failures",
          rv["summary"]["FAIL"] > 0, str(rv["summary"]))
    if clean_issuer:
        reset_mock_state()
        _, rclean, _ = run_audit(
            os.path.join(tmpdir, "7c"), clean_issuer,
            extra=(clean_extra or []) + ["--refresh-token", LAB_REFRESH,
                                         "--allow-refresh-replay",
                                         "--access-token", LAB_ACCESS,
                                         "--client-secret", mock_as.CLIENT_SECRET])
        check(S, "full run discriminates: TLS hardened has zero failures",
              rclean and rclean["summary"]["FAIL"] == 0, f"summary={(rclean or {}).get('summary')}")
        h = by_id(rclean) if rclean else h
        rh = rclean or rh
    check(S, "refresh-reuse detected on vulnerable, passed on hardened",
          v["refresh-reuse"]["status"] == "FAIL" and h["refresh-reuse"]["status"] == "PASS",
          f"v={v['refresh-reuse']['status']} h={h['refresh-reuse']['status']}")
    check(S, "introspection detected on vulnerable, passed on hardened",
          v["introspection"]["status"] == "FAIL" and h["introspection"]["status"] == "PASS",
          f"v={v['introspection']['status']} h={h['introspection']['status']}")


# ---------------------------------------------------------------------------
# Extras - gate, dry-run, unreachable, TLS + --target-ip
# ---------------------------------------------------------------------------


def extras(tmpdir: str, vuln_port: int) -> None:
    S = "extra-safety"
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = oa.main(["--issuer", f"http://127.0.0.1:{vuln_port}",
                      "--client-id", mock_as.CLIENT_ID, "--redirect-uri", REDIRECT_URI,
                      "--out", os.path.join(tmpdir, "gate")])
    check(S, "no --i-authorize-target -> exit 3, nothing sent", rc == 3, f"rc={rc}")
    check(S, "gate writes no report",
          not os.path.exists(os.path.join(tmpdir, "gate", "nullgrant-report.json")))

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = oa.main(["--issuer", f"http://127.0.0.1:{vuln_port}",
                      "--client-id", mock_as.CLIENT_ID, "--redirect-uri", REDIRECT_URI,
                      "--dry-run"])
    out = buf.getvalue()
    check(S, "--dry-run exits 0 and sends nothing", rc == 0 and "DRY RUN" in out, f"rc={rc}")
    check(S, "--dry-run lists every redirect variant",
          all(v["id"] in out or v["uri"] in out
              for v in oa.build_redirect_variants(REDIRECT_URI)))

    S2 = "extra-unreachable"
    dead = free_port()
    # An https issuer with an https redirect_uri: no finding is derivable from the URLs
    # alone, so every check must come back INDETERMINATE rather than guessing.
    rc, rep, _ = run_audit(
        os.path.join(tmpdir, "dead"), f"https://127.0.0.1:{dead}",
        extra=["--auth-endpoint", f"https://127.0.0.1:{dead}/authorize",
               "--token-endpoint", f"https://127.0.0.1:{dead}/token",
               "--jwks-uri", f"https://127.0.0.1:{dead}/jwks.json",
               "--redirect-uri", "https://app.example.test/callback",
               "--timeout", "3"])
    check(S2, "unreachable target yields NO false PASS",
          rep and all(f["status"] != "PASS" for f in rep["findings"]),
          f"pass={[f['check_id'] for f in (rep or {}).get('findings', []) if f['status'] == 'PASS']}")
    check(S2, "unreachable target reports all checks INDETERMINATE",
          rep and all(f["status"] == "INDETERMINATE" for f in rep["findings"]),
          f"summary={(rep or {}).get('summary')}")


def extras_session_cookie(tmpdir: str, vuln_port: int) -> None:
    """--session-cookie must reach the wire. A previous refactor silently broke this."""
    S = "extra-session-cookie"
    rc, rep, out = run_audit(
        os.path.join(tmpdir, "cookie"), f"http://127.0.0.1:{vuln_port}",
        extra=["--session-cookie", "sid=selftest-abc123",
               "--session-cookie", "theme=dark",
               "--checks", "discovery,redirect"])
    check(S, "--session-cookie does not crash the run",
          rep is not None and "Traceback" not in out and "AttributeError" not in out,
          f"rc={rc} out={out.strip()[:160]!r}")
    seen = mock_as.LAST_HEADERS.get("cookie") or ""
    check(S, "both cookies were sent on the wire",
          "sid=selftest-abc123" in seen and "theme=dark" in seen,
          f"server saw Cookie: {seen!r}")
    check(S, "Host header is still correct",
          (mock_as.LAST_HEADERS.get("host") or "") == f"127.0.0.1:{vuln_port}",
          f"saw {mock_as.LAST_HEADERS.get('host')!r}")


def extras_tui(tmpdir: str, vuln_port: int, clean_issuer: str = "", clean_extra=None) -> None:
    """The terminal interface must degrade cleanly, stay stdlib-only and never change a verdict."""
    tui = submod("tui")
    try:
        from nullgrant.checks import CHECK_IDS
    except ImportError:
        CHECK_IDS = oa.CHECK_IDS

    outdir = os.path.join(tmpdir, "tui")
    issuer = f"http://127.0.0.1:{vuln_port}"

    rc, report, out = run_audit(outdir, issuer, extra=["--tui"])
    plain_rc, plain_report, _ = run_audit(os.path.join(tmpdir, "tui-plain"), issuer)

    check("tui", "--tui keeps the same exit code as the plain run",
          rc == plain_rc == 1, f"tui rc={rc} plain rc={plain_rc}")
    check("tui", "--tui produces the same finding set as the plain run",
          report is not None and set(by_id(report)) == set(by_id(plain_report)),
          "finding sets differ between --tui and the plain run")

    check("tui", "target panel shows the issuer and both endpoints",
          "TARGET" in out and issuer in out
          and f"{issuer}/authorize" in out and f"{issuer}/token" in out)
    check("tui", "results dashboard shows all four verdict counters",
          "RESULTS" in out and all(k in out for k in ("FAIL", "WARN", "PASS", "UNKN")))

    n_fail = sum(1 for f in report["findings"] if f["status"] == "FAIL")
    check("tui", "dashboard FAIL counter agrees with the report",
          re.search(r"FAIL\s+" + str(n_fail) + r"\b", tui.strip_ansi(out)) is not None,
          f"expected FAIL {n_fail}")
    check("tui", "dashboard prints the failed verdict line",
          "AUDIT FAILED" in tui.strip_ansi(out))

    missing = [cid for cid in CHECK_IDS if cid not in out]
    check("tui", "every check id appears in the live progress rows", not missing,
          f"missing: {missing}")
    missing_panel = [f["check_id"] for f in report["findings"] if f["check_id"] not in out]
    check("tui", "every finding gets a panel carrying its check_id", not missing_panel,
          f"missing: {missing_panel}")

    ansi = re.findall(r"\033\[[0-9;]*m", out)
    check("tui", "piped output carries no colour escapes (auto mode degrades)",
          len(ansi) == 0, f"{len(ansi)} escapes leaked into piped output")
    cursor = [e for e in re.findall(r"\033\[[0-9;]*[A-Za-z]", out) if not e.endswith("m")]
    check("tui", "piped output carries no cursor-control escapes",
          not cursor, f"cursor escapes in non-tty output: {cursor[:4]}")

    rc2, _, out2 = run_audit(os.path.join(tmpdir, "tui-color"), issuer,
                             extra=["--tui", "--color", "always", "--format", "console"])
    check("tui", "--color always forces colour when stdout is not a tty",
          rc2 == 1 and len(re.findall(r"\033\[[0-9;]*m", out2)) > 50,
          f"rc={rc2} escapes={out2.count(chr(27))}")
    _, _, out3 = run_audit(os.path.join(tmpdir, "tui-nocolor"), issuer,
                           extra=["--tui", "--color", "never", "--format", "console"])
    check("tui", "--color never suppresses colour", "\033[" not in out3)

    w = tui.width()
    over = [(tui.vis_len(l), l[:40]) for l in out.splitlines() if tui.vis_len(l) > w]
    check("tui", f"no rendered line exceeds the terminal width ({w} columns)",
          not over, f"{len(over)} too wide: {over[:2]}")
    edges = (tui.BOX["tl"], tui.BOX["bl"], tui.BOX["v"],
             tui.BOX["dtl"], tui.BOX["dbl"])
    boxes = [l for l in out.splitlines() if l.startswith(edges)]
    check("tui", "every box border is exactly the terminal width",
          bool(boxes) and {tui.vis_len(b) for b in boxes} == {w},
          f"border widths: {sorted({tui.vis_len(b) for b in boxes})} vs {w}")
    check("tui", "utf-8 box drawing is used on a utf-8 terminal and ascii otherwise",
          tui.vis_len(tui.panel(["x"], title="T")[0]) == w
          and tui.vis_len(tui.panel(["x"], title="T", double=True)[0]) == w
          and tui.vis_len(tui.rule("T")) == w and tui.vis_len(tui.rule("")) == w)

    check("tui", "vis_len measures visible width, ignoring colour escapes",
          tui.vis_len(tui.c("abcdef", "red", "bold")) == 6 and tui.vis_len("") == 0)
    check("tui", "clip truncates to the visible budget, not the byte length",
          tui.vis_len(tui.clip(tui.c("x" * 80, "red"), 20)) <= 20)
    check("tui", "pad aligns coloured strings by visible width",
          tui.vis_len(tui.pad(tui.c("abc", "red"), 10)) == 10)

    if clean_issuer:
        rc4, _, out4 = run_audit(os.path.join(tmpdir, "tui-clean"), clean_issuer,
                                 extra=["--tui", "--format", "console"] + (clean_extra or []))
        text4 = tui.strip_ansi(out4)
        check("tui", "server with no failures renders a non-failing verdict line",
              rc4 == 0 and ("AUDIT CLEAN" in text4 or "REVIEW ADVISED" in text4)
              and "AUDIT FAILED" not in text4, f"rc={rc4}")

    real_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO("")            # immediate EOF -> leave the menu
        rc5 = oa.main(["--tui"])
    finally:
        sys.stdin = real_stdin
    check("tui", "menu with no input exits 0 without auditing anything", rc5 == 0, f"rc={rc5}")

    rc6 = oa.main(["--tui", "--dry-run", "--issuer", issuer,
                   "--client-id", mock_as.CLIENT_ID, "--redirect-uri", REDIRECT_URI])
    check("tui", "--tui --dry-run plans the requests and exits 0", rc6 == 0, f"rc={rc6}")

    import ast as _ast
    src_path = (os.path.join(ROOT, "nullgrant.py") if SINGLE_FILE
                else os.path.join(ROOT, "nullgrant", "tui.py"))
    tree = _ast.parse(open(src_path, encoding="utf-8").read())
    stdlib = stdlib_names()
    bad = []
    for node in _ast.walk(tree):
        mods = []
        if isinstance(node, _ast.Import):
            mods = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, _ast.ImportFrom) and node.level == 0 and node.module:
            mods = [node.module.split(".")[0]]
        bad += [m for m in mods if m not in stdlib and m != "nullgrant"]
    check("tui", "the interface imports nothing outside the standard library", not bad,
          str(sorted(set(bad))))


def extras_theme(tmpdir: str, vuln_port: int) -> None:
    """Palettes must be cosmetic: they may never change a verdict, a width or an exit code."""
    theme = submod("theme")

    issuer = f"http://127.0.0.1:{vuln_port}"
    prev_theme = theme.theme_name()

    check("theme", "the tool is named NullGrant and ships as the nullgrant package",
          theme is not None and oa.TOOL_NAME == "NullGrant"
          and oa.__version__ == oa.TOOL_VERSION and hasattr(oa, "main"))

    check("theme", "at least four palettes are available and neon is the default",
          len(theme.THEME_NAMES) >= 4 and theme.DEFAULT_THEME == "neon"
          and theme.DEFAULT_THEME in theme.THEME_NAMES,
          f"{theme.THEME_NAMES}")

    unknown = theme.set_theme("not-a-real-theme")
    check("theme", "an unknown theme name is ignored rather than crashing",
          unknown == prev_theme and theme.theme_name() == prev_theme, f"got {unknown}")

    # every palette must produce the identical verdict set
    base = None
    for name in theme.THEME_NAMES:
        rc, rep, out = run_audit(os.path.join(tmpdir, f"theme-{name}"), issuer,
                                 extra=["--tui", "--theme", name, "--color", "always",
                                        "--format", "console,json"])
        sig = sorted((f["check_id"], f["status"], f["severity"]) for f in rep["findings"])
        if base is None:
            base, base_rc = sig, rc
        check("theme", f"--theme {name} changes no verdict, severity or exit code",
              sig == base and rc == base_rc, f"{name} diverged from the neon baseline")
        over = [l for l in out.splitlines() if len(theme.strip_ansi(l)) > 120]
        check("theme", f"--theme {name} keeps every line within 120 columns",
              not over, f"{len(over)} lines too wide")
        check("theme", f"--theme {name} actually emits colour when forced on",
              "\033[" in out, "no escapes with --color always")

    # verdict colours are shared by every palette; only the chrome is themed
    def sgr(role, truecolor):
        if truecolor:
            os.environ["COLORTERM"] = "truecolor"
        else:
            os.environ.pop("COLORTERM", None)
        theme._init_color(); theme.force_color(True)
        seen = set()
        for name in theme.THEME_NAMES:
            theme.set_theme(name)
            seq = theme.c("X", role)
            seen.add(seq[2:seq.index("m", 2)] if seq.startswith("\033[") else "")
        return seen

    for tc in (False, True):
        label = "truecolor" if tc else "16-colour"
        for role in ("fail", "warn", "pass", "unknown"):
            check("theme", f"{role} is the same colour in every theme ({label})",
                  len(sgr(role, tc)) == 1, f"{role} varied: {sorted(sgr(role, tc))}")

    chrome = ("brand", "frame", "frame_hi", "title", "accent", "bar", "bar_track",
              "spinner", "menu_key", "notice")
    os.environ.pop("COLORTERM", None)
    theme._init_color(); theme.force_color(True)
    clash = []
    for name in theme.THEME_NAMES:
        theme.set_theme(name)
        fail = theme.c("X", "fail")
        clash += [(name, r) for r in chrome if theme.c("X", r) == fail]
    check("theme", "no chrome element shares the FAIL colour in 16-colour mode",
          not clash, f"collisions: {clash}")

    check("theme", "strip_ansi removes truecolor as well as 16-colour escapes",
          theme.strip_ansi("\033[38;2;255;45;149mabc\033[0m") == "abc"
          and theme.strip_ansi("\033[95mabc\033[0m") == "abc")

    os.environ["COLORTERM"] = "truecolor"
    theme._init_color(); theme.force_color(True)
    check("theme", "truecolor is used when the terminal advertises it",
          theme.truecolor_enabled() and "38;2;" in theme.c("X", "brand"),
          theme.c("X", "brand"))
    os.environ.pop("COLORTERM", None)
    theme._init_color(); theme.force_color(True)
    check("theme", "16-colour ANSI is used when it does not",
          not theme.truecolor_enabled() and "38;2;" not in theme.c("X", "brand"))

    theme.set_theme(prev_theme)
    theme._init_color()


def extras_tls(tmpdir: str) -> None:
    S = "extra-tls"
    crt, key = make_cert(tmpdir)
    if not crt:
        check(S, "TLS tests skipped (openssl not available)", True, "skipped")
        return

    port = free_port()
    start_mock("hardened", port, crt, key)
    issuer = f"https://localhost:{port}"

    # --target-ip: connect to 127.0.0.1 while presenting 'localhost' for Host + SNI
    rc, rep, _ = run_audit(os.path.join(tmpdir, "tls"), issuer,
                           extra=["--target-ip", "127.0.0.1", "--ca-bundle", crt])
    check(S, "--target-ip + --ca-bundle completes an audit", rep is not None and rc == 0,
          f"rc={rc}")
    check(S, "--target-ip preserved the issuer name (discovery issuer matched)",
          rep and rep["target"]["metadata_source"] == f"{issuer}/.well-known/openid-configuration",
          f"got={(rep or {}).get('target', {}).get('metadata_source')}")
    check(S, "--target-ip run has zero failures",
          rep and rep["summary"]["FAIL"] == 0, f"summary={(rep or {}).get('summary')}")

    # negative control: wrong hostname must be rejected by certificate verification
    rc2, rep2, out2 = run_audit(os.path.join(tmpdir, "tlsbad"),
                                f"https://wrongname.example:{port}",
                                extra=["--target-ip", "127.0.0.1", "--ca-bundle", crt,
                                       "--timeout", "5"])
    # Discovery cannot succeed, so main() exits 4 before running checks. The point of the
    # assertion is that TLS name checking is still enforced on the --target-ip path.
    check(S, "wrong hostname aborts the run (exit 4, no report)",
          rc2 == 4 and rep2 is None, f"rc={rc2} report={'yes' if rep2 else 'no'}")
    check(S, "certificate hostname verification is active on the --target-ip path",
          "Hostname mismatch" in out2 or "CERTIFICATE_VERIFY_FAILED" in out2,
          f"expected a TLS name-check failure; got: {out2.strip()[:160]!r}")


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-v", "--verbose", action="store_true", help="show audit console output")
    ap.add_argument("-k", "--filter", default="", help="only run checks whose name matches")
    a = ap.parse_args()

    tmpdir = tempfile.mkdtemp(prefix="nullgrant-selftest-")
    vuln_port, hard_port, tls_port = free_port(), free_port(), free_port()
    crt, key = make_cert(tmpdir)

    clean_issuer = f"https://localhost:{tls_port}" if crt else ""
    clean_extra = ["--ca-bundle", crt] if crt else None

    print("nullgrant self-test")
    print(f"  python    {sys.version.split()[0]} on {sys.platform}")
    print(f"  workspace {tmpdir}")
    print(f"  fixtures  vulnerable=http://127.0.0.1:{vuln_port}"
          f"  hardened=http://127.0.0.1:{hard_port}")
    print(f"            hardened+TLS={clean_issuer or 'unavailable (openssl missing)'}")
    print()

    t0 = time.time()
    try:
        start_mock("vulnerable", vuln_port)
        start_mock("hardened", hard_port)
        if crt:
            start_mock("hardened", tls_port, crt, key)

        reset_mock_state()
        step1_encoding()
        step1_end_to_end(vuln_port)
        reset_mock_state()
        steps2to5(tmpdir, vuln_port, hard_port, clean_issuer, clean_extra)
        reset_mock_state()
        step6(tmpdir, vuln_port, clean_issuer, clean_extra)
        step7(tmpdir, vuln_port, hard_port, clean_issuer, clean_extra)
        extras(tmpdir, vuln_port)
        extras_session_cookie(tmpdir, vuln_port)
        extras_tui(tmpdir, vuln_port, clean_issuer, clean_extra)
        extras_theme(tmpdir, vuln_port)
        extras_tls(tmpdir)
    finally:
        for srv in SERVERS:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass

    flt = a.filter.lower()
    rows = [r for r in RESULTS
            if not flt or flt in r["step"].lower() or flt in r["name"].lower()]

    print()
    cur = None
    for r in rows:
        if r["step"] != cur:
            cur = r["step"]
            print(f"  {cur}")
        mark = "PASS" if r["ok"] else "FAIL"
        print(f"     [{mark}] {r['name']}")
        if not r["ok"] and r["detail"]:
            print(f"            {r['detail']}")

    passed = sum(1 for r in rows if r["ok"])
    print()
    print("-" * 72)
    print(f"  {passed}/{len(rows)} assertions passed in {time.time() - t0:.1f}s")
    if passed != len(rows):
        print(f"  {len(rows) - passed} FAILED")
        for r in rows:
            if not r["ok"]:
                print(f"     - [{r['step']}] {r['name']}: {r['detail']}")
    print("-" * 72)

    shutil.rmtree(tmpdir, ignore_errors=True)
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted")
        sys.exit(130)
