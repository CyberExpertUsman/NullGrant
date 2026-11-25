"""Command-line interface: argument parsing, interactive mode, and the run loop."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import textwrap
import time
from typing import Optional, Sequence, Tuple

from ._version import TOOL_NAME, TOOL_VERSION
from .checks import CHECKS, CHECK_IDS, DEFAULT_CHECKS
from .context import AuditContext
from .discovery import discover
from .http import HttpClient
from .model import STATUS_FAIL, STATUS_INDETERMINATE, STATUS_WARN, Finding, Target
from .report import (
    print_console,
    summarise,
    write_html_report,
    write_json_report,
)
from .theme import (DEFAULT_THEME, THEME_NAMES, _init_color, force_color, set_theme)
from .util import _host_of
from .variants import RESPONSE_TYPES_TO_ENUMERATE, build_redirect_variants

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nullgrant",
        description="Audit an OAuth 2.0 / OpenID Connect authorization server you own or are "
                    "authorised to test, against RFC 9700, RFC 6749, RFC 7636 and RFC 8414.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Full audit of a lab authorization server
              python3 nullgrant.py --issuer https://as.lab.example.com \\
                  --client-id lab-client --redirect-uri https://app.lab.example.com/cb \\
                  --client-type public --i-authorize-target --out ./report

              # Preview every request without sending anything
              python3 nullgrant.py --issuer https://as.lab.example.com \\
                  --client-id lab-client --redirect-uri https://app.lab.example.com/cb \\
                  --dry-run

              # Only the redirect_uri and PKCE checks, verbosely
              python3 nullgrant.py ... --i-authorize-target --checks redirect,pkce -v
            """),
    )

    req = p.add_argument_group("required (or answer the prompts with --interactive)")
    req.add_argument("--issuer",
                     help="Authorization server issuer URL, e.g. https://as.lab.example.com")
    req.add_argument("--client-id",
                     help="The registered test client to audit with")
    req.add_argument("--redirect-uri",
                     help="The exact redirect_uri registered for that client")
    req.add_argument("-i", "--interactive", action="store_true",
                     help="MODE 2: prompt for the issuer, client_id, redirect_uri and target IP "
                          "instead of passing them as flags")

    opt = p.add_argument_group("client and endpoint options")
    opt.add_argument("--client-type", choices=["public", "confidential"], default="public",
                     help="Client type (default: public)")
    opt.add_argument("--client-secret", default=os.environ.get("NULLGRANT_CLIENT_SECRET"),
                     help="Client secret, for confidential clients "
                          "(prefer the NULLGRANT_CLIENT_SECRET environment variable)")
    opt.add_argument("--auth-endpoint", help="Override the authorization endpoint")
    opt.add_argument("--token-endpoint", help="Override the token endpoint")
    opt.add_argument("--jwks-uri", help="Override the JWKS URI")
    opt.add_argument("--scope", help="Scope to request (default: none)")

    deeper = p.add_argument_group("deeper checks (optional inputs)")
    deeper.add_argument("--session-cookie", action="append", default=[],
                        metavar="NAME=VALUE",
                        help="Cookie from an authenticated lab session, so checks can get past "
                             "the login page. Repeatable. Never use a real user's session.")
    deeper.add_argument("--auth-code",
                        help="A single-use lab authorization code, to exercise the token endpoint")
    deeper.add_argument("--refresh-token",
                        help="A lab refresh token, to test rotation and reuse detection. "
                             "DESTRUCTIVE - see --allow-refresh-replay.")
    deeper.add_argument("--allow-refresh-replay", action="store_true",
                        help="Required with --refresh-token. Confirms you accept that replaying "
                             "it will consume the token and, on a correct server, revoke the "
                             "entire token family and invalidate that lab session.")
    deeper.add_argument("--access-token",
                        help="A lab access token, to record what the introspection endpoint "
                             "reveals and to whom")
    deeper.add_argument("--introspection-endpoint",
                        help="Override the introspection endpoint from discovery")

    run = p.add_argument_group("run control")
    run.add_argument("--target-ip", metavar="IP[:PORT]",
                     help="Send the TCP connection to this address instead of resolving the "
                          "issuer's hostname, while keeping the issuer name in the Host header "
                          "and TLS SNI. For labs with no DNS. Example: 10.10.1.5 or 10.10.1.5:8443")
    run.add_argument("--checks", default=",".join(DEFAULT_CHECKS),
                     help=f"Comma-separated subset of: {', '.join(CHECK_IDS)}")
    run.add_argument("--out", default="./nullgrant-report",
                     help="Output directory for reports (default: ./nullgrant-report)")
    run.add_argument("--format", default="console,json,html",
                     help="Comma-separated report formats: console,json,html")
    run.add_argument("--timeout", type=float, default=20.0, help="Per-request timeout in seconds")
    run.add_argument("--delay", type=float, default=0.15,
                     help="Pause between requests in seconds, to be gentle on the target")
    run.add_argument("--ca-bundle", metavar="PEM",
                     help="Trust this PEM certificate/CA bundle for the target's TLS. "
                          "Prefer this over --insecure-tls: hostname verification stays on.")
    run.add_argument("--insecure-tls", action="store_true",
                     help="Disable TLS certificate and hostname verification (lab use only; "
                          "prefer --ca-bundle)")
    run.add_argument("--dry-run", action="store_true",
                     help="Print the planned checks and requests; send nothing")
    run.add_argument("--i-authorize-target", action="store_true",
                     help="REQUIRED to send traffic. Confirms you own the target or hold "
                          "written permission to test it.")
    run.add_argument("--tui", action="store_true",
                     help="Terminal interface: banner, live progress and a results dashboard. "
                          "With no other arguments, shows an interactive menu.")
    run.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                     help="Colourise output (default: auto - colour only on a TTY)")
    run.add_argument("--theme", choices=list(THEME_NAMES),
                     default=os.environ.get("NULLGRANT_THEME", DEFAULT_THEME),
                     help="Colour palette for the terminal interface. Verdict colours "
                          "(red=fail, amber=warn, green=pass) are the same in every theme; "
                          "only the chrome changes. Also settable via NULLGRANT_THEME "
                          f"(default: {DEFAULT_THEME})")
    run.add_argument("-v", "--verbose", action="store_true", help="Verbose progress and evidence")
    run.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    return p

def _ask(prompt: str, default: Optional[str] = None, required: bool = True,
         secret: bool = False, choices: Optional[Sequence[str]] = None) -> Optional[str]:
    """One prompted field. Empty input takes the default, or re-prompts if required."""
    while True:
        suffix = f" [{default}]" if default else ""
        try:
            raw = (getpass.getpass(f"  {prompt}{suffix}: ") if secret
                   else input(f"  {prompt}{suffix}: "))
        except EOFError:
            print()
            raise SystemExit(2)
        except KeyboardInterrupt:
            print()
            raise SystemExit(130)
        val = raw.strip()
        if not val and default:
            return default
        if not val and not required:
            return None
        if not val and required:
            print("      required - please enter a value")
            continue
        if choices and val.lower() not in choices:
            print(f"      choose one of: {', '.join(choices)}")
            continue
        return val

def prompt_for_inputs(args: argparse.Namespace) -> None:
    """MODE 2 - collect the target description interactively, then fill in `args`."""
    print()
    print("=" * 78)
    print(f" {TOOL_NAME} {TOOL_VERSION} - interactive mode")
    print("=" * 78)
    print(" Answer the four questions below. Press Enter to accept a [bracketed] default.")
    print(" Nothing is sent until you confirm authorisation at the end.")
    print()

    if not args.issuer:
        args.issuer = _ask("1. Issuer URL of the authorization server")
    else:
        args.issuer = _ask("1. Issuer URL of the authorization server", default=args.issuer)
    args.issuer = args.issuer.rstrip("/")

    if "://" not in args.issuer:
        print("      no scheme given - assuming https://")
        args.issuer = "https://" + args.issuer

    print()
    if not args.target_ip:
        args.target_ip = _ask(
            "2. IP to connect to (blank = resolve the issuer hostname)",
            required=False)
    else:
        args.target_ip = _ask("2. IP to connect to", default=args.target_ip, required=False)
    if args.target_ip:
        print(f"      will connect to {args.target_ip} while presenting "
              f"{_host_of(args.issuer)!r} as Host and TLS SNI")

    print()
    args.client_id = _ask("3. Client ID of the registered test client",
                          default=args.client_id)

    print()
    args.redirect_uri = _ask("4. Exact registered redirect_uri for that client",
                             default=args.redirect_uri)

    print()
    args.client_type = _ask("Client type", default=args.client_type,
                            choices=["public", "confidential"])
    if args.client_type == "confidential" and not args.client_secret:
        args.client_secret = _ask("Client secret (input hidden)", required=False, secret=True)
        if args.client_secret:
            os.environ["NULLGRANT_CLIENT_SECRET"] = args.client_secret
    args.scope = _ask("Scope to request (blank = none)", default=args.scope, required=False)

    host = _host_of(args.issuer) or ""
    connect = ""
    if args.target_ip:
        connect = f"  -> via {args.target_ip}"
    print()
    print("-" * 78)
    print(" Review:")
    print(f"   issuer        {args.issuer}{connect}")
    print(f"   client_id     {args.client_id}")
    print(f"   redirect_uri  {args.redirect_uri}")
    print(f"   client_type   {args.client_type}")
    print(f"   scope         {args.scope or '(none)'}")
    print("-" * 78)
    print()

    if args.dry_run:
        # Nothing will be sent, so authorisation confirmation is not required.
        print(" --dry-run given: no confirmation needed, nothing will be sent.")
        print()
        args.i_authorize_target = True
        return

    print(f" To authorise testing of {host}, type its hostname exactly:")
    confirm = _ask("Confirm", required=True)
    if confirm != host:
        print()
        print(f"  Typed {confirm!r}, expected {host!r}. Nothing was sent. Aborting.")
        print()
        raise SystemExit(3)
    args.i_authorize_target = True
    print()

def parse_target_ip(spec: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
    """Split 'IP' or 'IP:PORT' (also accepts [IPv6]:port)."""
    if not spec:
        return None, None
    spec = spec.strip()
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port) if port else None
    if spec.count(":") == 1:
        host, _, port = spec.partition(":")
        return host, int(port)
    return spec, None

AUTHORISATION_BANNER = """\
NullGrant is a security auditing tool. It will send live HTTP requests to the target
authorization server, including deliberately malformed and off-site redirect_uri values.

Only run it against a server you own, or one you hold written permission to test.
Re-run with --i-authorize-target to confirm you are authorised.
Use --dry-run first to see exactly what would be sent."""

def resolve_target(args: argparse.Namespace, http: HttpClient) -> Target:
    t = Target(
        issuer=args.issuer.rstrip("/"),
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        client_type=args.client_type,
        client_secret=args.client_secret,
        auth_endpoint=args.auth_endpoint,
        token_endpoint=args.token_endpoint,
        jwks_uri=args.jwks_uri,
        scopes=args.scope,
    )
    info = discover(t, http, verbose=args.verbose)
    t.metadata = info["metadata"]
    t.metadata_source = info["source"]
    t.metadata_error = info["error"]
    t.metadata_reachable = bool(info.get("reachable"))
    md = t.metadata
    if not t.auth_endpoint:
        t.auth_endpoint = md.get("authorization_endpoint")
    if not t.token_endpoint:
        t.token_endpoint = md.get("token_endpoint")
    if not t.jwks_uri:
        t.jwks_uri = md.get("jwks_uri")
    return t

def emit(on_event, kind: str, **payload) -> None:
    """Fire a progress event. Callbacks must never break the run."""
    if not on_event:
        return
    try:
        on_event(kind, payload)
    except Exception:
        pass


def main(argv: Optional[Sequence[str]] = None, on_event=None) -> int:
    args = build_parser().parse_args(argv)
    _init_color()
    set_theme(args.theme)
    if args.color == "always":
        force_color(True)
    elif args.color == "never":
        force_color(False)

    # --tui hands the whole run to the terminal interface, which calls back into main()
    # with the flag removed. No recursion: the inner call has no --tui.
    if args.tui and on_event is None:
        from .tui import run_tui

        return run_tui(args, list(argv or sys.argv[1:]))

    # MODE 2: prompt for the target description, then fall through to the same code path.
    if args.interactive:
        prompt_for_inputs(args)

    missing = [flag for attr, flag in (("issuer", "--issuer"),
                                       ("client_id", "--client-id"),
                                       ("redirect_uri", "--redirect-uri"))
               if not getattr(args, attr, None)]
    if missing:
        print(f"error: the following arguments are required: {', '.join(missing)}",
              file=sys.stderr)
        print("       (or pass -i / --interactive to be prompted for them)", file=sys.stderr)
        return 2

    try:
        connect_host, connect_port = parse_target_ip(args.target_ip)
    except ValueError:
        print(f"error: --target-ip must be IP or IP:PORT with a numeric port, "
              f"got {args.target_ip!r}", file=sys.stderr)
        return 2

    requested = [c.strip() for c in args.checks.split(",") if c.strip()]
    unknown = [c for c in requested if c not in CHECK_IDS]
    if unknown:
        print(f"error: unknown check(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"available: {', '.join(CHECK_IDS)}", file=sys.stderr)
        return 2
    # token-leakage consumes evidence from the other checks; always run it last.
    ordered = [c for c in CHECK_IDS if c in requested]
    if "token-leakage" in ordered:
        ordered.remove("token-leakage")
        ordered.append("token-leakage")
    args.checks = ordered

    if args.client_type == "confidential" and not args.client_secret and not args.dry_run:
        print("warning: --client-type confidential with no --client-secret; "
              "token endpoint checks will treat the client as unauthenticated", file=sys.stderr)
    if args.client_secret:
        os.environ.pop("NULLGRANT_CLIENT_SECRET", None)

    if args.dry_run:
        print_dry_run(args)
        return 0

    if not args.i_authorize_target:
        print()
        print(textwrap.fill(AUTHORISATION_BANNER, 88))
        print()
        print(f"  Target: {args.issuer}")
        print(f"  Client: {args.client_id}")
        print()
        return 3

    if args.insecure_tls:
        print("warning: --insecure-tls disables certificate AND hostname verification; "
              "results cannot be trusted against an active network attacker. "
              "Prefer --ca-bundle.", file=sys.stderr)
    http = HttpClient(timeout=args.timeout, insecure_tls=args.insecure_tls,
                      connect_host=connect_host, connect_port=connect_port,
                      ca_bundle=args.ca_bundle, cookies=args.session_cookie)
    emit(on_event, "phase", phase="discovery")
    target = resolve_target(args, http)
    emit(on_event, "discovered", target=target)

    if not target.auth_endpoint:
        print("error: no authorization_endpoint could be determined. Discovery failed "
              f"({target.metadata_error}) and --auth-endpoint was not given.", file=sys.stderr)
        return 4


    # Patch probe to honour the inter-request delay.
    original_get = http.get
    original_post = http.post_form

    def delayed_get(*a, **k):
        time.sleep(args.delay)
        return original_get(*a, **k)

    def delayed_post(*a, **k):
        time.sleep(args.delay)
        return original_post(*a, **k)

    http.get = delayed_get          # type: ignore[method-assign]
    http.post_form = delayed_post   # type: ignore[method-assign]

    ctx = AuditContext(target, http, args)
    by_id = {cid: (label, fn) for cid, label, fn in CHECKS}
    titles = {cid: label for cid, label, _ in CHECKS}
    total = len(args.checks)
    emit(on_event, "checks-start", total=total, ids=list(args.checks))
    for index, cid in enumerate(args.checks, start=1):
        if args.verbose:
            print(f"  running check: {cid}", file=sys.stderr)
        emit(on_event, "check-start", check=cid, title=titles.get(cid, cid),
             index=index, total=total)
        first_new = len(ctx.findings)
        started = time.time()
        try:
            by_id[cid][1](ctx)
        except KeyboardInterrupt:
            print("\ninterrupted", file=sys.stderr)
            return 130
        except Exception as exc:  # a failing check must not kill the run
            ctx.add(Finding(
                check_id=cid,
                check=cid,
                title=f"Check '{cid}' raised an exception",
                status=STATUS_INDETERMINATE,
                severity="INFO",
                summary=f"{type(exc).__name__}: {exc}",
                evidence=[{"exception": type(exc).__name__, "message": str(exc)}],
                recommendation="Re-run with -v and report the failing check.",
            ))
        # Correlate every finding this check produced with its --checks id.
        for added in ctx.findings[first_new:]:
            if not added.check:
                added.check = cid
        emit(on_event, "check-end", check=cid, title=titles.get(cid, cid),
             index=index, total=total, elapsed=time.time() - started,
             findings=ctx.findings[first_new:], requests=http.request_count)

    emit(on_event, "checks-done", findings=ctx.findings, requests=http.request_count,
         elapsed=time.time() - ctx.started_at)

    label = f"{target.issuer} ({_host_of(target.issuer)})"
    if "console" in args.format:
        if on_event is None:
            print_console(ctx, label)
        else:
            # TUI mode: the dashboard has already been drawn by the checks-done event,
            # so render the finding panels instead of the plain-text console report.
            from .tui import render_findings

            sys.stdout.write("\n".join(render_findings(ctx.findings, args.verbose)) + "\n")
            sys.stdout.flush()

    os.makedirs(args.out, exist_ok=True)
    stem = os.path.join(args.out, "nullgrant-report")
    written = []
    if "json" in args.format:
        write_json_report(ctx, stem + ".json")
        written.append(stem + ".json")
    if "html" in args.format:
        write_html_report(ctx, stem + ".html")
        written.append(stem + ".html")
    if written:
        print("Reports written:")
        for w in written:
            print(f"  {w}")

    counts = summarise(ctx.findings)
    if counts[STATUS_FAIL]:
        return 1
    if counts[STATUS_WARN]:
        return 0
    return 0

def print_dry_run(args: argparse.Namespace) -> None:
    t = Target(issuer=args.issuer.rstrip("/"), client_id=args.client_id,
               redirect_uri=args.redirect_uri, client_type=args.client_type)
    print(f"\n{TOOL_NAME} {TOOL_VERSION} - DRY RUN (no requests sent)\n")
    print(f"Target        : {t.issuer}")
    if args.target_ip:
        print(f"Connect to    : {args.target_ip}  "
              f"(Host header and TLS SNI stay {_host_of(t.issuer)!r})")
    print(f"Client        : {t.client_id} ({t.client_type})")
    print(f"Redirect URI  : {t.redirect_uri}")
    print(f"Checks queued : {', '.join(args.checks)}")
    print("\nRequests that would be sent:\n")
    print(f"  1. GET {t.issuer}/.well-known/openid-configuration")
    print(f"  2. GET {t.issuer}/.well-known/oauth-authorization-server")
    print("\n  3. Authorization endpoint probes (one GET each):")
    for v in build_redirect_variants(t.redirect_uri):
        print(f"     - redirect_uri variant [{v['id']}]: {v['description']}")
        print(f"         {v['uri']}")
    print(f"     - response_type enumeration: "
          f"{', '.join(rt for rt, _ in RESPONSE_TYPES_TO_ENUMERATE)}")
    print("     - PKCE: absent, plain, undersized challenge, non-base64url, bogus method")
    print("     - state: unique value echoed, state omitted, same state sent twice")
    print("     - error hygiene: unknown client_id, empty parameters, unknown parameters")
    print("\n  4. Token endpoint probes (POST each):")
    print("     - invalid code with no client authentication")
    print("     - unsupported grant_type")
    if args.auth_code:
        print("     - supplied --auth-code exchanged WITHOUT code_verifier")
    if args.refresh_token and args.allow_refresh_replay:
        print("     - supplied --refresh-token used once, then REPLAYED  ** DESTRUCTIVE **")
        print("       a correct server revokes the whole token family on the replay")
    elif args.refresh_token:
        print("     - skipped refresh-token replay (--allow-refresh-replay not given)")
    if args.access_token:
        print("     - introspection: POST with token unauthenticated, then authenticated")
    print("\n  5. JWKS: GET the published jwks_uri")

    total = 2 + len(build_redirect_variants(t.redirect_uri)) + len(RESPONSE_TYPES_TO_ENUMERATE) + 7 + 3 + 1
    print(f"\nApproximately {total} HTTP requests. Redirects are never followed.")
    print("No brute forcing, no credential stuffing, no user accounts touched.\n")
