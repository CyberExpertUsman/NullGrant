"""
tui.py - terminal interface for NullGrant.

Pure stdlib: ANSI escapes plus Unicode box drawing, with an ASCII fallback for terminals
that are not UTF-8. Colour and decoration degrade automatically when stdout is not a TTY,
so piping the output still gives clean, greppable text.

The renderer is driven by events emitted from cli.main(), so the run loop stays the single
source of truth and this module only draws.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import sys
import threading
import time
import unicodedata
from typing import Any, Dict, List, Optional, Sequence

from ._version import TOOL_NAME, TOOL_VERSION
from .model import (
    SEVERITY_ORDER,
    STATUS_FAIL,
    STATUS_INDETERMINATE,
    STATUS_INFO,
    STATUS_PASS,
    STATUS_WARN,
    Finding,
)
from .theme import c, palette_summary, strip_ansi

# ---------------------------------------------------------------------------
# Terminal capabilities
# ---------------------------------------------------------------------------

_UTF8 = (sys.stdout.encoding or "").lower().replace("-", "").startswith("utf")

BOX = {
    "h": "─" if _UTF8 else "-",
    "v": "│" if _UTF8 else "|",
    "tl": "┌" if _UTF8 else "+",
    "tr": "┐" if _UTF8 else "+",
    "bl": "└" if _UTF8 else "+",
    "br": "┘" if _UTF8 else "+",
    "lm": "├" if _UTF8 else "+",
    "rm": "┤" if _UTF8 else "+",
    "dh": "═" if _UTF8 else "=",
    "dtl": "╔" if _UTF8 else "+",
    "dtr": "╗" if _UTF8 else "+",
    "dbl": "╚" if _UTF8 else "+",
    "dbr": "╝" if _UTF8 else "+",
    "tick": "✓" if _UTF8 else "v",
    "cross": "✗" if _UTF8 else "x",
    "bang": "!" ,
    "ques": "?" if _UTF8 else "?",
    "arrow": "▸" if _UTF8 else ">",
    "dot": "·" if _UTF8 else "-",
}

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if _UTF8 else r"|/-\\"
BLOCK = "█" if _UTF8 else "#"

STATUS_STYLE = {
    STATUS_FAIL: ("fail", BOX["cross"], "FAIL"),
    STATUS_WARN: ("warn", BOX["bang"], "WARN"),
    STATUS_PASS: ("pass", BOX["tick"], "PASS"),
    STATUS_INDETERMINATE: ("unknown", BOX["ques"], "UNKN"),
    STATUS_INFO: ("info", BOX["dot"], "INFO"),
}

SEV_STYLE = {
    "CRITICAL": "sev_critical",
    "HIGH": "sev_high",
    "MEDIUM": "sev_medium",
    "LOW": "sev_low",
    "INFO": "sev_info",
}

# "NULLGRANT" in box-drawing glyphs, one row per line.
LOGO = [
    "\u2554\u2557\u2554 \u2566 \u2566 \u2566   \u2566   \u2554\u2550\u2557 \u2566\u2550\u2563 \u2554\u2550\u2557 \u2554\u2557\u2554 \u2554\u2566\u2557",
    "\u2551\u2551\u2551 \u2551 \u2551 \u2551   \u2551   \u2551 \u2566 \u2560\u2566\u255d \u2560\u2550\u2563 \u2551\u2551\u2551  \u2551 ",
    "\u255d\u255a\u255d \u255a\u2550\u255d \u2569\u2550\u255d \u2569\u2550\u255d \u255a\u2550\u255d \u2569\u255a\u2550 \u2569 \u2569 \u255d\u255a\u255d  \u2569 ",
]


def is_tty() -> bool:
    """True when stdout is an interactive terminal, so cursor control is safe."""
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def width() -> int:
    """Usable drawing width. One column of slack is kept so a full-width border never
    lands on the last cell, which some terminals wrap immediately."""
    try:
        cols = shutil.get_terminal_size((100, 24)).columns
    except Exception:
        cols = 100
    return max(40, min(cols - 1, 120))


def vis_len(s: str) -> int:
    """Visible width, ignoring ANSI escapes and counting wide glyphs as 2."""
    n = 0
    for ch in strip_ansi(s):
        if unicodedata.combining(ch):
            continue
        n += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return n


def clip(s: str, n: int) -> str:
    """Truncate to n visible columns, preserving any colour reset."""
    if vis_len(s) <= n:
        return s
    out, used = [], 0
    for ch in strip_ansi(s):
        w = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if used + w > n - 1:
            break
        out.append(ch)
        used += w
    return "".join(out) + ("…" if _UTF8 else ".")


def pad(s: str, n: int) -> str:
    return s + " " * max(0, n - vis_len(s))


# ---------------------------------------------------------------------------
# Drawing primitives
# ---------------------------------------------------------------------------


def rule(title: str = "", w: Optional[int] = None, colour: str = "muted") -> str:
    w = w or width()
    if not title:
        return c(BOX["h"] * w, colour)
    left = f"{BOX['h'] * 2} {title.upper()} "
    fill = max(0, w - vis_len(left) - 2)
    return c(left + BOX["h"] * fill + BOX["h"] * 2, colour)


def panel(lines: Sequence[str], title: str = "", w: Optional[int] = None,
          colour: str = "frame", double: bool = False) -> List[str]:
    w = w or width()
    inner = w - 4
    tl, tr = (BOX["dtl"], BOX["dtr"]) if double else (BOX["tl"], BOX["tr"])
    bl, br = (BOX["dbl"], BOX["dbr"]) if double else (BOX["bl"], BOX["br"])
    h = BOX["dh"] if double else BOX["h"]

    if title:
        head = f"{tl}{h * 2} {title} "
        # fill == w - vis_len(head) - 1 so head + fill + tr is exactly w columns wide
        out = [c(head + h * max(0, w - vis_len(head) - 1) + tr, colour)]
    else:
        out = [c(tl + h * (w - 2) + tr, colour)]

    for line in lines:
        out.append(c(BOX["v"], colour) + " " + pad(clip(line, inner), inner)
                   + " " + c(BOX["v"], colour))
    out.append(c(bl + h * (w - 2) + br, colour))
    return out


def bar(frac: float, n: int, colour: str = "bar") -> str:
    frac = max(0.0, min(1.0, frac))
    filled = int(round(frac * n))
    return c(BLOCK * filled, colour) + c(BOX["h"] * max(0, n - filled), "bar_track")


def sev_chip(sev: str) -> str:
    return c(sev, SEV_STYLE.get(sev, "muted"), "bold")


def status_chip(status: str) -> str:
    colour, glyph, label = STATUS_STYLE.get(status, ("muted", BOX["dot"], status[:4]))
    return c(f"[{glyph}] {label}", colour, "bold")


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------


def banner(w: Optional[int] = None) -> List[str]:
    w = w or width()
    out: List[str] = []
    logo_w = max(len(r) for r in LOGO)

    if _UTF8 and w >= logo_w + 6:
        out.append("")
        for row in LOGO:
            out.append("  " + c(row, "brand", "bold"))
        out.append("  " + c(
            f"{TOOL_NAME} v{TOOL_VERSION}  {BOX['dot']}  OAuth 2.0 / OIDC authorization "
            f"server configuration audit", "accent"))
        out.append("  " + c(
            f"RFC 9700 {BOX['dot']} RFC 6749 {BOX['dot']} RFC 7636 {BOX['dot']} "
            f"RFC 7662 {BOX['dot']} RFC 8414  {BOX['dot']}  {palette_summary()}", "muted"))
        out.append("")
    else:
        out.append("")
        out.append(c(f"  {TOOL_NAME} v{TOOL_VERSION}", "brand", "bold"))
        out.append(c("  OAuth 2.0 / OIDC authorization server configuration audit", "accent"))
        out.append("")
    return out


def warning_banner() -> List[str]:
    lines = [
        c("AUTHORISED TESTING ONLY", "warn", "bold"),
        "",
        "This tool sends live requests to the target, including deliberately malformed",
        "and off-site redirect_uri values. Run it only against a server you own or hold",
        "written permission to test.",
    ]
    return panel(lines, title="! NOTICE", colour="notice", double=True)


# ---------------------------------------------------------------------------
# Spinner
# ---------------------------------------------------------------------------


class Spinner:
    """Braille spinner animated on its own line while a check blocks."""

    def __init__(self, label: str, enabled: bool = True):
        self.label = label
        self.enabled = enabled and sys.stdout.isatty()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._suffix = ""

    def __enter__(self) -> "Spinner":
        if not self.enabled:
            print(f"  {BOX['arrow']} {self.label}")
            sys.stdout.flush()
            return self
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def _spin(self) -> None:
        i = 0
        w = width()
        while not self._stop.is_set():
            frame = SPINNER[i % len(SPINNER)]
            line = f"  {c(frame, 'spinner', 'bold')} {self.label} {c(self._suffix, 'muted')}"
            sys.stdout.write("\r" + clip(line, w - 1).ljust(max(0, w - vis_len(line))))
            sys.stdout.flush()
            i += 1
            self._stop.wait(0.08)

    def note(self, text: str) -> None:
        self._suffix = text

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        if self.enabled:
            sys.stdout.write("\r" + " " * (width() - 1) + "\r")
            sys.stdout.flush()


# ---------------------------------------------------------------------------
# Event-driven renderer
# ---------------------------------------------------------------------------


class TuiRenderer:
    """Consumes progress events from cli.main() and draws the live interface."""

    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self.w = width()
        self._spinner: Optional[Spinner] = None
        self._rows: List[str] = []
        self._index = 0
        self._total = 0
        self._started = time.time()
        self._requests = 0

    # -- event entry point -------------------------------------------------
    def event(self, kind: str, payload: Dict[str, Any]) -> None:
        if self.quiet:
            return
        handler = getattr(self, f"_on_{kind.replace('-', '_')}", None)
        if handler:
            handler(payload)

    def _on_phase(self, p: Dict[str, Any]) -> None:
        if p.get("phase") == "discovery":
            self._print_live(f"  {c(SPINNER[0], 'spinner')} discovering endpoints "
                             f"and reading metadata {c(BOX['dot']*3, 'muted')}")

    def _on_discovered(self, p: Dict[str, Any]) -> None:
        self._clear_live()
        t = p.get("target")
        if t is None:
            return
        k = lambda name: pad(c(name, "muted"), 14)
        rows = [
            k("issuer") + t.issuer,
            k("client") + f"{t.client_id}  {c(f'({t.client_type})', 'muted')}",
            k("redirect_uri") + t.redirect_uri,
            k("authorize") + (t.auth_endpoint or c("not found", "notice")),
            k("token") + (t.token_endpoint or c("not found", "notice")),
            k("jwks") + (t.jwks_uri or c("not published", "muted")),
        ]
        if t.metadata_source:
            rows.append(k("metadata") + c("ok", "pass") + " "
                        + c(t.metadata_source, "muted"))
        else:
            rows.append(k("metadata") + c("unavailable", "notice") + " "
                        + c(str(t.metadata_error or "")[:60], "muted"))
        for line in panel(rows, title="TARGET", colour="frame"):
            self._write(line)
        self._write("")

    def _on_checks_start(self, p: Dict[str, Any]) -> None:
        self._total = p.get("total", 0)
        self._index = 0
        self._rows = []
        self._write(rule(f"RUNNING {self._total} CHECKS", colour="accent"))

    def _on_check_start(self, p: Dict[str, Any]) -> None:
        self._index = p.get("index", self._index + 1)
        label = f"{self._index:>2}/{self._total}  {p.get('check', ''):<16} {p.get('title', '')}"
        self._spinner = Spinner(label)
        self._spinner.__enter__()

    def _on_check_end(self, p: Dict[str, Any]) -> None:
        if self._spinner:
            self._spinner.__exit__()
            self._spinner = None
        self._requests = p.get("requests", self._requests)
        findings: List[Finding] = p.get("findings") or []
        f = findings[0] if findings else None
        status = f.status if f else STATUS_INDETERMINATE
        sev = f.severity if f else "INFO"
        elapsed = p.get("elapsed", 0.0)

        name = pad(p.get("check", ""), 16)
        title = clip(p.get("title", ""), max(10, self.w - 52))
        sev_txt = pad(sev_chip(sev) if status == STATUS_FAIL else c(sev, "muted"), 17)
        line = (f"  {status_chip(status)}  {c(name, 'bold')}{c(title, 'muted')}"
                f"  {sev_txt}{c(f'{elapsed:4.1f}s', 'muted')}")
        self._rows.append(line)
        self._write(line)
        if is_tty():
            frac = self._index / self._total if self._total else 1.0
            self._write(f"  {bar(frac, min(30, self.w - 24))} {int(frac * 100):>3}%  "
                        f"{c(f'{self._requests} req', 'muted')}")
            self._erase_line_back()

    def _on_checks_done(self, p: Dict[str, Any]) -> None:
        self._write("")
        self._requests = p.get("requests", self._requests)
        self.render_dashboard(p.get("findings") or [], p.get("elapsed", 0.0))

    # -- dashboard ---------------------------------------------------------
    def render_dashboard(self, findings: Sequence[Finding], elapsed: float) -> None:
        self.w = width()               # the terminal may have been resized during the run
        counts = {STATUS_FAIL: 0, STATUS_WARN: 0, STATUS_PASS: 0, STATUS_INDETERMINATE: 0}
        for f in findings:
            counts[f.status] = counts.get(f.status, 0) + 1
        sevs: Dict[str, int] = {}
        for f in findings:
            if f.status == STATUS_FAIL:
                sevs[f.severity] = sevs.get(f.severity, 0) + 1

        head = []
        if sevs:
            head.append("  " + "   ".join(
                f"{sev_chip(s)} {c(str(n), 'bold')}"
                for s, n in sorted(sevs.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))))
        else:
            head.append("  " + c("no failures by severity", "muted"))
        head.append("")
        head.append("  " + "   ".join([
            c(f"FAIL {counts[STATUS_FAIL]}", "fail", "bold"),
            c(f"WARN {counts[STATUS_WARN]}", "warn", "bold"),
            c(f"PASS {counts[STATUS_PASS]}", "pass", "bold"),
            c(f"UNKN {counts[STATUS_INDETERMINATE]}", "unknown", "bold"),
        ]))

        total = max(1, len(findings))
        budget = self.w - 8            # 2 columns of panel padding either side
        order = ((STATUS_FAIL, "fail"), (STATUS_WARN, "warn"),
                 (STATUS_INDETERMINATE, "unknown"), (STATUS_PASS, "pass"))
        present = [(counts.get(st, 0), col) for st, col in order if counts.get(st, 0)]
        # Largest-remainder allocation so the segments add up to exactly `budget`.
        raw = [n / total * budget for n, _ in present]
        sizes = [max(1, int(r)) for r in raw]
        for i, _ in enumerate(sorted(range(len(raw)), key=lambda i: raw[i] - sizes[i],
                                     reverse=True)):
            if sum(sizes) >= budget:
                break
            sizes[i] += 1
        while sum(sizes) > budget and max(sizes) > 1:
            sizes[sizes.index(max(sizes))] -= 1
        head.append("  " + "".join(c(BLOCK * n, col) for n, (_, col) in zip(sizes, present)))
        head.append("")
        head.append("  " + c(f"{len(findings)} checks {BOX['dot']} {self._requests} requests "
                             f"{BOX['dot']} {elapsed:.1f}s", "muted"))

        verdict = ("AUDIT FAILED - findings require remediation" if counts[STATUS_FAIL]
                   else "REVIEW ADVISED - warnings present" if counts[STATUS_WARN]
                   else "AUDIT CLEAN - no failures observed")
        vcol = ("fail" if counts[STATUS_FAIL]
                else "warn" if counts[STATUS_WARN] else "pass")
        head.append("  " + c(verdict, vcol, "bold"))

        for line in panel(head, title="RESULTS", colour=vcol, double=True):
            self._write(line)

    # -- output helpers ----------------------------------------------------
    def _write(self, line: str) -> None:
        sys.stdout.write(line.rstrip() + "\n")
        sys.stdout.flush()

    def _print_live(self, line: str) -> None:
        if not is_tty():
            self._write(clip(line, self.w - 1))
            return
        self._live = True
        sys.stdout.write(clip(line, self.w - 1))
        sys.stdout.flush()

    def _clear_live(self) -> None:
        if getattr(self, "_live", False):
            sys.stdout.write("\r" + " " * (self.w - 1) + "\r")
            sys.stdout.flush()
            self._live = False

    def _erase_line_back(self) -> None:
        """Move the cursor up over the transient progress bar and clear it."""
        if not is_tty():
            return
        sys.stdout.write("\033[1A\033[2K")
        sys.stdout.flush()

    def close(self) -> None:
        if self._spinner:
            self._spinner.__exit__()
            self._spinner = None
        self._clear_live()


# ---------------------------------------------------------------------------
# Detailed finding view
# ---------------------------------------------------------------------------


def render_findings(findings: Sequence[Finding], verbose: bool = False) -> List[str]:
    ordered = sorted(findings, key=lambda f: (
        0 if f.status == STATUS_FAIL else 1 if f.status == STATUS_WARN
        else 2 if f.status == STATUS_INDETERMINATE else 3,
        SEVERITY_ORDER.get(f.severity, 9), f.check_id))

    out: List[str] = []
    for f in ordered:
        colour = {"FAIL": "fail", "WARN": "warn", "PASS": "pass",
                  "INDETERMINATE": "unknown"}.get(f.status, "info")
        head = [
            f"{status_chip(f.status)}  {c(f.title, 'bold')}",
            f"  {c('--checks', 'muted')} {f.check or '-'}   "
            f"{c('check_id', 'muted')} {f.check_id}   "
            f"{c('severity', 'muted')} {sev_chip(f.severity)}",
            "",
        ]
        for chunk in _wrap(f.summary, width() - 8):
            head.append("  " + chunk)
        if f.status != STATUS_PASS and f.recommendation:
            head.append("")
            head.append("  " + c("REMEDIATION", "muted", "bold"))
            for chunk in _wrap(f.recommendation, width() - 8):
                head.append("  " + c(chunk, "muted"))
        if verbose and f.evidence:
            head.append("")
            head.append("  " + c("EVIDENCE", "muted", "bold"))
            import json
            text = json.dumps(f.evidence, indent=2, default=str)
            for chunk in text.splitlines()[:60]:
                head.append("  " + c(chunk[:width() - 8], "muted"))
        if f.references:
            head.append("")
            head.append("  " + c("refs: " + ", ".join(f.references), "muted"))
        out.extend(panel(head, colour=colour))
        out.append("")
    return out


def _wrap(text: str, n: int) -> List[str]:
    import textwrap
    return textwrap.wrap(text, max(20, n)) or [""]


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------


def menu(args) -> Optional[List[str]]:
    """Main menu. Returns argv for cli.main(), or None to exit."""
    items = [
        ("1", "Guided audit", "answer prompts for issuer, client, redirect_uri, target IP"),
        ("2", "Audit with current flags", "run using the arguments already supplied"),
        ("3", "Dry run", "print every request that would be sent, send nothing"),
        ("4", "Self-test", "run the bundled assertion suite against the local fixtures"),
        ("5", "Show a saved report", "summarise a JSON report from a previous run"),
        ("0", "Exit", ""),
    ]
    while True:
        w = width()
        for line in banner(w):
            print(line)
        for line in warning_banner():
            print(line)
        print()
        rows = []
        for key, name, desc in items:
            rows.append(f"  {c(f'[{key}]', 'menu_key', 'bold')} "
                        f"{c(pad(name, 26), 'text', 'bold')}{c(desc, 'muted')}")
        for line in panel(rows, title="MAIN MENU", colour="accent"):
            print(line)
        print()
        try:
            choice = input(c("  select " + BOX["arrow"] + " ", "menu_key", "bold")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None

        if choice == "0" or choice.lower() in ("q", "quit", "exit"):
            return None
        if choice == "1":
            return ["--interactive"]
        if choice == "2":
            if not (args.issuer and args.client_id and args.redirect_uri):
                print(c("  issuer, client-id and redirect-uri are all required "
                        "for this option - use [1] instead.", "notice"))
                input(c("  press enter to continue ", "muted"))
                continue
            return []
        if choice == "3":
            if not (args.issuer and args.client_id and args.redirect_uri):
                print(c("  issuer, client-id and redirect-uri are all required.", "notice"))
                input(c("  press enter to continue ", "muted"))
                continue
            return ["--dry-run"]
        if choice == "4":
            _run_selftest()
            input(c("\n  press enter to return to the menu ", "muted"))
            continue
        if choice == "5":
            _show_report()
            input(c("\n  press enter to return to the menu ", "muted"))
            continue
        print(c("  unrecognised option", "notice"))
        time.sleep(0.7)


def _run_selftest() -> None:
    import subprocess
    # Package layout:  <root>/nullgrant/tui.py   -> dirname twice
    # Single-file:     <root>/nullgrant.py       -> dirname once
    here = os.path.dirname(os.path.abspath(__file__))
    roots = [here, os.path.dirname(here), os.path.dirname(os.path.dirname(here))]
    candidates = [os.path.join(r, "tests", "selftest.py") for r in roots]
    path = next((p for p in candidates if os.path.exists(p)), None)
    print()
    if not path:
        print(c("  selftest.py not found - it ships in tests/ of the source checkout,", "notice"))
        print(c("  not in the installed package.", "notice"))
        return
    print(c(f"  running {path}", "muted"))
    print()
    subprocess.call([sys.executable, path])


def _show_report() -> None:
    import json
    print()
    default = ""
    for cand in ("./nullgrant-report/nullgrant-report.json",
                 "./report/nullgrant-report.json"):
        if os.path.exists(cand):
            default = cand
            break
    try:
        path = input(c("  report path", "menu_key")
                     + (f" [{default}]" if default else "") + ": ").strip() or default
    except (EOFError, KeyboardInterrupt):
        return
    if not path or not os.path.exists(path):
        print(c("  no such file", "notice"))
        return
    try:
        d = json.load(open(path, encoding="utf-8"))
    except Exception as exc:
        print(c(f"  could not parse: {exc}", "notice"))
        return
    print()
    t = d.get("target", {})
    k = lambda name: pad(c(name, "muted"), 12)
    head = [
        k("issuer") + str(t.get("issuer") or "-"),
        k("generated") + str(d.get("generated_at") or "-"),
        k("tool") + f"{d.get('tool')} {d.get('version')}",
        k("platform") + str(d.get("run", {}).get("platform", ""))[:44],
    ]
    for line in panel(head, title="REPORT", colour="frame"):
        print(line)
    print()
    fields = {fld.name for fld in dataclasses.fields(Finding)}
    loaded = [Finding(**{k: v for k, v in f.items() if k in fields})
              for f in d.get("findings", [])]
    for line in render_findings(loaded):
        print(line)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _print(lines: Sequence[str]) -> None:
    sys.stdout.write("\n".join(l.rstrip() for l in lines) + "\n")
    sys.stdout.flush()


def run_tui(args, argv: List[str]) -> int:
    """Take over the run: banner, live progress, dashboard, finding panels."""
    from .cli import main as cli_main

    inner = [a for a in argv if a != "--tui"]

    def enough(a) -> bool:
        return bool(a.issuer and a.client_id and a.redirect_uri) or a.interactive

    if enough(args):
        _print(banner())
        if not args.dry_run and not args.i_authorize_target:
            _print(warning_banner())
            _print([""])
    else:
        # Nothing to run yet: menu() draws the banner, the notice and the options itself.
        chosen = menu(args)
        if chosen is None:
            _print(["", c(f"  bye {BOX['dot']} no requests were sent", "muted"), ""])
            return 0
        if chosen:
            inner = inner + chosen
        from .cli import build_parser
        try:
            args = build_parser().parse_args(inner)
        except SystemExit:
            return 2
        _print([""])

    renderer = TuiRenderer(quiet=False)
    t0 = time.time()
    try:
        code = cli_main(inner, on_event=renderer.event)
    except KeyboardInterrupt:
        code = 130
    finally:
        renderer.close()

    _print(["", c(f"  finished in {time.time() - t0:.1f}s {BOX['dot']} exit code {code}",
                  "muted"), ""])
    return code
