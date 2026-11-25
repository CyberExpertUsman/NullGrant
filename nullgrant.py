#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NullGrant - configuration auditing for OAuth 2.0 / OpenID Connect authorization servers.

Single-file edition: the whole package merged into one script so it can be run on a
stock Kali/Linux python3 with no installation step and no third-party dependency.

    python3 nullgrant.py --help
    python3 nullgrant.py --tui                      # interactive menu
    python3 nullgrant.py --tui --theme matrix \
        --issuer https://as.lab.example --client-id lab-client \
        --redirect-uri https://app.lab.example/cb --i-authorize-target

Audits a server you own or are authorised to test against RFC 9700, RFC 6749,
RFC 7636, RFC 7662 and RFC 8414. Sends no traffic until you confirm with
--i-authorize-target. Exit codes: 0 clean, 1 findings, 2 bad arguments,
3 authorisation not confirmed, 4 no authorization endpoint, 130 interrupted.

Generated from the nullgrant package by tools/build_singlefile.py - the build is
deterministic, so CI can regenerate this file and fail if it drifts from the
committed copy. Prefer the package (pip install . / python3 -m nullgrant) for
development; this file is for deployment.
this file is for deployment. tests/selftest.py validates the package form.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import dataclasses
import datetime as _dt
import functools
import getpass
import hashlib
import html
import http.client
import json
import os
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import textwrap
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


# ============================================================================
# _version.py - Tool identity and version. Single source of truth for the vers
# ============================================================================

TOOL_NAME = "NullGrant"

TOOL_VERSION = "1.0.0"

USER_AGENT = f"{TOOL_NAME}/{TOOL_VERSION} (standards-compliance audit)"

#: PEP 440 version, kept identical to TOOL_VERSION.
__version__ = TOOL_VERSION

# ============================================================================
# model.py - Core data model: findings, captured HTTP responses, and the audit
# ============================================================================

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

STATUS_PASS = "PASS"

STATUS_FAIL = "FAIL"

STATUS_WARN = "WARN"

STATUS_INFO = "INFO"

STATUS_INDETERMINATE = "INDETERMINATE"

STATUS_LABEL = {
    STATUS_PASS: "pass",
    STATUS_FAIL: "FAIL",
    STATUS_WARN: "warn",
    STATUS_INFO: "info",
    STATUS_INDETERMINATE: "indeterminate",
}

@dataclass
class Finding:
    """A single audited control and its verdict."""

    check_id: str
    title: str
    status: str
    check: str = ""          # the --checks CLI id that produced this finding
    severity: str = "INFO"
    summary: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    recommendation: str = ""
    references: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

@dataclass
class HttpResponse:
    """A captured HTTP response. Redirects are NOT followed."""

    url: str
    status: int
    headers: Dict[str, str]
    body: bytes
    transport_error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.transport_error is None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def location(self) -> Optional[str]:
        return self.headers.get("location")

    @property
    def location_parts(self) -> Optional[Dict[str, Any]]:
        """Parsed Location header, if present."""
        if not self.location:
            return None
        p = urllib.parse.urlsplit(self.location)
        return {
            "raw": self.location,
            "scheme": p.scheme,
            "netloc": p.netloc,
            "host": p.hostname,
            "port": p.port,
            "path": p.path,
            "query": dict(urllib.parse.parse_qsl(p.query, keep_blank_values=True)),
            "fragment": dict(urllib.parse.parse_qsl(p.fragment, keep_blank_values=True)),
            "fragment_raw": p.fragment,
        }

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

@dataclass
class Target:
    """The authorization server under audit and the test client used to reach it."""

    issuer: str
    client_id: str
    redirect_uri: str
    client_type: str  # "public" | "confidential"
    client_secret: Optional[str] = None
    auth_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    jwks_uri: Optional[str] = None
    registration_endpoint: Optional[str] = None
    scopes: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    metadata_source: Optional[str] = None
    metadata_error: Optional[str] = None
    metadata_reachable: bool = False

# ============================================================================
# theme.py - Terminal colour and theming.
# ============================================================================

_COLOR_OK = False
_TRUECOLOR = False

_ATTRS = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "italic": "\033[3m", "underline": "\033[4m", "reverse": "\033[7m",
}

# The 16 base ANSI colours as RGB, used for the non-truecolor fallback. Order matters:
# index -> SGR code (30-37 normal, 90-97 bright).
_BASE16 = [
    ("black", (0, 0, 0), 30), ("red", (170, 0, 0), 31),
    ("green", (0, 170, 0), 32), ("yellow", (170, 85, 0), 33),
    ("blue", (0, 0, 170), 34), ("magenta", (170, 0, 170), 35),
    ("cyan", (0, 170, 170), 36), ("white", (170, 170, 170), 37),
    ("grey", (85, 85, 85), 90), ("bright_red", (255, 85, 85), 91),
    ("bright_green", (85, 255, 85), 92), ("bright_yellow", (255, 255, 85), 93),
    ("bright_blue", (85, 85, 255), 94), ("bright_magenta", (255, 85, 255), 95),
    ("bright_cyan", (85, 255, 255), 96), ("bright_white", (255, 255, 255), 97),
]
_BASE16_RGB = {name: rgb for name, rgb, _ in _BASE16}
_BASE16_SGR = {name: f"\033[{code}m" for name, _, code in _BASE16}

# Raw names accepted for backwards compatibility.
_ANSI = dict(_ATTRS)
_ANSI.update(_BASE16_SGR)

# --- roles shared by every theme -------------------------------------------
# Semantics, not decoration: these never change between themes.
_STATUS_ROLES = {
    "fail": "#FF3B5C",
    "warn": "#FFC400",
    "pass": "#2BFF88",
    "unknown": "#4DA6FF",
    "info": "#8FA6B8",
    "sev_critical": "#FF1744",
    "sev_high": "#FF6B7A",
    "sev_medium": "#FFC400",
    "sev_low": "#4DA6FF",
    "sev_info": "#8FA6B8",
}

# --- chrome, per theme ------------------------------------------------------
THEMES = {
    # Cyberpunk: hot magenta on electric cyan. The default.
    "neon": {
        "brand": "#FF2D95", "frame": "#00E5FF", "frame_hi": "#FF2D95",
        "title": "#00E5FF", "text": "#E8F6FF", "muted": "#6E8CA0",
        "accent": "#B967FF", "bar": "#FF2D95", "bar_track": "#1D3A47",
        "spinner": "#00E5FF", "notice": "#FFC400", "menu_key": "#FF2D95",
    },
    # Phosphor green CRT.
    "matrix": {
        "brand": "#39FF14", "frame": "#1FA80C", "frame_hi": "#39FF14",
        "title": "#39FF14", "text": "#D3FFC8", "muted": "#3E7A38",
        "accent": "#9DFF8A", "bar": "#39FF14", "bar_track": "#12330F",
        "spinner": "#39FF14", "notice": "#FFD60A", "menu_key": "#39FF14",
    },
    # Acid green with a yellow core.
    "toxic": {
        "brand": "#CCFF00", "frame": "#6FE000", "frame_hi": "#CCFF00",
        "title": "#CCFF00", "text": "#F4FFD6", "muted": "#6F7F3C",
        "accent": "#FFE600", "bar": "#CCFF00", "bar_track": "#2C3312",
        "spinner": "#CCFF00", "notice": "#FFB300", "menu_key": "#CCFF00",
    },
    # Hot metal: orange and red.
    "ember": {
        "brand": "#FF7A18", "frame": "#C43A2B", "frame_hi": "#FF7A18",
        "title": "#FF9A4D", "text": "#FFE8D6", "muted": "#8A5A44",
        "accent": "#FFC46B", "bar": "#FF7A18", "bar_track": "#3A2018",
        "spinner": "#FF9A4D", "notice": "#FFC46B", "menu_key": "#FF7A18",
    },
    # Cold blue, low aggression.
    "ice": {
        "brand": "#7FDBFF", "frame": "#3A7BD5", "frame_hi": "#7FDBFF",
        "title": "#9BE3FF", "text": "#EAF6FF", "muted": "#5A7A94",
        "accent": "#B8E6FF", "bar": "#7FDBFF", "bar_track": "#16283A",
        "spinner": "#7FDBFF", "notice": "#FFC400", "menu_key": "#7FDBFF",
    },
    # No chrome colour at all; attributes only. Verdicts stay coloured.
    "mono": {
        "brand": "#FFFFFF", "frame": "#808080", "frame_hi": "#FFFFFF",
        "title": "#FFFFFF", "text": "#E0E0E0", "muted": "#707070",
        "accent": "#FFFFFF", "bar": "#FFFFFF", "bar_track": "#404040",
        "spinner": "#FFFFFF", "notice": "#FFFFFF", "menu_key": "#FFFFFF",
    },
}

# Nearest-RGB snapping can put chrome and verdicts on the same base colour (neon's hot pink
# lands on bright red, which is also `fail`), so every role gets a hand-picked 16-colour
# fallback. _nearest16() remains only as a safety net for roles not listed here.
_STATUS_FALLBACK = {
    "fail": "bright_red", "warn": "bright_yellow", "pass": "bright_green",
    "unknown": "bright_blue", "info": "grey",
    "sev_critical": "bright_red", "sev_high": "red", "sev_medium": "yellow",
    "sev_low": "cyan", "sev_info": "grey",
}

_FALLBACKS = {
    "neon":   {"brand": "bright_magenta", "frame": "bright_cyan", "frame_hi": "bright_magenta",
               "title": "bright_cyan", "text": "bright_white", "muted": "grey",
               "accent": "magenta", "bar": "bright_magenta", "bar_track": "grey",
               "spinner": "bright_cyan", "notice": "bright_yellow", "menu_key": "bright_magenta"},
    "matrix": {"brand": "bright_green", "frame": "green", "frame_hi": "bright_green",
               "title": "bright_green", "text": "bright_white", "muted": "green",
               "accent": "bright_green", "bar": "bright_green", "bar_track": "grey",
               "spinner": "bright_green", "notice": "bright_yellow", "menu_key": "bright_green"},
    "toxic":  {"brand": "bright_yellow", "frame": "green", "frame_hi": "bright_yellow",
               "title": "bright_yellow", "text": "bright_white", "muted": "grey",
               "accent": "yellow", "bar": "bright_yellow", "bar_track": "grey",
               "spinner": "bright_yellow", "notice": "bright_yellow", "menu_key": "bright_yellow"},
    "ember":  {"brand": "bright_yellow", "frame": "red", "frame_hi": "red",
               "title": "bright_yellow", "text": "bright_white", "muted": "grey",
               "accent": "yellow", "bar": "bright_yellow", "bar_track": "grey",
               "spinner": "bright_yellow", "notice": "bright_yellow", "menu_key": "bright_yellow"},
    "ice":    {"brand": "bright_cyan", "frame": "blue", "frame_hi": "bright_cyan",
               "title": "bright_cyan", "text": "bright_white", "muted": "grey",
               "accent": "bright_cyan", "bar": "bright_cyan", "bar_track": "grey",
               "spinner": "bright_cyan", "notice": "bright_yellow", "menu_key": "bright_cyan"},
    "mono":   {"brand": "bright_white", "frame": "grey", "frame_hi": "bright_white",
               "title": "bright_white", "text": "white", "muted": "grey",
               "accent": "bright_white", "bar": "bright_white", "bar_track": "grey",
               "spinner": "bright_white", "notice": "bright_white", "menu_key": "bright_white"},
}

THEME_NAMES = tuple(THEMES)
DEFAULT_THEME = "neon"

_active = DEFAULT_THEME
_roles: dict = {}
_fallback: dict = {}
_cache: dict = {}


def _hex2rgb(h: str):
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _nearest16(h: str) -> str:
    r, g, b = _hex2rgb(h)
    best, dist = "white", None
    for name, (br, bg, bb) in _BASE16_RGB.items():
        # "redmean" approximation of perceptual distance - better than raw weighted RGB.
        rmean = (r + br) // 2
        d = ((2 + rmean / 256) * (r - br) ** 2 + 4 * (g - bg) ** 2
             + (2 + (255 - rmean) / 256) * (b - bb) ** 2)
        if dist is None or d < dist:
            best, dist = name, d
    return best


def _rebuild() -> None:
    global _roles, _fallback, _cache
    _roles = dict(_STATUS_ROLES)
    _roles.update(THEMES.get(_active, THEMES[DEFAULT_THEME]))
    _fallback = dict(_STATUS_FALLBACK)
    _fallback.update(_FALLBACKS.get(_active, {}))
    _cache = {}


_rebuild()


def _detect_truecolor() -> bool:
    override = os.environ.get("NULLGRANT_TRUECOLOR")
    if override is not None:
        return override.strip().lower() not in ("0", "", "no", "false", "off")
    if os.environ.get("COLORTERM", "").strip().lower() in ("truecolor", "24bit"):
        return True
    term = os.environ.get("TERM", "")
    if "direct" in term:
        return True
    return os.environ.get("TERM_PROGRAM", "") in (
        "iTerm.app", "Hyper", "vscode", "WezTerm", "mintty", "Tabby", "ghostty")


def _init_color() -> None:
    global _COLOR_OK, _TRUECOLOR
    if os.environ.get("NO_COLOR") is not None:
        _COLOR_OK = False
        return
    if os.environ.get("NULLGRANT_NO_COLOR") is not None:
        _COLOR_OK = False
        return
    try:
        _COLOR_OK = bool(sys.stdout.isatty())
    except Exception:
        _COLOR_OK = False
    _TRUECOLOR = _detect_truecolor()


def set_theme(name: str) -> str:
    """Activate a palette. Unknown names are ignored so a typo cannot break a run."""
    global _active
    if name in THEMES:
        _active = name
        _rebuild()          # _rebuild() resets _cache, so no stale colours survive
    return _active


def theme_name() -> str:
    return _active


def truecolor_enabled() -> bool:
    return _TRUECOLOR and _COLOR_OK


def _sgr(code: str) -> str:
    hit = _cache.get(code)
    if hit is not None:
        return hit
    if code in _ATTRS:
        out = _ATTRS[code]
    elif code in _BASE16_SGR and code not in _roles:
        out = _BASE16_SGR[code]
    elif code in _roles:
        hexv = _roles[code]
        if _TRUECOLOR:
            r, g, b = _hex2rgb(hexv)
            out = f"\033[38;2;{r};{g};{b}m"
        else:
            out = _BASE16_SGR[_fallback.get(code) or _nearest16(hexv)]
    else:
        out = ""
    _cache[code] = out
    return out


def c(text: str, *codes: str) -> str:
    """Wrap text in ANSI codes when colour is enabled; otherwise return it unchanged."""
    if not _COLOR_OK:
        return text
    prefix = "".join(_sgr(x) for x in codes)
    return f"{prefix}{text}{_ATTRS['reset']}" if prefix else text


def color_enabled() -> bool:
    """True when ANSI colour will actually be emitted."""
    return _COLOR_OK


def force_color(on: bool) -> None:
    """Override TTY autodetection. Used by --color=always / never."""
    global _COLOR_OK, _TRUECOLOR
    _COLOR_OK = bool(on)
    if on:
        _TRUECOLOR = _detect_truecolor()
    _cache.clear()


def strip_ansi(text: str) -> str:
    """Remove ANSI escapes - needed to measure the visible width of a string."""
    return re.sub(r"\033\[[0-9;]*m", "", text)


def palette_summary() -> str:
    """One-line description of the active rendering mode, for the banner."""
    if not _COLOR_OK:
        return "plain text (colour disabled)"
    return f"{_active} theme, {'truecolor 24-bit' if _TRUECOLOR else '16-colour ANSI'}"

# ============================================================================
# tui.py - tui.py - terminal interface for NullGrant.
# ============================================================================

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
        try:
            args = build_parser().parse_args(inner)
        except SystemExit:
            return 2
        _print([""])

    renderer = TuiRenderer(quiet=False)
    t0 = time.time()
    try:
        code = main(inner, on_event=renderer.event)
    except KeyboardInterrupt:
        code = 130
    finally:
        renderer.close()

    _print(["", c(f"  finished in {time.time() - t0:.1f}s {BOX['dot']} exit code {code}",
                  "muted"), ""])
    return code

# ============================================================================
# util.py - Small pure helpers: encoding, URI normalisation, redaction, detail
# ============================================================================

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def random_verifier(length: int = 64) -> str:
    """RFC 7636 compliant code_verifier (43-128 chars, unreserved charset)."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def s256_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())

def _host_of(url: str) -> Optional[str]:
    try:
        return urllib.parse.urlsplit(url).hostname
    except Exception:
        return None

def _origin_of(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    netloc = p.netloc
    if not netloc:
        return ""
    try:
        if p.port is None:
            netloc = p.hostname or ""
    except ValueError:
        pass
    return f"{p.scheme}://{netloc}".lower()

def normalize_uri(url: str) -> Optional[Tuple[str, str, Optional[int], str]]:
    """(scheme, host, effective_port, path) with RFC 3986 case/scheme-default normalisation."""
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    host = (p.hostname or "").lower()
    scheme = (p.scheme or "").lower()
    try:
        port = p.port
    except ValueError:
        port = None
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme)
    return scheme, host, port, p.path

def same_uri(a: str, b: str) -> bool:
    """True if a and b are the same URI after scheme/host case and default-port normalisation.

    The path is compared exactly - RFC 6749 s3.1.2.3 requires exact string matching, and
    case-folding the path would hide genuine matching bugs.
    """
    na, nb = normalize_uri(a), normalize_uri(b)
    if na is None or nb is None:
        return False
    return na == nb

def base_url(url: str) -> str:
    """Strip query and fragment."""
    return url.split("#", 1)[0].split("?", 1)[0]

def parse_json_maybe(text: str) -> Optional[Any]:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None

TRACE_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"java\.lang\.[A-Za-z]*Exception", "Java exception class name"),
    (r"at [\w.$]+\([\w.]+\.java:\d+\)", "Java stack frame"),
    (r"System\.(NullReference|Argument)Exception", ".NET exception"),
    (r"org\.springframework\.[\w.]+", "Spring framework internals"),
    (r"/var/www/|/home/\w+/|C:\\\\", "Server filesystem path"),
    (r"\bSELECT\b.+\bFROM\b.+\bWHERE\b", "Raw SQL fragment"),
    (r"sqlstate|ORA-\d{5}|pg_query", "Database driver error"),
]

def scan_for_internal_detail(text: str) -> List[str]:
    hits = []
    for pattern, label in TRACE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            hits.append(label)
    # de-duplicate, keep order
    seen = set()
    out = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out

SENSITIVE_KEYS = {"access_token", "id_token", "refresh_token", "code", "code_verifier",
                  "client_secret", "client_assertion", "password", "token"}

def redact_value(key: str, value: str) -> str:
    """Keep enough of a credential-like value to prove presence, hide the rest."""
    if key.lower() in SENSITIVE_KEYS and isinstance(value, str) and value:
        if len(value) <= 8:
            return "<redacted>"
        return f"<redacted len={len(value)} {value[:4]}...>"
    return value

def redact_url(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    if not p.query:
        return url
    q = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    red = urllib.parse.urlencode([(k, redact_value(k, v)) for k, v in q])
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, red, p.fragment))

def redact_body_snippet(text: str, limit: int = 400) -> str:
    t = re.sub(r"\s+", " ", text).strip()
    return t[:limit] + ("..." if len(t) > limit else "")

def build_url_with_params(url: str, params: Dict[str, Any]) -> str:
    clean = {k: v for k, v in params.items() if v is not None}
    sep = "&" if urllib.parse.urlsplit(url).query else "?"
    return url + sep + urllib.parse.urlencode(clean, quote_via=urllib.parse.quote)

# ============================================================================
# variants.py - Test inputs: redirect_uri mutations and the response types to 
# ============================================================================

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

# ============================================================================
# http.py - HTTP client. Redirects are never followed, so Location headers can
# ============================================================================

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

# ============================================================================
# context.py - Shared audit state: the target, the HTTP client, and the probe/
# ============================================================================

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

# ============================================================================
# discovery.py - Authorization server metadata discovery (RFC 8414 / OpenID Co
# ============================================================================

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

# ============================================================================
# report.py - Report rendering: colourised console output, JSON, and self-cont
# ============================================================================

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

# ============================================================================
# checks.py - The audit checks. Each takes an AuditContext and appends exactly
# ============================================================================

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

# ============================================================================
# cli.py - Command-line interface: argument parsing, interactive mode, and the
# ============================================================================

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

# ============================================================================
# entry point
# ============================================================================

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted")
        sys.exit(130)
