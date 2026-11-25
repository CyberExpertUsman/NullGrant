"""Terminal colour and theming.

Colour is emitted only when it is safe to: stdout must be a TTY (or `--color always`), and
`NO_COLOR` / `NULLGRANT_NO_COLOR` always win. When colour is off, `c()` is the identity
function, so every caller can format unconditionally.

Two rendering tiers:

* **truecolor** (24-bit `38;2;R;G;B`) when the terminal advertises it, so the neon and
  matrix palettes are the exact colours they were designed as;
* **16-colour ANSI** otherwise, by snapping each palette colour to its nearest base colour.

Callers pass *semantic roles* (`brand`, `frame`, `fail`, ...) rather than raw colour names,
which is what makes `--theme` a one-line switch. Raw names (`red`, `bright_cyan`, ...) and
attributes (`bold`, `dim`, ...) still resolve, so older call sites keep working.

Verdict and severity colours are deliberately identical in every theme: red means fail,
amber means warn, green means pass. Only the chrome is themed, so a report never changes
meaning because someone liked a different palette.
"""

from __future__ import annotations

import os
import re
import sys

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
