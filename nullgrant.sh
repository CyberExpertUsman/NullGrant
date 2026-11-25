#!/usr/bin/env bash
#
# NullGrant launcher.
#
#   ./nullgrant.sh                       interactive menu
#   ./nullgrant.sh --help                all options
#   ./nullgrant.sh selftest              run the 143-assertion suite
#   ./nullgrant.sh --tui --theme matrix \
#       --issuer https://as.lab.example --client-id lab-client \
#       --redirect-uri https://app.lab.example/cb --i-authorize-target
#
# Everything else is passed straight through to the tool. Works from any directory,
# through a symlink, and with either layout: the single-file nullgrant.py or the
# nullgrant/ package. Needs nothing but a Python 3.8+ interpreter.
#
# Set PYTHON=/path/to/python3 to override interpreter detection.

set -euo pipefail

# --- locate this script, following symlinks ---------------------------------
src="${BASH_SOURCE[0]}"
while [ -L "$src" ]; do
    dir="$(cd -P "$(dirname "$src")" && pwd)"
    src="$(readlink "$src")"
    [[ "$src" != /* ]] && src="$dir/$src"
done
HERE="$(cd -P "$(dirname "$src")" && pwd)"

die() { printf 'nullgrant.sh: %s\n' "$*" >&2; exit 1; }

# --- find an interpreter ----------------------------------------------------
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1; then PY="$candidate"; break; fi
    done
fi
[ -n "$PY" ] || die "no python3 on PATH. Install it (Kali: sudo apt install python3),
           or point at one with:  PYTHON=/usr/bin/python3.11 $0 $*"

# --- it must actually run, and be 3.8 or newer ------------------------------
# Checked separately: otherwise a bad $PYTHON produces a shell error string that
# gets spliced into the "too old" message.
if ! "$PY" -c 'pass' >/dev/null 2>&1; then
    die "cannot run '$PY' - not found, not executable, or not a Python interpreter."
fi
if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
    die "$("$PY" -V 2>&1 || echo 'that interpreter') is too old. NullGrant needs Python 3.8+."
fi

# --- pick a layout ----------------------------------------------------------
SINGLE="$HERE/nullgrant.py"
PKGDIR="$HERE/nullgrant"

run_selftest() {
    local t
    for t in "$HERE/tests/selftest.py" "$HERE/../tests/selftest.py"; do
        if [ -f "$t" ]; then
            printf 'NullGrant self-test (%s)\n\n' "$t"
            # selftest.py puts the repo root on sys.path, so it imports whichever
            # layout is present: the nullgrant/ package or the merged nullgrant.py.
            exec "$PY" "$t" "$@"
        fi
    done
    die "tests/selftest.py not found. It ships in the repository, not in a bare
       single-file download - grab the zip from the releases page."
}

case "${1:-}" in
    selftest|self-test|--self-test)
        shift
        run_selftest "$@"
        ;;
esac

if [ -f "$SINGLE" ]; then
    exec "$PY" "$SINGLE" "$@"
fi

if [ -f "$PKGDIR/__init__.py" ]; then
    # -m needs the parent directory importable, whatever the current directory is.
    PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}" exec "$PY" -m nullgrant "$@"
fi

die "neither nullgrant.py nor the nullgrant/ package is next to this script ($HERE).
     Put nullgrant.sh in the same directory as one of them."
