#!/usr/bin/env bash
#
# Tests for nullgrant.sh. Runnable locally and in CI:
#
#     bash tests/test_launcher.sh
#
# Exits 0 if every case passes. Builds throwaway directory layouts in a temp dir to
# exercise the cases that cannot happen in a real checkout (package without the single
# file, single file without the package, launcher with nothing next to it).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
ck() { # ck <description> <expected-exit> <actual-exit> [extra-condition-output]
    if [ "$2" = "$3" ]; then
        printf '  [OK  ] %s\n' "$1"; pass=$((pass + 1))
    else
        printf '  [FAIL] %s  (expected exit %s, got %s) %s\n' "$1" "$2" "$3" "${4:-}"; fail=$((fail + 1))
    fi
}
ckout() { # ckout <description> <needle> <haystack>
    case "$3" in
        *"$2"*) printf '  [OK  ] %s\n' "$1"; pass=$((pass + 1)) ;;
        *) printf '  [FAIL] %s  (expected %q in output)\n' "$1" "$2"; fail=$((fail + 1)) ;;
    esac
}
cknot() { # cknot <description> <forbidden> <haystack>
    case "$3" in
        *"$2"*) printf '  [FAIL] %s  (output must not contain %q)\n' "$1" "$2"; fail=$((fail + 1)) ;;
        *) printf '  [OK  ] %s\n' "$1"; pass=$((pass + 1)) ;;
    esac
}

echo "nullgrant.sh launcher tests"
echo "  repo   $ROOT"
echo "  bash   $BASH_VERSION"
echo

# --- 1. syntax ---------------------------------------------------------------
bash -n "$ROOT/nullgrant.sh"; ck "bash -n: script parses" 0 $?

# --- 2. both layouts present (the real checkout) ------------------------------
out="$("$ROOT/nullgrant.sh" --version 2>&1)"; rc=$?
ck "runs from the checkout" 0 $rc
ckout "--version prints the tool name" "NullGrant" "$out"

cd /; out="$("$ROOT/nullgrant.sh" --version 2>&1)"; rc=$?
ck "runs with cwd=/ (no cwd dependency)" 0 $rc
cd "$ROOT" || exit 1

ln -sf "$ROOT/nullgrant.sh" "$WORK/link.sh"
out="$("$WORK/link.sh" --version 2>&1)"; rc=$?
ck "runs through a symlink" 0 $rc
ckout "symlink resolves to the real script" "NullGrant" "$out"

# --- 3. argument passthrough --------------------------------------------------
"$ROOT/nullgrant.sh" --dry-run --issuer https://as.example.test \
    --client-id c --redirect-uri https://a.test/cb >"$WORK/dry" 2>&1
ck "--dry-run passthrough exits 0" 0 $?
ckout "--dry-run actually reached the tool" "DRY RUN" "$(cat "$WORK/dry")"

"$ROOT/nullgrant.sh" --issuer https://as.example.test --client-id c \
    --redirect-uri https://a.test/cb --out "$WORK/gate" >"$WORK/gate.out" 2>&1
ck "authorisation gate still exits 3 through the launcher" 3 $?
if [ ! -e "$WORK/gate/nullgrant-report.json" ]; then st=0; else st=1; fi
ck "gate wrote no report" 0 $st

"$ROOT/nullgrant.sh" --checks bogus --issuer https://x.test --client-id c \
    --redirect-uri https://a.test/cb >/dev/null 2>&1
ck "bad --checks still exits 2 through the launcher" 2 $?

"$ROOT/nullgrant.sh" --theme bogus --version >/dev/null 2>&1
ck "bad --theme still exits 2 through the launcher" 2 $?

printf '0\n' | "$ROOT/nullgrant.sh" --tui --color never >"$WORK/menu" 2>&1
ck "--tui menu opens and exits 0" 0 $?
ckout "menu was drawn" "MAIN MENU" "$(cat "$WORK/menu")"

# --- 4. selftest shortcut -----------------------------------------------------
out="$("$ROOT/nullgrant.sh" selftest -k step1 2>&1)"; rc=$?
ck "'selftest' shortcut runs the suite (filtered)" 0 $rc
ckout "suite actually ran" "assertions passed" "$out"

# --- 5. interpreter handling --------------------------------------------------
out="$(PYTHON=/nonexistent/python3 "$ROOT/nullgrant.sh" --version 2>&1)"; rc=$?
ck "nonexistent \$PYTHON exits 1" 1 $rc
ckout "says it cannot run the interpreter" "cannot run" "$out"

out="$(PYTHON=/etc/hostname "$ROOT/nullgrant.sh" --version 2>&1)"; rc=$?
ck "non-interpreter \$PYTHON exits 1" 1 $rc
ckout "reports it cannot run" "cannot run" "$out"
# the real regression: this used to splice the shell's own error text into the "too old"
# message, producing "...: No such file or directory is too old."
cknot "does not misreport an unusable interpreter as merely too old" "too old" "$out"

PYTHON="$(command -v python3)" "$ROOT/nullgrant.sh" --version >/dev/null 2>&1
ck "explicit \$PYTHON override works" 0 $?

# --- 6. package-only layout ---------------------------------------------------
mkdir -p "$WORK/pkg"; cp -r "$ROOT/nullgrant" "$WORK/pkg/"; cp "$ROOT/nullgrant.sh" "$WORK/pkg/"
out="$("$WORK/pkg/nullgrant.sh" --version 2>&1)"; rc=$?
ck "package-only layout works" 0 $rc
ckout "package-only prints the version" "NullGrant" "$out"

# --- 7. single-file-only layout ----------------------------------------------
mkdir -p "$WORK/single"; cp "$ROOT/nullgrant.py" "$ROOT/nullgrant.sh" "$WORK/single/"
out="$("$WORK/single/nullgrant.sh" --version 2>&1)"; rc=$?
ck "single-file-only layout works" 0 $rc
"$WORK/single/nullgrant.sh" --dry-run --issuer https://as.example.test \
    --client-id c --redirect-uri https://a.test/cb 2>&1 | grep -q "DRY RUN"
ck "single-file-only passes arguments through" 0 $?

# --- 8. launcher with nothing to run -----------------------------------------
mkdir -p "$WORK/empty"; cp "$ROOT/nullgrant.sh" "$WORK/empty/"
out="$("$WORK/empty/nullgrant.sh" --version 2>&1)"; rc=$?
ck "launcher alone exits 1" 1 $rc
ckout "explains what is missing" "neither nullgrant.py nor" "$out"

mkdir -p "$WORK/notests"; cp "$ROOT/nullgrant.py" "$ROOT/nullgrant.sh" "$WORK/notests/"
out="$("$WORK/notests/nullgrant.sh" selftest 2>&1)"; rc=$?
ck "'selftest' without tests/ exits 1" 1 $rc
ckout "explains where the suite ships" "tests/selftest.py not found" "$out"

# --- 9. it must not swallow the tool's stdout or mangle colour ---------------
"$ROOT/nullgrant.sh" --tui --color always --dry-run --issuer https://as.example.test \
    --client-id c --redirect-uri https://a.test/cb >"$WORK/color" 2>&1
grep -q $'\033\[' "$WORK/color"
ck "--color always survives the launcher" 0 $?

echo
echo "----------------------------------------------------------------------"
printf '  %d/%d launcher cases passed\n' "$pass" "$((pass + fail))"
[ "$fail" -eq 0 ] || printf '  %d FAILED\n' "$fail"
echo "----------------------------------------------------------------------"
[ "$fail" -eq 0 ]
