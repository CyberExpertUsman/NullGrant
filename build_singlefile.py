"""Merge the nullgrant package into one runnable single-file script.

AST-driven, not text-splicing: module docstrings and import statements are removed by
their exact line ranges, modules are emitted in topological order, and stdlib imports are
hoisted and de-duplicated. The deferred cli<->tui imports simply disappear because every
name is global in a single file.

Regenerate with:  python3 tools/build_singlefile.py
Then verify with:  python3 tests/compare_singlefile.py
CI regenerates the file and fails if it differs from the committed copy, so the shipped
single file can never silently drift from the package.
"""
import ast, os, sys, collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PKG_DIR = os.path.join(ROOT, "nullgrant")
OUT_FILE = os.path.join(ROOT, "nullgrant.py")
PKG = "nullgrant"
SKIP = {"__init__", "__main__"}


def stdlib_names() -> set:
    """Names of the standard library.

    sys.stdlib_module_names is Python 3.10+, but CI regenerates the single file on every
    leg of the 3.8-3.13 matrix, so this has to work on 3.8 and 3.9 too. The fallback scans
    the stdlib directory. Mirrors tests/selftest.py:stdlib_names().
    """
    names = getattr(sys, "stdlib_module_names", None)
    if names:
        return set(names)
    import importlib.machinery
    import sysconfig
    root = sysconfig.get_paths()["stdlib"]
    suffixes = sorted(importlib.machinery.all_suffixes(), key=len, reverse=True)
    out = set(sys.builtin_module_names) | {"__future__"}
    dirs = [root]
    dynload = os.path.join(root, "lib-dynload")   # C extensions are not in the root
    if os.path.isdir(dynload):
        dirs.append(dynload)
    for entry in [e for d in dirs for e in os.listdir(d)]:
        if entry == "__pycache__":
            continue
        for suf in suffixes:                      # unicodedata.cpython-38-x86_64-linux-gnu.so
            if entry.endswith(suf):
                entry = entry[:-len(suf)]
                break
        out.add(entry)
    return out
mods = [f[:-3] for f in sorted(os.listdir(PKG_DIR))
        if f.endswith(".py") and f[:-3] not in SKIP]

# ---- module-level dependency edges (deferred/function-local ones are ignored: in a single
# ---- file every name is already global, so those imports simply disappear) ----
deps, trees, sources = {}, {}, {}
for m in mods:
    src = open(os.path.join(PKG_DIR, m + ".py"), encoding="utf-8").read()
    sources[m], trees[m] = src, ast.parse(src)
    d = set()
    for n in trees[m].body:
        if isinstance(n, ast.ImportFrom) and n.level >= 1 and n.module:
            d.add(n.module.split(".")[0])
    deps[m] = d

order, done = [], set()
while len(done) < len(mods):
    prog = False
    for m in sorted(mods):
        if m not in done and deps[m] <= done:
            order.append(m); done.add(m); prog = True
    if not prog:
        sys.exit(f"CYCLE in module-level imports: {sorted(set(mods) - done)}")
print("topological order:", " -> ".join(order))

# ---- collect stdlib imports to hoist, and line ranges to delete ----
stdlib = stdlib_names()
hoist, hoist_from = set(), collections.defaultdict(set)
delete = collections.defaultdict(set)      # module -> set of 1-based line numbers

for m in mods:
    for n in ast.walk(trees[m]):
        # Every stdlib import is hoisted, including function-local ones: the merged file
        # has no module boundaries, so deleting `import subprocess` from inside a function
        # without hoisting it would leave a NameError waiting at that call site.
        if isinstance(n, ast.Import):
            delete[m].update(range(n.lineno, n.end_lineno + 1))
            for a in n.names:
                root = a.name.split(".")[0]
                if root in stdlib:
                    hoist.add(a.name if not a.asname else f"{a.name} as {a.asname}")
                elif root not in mods:
                    raise SystemExit(f"{m}.py imports unknown module {a.name!r}")
        elif isinstance(n, ast.ImportFrom):
            delete[m].update(range(n.lineno, n.end_lineno + 1))
            if n.level == 0 and n.module:
                root = n.module.split(".")[0]
                if root == "__future__":
                    continue        # emitted once, at the top, by the header
                if root in stdlib:
                    for a in n.names:
                        hoist_from[n.module].add(a.name if not a.asname else f"{a.name} as {a.asname}")
                elif root not in mods:
                    raise SystemExit(f"{m}.py imports unknown module {n.module!r}")

# ---- emit ----
out = []
out.append('#!/usr/bin/env python3')
out.append('# -*- coding: utf-8 -*-')
out.append('"""')
out.append('NullGrant - configuration auditing for OAuth 2.0 / OpenID Connect authorization servers.')
out.append('')
out.append('Single-file edition: the whole package merged into one script so it can be run on a')
out.append('stock Kali/Linux python3 with no installation step and no third-party dependency.')
out.append('')
out.append('    python3 nullgrant.py --help')
out.append('    python3 nullgrant.py --tui                      # interactive menu')
out.append('    python3 nullgrant.py --tui --theme matrix \\')
out.append('        --issuer https://as.lab.example --client-id lab-client \\')
out.append('        --redirect-uri https://app.lab.example/cb --i-authorize-target')
out.append('')
out.append('Audits a server you own or are authorised to test against RFC 9700, RFC 6749,')
out.append('RFC 7636, RFC 7662 and RFC 8414. Sends no traffic until you confirm with')
out.append('--i-authorize-target. Exit codes: 0 clean, 1 findings, 2 bad arguments,')
out.append('3 authorisation not confirmed, 4 no authorization endpoint, 130 interrupted.')
out.append('')
out.append('Generated from the nullgrant package by tools/build_singlefile.py - the build is')
out.append('deterministic, so CI can regenerate this file and fail if it drifts from the')
out.append('committed copy. Prefer the package (pip install . / python3 -m nullgrant) for')
out.append('development; this file is for deployment.')
out.append('this file is for deployment. tests/selftest.py validates the package form.')
out.append('"""')
out.append('')
out.append('from __future__ import annotations')
out.append('')
for name in sorted(hoist):
    out.append(f'import {name}')
for mod in sorted(hoist_from):
    out.append(f'from {mod} import ' + ", ".join(sorted(hoist_from[mod])))
out.append('')

for m in order:
    lines = sources[m].splitlines()
    # Remove the module docstring by its exact AST line range - a text heuristic here
    # once ate a line inside checks.py and produced an unterminated string literal.
    doc_txt = ""
    b0 = trees[m].body[0] if trees[m].body else None
    if isinstance(b0, ast.Expr) and isinstance(b0.value, ast.Constant) \
            and isinstance(b0.value.value, str):
        delete[m].update(range(b0.lineno, b0.end_lineno + 1))
        doc_txt = b0.value.value.strip().splitlines()[0].strip()
    body = [ln for i, ln in enumerate(lines, 1) if i not in delete[m]]
    while body and not body[0].strip():
        body.pop(0)
    header = f"{m}.py - {doc_txt}" if doc_txt else f"{m}.py"
    out.append('')
    out.append('# ' + '=' * 76)
    out.append('# ' + header[:76])
    out.append('# ' + '=' * 76)
    out.append('')
    out.extend(body)

src = "\n".join(out)
# the deferred `from .cli import main as cli_main` is gone, so point the alias at the global
src = src.replace("cli_main(", "main(")
src += '''

# ============================================================================
# entry point
# ============================================================================

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\\ninterrupted")
        sys.exit(130)
'''
open(OUT_FILE, "w", encoding="utf-8").write(src)
# len(src) counts characters; the file on disk is UTF-8, and the TUI box drawing is
# multi-byte, so report the encoded length or the number will not match `ls -l`.
print(f"wrote {OUT_FILE}: {len(src.splitlines()):,} lines, {len(src.encode('utf-8')):,} bytes")
