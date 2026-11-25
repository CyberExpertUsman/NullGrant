# Architecture and module wiring

Every file in this repository, what it does, and exactly which other files it depends on.
The import graph below is **generated and verified**, not hand-written: `tests/selftest.py`
and CI both fail if a module stops resolving.

## Dependency graph

```
                        python -m nullgrant          nullgrant  (console script)
                                │                          │
                                └──────────┬───────────────┘
                                           ▼
                                    ┌────────────┐
                                    │    cli     │  argparse, authorisation gate,
                                    └────────────┘  interactive mode, run loop
                                     │  │  │  │  │
        ┌────────────┬───────────┬───┘  │  │  │  └───────┬────────────┐
        ▼            ▼           ▼      ▼  ▼  ▼          ▼            ▼
  ┌──────────┐ ┌──────────┐ ┌───────┐ │  │  │    ┌──────────┐  ┌──────────┐
  │discovery │ │ variants │ │checks │ │  │  │    │  report  │  │   tui    │
  └──────────┘ └──────────┘ └───────┘ │  │  │    └──────────┘  └──────────┘
        │            │           │     │  │  │          │            │
        └────────────┴─────┬─────┴─────┘  │  └──────────┤            │
                           ▼              ▼             ▼            ▼
                     ┌──────────┐   ┌──────────┐  ┌──────────┐  ┌──────────┐
                     │ context  │   │   http   │  │  theme   │  │  model   │
                     └──────────┘   └──────────┘  └──────────┘  └──────────┘
                           │              │                          ▲
                           └──────┬───────┘                          │
                                  ▼                                  │
                            ┌──────────┐   ┌──────────────┐          │
                            │   util   │   │   _version   │──────────┘
                            └──────────┘   └──────────────┘
```

Leaf modules (`model`, `util`, `variants`, `theme`, `_version`) import nothing from the
package, so there is no cycle at module load time.

## File-by-file

| File | Lines | Purpose | Imports from the package | Imported by |
|---|---:|---|---|---|
| `nullgrant/__init__.py` | 127 | public API re-exports + lazy `__getattr__` for `main`/`build_parser`, so `import nullgrant` stays cheap | `_version`, `checks`, `context`, `discovery`, `http`, `model`, `report`, `util`, `variants` | `tests/` |
| `nullgrant/__main__.py` | 14 | `python -m nullgrant` entry point | `cli` | — (entry point) |
| `nullgrant/_version.py` | 10 | single source of truth: `TOOL_NAME`, `TOOL_VERSION`, `USER_AGENT`, `__version__` | *(none)* | `__init__`, `cli`, `http`, `report`, `tui` |
| `nullgrant/model.py` | 107 | dataclasses `Finding`, `HttpResponse`, `Target`; status and severity constants | *(none)* | everything |
| `nullgrant/util.py` | 130 | base64url, PKCE generation, RFC 3986 URI helpers, credential redaction, internal-detail scanner | *(none)* | `__init__`, `checks`, `cli`, `context`, `discovery` |
| `nullgrant/variants.py` | 153 | the 17 `redirect_uri` mutations and the 8 response types to enumerate | *(none)* | `__init__`, `checks`, `cli` |
| `nullgrant/theme.py` | 289 | colour engine: 6 palettes, semantic roles, truecolor + 16-colour tiers, `strip_ansi` | *(none)* | `cli`, `report`, `tui` |
| `nullgrant/http.py` | 181 | `HttpClient`; **never follows redirects**; SNI/Host override for `--target-ip` | `_version`, `model` | `__init__`, `cli`, `context`, `discovery` |
| `nullgrant/discovery.py` | 54 | RFC 8414 / OIDC metadata discovery | `http`, `model`, `util` | `__init__`, `cli` |
| `nullgrant/context.py` | 163 | `AuditContext`: shared run state, `probe_authorize`, `build_authorize_params`, probe/classify helper | `http`, `model`, `util` | `__init__`, `checks`, `cli`, `report` |
| `nullgrant/checks.py` | 1,406 | the eleven checks and the `CHECKS` registry | `context`, `model`, `util`, `variants` | `__init__`, `cli` |
| `nullgrant/report.py` | 282 | `summarise`, `print_console`, JSON writer, self-contained HTML writer | `_version`, `context`, `model`, `theme` | `__init__`, `cli` |
| `nullgrant/tui.py` | 681 | `--tui` terminal interface: banner, spinner, progress, dashboard, menu | `_version`, `cli`\*, `model`, `theme` | `cli`\* |
| `nullgrant/cli.py` | 513 | `build_parser`, interactive prompts, authorisation gate, `emit()`, `main()` run loop | `_version`, `checks`, `context`, `discovery`, `http`, `model`, `report`, `theme`, `tui`\*, `util`, `variants` | `__main__`, `tui`\* |

\* `cli` and `tui` reference each other, but **only from inside functions** — never at module
level. That is what keeps the cycle from deadlocking: `cli.main()` imports `run_tui` lazily
when `--tui` is passed, and `tui.run_tui()` imports `cli.main` lazily to hand the run back.
Both `import nullgrant.cli` and `import nullgrant.tui` work standalone, in either order.

## Supporting files

| File | Lines | Role | Depends on |
|---|---|---|---|
| `tests/mock_as.py` | 395 | deliberately misconfigured **and** correctly configured authorization servers, bound to `127.0.0.1` only. `flavour`/`scheme` are bound to a per-call subclass so two fixtures never interfere | stdlib only |
| `tests/selftest.py` | 852 | 143 assertions. Boots all three fixtures in-process on free ports and drives the real `nullgrant.main()` | `mock_as`, `nullgrant` |
| `tests/test_selftest.py` | 24 | pytest wrapper, so `pytest` and `python tests/selftest.py` run the same suite | `selftest` |
| `nullgrant.sh` | 86 | shell launcher: resolves its own directory through symlinks, finds a `python3` (`PYTHON=` overrides), checks 3.8+, picks the layout, then `exec`s the tool. `selftest` as the first argument runs the assertion suite | `nullgrant.py` **or** `nullgrant/` |
| `tests/test_launcher.sh` | 139 (31 cases) | exercises the launcher: both layouts, symlink invocation, `cwd=/`, argument passthrough, exit-code propagation, the TUI menu, colour surviving the wrapper, all four failure modes | `nullgrant.sh` |
| `tests/compare_singlefile.py` | — | differential test: package vs single file over three audit scenarios (report JSON must be byte-identical) and three exit-code cases. Mismatches print a structural diff by JSON path | `nullgrant.py`, `nullgrant/`, `mock_as` |
| `tools/build_singlefile.py` | — | AST-driven generator that merges the package into `nullgrant.py` | `nullgrant/` |
| `.github/workflows/ci.yml` | 3 jobs / 23 steps. **selftest** (3.8–3.13 matrix): import check, **AST assertion that no non-stdlib import exists**, the 143 assertions, authorisation-gate check, single-file up-to-date + AST name-resolution + self-test + behavioural-identity gates, `--dry-run` sends-nothing check. **shell**: `shellcheck --severity=warning`, `bash -n`, launcher runs with no `+x` bit, the 31 launcher cases. **lint**: `compileall` + `ruff --select E9,F --target-version py38` over all sources | `tests/`, `nullgrant/`, `nullgrant.sh` |
| `pyproject.toml` | PEP 621 metadata, PEP 639 SPDX licence, `nullgrant = "nullgrant.cli:main"` console script, `dependencies = []` | — |
| `MANIFEST.in` | keeps `tests/` and `docs/` in the sdist so a source install can self-verify | — |
| `docs/sample-vulnerable/` | report from the misconfigured fixture: FAIL 10, PASS 1 | generated by the tool |
| `docs/sample-hardened/` | report from the correct fixture over TLS via `--target-ip` + `--ca-bundle`: FAIL 0, WARN 1, PASS 10 | generated by the tool |
| `docs/tui-demo.txt` | captured `--tui` session, colour stripped | generated by the tool |

## Data flow of one run

```
argv ──▶ cli.build_parser() ──▶ authorisation gate ──▶ discovery.discover()
                                        │                        │
                                        │ (exit 3, no traffic)   ▼
                                        │                 model.Target
                                        ▼                        │
                              context.AuditContext  ◀────────────┘
                                        │
                                        ├──▶ http.HttpClient (never follows redirects)
                                        │
              for each check in checks.CHECKS:
                                        ├──▶ emit(on_event, "check-start"/"check-end")
                                        │           │
                                        │           └──▶ tui.TuiRenderer  (live progress)
                                        ▼
                              model.Finding  (verdict + evidence + severity + fix + refs)
                                        │
                    ┌───────────────────┼───────────────────┐
                    ▼                   ▼                   ▼
          report.print_console   report.write_json    report.write_html
          or tui.render_findings
                    │
                    ▼
             exit code  0 = clean · 1 = ≥1 FAIL · 2 = bad args · 3 = no consent
                        4 = no authorization endpoint · 130 = interrupted
```

The `emit()` hook is the seam between the run loop and the interface: `main(argv, on_event)`
stays the single source of truth, and `tui` only draws. With `on_event=None` (the default)
the plain console path is used, which is why the self-test can assert that `--tui` produces
an identical finding set.

## The single-file edition

`nullgrant.py` in the repository root is the same code with the module boundaries removed.
`tools/build_singlefile.py` generates it:

1. Build the module-level dependency graph (deferred `cli ↔ tui` imports excluded — in one
   file every name is already global, so those imports are simply deleted).
2. Topologically sort; fail loudly on a cycle.
3. For each module, delete the module docstring and every `import`/`from … import` statement
   **by exact AST line range** — never by text matching, which once ate a line inside
   `checks.py` and produced an unterminated string literal.
4. Hoist and de-duplicate all stdlib imports, including function-local ones.
5. Emit with a shebang, one `from __future__ import annotations`, and a section banner per
   module.

The result is 3,842 lines with 129 top-level names and **zero collisions** — verified before
merging, since a collision would silently shadow one module's definition with another's.
The build carries no timestamp, so it is byte-reproducible and CI can assert the committed
file matches a fresh build.

`tests/selftest.py` runs against either layout: `submod("tui")` imports `nullgrant.tui` when
the package is present and falls back to the merged module when it is not.

## Entry points

Four ways in, and all four reach the same `cli.main()`:

| Entry point | Path |
|---|---|
| `nullgrant` (console script) | `pyproject.toml` → `nullgrant.cli:main` |
| `python3 -m nullgrant` | `nullgrant/__main__.py` → `cli.main()` |
| `python3 nullgrant.py` | merged single file → `main()` at the bottom |
| `./nullgrant.sh` | detects interpreter and layout, then `exec`s one of the above |

The launcher uses `exec`, not a subprocess, so the tool *replaces* the shell process. Exit
codes, signals and the controlling terminal behave exactly as if Python had been invoked
directly — which matters because the exit code is part of the tool's contract (0 clean, 1
findings, 2 bad arguments, 3 no consent, 4 no authorization endpoint, 130 interrupted). It
also means `Ctrl-C` in the TUI reaches Python rather than killing the wrapper first.

## Verified invariants

These are checked mechanically, not by inspection:

- Every module is reachable from an entry point — **no orphans**.
- Every name in every module resolves — an AST undefined-name scan runs over `nullgrant/`
  and `tests/`. This is not paranoia: a module split once shipped nine `NameError`s that a
  plain `import` test could not catch, because the names only resolve at call time.
- No file imports anything outside the standard library (enforced in CI on all six Python
  versions, including the 3.8/3.9 path where `sys.stdlib_module_names` does not exist).
- `CHECK_IDS` == the `CHECKS` registry == the `check` ids in every generated report.
- All six colour themes produce an identical verdict/severity/exit-code signature.
- `nullgrant.py` matches a fresh build byte for byte, resolves every name, passes all 143
  assertions, and produces reports identical to the package form.
- `--tui` produces the same exit code and the same finding set as a plain run.
