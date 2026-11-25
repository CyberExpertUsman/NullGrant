# NullGrant

[![CI](https://github.com/YOUR-USERNAME/nullgrant/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-USERNAME/nullgrant/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](#)

Configuration auditing for OAuth 2.0 / OpenID Connect authorization servers, from the
command line. You point it at an authorization server you own (or are authorised to test)
plus one registered test client, and it reports whether the server correctly enforces the
controls in **RFC 9700** (OAuth 2.0 Security BCP), RFC 6749, RFC 7636 (PKCE) and RFC 8414.

It prints one finding per check with evidence, and saves JSON + HTML reports. Add `--tui` for a
live terminal interface: banner, per-check progress, a results dashboard and
switchable colour palettes.

**Zero dependencies.** Python 3.8+ stdlib only.

---

## Authorisation gate

The tool refuses to send any traffic until you pass `--i-authorize-target`:

```
NullGrant is a security auditing tool. It will send live HTTP requests to the target
authorization server, including deliberately malformed and off-site redirect_uri values.
Only run it against a server you own, or one you hold written permission to test.
```

Exit code `3` means you did not confirm. Use `--dry-run` to print every request that
*would* be sent without sending any of them.

---

## Running on Kali

Stdlib only — there are no third-party dependencies to install.

```bash
# Option 0: one file, nothing to clone or install - copy it over and run it
scp nullgrant.py kali@box:~/
python3 nullgrant.py --tui

# Option 0b: the shell launcher - finds python3, checks it is 3.8+, runs the tool
./nullgrant.sh --tui
./nullgrant.sh selftest

git clone https://github.com/YOUR-USERNAME/nullgrant.git
cd nullgrant

# Option A: run straight from the checkout, no install step
python3 -m nullgrant --help
python3 tests/selftest.py            # verify: 143 assertions, ~2s

# Option B: install the `nullgrant` command
python3 -m pip install --user .
nullgrant --help

# Option C: install for all users
sudo python3 -m pip install .
```

Or from PyPI, once published:

```bash
pipx install nullgrant        # or: python3 -m pip install --user nullgrant
```

Verified portable: no third-party imports, no `winreg`/`msvcrt`/`/proc` access, and no
Python 3.9+ syntax (`removeprefix`, `match`, PEP 604 unions, dict `|`), so it runs on any
Python 3.8+ that Kali ships. The only `subprocess` call in the whole tool is the TUI menu's
"run the self-test" option, which shells out to `tests/selftest.py`; no audit path uses it.

---

## Shell launcher: `nullgrant.sh`

A thin wrapper for people who would rather type `./nullgrant.sh` than `python3 nullgrant.py`.
It resolves its own directory through symlinks, finds a `python3` (override with
`PYTHON=/path/to/python3`), verifies it is 3.8+, picks whichever layout is present — the
single file or the package — and `exec`s the tool so **exit codes and signals pass straight
through**. With no arguments it opens the TUI menu; `selftest` runs the assertion suite.

```bash
./nullgrant.sh                       # interactive menu
./nullgrant.sh selftest              # 143 assertions
./nullgrant.sh --tui --theme matrix --issuer https://as.lab.example ...
PYTHON=/usr/bin/python3.11 ./nullgrant.sh --help
```

It fails loudly rather than mysteriously: a missing interpreter, a file that is not an
interpreter, a Python that is too old, and a launcher sitting next to neither layout each
produce a distinct one-line message and exit 1. `bash tests/test_launcher.sh` covers all of
that — 31 cases, including running through a symlink, from `/`, and in package-only and
single-file-only directories.

> **Executable bit.** `git clone` and `unzip` preserve `+x`; **GitHub's web "upload files"
> does not** — every web-uploaded file lands as mode 100644. If `./nullgrant.sh` gives
> "Permission denied", either run `bash nullgrant.sh ...`, or restore the bit and push:
>
> ```bash
> git update-index --chmod=+x nullgrant.sh nullgrant.py tests/selftest.py
> git commit -m "Restore executable bits" && git push
> ```

---

## Single-file edition: `nullgrant.py`

The repository root also ships **`nullgrant.py`** — the entire package merged into one
3,800-line script. Copy it to a target box and run it with the stock `python3`; there is
nothing to install, unpack or put on `PYTHONPATH`.

```bash
python3 nullgrant.py --tui                          # interactive menu
python3 nullgrant.py --version
python3 nullgrant.py --tui --theme matrix \
    --issuer https://as.lab.example --client-id lab-client \
    --redirect-uri https://app.lab.example/cb --i-authorize-target
chmod +x nullgrant.py && ./nullgrant.py --help      # it has a shebang
```

It is a **generated artefact, not a second copy to maintain**:

```bash
python3 tools/build_singlefile.py       # regenerate from nullgrant/
python3 tests/compare_singlefile.py     # prove it behaves identically
```

The builder is AST-driven, not text-splicing. It topologically sorts the modules
(`_version → model → theme → tui → util → variants → http → context → discovery → report →
checks → cli`), deletes every import statement by its exact AST line range, hoists and
de-duplicates the stdlib imports to the top, and drops the deferred `cli ↔ tui` imports
(unnecessary once every name is global). The build is deterministic — no timestamp — so CI
regenerates the file and **fails if it differs from the committed copy**. It cannot drift.

Three guarantees, all enforced in CI:

| Gate | What it proves |
|---|---|
| `cmp` against a fresh build | the committed `nullgrant.py` is current |
| AST undefined-name scan | the merge lost no name (this caught a real bug: function-local `import subprocess` was being deleted without being hoisted) |
| `tests/selftest.py` run against the single file | **143/143 assertions pass** in the single-file layout too |
| `tests/compare_singlefile.py` | both forms produce byte-identical JSON reports and exit codes |

`compare_singlefile.py` first asserts that the *same* form run twice matches itself after
canonicalising per-run random values (`state`, PKCE verifier and challenge), so a reported
divergence is real and not nondeterminism.

The self-test is layout-agnostic: `submod()` resolves `nullgrant.tui` in the package and
falls back to the merged namespace when only `nullgrant.py` is present, so
`cp nullgrant.py tests/*.py box:~/` gives you a self-verifying deployment.

Console output is colourised on a TTY — FAIL red, WARN yellow, PASS green, INDETERMINATE
blue. Colour is automatically disabled when output is piped or redirected, and honours
`NO_COLOR` and `NULLGRANT_NO_COLOR`, so `grep` and CI logs stay clean:

```bash
nullgrant ... | grep FAIL        # no escape sequences
NO_COLOR=1 nullgrant ...         # plain text on a TTY
```

The report records what produced it, so a finding can be reproduced later:

```json
"run": {
  "platform": "Linux-6.1.189+-x86_64-with-glibc2.36",
  "python_version": "3.13.18",
  "tool_version": "1.0.0",
  "connection": { "target_ip": "10.10.1.5", "ca_bundle": true, "insecure_tls": false }
}
```

The tool is not Linux-specific in its logic and will run anywhere Python 3.8+ does; the
platform string is recorded for provenance, not enforced as a restriction. Blocking
non-Linux hosts would add friction without adding safety, so it warns in the report rather
than refusing to run.

---

## Terminal interface: `--tui`

`--tui` replaces the plain text report with a live terminal interface. It is pure stdlib —
ANSI escapes and Unicode box drawing, no `rich`, no `textual` — so the zero-dependency
promise is unchanged.

```bash
nullgrant --tui                        # no other arguments: interactive menu
nullgrant --tui --issuer https://as.lab.example --client-id lab-client \
           --redirect-uri https://app.lab.example/cb --i-authorize-target
nullgrant --tui -v                     # the same, with per-finding evidence
```

Run against the bundled misconfigured fixture:

```text
  ╔╗╔ ╦ ╦ ╦   ╦   ╔═╗ ╦═╣ ╔═╗ ╔╗╔ ╔╦╗
  ║║║ ║ ║ ║   ║   ║ ╦ ╠╦╝ ╠═╣ ║║║  ║
  ╝╚╝ ╚═╝ ╩═╝ ╩═╝ ╚═╝ ╩╚═ ╩ ╩ ╝╚╝  ╩
  NullGrant v1.0.0  ·  OAuth 2.0 / OIDC authorization server configuration audit
  RFC 9700 · RFC 6749 · RFC 7636 · RFC 7662 · RFC 8414  ·  neon theme, truecolor 24-bit

┌── TARGET ───────────────────────────────────────────────────────────────────────────────────────────────────┐
│ issuer        http://127.0.0.1:58623                                                                        │
│ client        lab-client  (public)                                                                          │
│ redirect_uri  http://127.0.0.1:58623/cb                                                                     │
│ authorize     http://127.0.0.1:58623/authorize                                                              │
│ token         http://127.0.0.1:58623/token                                                                  │
│ jwks          http://127.0.0.1:58623/jwks.json                                                              │
│ metadata      ok http://127.0.0.1:58623/.well-known/openid-configuration                                    │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

── RUNNING 11 CHECKS ──────────────────────────────────────────────────────────────────────────────────────────
  [✗] FAIL  discovery       TLS, discovery document and advertised capabilities  HIGH              0.0s
  [✗] FAIL  redirect        Strict redirect_uri validation (open redirection)  CRITICAL          0.9s
  [✗] FAIL  pkce            PKCE enforcement  CRITICAL          0.3s
  [✗] FAIL  response-types  Supported response types  HIGH              0.4s
  [✗] FAIL  token-auth      Token endpoint client authentication  HIGH              0.1s
  [✓] PASS  state           State parameter handling  INFO              0.2s
  [?] UNKN  refresh-reuse   Refresh token rotation and reuse detection  INFO              0.0s
  [✗] FAIL  introspection   Token introspection endpoint behaviour  HIGH              0.1s
  [✗] FAIL  jwks            JWK Set hygiene  CRITICAL          0.1s
  [✗] FAIL  error-hygiene   Error response hygiene  MEDIUM            0.2s
  [✗] FAIL  token-leakage   Credentials exposed in redirect URLs  CRITICAL          0.0s

╔══ RESULTS ══════════════════════════════════════════════════════════════════════════════════════════════════╗
│   CRITICAL 4   HIGH 4   MEDIUM 1                                                                            │
│                                                                                                             │
│   FAIL 9   WARN 0   PASS 1   UNKN 1                                                                         │
│   ███████████████████████████████████████████████████████████████████████████████████████████████████████   │
│                                                                                                             │
│   11 checks · 44 requests · 2.3s                                                                            │
│   AUDIT FAILED - findings require remediation                                                               │
╚═════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ [✗] FAIL  JWK Set hygiene                                                                                   │
│   --checks jwks   check_id jwks-hygiene   severity CRITICAL                                                 │
│                                                                                                             │
│   5 problem(s) in the published JWK Set.                                                                    │
│                                                                                                             │
│   REMEDIATION                                                                                               │
│   Publish only public key material, give every key a 'kid', use RSA >= 2048 bits or P-256+, never publish   │
│   symmetric or private keys, and rotate on a defined schedule.                                              │
│                                                                                                             │
│   refs: RFC 7517, RFC 7518 s3.3, RFC 9700 s2.1                                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  ... one panel per finding, failures first ...
```

What it does:

- **Banner and target panel.** The resolved issuer, client, both endpoints, the JWKS URI and
  whether the discovery document was found are shown before any check runs, so you can see
  exactly what the tool decided to talk to.
- **Live progress.** Each check runs behind an animated spinner on its own thread, then is
  replaced by a one-line result carrying the verdict, severity and wall-clock time, with a
  progress bar and a running request counter underneath.
- **Results dashboard.** Failures grouped by severity, the four verdict counters, a
  proportional status bar, the request total and the duration, and an overall verdict line.
- **Finding panels.** One bordered panel per check, ordered failures first, each with its
  `--checks` id, `check_id`, severity, summary, remediation and RFC references. `-v` adds the
  evidence.
- **Interactive menu.** With no issuer/client/redirect-uri supplied, `--tui` opens a menu:
  guided audit, run with the current flags, dry run, self-test, or open a previously saved
  JSON report.

It degrades instead of breaking:

| Situation | Behaviour |
|---|---|
| stdout is not a TTY (pipe, `>` file, CI log) | no colour, no cursor control, no spinner — plain greppable text |
| `NO_COLOR` or `NULLGRANT_NO_COLOR` set | colour off |
| `--color always` | colour on even when piped |
| terminal is not UTF-8 | ASCII box drawing (`+`, `-`, `|`, `v`, `x`) instead of Unicode |
| narrow terminal | width is read from the terminal and clamped to 40–120 columns; text is clipped to visible width, never wrapped mid-border |

### Colour palettes: `--theme`

Six palettes, selectable with `--theme` or the `NULLGRANT_THEME` environment variable.

| Theme | Look | Chrome |
|---|---|---|
| `neon` *(default)* | cyberpunk | hot magenta `#FF2D95` on electric cyan `#00E5FF`, purple accents |
| `matrix` | phosphor CRT | green `#39FF14` on dark green |
| `toxic` | acid | acid yellow-green `#CCFF00` on green |
| `ember` | hot metal | orange-yellow on deep red |
| `ice` | cold | pale cyan on blue |
| `mono` | no chrome colour | white/grey; attributes only |

```bash
nullgrant --tui --theme matrix ...
NULLGRANT_THEME=toxic nullgrant --tui ...
```

Two things are deliberately fixed across every palette:

- **Verdict colours never change.** Red is fail, amber is warn, green is pass, blue is
  indeterminate — in all six themes. A palette is cosmetic; it must never change what a
  report *means*, or make a failure look like a pass. The self-test asserts this for every
  theme, in both colour tiers.
- **No chrome element ever shares the FAIL colour.** The self-test checks all six palettes
  in 16-colour mode, where distinct hex values can collapse onto the same base colour. This
  caught two real collisions during development (neon's magenta and ember's accent both
  snapped to bright red).

Rendering tiers: when the terminal advertises truecolor (`COLORTERM=truecolor` or `24bit`,
or a known truecolor terminal program) the palettes are emitted as exact 24-bit RGB
(`38;2;R;G;B`). Otherwise each colour snaps to the nearest of the 16 base ANSI colours via
a hand-picked mapping, with a redmean perceptual distance as the safety net. Override with
`NULLGRANT_TRUECOLOR=0` or `=1`. The banner prints which tier is active.

`--tui` changes only how results are drawn. The run loop, the checks, the exit codes and the
written JSON/HTML reports are byte-identical to a plain run — the self-test asserts this.

---

## Two modes

Both modes run the same eight checks and produce the same reports. They differ only in how
the target is described.

### Mode 1 - flags

Everything on the command line. Best for scripts and CI.

```bash
# See exactly what would be sent, send nothing
nullgrant \
    --issuer https://as.lab.example.com \
    --client-id lab-client \
    --redirect-uri https://app.lab.example.com/callback \
    --dry-run

# Run the real audit
nullgrant \
    --issuer https://as.lab.example.com \
    --client-id lab-client \
    --redirect-uri https://app.lab.example.com/callback \
    --client-type public \
    --i-authorize-target \
    --out ./report
```

### Mode 2 - interactive

`-i` / `--interactive` prompts for the four inputs, shows a review block, and then requires
you to **type the target hostname exactly** before anything is sent.

```
$ nullgrant --interactive

  1. Issuer URL of the authorization server: https://as.lab.example.com
  2. IP to connect to (blank = resolve the issuer hostname): 10.10.1.5
      will connect to 10.10.1.5 while presenting 'as.lab.example.com' as Host and TLS SNI

  3. Client ID of the registered test client: lab-client
  4. Exact registered redirect_uri for that client: https://app.lab.example.com/callback
  Client type [public]:
  Scope to request (blank = none):
------------------------------------------------------------------------------
 Review:
   issuer        https://as.lab.example.com  -> via 10.10.1.5
   client_id     lab-client
   redirect_uri  https://app.lab.example.com/callback
   client_type   public
   scope         (none)
------------------------------------------------------------------------------

 To authorise testing of as.lab.example.com, type its hostname exactly:
  Confirm: as.lab.example.com
```

Typing the wrong value aborts with exit `3` and sends nothing. The client secret is read
with `getpass` (input hidden) and never echoed. `--dry-run` with `-i` skips the
confirmation, since nothing is sent.

Writes `./report/nullgrant-report.json` and `./report/nullgrant-report.html`.

Exit codes: `0` no failures · `1` at least one FAIL · `2` bad arguments ·
`3` authorisation not confirmed · `4` could not determine the authorization endpoint.

---

## Labs with no DNS: `--target-ip`

`--target-ip` sends the TCP connection to an address you choose while leaving the issuer's
hostname in the **Host header** and the **TLS SNI `server_name`**, and verifies the
certificate against that hostname — not against the IP.

```bash
nullgrant --issuer https://as.lab.example.com \
    --client-id lab-client --redirect-uri https://app.lab.example.com/callback \
    --target-ip 10.10.1.5:8443 --ca-bundle ./lab-ca.pem \
    --i-authorize-target --out ./report
```

This matters: discovery `issuer` matching, Host-based virtual hosting, cookie scoping and
certificate validation all keep working, so you audit the server as its real clients see it
rather than as a bare IP would see it.

Accepts `IP`, `IP:PORT` and `[IPv6]:PORT`. Blank means resolve the issuer normally.

### TLS trust: prefer `--ca-bundle`

```bash
--ca-bundle lab-ca.pem    # trust your lab CA; hostname verification stays ON
--insecure-tls            # disables certificate AND hostname verification
```

Use `--ca-bundle`. `--insecure-tls` prints a warning and should only be used when you have
no way to obtain the lab CA, because with it disabled an active network attacker can
silently substitute responses and your findings become meaningless.

Verified behaviour: pointing at a server whose certificate does not cover the issuer
hostname fails with `Hostname mismatch, certificate is not valid for '<host>'` — proof that
name checking is genuinely active on the `--target-ip` path, not bypassed.

---

## Checks

Eleven checks. The first eight run unattended; the last two are opt-in because they need
real credentials.

| `--checks` id      | What it audits |
|--------------------|----------------|
| `discovery`        | TLS on every endpoint, discovery document reachable, `issuer` matches its own URL, advertised capabilities |
| `redirect`         | Strict `redirect_uri` validation — 17 variants probing open redirection |
| `pkce`             | PKCE enforcement for public clients, `plain` rejection, challenge length/encoding |
| `response-types`   | Which `response_type` values the server answers; implicit/hybrid exposure |
| `token-auth`       | Token endpoint client authentication and error hygiene |
| `state`            | `state` echoed verbatim; missing-state and reused-state behaviour recorded |
| `refresh-reuse`    | **opt-in** — replay a used refresh token; rotation and reuse detection |
| `introspection`    | **opt-in** — what the introspection endpoint reveals, and to whom |
| `jwks`             | Published JWK Set: private/symmetric keys, missing `kid`, weak RSA moduli |
| `error-hygiene`    | Stack traces, SQL, filesystem paths and HTTP 5xx in error responses |
| `token-leakage`    | Tokens appearing in redirect URLs, especially in the **query** component |

`token-leakage` always runs last — it inspects the redirects captured by the other checks.

### A note on the `state` check

`state` is the **client's** CSRF defence (RFC 6749 §10.12). The authorization server is not
required to reject a request that omits it, and it cannot detect a reused value because it
does not track state. So those two probes are recorded as **observations**, not failures.

What the spec *does* require (§4.1.2, §4.1.2.1) is that the AS returns `state` unchanged
whenever the client sent one — including on error responses. Dropping or altering it is a
genuine **FAIL**, because it makes client-side CSRF protection impossible.

### The destructive check

`refresh-reuse` uses the token you supply, then replays it. On a **correctly configured**
server that replay triggers family revocation and invalidates the session the token came
from. It therefore needs two flags:

```bash
--refresh-token rt-lab-...      # a throwaway lab token
--allow-refresh-replay          # explicit consent to the destructive step
```

Without `--allow-refresh-replay` the check reports INDETERMINATE and sends nothing. Use a
throwaway session — never a token from a real user.

If the token was already consumed, the check says so and reports INDETERMINATE rather than
guessing:

```
The supplied refresh token was rejected on first use (error=invalid_grant),
so reuse detection could not be tested.
```

### The redirect_uri variants

`control-exact`, `trailing-slash`, `path-suffix`, `dot-segment-escape`,
`encoded-traversal`, `subdomain-confusion`, `host-swap`, `userinfo-override`,
`backslash-override`, `scheme-downgrade`, `scheme-upgrade`, `port-change`, `case-change`,
`protocol-relative`, `javascript-scheme`, `data-scheme`, `fragment-append`, `query-append`.

Classification is deliberately conservative:

- redirect to a host that is **neither** the registered client **nor** the AS → open redirect (**CRITICAL**)
- redirect to the registered host but a **non-identical** URI → loose matching (**HIGH**)
- redirect to the registered URI after RFC 3986 scheme/host case and default-port
  normalisation → accepted equivalent (not a finding)
- `error=invalid_request` / HTTP 4xx → rejected (**PASS**)
- AS-hosted login or consent page → **INDETERMINATE**, because validation has not run yet

That last case is why `--session-cookie` exists.

---

## Getting past the login page

Unauthenticated, most real authorization servers answer every probe with a redirect to
their own login page, so redirect/PKCE/response-type checks come back **INDETERMINATE**
rather than guessing. Two optional inputs deepen the run:

```bash
--session-cookie NAME=VALUE    # repeatable; a lab session you created for the test client
--auth-code CODE               # one single-use lab code, to exercise the token endpoint
```

`--auth-code` enables the strongest PKCE test: exchanging a real code with **no**
`code_verifier`. If that returns tokens, PKCE is not enforced.

> Use a throwaway lab session and a throwaway client. Never a real user's session.

---

## Other options

```
-i, --interactive                     MODE 2: prompt for the target description
--target-ip IP[:PORT]                 connect here, keep the issuer name in Host + TLS SNI
--ca-bundle PEM                       trust a lab CA; keeps hostname verification on
--insecure-tls                        disable TLS cert AND hostname checks (avoid; see above)
--client-type {public,confidential}   default: public
--client-secret SECRET                prefer NULLGRANT_CLIENT_SECRET in the environment
--auth-endpoint / --token-endpoint / --jwks-uri / --introspection-endpoint
                                      override values from the discovery document
--scope SCOPE                         scope to request
--session-cookie NAME=VALUE           repeatable; lab session to get past the login page
--auth-code CODE                      single-use lab code; enables the token-endpoint PKCE test
--refresh-token TOKEN                 lab refresh token for the refresh-reuse check
--allow-refresh-replay                consent to the destructive replay (see above)
--access-token TOKEN                  lab access token for the introspection check
--checks a,b,c                        run a subset
--format console,json,html            default: all three
--out DIR                             default: ./nullgrant-report
--timeout SECONDS                     default: 20
--delay SECONDS                       default: 0.15 between requests
--dry-run                             print planned requests, send nothing
--tui                                 terminal interface: banner, live progress, dashboard
                                      (with no other arguments, an interactive menu)
--color {auto,always,never}           default: auto - colour only when stdout is a TTY
--theme {neon,matrix,toxic,ember,ice,mono}
                                      colour palette; also NULLGRANT_THEME (default: neon)
-v, --verbose                         per-probe progress and inline evidence
```

The four credential inputs are all optional. Without them the corresponding checks report
**INDETERMINATE** with an explanation of what to supply — they never guess, and never report
a pass they did not earn.

`--delay` defaults to a pause between requests so the audit stays gentle on the target.

---

## Report redaction

Credential-like values (`access_token`, `id_token`, `refresh_token`, `code`,
`client_secret`, `code_verifier`, `password`) are truncated in both the console output and
the saved reports, keeping only enough to prove presence:

```
<redacted len=43 ya29...>
```

`state` is **not** redacted — verifying that it is echoed back verbatim is the point of
the CSRF check.

---

## Testing it: `tests/mock_as.py`

A deliberately misconfigured authorization server, included so the checks can be verified
end to end without pointing the tool at anything real. It binds to `127.0.0.1` only, has
no user store, no authentication and no data.

```bash
# Terminal 1 - misconfigured: prefix redirect_uri matching, no PKCE enforcement,
# implicit flows served, access_token in the query string, private key in the JWKS,
# tracebacks in error responses, discovery issuer mismatch.
python3 tests/mock_as.py --port 8765 --flavour vulnerable

# Terminal 2 - audit it
nullgrant --issuer http://127.0.0.1:8765 \
    --client-id lab-client --redirect-uri http://localhost:9999/callback \
    --client-type public --i-authorize-target --out ./report-vulnerable
```

`--flavour hardened` flips the same fixture to a correct server. This is the
**false-positive control**: a tool that reports FAIL against everything is worthless, so
the hardened run must come back clean.

Verified results from this repository:

| Fixture | Result (11 checks) |
|---|---|
| `vulnerable`, all credentials supplied | **FAIL 10**, WARN 0, PASS 1, INDET 0 |
| `hardened`, plaintext HTTP | FAIL 3 *(all three are the missing TLS)*, WARN 1, PASS 6, INDET 1 |
| `hardened` over TLS, `--access-token` | **FAIL 0**, WARN 1, PASS 9, INDET 1 |
| `hardened` over TLS via `--target-ip` + `--ca-bundle` | **FAIL 0** — Host header and SNI preserved |
| `vulnerable` via `--target-ip` | **FAIL 10** — server saw the issuer hostname, not the IP |
| unreachable host | FAIL 0, **INDET 11** |

The single PASS on the `vulnerable` run is `state-handling`, and it is correct: that fixture
echoes `state` verbatim even though it is broken everywhere else. A fixture that fails every
check would prove nothing about whether the checks can pass.

The INDET on the `hardened` runs is `refresh-reuse` — the lab token had already been
consumed by an earlier rotation, so the check reported uncertainty instead of claiming a
pass it could not earn.

The single WARN on the TLS run is honest uncertainty, not a defect: the AS advertises the
`refresh_token` grant for a public client, and whether those tokens are rotated with reuse
detection (RFC 9700 §2.2.2) **cannot be determined by external probing**. The tool says so
rather than claiming a pass or a fail.

To reproduce the clean run:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/mock.key -out /tmp/mock.crt \
  -days 2 -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"

python3 tests/mock_as.py --port 8767 --flavour hardened --certfile /tmp/mock.crt --keyfile /tmp/mock.key

nullgrant --issuer https://127.0.0.1:8767 \
    --client-id lab-client --redirect-uri http://localhost:9999/callback \
    --client-type public --i-authorize-target --insecure-tls --out ./report-hardened-tls
```

---

## Self-test

`tests/selftest.py` is the reproducible form of every "TEST IT" step. It boots all three fixtures
in-process on random free ports, runs the real CLI entry point against them, and asserts the
expected verdicts. Nothing leaves `127.0.0.1`.

```bash
python3 tests/selftest.py            # 143 assertions, ~2s
python3 tests/selftest.py -v         # also show audit console output
python3 tests/selftest.py -k pkce    # only assertions matching 'pkce'
```

Exit `0` if everything passes, `1` otherwise. It covers:

| Group | Assertions |
|---|---|
| `step1-encoding` | all parameters present, exact round-trip, `%2B` for `+`, space encoding, nested `redirect_uri` escaping, base64url intact, single `?`; plus server-side decode proof |
| `step2-redirect` | loose fixture → CRITICAL, strict fixture → PASS, reports differ, off-site redirects recorded |
| `step3-pkce` | non-enforcing → CRITICAL, enforcing → PASS, verdicts differ |
| `step4-response-types` | reported implicit flows **equal** the flows the fixture enables |
| `step5-token-in-url` | token-carrying redirect flagged, `code`-only redirect not flagged, inspection not vacuous |
| `step6-cli` | two runs with different settings, `--checks` subset honoured, `--format` honoured, arg validation exit codes |
| `step7-full-run` | all 11 checks present in both reports, every one with verdict + severity + non-empty evidence + remediation + references + `--checks` id; summary counts agree; HTML mirrors JSON and is self-contained |
| `extra-safety` | gate exits 3 and writes nothing; `--dry-run` sends nothing and lists every variant |
| `extra-unreachable` | no false PASS; all checks INDETERMINATE |
| `extra-session-cookie` | every cookie reaches the wire; the `Host` header is still correct |
| `tui` | `--tui` produces the same exit code and the same finding set as a plain run; target panel, dashboard counters and verdict line all agree with the report; every check id and `check_id` is drawn; **zero** colour and cursor escapes when piped; `--color always`/`never` honoured; no line exceeds the terminal width and every border is exactly that width; `vis_len`/`clip`/`pad` measure visible width through ANSI; menu exits 0 on EOF; `--tui --dry-run` sends nothing; `tui.py` imports nothing outside the stdlib |
| `theme` | all six palettes produce a byte-identical verdict/severity/exit-code signature; every line stays within 120 columns; an unknown theme name is ignored rather than crashing; `fail`/`warn`/`pass`/`unknown` are the *same* colour in every theme in both truecolor and 16-colour mode; no chrome element shares the FAIL colour; `strip_ansi` handles 24-bit escapes; truecolor is used only when advertised |
| `extra-tls` | `--target-ip` preserves the issuer name; wrong hostname rejected by certificate verification |

`tests/compare_singlefile.py` is a separate harness (not part of the 143): it runs both
builds against the same fixtures and diffs the saved JSON reports.

The self-test found two real defects that manual runs had missed:

1. **`MockAS.flavour` was a class attribute.** Starting the hardened fixture silently
   reconfigured the already-running vulnerable one, so both servers behaved identically and
   every differential test was comparing a server against itself. Fixed by binding flavour
   and scheme to a per-call subclass.
2. **Discovery failures were not recorded in the report.** When the metadata fetch failed,
   the JSON had `metadata_source: null` with no explanation. `metadata_error` is now saved
   and shown in the HTML, which is what made the TLS hostname-mismatch assertion testable.


## Sample reports in this directory

- `docs/sample-vulnerable/nullgrant-report.html` — the misconfigured fixture: **FAIL 10**, PASS 1
- `docs/sample-hardened/nullgrant-report.html` — the correct fixture over TLS, reached via
  `--target-ip` + `--ca-bundle`: **FAIL 0**, WARN 1, PASS 10

Both were produced by a full run with every credential supplied, so all eleven checks carry
a real verdict rather than INDETERMINATE. Both are self-contained HTML (inline CSS, no
external requests), so they render offline.

The single PASS on the vulnerable report is `state-handling` — that fixture echoes `state`
correctly while being broken everywhere else. A fixture that failed all eleven checks would
prove nothing about whether the checks are capable of passing.

---

## Verification of each build step

Every step below was tested against the two mock fixtures. Step 1 was verified last and
is the one most easily skipped — a mis-encoded parameter makes the server test something
other than what you intended, silently.

**Step 1 — request building and encoding.** All 8 parameters round-trip exactly, including
deliberately awkward values:

```
scope '+' must be %2B not literal +     OK
space in response_type encoded          OK   (id_token%20token)
nested redirect_uri fully escaped       OK   (redirect_uri=https%3A%2F%2F...%3Fx%3D1%26y%3D)
state '&' escaped (no param split)      OK
base64url challenge not mangled         OK   (- _ ~ . left intact)
exactly one '?' in the URL              OK
```

End-to-end confirmation that the space survives server-side decoding:

```
response_type='code'                -> code=True  tokens_in_query=['code']
response_type='id_token token'      -> code=False tokens_in_query=['access_token','id_token']
response_type='code id_token token' -> code=False tokens_in_query=['access_token','id_token']
```

**Step 2 — redirect variants.** Loose-matching fixture: 4 confirmed off-site redirects,
CRITICAL. Strict-matching fixture: 16 of 17 rejected, 1 resolved to the exact registered
URI, PASS. The reports differ as required.

**Step 3 — PKCE.** Non-enforcing fixture: CRITICAL, "an authorization code was issued or
redeemed without a code_verifier". Enforcing fixture: PASS, all five malformed-challenge
probes refused.

**Step 4 — response types.** Fixture advertising 7 types: 6 implicit/hybrid reported as
served. Fixture advertising `code` only: 7 explicitly rejected, PASS. Reported flows match
the flows enabled on the fixture.

**Step 5 — token-in-URL.** Implicit-flow redirects carrying `access_token`/`id_token` in the
query string: 12 flagged, CRITICAL. Authorization-code redirects carrying only `code`: not
flagged, because `code` belongs in the query component.

**Step 6 — CLI and reports.** Run repeatedly with different flags, check subsets, both
fixture flavours, plaintext and TLS, and `--target-ip`. Every run produced a complete JSON
and HTML report with a verdict, severity, summary, evidence blocks, remediation and
references for all eleven checks.

**Step 7 — full end-to-end run, report read start to finish.** Both fixtures run with every
credential supplied, then both saved reports read back and asserted structurally:

```
                            vulnerable        hardened+TLS
  findings                  11/11             11/11
  verdicts                  FAIL 10, PASS 1   PASS 10, WARN 1, FAIL 0
  evidence blocks           53 (min 2, max 8) 53 (min 2, max 8)
  json / html bytes         55334 / 67408     43790 / 54609
  external refs in HTML     0                 0
```

Asserted for **every** finding in **both** reports: a status from the valid set, a severity
from the valid set, a non-empty title, a summary longer than 10 characters, a non-empty
evidence list with no empty blocks, remediation text, at least one RFC reference, and a
`--checks` id. Also asserted: summary counts agree with the findings, no duplicate checks,
HTML card and `<details>` counts equal the finding count, every title and badge appears in
the HTML, no external resource references, and the HTML is not truncated.

This step found a real defect: the `--checks` CLI ids (`redirect`, `pkce`, `jwks`) did not
match the report's `check_id` values (`redirect-uri-strictness`, `pkce-enforcement`,
`jwks-hygiene`), so a finding could not be correlated back to the flag that produced it.
Findings now carry both, and the HTML card header shows them together.


What this tool does:

- sends only requests an OAuth client would legitimately send, using the one test client you name
- never follows redirects, so it can inspect `Location` headers directly
- reports configuration observations for you to verify and remediate

What it deliberately does not do:

- no brute forcing, no credential stuffing, no rate-limit testing
- no enumeration of other clients, users, tenants or accounts
- no exploitation of anything it finds — it reports the condition, not a working attack
- no writes, no state changes, no token revocation

**Known limits.** Checks that require an authenticated session return INDETERMINATE rather
than guessing. Token-lifetime, consent-skip, refresh-token-rotation and sender-constraint
behaviour cannot be observed externally without real credentials, and are reported as
"to verify" advisories. A PASS means "no weakness observed from this position", not
"this server is secure".

**No false passes.** A false PASS is the most dangerous thing an audit tool can emit, so
every check treats an unreachable endpoint as INDETERMINATE rather than as clean. Point it
at a dead host and all eleven checks return INDETERMINATE:

```
 FAIL 0   WARN 0   PASS 0   INDETERMINATE 11
```

The only findings derivable without a response are the URL-shape ones — an `http://` issuer
or a non-localhost `http://` redirect URI — because those follow from the strings you
supplied, not from anything the server said.


---

## Repository layout

```
nullgrant/
├── nullgrant/               the package (stdlib only, no dependencies)
│   ├── __init__.py           public API re-exports
│   ├── __main__.py           python -m nullgrant
│   ├── _version.py           single source of truth for the version
│   ├── cli.py                argparse, interactive mode, run loop
│   ├── model.py              Finding, HttpResponse, Target
│   ├── http.py               HTTP client; never follows redirects; SNI override
│   ├── discovery.py          RFC 8414 / OIDC metadata discovery
│   ├── variants.py           redirect_uri mutations, response types to enumerate
│   ├── context.py            shared audit state and the probe/classify helper
│   ├── checks.py             the eleven checks and the CHECKS registry
│   ├── report.py             console, JSON and HTML rendering
│   ├── tui.py                --tui terminal interface: banner, progress, dashboard, menu
│   ├── theme.py              colour engine: 6 themes, truecolor + 16-colour tiers, roles
│   ├── util.py               encoding, URI normalisation, redaction
│   └── py.typed
├── tests/
│   ├── mock_as.py            vulnerable + hardened fixtures, 127.0.0.1 only
│   ├── selftest.py           143 assertions, runnable with no dependencies
│   ├── compare_singlefile.py proves nullgrant.py == the package, report for report
│   ├── test_launcher.sh      31 cases for nullgrant.sh
│   └── test_selftest.py      pytest wrapper around selftest.py
├── docs/
│   ├── ARCHITECTURE.md       module wiring, dependency graph and data flow
│   ├── sample-vulnerable/    report from the misconfigured fixture
│   ├── sample-hardened/      report from the correct fixture over TLS
│   └── tui-demo.txt          captured --tui session (colour stripped)
├── .github/workflows/ci.yml  self-test on Python 3.8-3.13
├── pyproject.toml            PEP 621 metadata, `nullgrant` console script
├── nullgrant.py              single-file edition (generated; 3,842 lines)
├── nullgrant.sh              shell launcher: finds python3, execs the tool
├── tools/
│   └── build_singlefile.py   AST-driven merge that generates nullgrant.py
├── MANIFEST.in               keep tests/ and docs/ in the source distribution
├── SECURITY.md               what the tool will and will not do
├── CHANGELOG.md
└── LICENSE                   MIT
```

### Before you push

Replace the two placeholders:

```bash
grep -rl "YOUR-USERNAME" . --exclude-dir=.git | xargs sed -i 's/YOUR-USERNAME/<your-github-username>/g'
sed -i 's/YOUR-NAME-HERE/<your name>/' LICENSE
```

Then:

```bash
git add -A
git commit -m "Initial release: NullGrant 1.0.0"
git branch -M main
git remote add origin git@github.com:<your-github-username>/nullgrant.git
git push -u origin main
```

CI is three jobs, 23 steps:

| job | runs on | what it proves |
|---|---|---|
| `selftest` | Python 3.8–3.13 | the 143 assertions pass; the package imports; **no third-party import exists** (AST scan); the authorisation gate exits 3 and writes nothing; `nullgrant.py` is byte-identical to a fresh merge; the merged file resolves every name; it passes the same 143 assertions; it is *behaviourally* identical to the package (`compare_singlefile.py`); `--dry-run` sends nothing |
| `shell` | ubuntu | `shellcheck --severity=warning` and `bash -n` are clean; the launcher works with no `+x` bit; all 31 launcher cases pass |
| `lint` | 3.13 | every module compiles; `ruff --select E9,F --target-version py38` is clean over all sources |

The `--target-version py38` on the lint job is not decorative. That job runs on 3.13, and
3.13 happily accepts syntax that 3.8 rejects — a dict literal written across two lines
inside a single-quoted f-string was exactly that, and it made the whole package unimportable
on four of the six supported versions. `ast.parse(..., feature_version=(3, 8))` does not
catch it either: `feature_version` covers only a few grammar changes, not f-string
tokenization. Telling ruff the floor version does.

The suite has been run on real CPython **3.8.20, 3.9.25, 3.11.18 and 3.13.18** — all three
entry points (`python3 nullgrant.py`, `python3 -m nullgrant`, `./nullgrant.sh`) and all 143
assertions on each.

---

## References

RFC 9700 (OAuth 2.0 Security Best Current Practice) · RFC 6749 · RFC 7636 (PKCE) ·
RFC 8414 (AS metadata) · RFC 8252 (native apps) · RFC 6819 (threat model) ·
OpenID Connect Discovery 1.0
