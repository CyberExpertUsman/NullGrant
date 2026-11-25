"""Prove the single-file build is behaviourally identical to the package.

Runs both forms against the same in-process fixtures and compares the saved JSON reports.
Per-run random values (state, PKCE verifier/challenge) are canonicalised first - the
baseline assertion checks that the SAME form run twice matches itself, so a failure below
it is a real divergence and not nondeterminism.

Usage:  python3 tests/compare_singlefile.py     (exit 0 = identical)
"""
import json, os, re, shutil, socket, subprocess, sys, tempfile, threading
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests")); sys.path.insert(0, ROOT)
import mock_as

def fp():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def start(flavour, port, crt="", key=""):
    srv = mock_as.serve(port, flavour, False, crt, key)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    for _ in range(60):
        try: socket.create_connection(("127.0.0.1", port), .25).close(); break
        except OSError: pass
    return srv

def reset():
    mock_as.ISSUED_REFRESH_TOKENS.clear(); mock_as.ISSUED_REFRESH_TOKENS.add(mock_as.LAB_REFRESH_TOKEN)
    mock_as.USED_REFRESH_TOKENS.clear()

tmp = tempfile.mkdtemp(prefix="diff")
crt = os.path.join(tmp, "c.crt"); key = os.path.join(tmp, "c.key")
ok = subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",key,
                     "-out",crt,"-days","1","-subj","/CN=localhost",
                     "-addext","subjectAltName=IP:127.0.0.1,DNS:localhost"],
                    capture_output=True).returncode == 0

vp, hp = fp(), fp()
start("vulnerable", vp)
if ok: start("hardened", hp, crt, key)

def base_args(issuer, out):
    return ["--issuer", issuer, "--client-id", mock_as.CLIENT_ID,
            "--redirect-uri", mock_as.REDIRECT_URI, "--client-type", "public",
            "--client-secret", mock_as.CLIENT_SECRET, "--auth-code", "lab-code-abcdef",
            "--refresh-token", mock_as.LAB_REFRESH_TOKEN, "--allow-refresh-replay",
            "--access-token", mock_as.LAB_ACCESS_TOKEN, "--delay", "0", "--timeout", "15",
            "--out", out, "--format", "json", "--i-authorize-target"]

def run(cmd, extra):
    reset()
    r = subprocess.run(cmd + extra, capture_output=True, text=True, cwd=ROOT)
    out = extra[extra.index("--out") + 1]
    rep = json.load(open(os.path.join(out, "nullgrant-report.json"))) if r.returncode in (0, 1) else None
    return r.returncode, rep, r.stdout, r.stderr

RANDOM_KEYS = {"state", "nonce", "code_verifier", "code_challenge", "verifier", "challenge",
               "challenge_raw", "sent_state", "expected_state"}
STATE_RE = re.compile(r"oa-[A-Za-z0-9_\-]{8,}")
CHAL_RE = re.compile(r"(code_challenge|code_verifier)(=[^&\"\s]*)")
# Delimited by non-token characters rather than \b. A \b after the class requires a WORD
# character on the far side, but the class itself admits '-' and '_' - and the tool's probe
# identifiers end in secrets.token_urlsafe() output, whose alphabet includes both. A token
# ending in '-' therefore matched one character short, leaving "<RANDOM>-" in one run and
# "<RANDOM>" in the next, which made two identical runs compare unequal about 1 time in 10.
_TOKEN = r"[A-Za-z0-9_\-]"
B64_RE = re.compile(rf"(?<!{_TOKEN}){_TOKEN}{{24,}}(?!{_TOKEN})")

def canon(x):
    """Replace per-run random values so two runs can be compared structurally."""
    if isinstance(x, dict):
        return {k: ("<RANDOM>" if k in RANDOM_KEYS else canon(v)) for k, v in x.items()}
    if isinstance(x, list):
        return [canon(v) for v in x]
    if isinstance(x, str):
        x = STATE_RE.sub("oa-<RANDOM>", x)
        x = CHAL_RE.sub(r"\1=<RANDOM>", x)
        # any remaining high-entropy token (fresh verifiers/challenges echoed in evidence)
        x = B64_RE.sub("<RANDOM>", x)
        return x
    return x

def norm(rep):
    r = canon(json.loads(json.dumps(rep)))
    r.pop("generated_at", None)
    run = r.get("run", {})
    for k in ("duration_seconds", "elapsed"):
        run.pop(k, None)
    for f in r.get("findings", []):
        for e in f.get("evidence", []):
            for k in list(e):
                if any(v in k.lower() for v in ("elapsed", "duration", "took")):
                    e.pop(k)
    return r

def diff_paths(a, b, path="$", limit=10, out=None):
    """Structural diff of two canonicalised reports, as (json_path, left, right) tuples.

    A failure in this file is only actionable if it names the value that moved, so every
    mismatch is reported by path rather than as an opaque 'DIFFER'.
    """
    if out is None:
        out = []
    if len(out) >= limit:
        return out
    if type(a) is not type(b):
        out.append((path, "<%s>" % type(a).__name__, "<%s>" % type(b).__name__))
    elif isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if len(out) >= limit:
                break
            if k not in a:
                out.append((f"{path}.{k}", "<missing>", b[k]))
            elif k not in b:
                out.append((f"{path}.{k}", a[k], "<missing>"))
            else:
                diff_paths(a[k], b[k], f"{path}.{k}", limit, out)
    elif isinstance(a, list):
        if len(a) != len(b):
            out.append((f"{path}[]", f"len={len(a)}", f"len={len(b)}"))
        for i, (x, y) in enumerate(zip(a, b)):
            if len(out) >= limit:
                break
            diff_paths(x, y, f"{path}[{i}]", limit, out)
    elif a != b:
        out.append((path, a, b))
    return out


# Regression guard for the fix above: probe identifiers whose random suffix ends in '-' or
# '_' must canonicalise identically to one that ends in a letter.
for _suffix in ("K", "-", "_", "a-", "9_"):
    _probe = "nullgrant-nonexistent-Ab3xYz9" + _suffix
    _got = canon(_probe)
    assert _got == "<RANDOM>", f"canon({_probe!r}) == {_got!r}, expected '<RANDOM>'"
assert canon("short-token-abc") == "short-token-abc", "canon() over-matched a short token"

CLIP = int(os.environ.get("NULLGRANT_DIFF_CLIP", "160"))


def show_diff(a, b, indent="        "):
    def clip(v):
        t = v if isinstance(v, str) else repr(v)
        return t if len(t) <= CLIP else t[:CLIP - 3] + "..."
    for path, left, right in diff_paths(a, b):
        print(f"{indent}{path}\n{indent}  A: {clip(left)}\n{indent}  B: {clip(right)}")


scenarios = [
    ("vulnerable / all credentials", f"http://127.0.0.1:{vp}", []),
    ("vulnerable / no credentials",  f"http://127.0.0.1:{vp}",
     ["--client-secret", "", "--auth-code", "", "--refresh-token", "", "--access-token", ""]),
    ("hardened+TLS / --target-ip",   f"https://localhost:{hp}",
     ["--target-ip", "127.0.0.1", "--ca-bundle", crt] if ok else None),
]
PKG = [sys.executable, "-m", "nullgrant"]
ONE = [sys.executable, os.path.join(ROOT, "nullgrant.py")]

fails = 0
# baseline: run the PACKAGE form twice; after canonicalisation they must match exactly,
# otherwise the comparison below would be meaningless.
o0 = os.path.join(tmp, "z0")
rcA, rA, _, _ = run(PKG, base_args(f"http://127.0.0.1:{vp}", o0) + [])
rcB, rB, _, _ = run(PKG, base_args(f"http://127.0.0.1:{vp}", os.path.join(tmp, "z1")) + [])
base_ok = rA is not None and rB is not None and norm(rA) == norm(rB)
print(f"  [{'OK ' if base_ok else 'FAIL'}] baseline: the same form run twice is identical "
      f"after canonicalising random values")
if not base_ok:
    if rA is None or rB is None:
        print(f"        a baseline run produced no report (exit {rcA} / {rcB})")
    else:
        show_diff(norm(rA), norm(rB))
fails += 0 if base_ok else 1
shutil.rmtree(o0, ignore_errors=True)

for name, issuer, extra in scenarios:
    if extra is None:
        print(f"  [SKIP] {name} (openssl unavailable)"); continue
    o1 = os.path.join(tmp, "a"); o2 = os.path.join(tmp, "b")
    rc1, r1, _, e1 = run(PKG, base_args(issuer, o1) + extra)
    rc2, r2, _, e2 = run(ONE, base_args(issuer, o2) + extra)
    same_rc = rc1 == rc2
    same_rep = r1 is not None and r2 is not None and norm(r1) == norm(r2)
    okall = same_rc and same_rep and not e1.strip() and not e2.strip()
    fails += 0 if okall else 1
    print(f"  [{'OK ' if okall else 'FAIL'}] {name}")
    print(f"        exit codes  pkg={rc1} single={rc2}   reports identical: {same_rep}")
    if r1: print(f"        summary     {r1['summary']}")
    if not same_rep and r1 and r2:
        show_diff(norm(r1), norm(r2))
    if e1.strip() or e2.strip():
        print(f"        stderr pkg={e1[:120]!r} single={e2[:120]!r}")
    shutil.rmtree(o1, ignore_errors=True); shutil.rmtree(o2, ignore_errors=True)

# exit-code-only scenarios
for name, extra, want in [
    ("authorisation gate refuses", ["--issuer","https://as.example.test","--client-id","c",
                                    "--redirect-uri","https://a.test/cb","--out",tmp+"/g"], 3),
    ("dry run sends nothing", ["--dry-run","--issuer","https://as.example.test","--client-id","c",
                               "--redirect-uri","https://a.test/cb"], 0),
    ("unknown check id rejected", ["--checks","bogus","--issuer","https://as.example.test",
                                   "--client-id","c","--redirect-uri","https://a.test/cb"], 2),
]:
    rc1 = subprocess.run(PKG+extra, capture_output=True, cwd=ROOT).returncode
    rc2 = subprocess.run(ONE+extra, capture_output=True, cwd=ROOT).returncode
    good = rc1 == rc2 == want
    fails += 0 if good else 1
    print(f"  [{'OK ' if good else 'FAIL'}] {name}: pkg={rc1} single={rc2} want={want}")

print()
print("IDENTICAL" if not fails else f"{fails} SCENARIO(S) DIFFER")
sys.exit(1 if fails else 0)
