#!/usr/bin/env python3
"""tests/test_scan_secrets.py — the pre-push gate, in both directions.

A secret scanner can be wrong two ways, and BOTH are expensive:
  * false NEGATIVE — a real credential ships, and once pushed it is public
                     forever; no .gitignore can recall it.
  * false POSITIVE — ordinary code is blocked, so people weaken the rules or
                     learn to ignore the exit code, which is how the next real
                     leak gets waved through.

So every case here asserts a DIRECTION, not just a shape. Four real bugs were
found by writing these:

  1. The scanner matched its OWN pattern definitions (the regex
     `-----BEGIN PGP PRIVATE KEY BLOCK` matched the line that defines it).
  2. `\\s*` after `[=:]` crossed newlines, so an EMPTY `BLNQ_ADMIN_TOKEN=`
     swallowed the line break and read the next line's identifier as a
     21-char secret.
  3. Docstrings were scanned as source, so an instruction like
     `Run: BLNQ_ADMIN_TOKEN=admintest123 python3 t.py` was treated as a leak.
  4. THIS FILE flagged itself: a scanner's test must feed it credential-shaped
     input, so the fixtures are assembled from fragments below — the value
     `password = "hunter2"` exists only at runtime, never contiguously in the
     repository.

Run:  python3 tests/test_scan_secrets.py
Exit: 0 = all checks pass.
"""
from __future__ import annotations

import base64
import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("scan_secrets",
                                              ROOT / "scripts" / "scan_secrets.py")
ss = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ss)

PASS = FAIL = 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  \033[32m✓\033[0m {label}")
    else:
        FAIL += 1
        print(f"  \033[31m✗\033[0m {label}{'  → ' + detail if detail else ''}")


def cred(*parts: str) -> str:
    """Assemble a credential-shaped string at runtime.

    Writing these contiguously would make the scanner correctly flag its own
    test file — the same self-match trap as matching a pattern's own
    definition. Joining fragments yields an identical value at runtime while
    leaving no complete credential anywhere in the repository.
    """
    return "".join(parts)


def findings(text: str):
    """Actionable severities only — NOISE (infra layout) is informational."""
    return [(sev, kind) for sev, kind, _ln, _src in ss.scan_text(text, "probe.txt")
            if sev in ("BLOCK", "WARN")]


def detected(text: str) -> bool:
    """Any actionable finding — BLOCK or WARN (they mean different things:
    'do not push' vs 'review', but both are the scanner doing its job)."""
    return bool(findings(text))


def blocks(text: str) -> bool:
    return any(sev == "BLOCK" for sev, _ in findings(text))


def first_line(text: str) -> int:
    for _sev, _kind, ln, _src in ss.scan_text(text, "p"):
        if _sev in ("BLOCK", "WARN"):
            return ln
    return -1


# ── 1. must still CATCH real credentials ───────────────────────────────────
print("\nreal credentials must be detected:")
BLOB = base64.b64encode(os.urandom(96)).decode()

real = [
    ("OpenSSH private key",
     f"-----BEGIN OPENSSH PRIVATE KEY-----\n{BLOB}\n-----END OPENSSH PRIVATE KEY-----\n"),
    ("RSA private key",
     f"-----BEGIN RSA PRIVATE KEY-----\n{BLOB}\n-----END RSA PRIVATE KEY-----\n"),
    ("PGP private key block",
     f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n{BLOB}\n-----END PGP PRIVATE KEY BLOCK-----\n"),
    ("AWS access key id", cred("AKIA", "ABCDEFGH12345678")),
    ("AWS secret access key", cred("aws_secret_access_key = ", "A" * 40)),
    ("GitHub token", cred("ghp_", "A" * 36)),
    ("Stripe live key", cred("sk_live_", "a" * 24)),
    ("Google API key", cred("AIza", "A" * 35)),
    ("connection string password",
     cred("postgres://user:", "S3cr3tPw", "@db.example:5432/x")),
    ("password assignment", cred("password = ", '"', "hunter2", '"')),
    ("password assignment, spaced", cred("passwd  =  ", '"', "s3cretvalue", '"')),
    ("admin token assignment", cred("BLNQ_ADMIN_TOKEN=", "realValue123")),
    ("secret inside a quoted list",
     cred("cfg = ['", "password = ", '"', "hunter2x", "']")),
    ("secret inside a nested string",
     cred("items = ['api_key = ", '"', "sk-proj-", "abcdef1234567890", "']")),
]
for name, text in real:
    check(f"catches {name}", detected(text), f"no finding for {name!r}")

# admin token is deliberately WARN (an env reference), not BLOCK — assert the
# level explicitly so nobody "fixes" this by silently promoting it.
check("admin token is WARN (review), not BLOCK (do-not-push)",
      blocks(cred("BLNQ_ADMIN_TOKEN=", "realValue123")) is False
      and detected(cred("BLNQ_ADMIN_TOKEN=", "realValue123")) is True)

# ── 2. must NOT flag ordinary code ─────────────────────────────────────────
print("\nordinary code must NOT be blocked:")
clean = [
    ("the scanner's own PGP pattern line",
     '("PGP key block",          r"-----BEGIN PGP PRIVATE KEY BLOCK", "BLOCK"),'),
    ("the scanner's own private-key pattern line",
     '("private key", r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY", "BLOCK"),'),
    ("a header with no key body (not a credential)",
     "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"),
    ("empty admin token followed by a long identifier",
     "BLNQ_ADMIN_TOKEN=\nBLNQ_KEEPALIVE_AGENT=0"),
    ("empty password followed by a long identifier",
     "password=\nSOME_REALLY_LONG_NAME=1"),
    ("empty secret followed by a long identifier",
     "secret=\nANOTHER_LONG_NAME_HERE=2"),
    ("usage line inside a docstring",
     '"""\nRun: ' + cred("BLNQ_ADMIN_TOKEN=", "admintest123")
     + ' python3 tests/e2e.py\n"""'),
    ("credential named in a # comment",
     "# set " + cred("password = ", '"', "hunter2", '"') + " in the env file"),
    ("test helper reading the password from the environment",
     'env = dict(os.environ, PGPASSWORD=os.environ.get("PGPASSWORD", "postgres"))'),
]
for name, text in clean:
    check(f"ignores {name}", not blocks(text), f"false BLOCK: {name!r}")

# A `#` inside an ordinary string must not start a comment and swallow the
# rest of the file — the credential on the NEXT line must still be found, at
# its own line number.
URL_CASE = ('x = "http://a/#frag"\n'
            + cred("password = ", '"', "realpass1", '"') + "\n")
check("`#` inside a string does not truncate the line after it",
      first_line(URL_CASE) == 2,
      "reported line %d" % first_line(URL_CASE))

# ── 3. prose is blanked, ordinary strings are NOT ──────────────────────────
print("\nprose removal must not blind the scanner:")
check("keeps ordinary string literals scannable",
      blocks(cred("password = ", '"', "hunter2", '"')))
check("removes comments",
      not blocks("# " + cred("password = ", '"', "hunter2", '"') + " (see env file)"))

OFFSET_SAMPLE = "x = 1\n# pad\n" + cred("password = ", '"', "hunter2", '"') + "\n"
check("line numbers survive prose removal (reports line 3, not 2)",
      first_line(OFFSET_SAMPLE) == 3,
      "got line %d" % first_line(OFFSET_SAMPLE))

# ── 4. the scanner must survive scanning itself ────────────────────────────
print("\nself-scan:")
own = (ROOT / "scripts" / "scan_secrets.py").read_text(encoding="utf-8")
own_hits = [k for sev, k, _ln, _s in ss.scan_text(own, "scan_secrets.py")
            if sev in ("BLOCK", "WARN")]
check("scripts/scan_secrets.py scans clean", not own_hits, ", ".join(own_hits))

# ── 5. real files in this repo ─────────────────────────────────────────────
print("\nrepository:")
staged = ss.committed_files()
bad_files = []
for rel in staged:
    p = ROOT / rel
    if not p.is_file():
        continue
    text = ss.read(p)
    if not text:
        continue
    hits = [k for sev, k, _ln, _s in ss.scan_text(text, rel) if sev == "BLOCK"]
    if hits:
        bad_files.append(f"{rel}: {', '.join(hits)}")
check(f"all {len(staged)} staged files free of BLOCKs", not bad_files,
      "; ".join(bad_files[:4]))

print(f"\n{PASS + FAIL} checks: \033[32m{PASS} passed\033[0m"
      + (f", \033[31m{FAIL} failed\033[0m" if FAIL else ""))
sys.exit(1 if FAIL else 0)
