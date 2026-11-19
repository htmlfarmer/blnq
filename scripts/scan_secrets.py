#!/usr/bin/env python3
"""Pre-push secret scanner for the blnq.org repository.

Two things get scanned, because they leak in two different ways:

  A) the WORKING SET — everything `git add -A` would stage. .gitignore guards
     this, so this pass proves the guards actually hold.
  B) git HISTORY — every blob ever committed. A secret committed in 2024 and
     deleted in 2025 is still fully public once the repo is pushed, and no
     .gitignore rule can reach it.

Findings are reported as file:line + the PATTERN that matched, never the value —
printing a live credential into a report (or a chat log) is itself a leak.

Run:  python3 scripts/scan_secrets.py
Exit: 0 = clean, 1 = findings to review.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── patterns ───────────────────────────────────────────────────────────────
# (name, regex, severity)   severity: BLOCK = do not push, WARN = review
PATTERNS = [
    # Key-block rules require the base64 BODY and the END marker, not just the
    # header. Two reasons: (1) a header line alone is not a credential, and
    # (2) a detector must not match its own pattern text — requiring the body
    # is what stops this file from flagging the very line that defines these
    # regexes. (It used to: "PGP key block" matched its own definition.)
    ("private key",            r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----[\sA-Za-z0-9+/=]{40,}?-----END", "BLOCK"),
    ("PGP key block",          r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\sA-Za-z0-9+/=]{40,}?-----END PGP PRIVATE KEY BLOCK", "BLOCK"),
    ("AWS access key",         r"\bAKIA[0-9A-Z]{16}\b", "BLOCK"),
    ("AWS secret key",         r"(?i)\baws_secret_access_key[ \t]*[=:][ \t]*['\"]?[A-Za-z0-9/+=]{30,}", "BLOCK"),
    ("OpenAI-style key",       r"\bsk-[A-Za-z0-9][A-Za-z0-9\-_]{18,}", "BLOCK"),
    ("Anthropic key",          r"\bsk-ant-[A-Za-z0-9\-_]{20,}", "BLOCK"),
    ("Google API key",         r"\bAIza[0-9A-Za-z_\-]{35}\b", "BLOCK"),
    ("GitHub token",           r"\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}", "BLOCK"),
    ("GitLab token",           r"\bglpat-[A-Za-z0-9_\-]{20,}", "BLOCK"),
    ("Slack token",            r"\bxox[baprs]-[A-Za-z0-9\-]{10,}", "BLOCK"),
    ("Slack webhook",          r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", "BLOCK"),
    ("SendGrid key",           r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", "BLOCK"),
    ("Stripe key",             r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}", "BLOCK"),
    ("Twilio key",             r"\bAC[0-9a-fA-F]{32}\b", "BLOCK"),
    ("Discord token",          r"[MN][A-Za-z0-9_\-]{23,}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}", "BLOCK"),
    ("JWT",                    r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", "WARN"),
    ("connection string pwd",  r"(?i)\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis|amqp)://[^\s:/@]+:[^\s@/]{3,}@", "BLOCK"),
    ("assigned password",      r"(?i)(?:password|passwd|pwd)[ \t]*[=:][ \t]*['\"][^'\"\s]{4,}['\"]", "BLOCK"),
    ("assigned secret/token",  r"(?i)(?:secret|api_key|apikey|api[_-]key|access[_-]token|auth[_-]token|private[_-]key)[ \t]*[=:][ \t]*['\"][^'\"\s]{6,}['\"]", "BLOCK"),
    ("hardcoded bearer",       r"(?i)\bBearer\s+[A-Za-z0-9._\-]{24,}", "BLOCK"),
    # (?<!\$): '$BLNQ_ADMIN_TOKEN: …' is a shell-variable REFERENCE in
    # documentation, never a value; a bare assignment still warns.
    ("admin token env ref",    r"(?<!\$)BLNQ_ADMIN_TOKEN[ \t]*[=:][ \t]*['\"]?[A-Za-z0-9][^\s'\"]{5,}", "WARN"),
    ("secrets key material",   r"(?<!\$)BLNQ_SECRETS_KEY[ \t]*[=:][ \t]*['\"]?[A-Za-z0-9][^\s'\"]{5,}", "WARN"),
    ("hivv scan key",          r"HIVV_SCAN_KEY[ \t]*[=:][ \t]*['\"]?[0-9a-f]{32,}", "BLOCK"),
    ("ed25519 hex seed (32B)", r"(?i)\b[0-9a-f]{64}\b(?=[^\n]{0,40}(?:seed|priv|secret))", "WARN"),
]

# Host / infra layout — not credentials, but publishes the box's map to anyone.
NOISE_PATTERNS = [
    ("private RFC1918 IP",  r"\b192\.168\.\d{1,3}\.\d{1,3}\b|\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
    ("vhost absolute path", r"/var/www/vhosts/[a-z0-9.\-]+"),
]

BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2",
              ".ttf", ".eot", ".zip", ".gz", ".tar", ".pdf", ".bin", ".pyc"}


def _blank_prose(text: str) -> str:
    """Replace comments and docstrings with spaces, preserving byte offsets.

    A MENTION of a credential in documentation is not a credential: the usage
    line inside a module docstring (`Run: BLNQ_ADMIN_TOKEN=... python3 x.py`)
    is instruction, not a leaked value.

    Ordinary string literals are deliberately left ALONE. `password = "hunter2"`
    IS the secret, and blanking strings would blind the scanner to precisely
    the thing it exists to find. Only `#` comments and triple-quoted blocks are
    removed; a `#` inside an ordinary string is consumed as part of that
    string, so `"http://x/#frag"` does not truncate the line.

    Offsets are preserved (blanked, not deleted) so reported line numbers
    still point at the original file.
    """
    out = list(text)
    n = len(text)
    i = 0

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if c == "#":
            j = i
            while j < n and text[j] != "\n":
                j += 1
            blank(i, j)
            i = j
        elif c in "\"'":
            q = c
            if text.startswith(q * 3, i):          # docstring / block literal
                end = text.find(q * 3, i + 3)
                stop = n if end == -1 else end + 3
                blank(i, stop)
                i = stop
            else:                                  # ordinary literal: keep it
                i += 1
                while i < n and text[i] != q:
                    if text[i] == "\\":
                        i += 1
                    if i < n and text[i] == "\n":
                        break
                    i += 1
                i += 1
        else:
            i += 1
    return "".join(out)


def scan_text(text: str, source: str):
    """Yield (severity, kind, lineno, line) for every match."""
    # Credentials are matched against source with prose removed; infra NOISE
    # is matched against the raw text, because a vhost path in a comment still
    # publishes the box's layout.
    code_only = _blank_prose(text)
    for kind, rx, sev in PATTERNS:
        for m in re.finditer(rx, code_only):
            lineno = text.count("\n", 0, m.start()) + 1
            yield sev, kind, lineno, source
            break  # one finding per kind per file is enough to act on
    if source.endswith(("AGENTS.md", "CLAUDE.md", "SITE-NOTES.md", "PORTMAP.md")):
        return  # already ignored; don't drown the signal
    for kind, rx in NOISE_PATTERNS:
        if re.search(rx, text):
            lineno = text.count("\n", 0, re.search(rx, text).start()) + 1
            yield "NOISE", kind, lineno, source


def committed_files() -> list[str]:
    """Everything git would stage, as INDIVIDUAL FILES.

    `git status --porcelain` collapses a wholly-untracked directory into one
    entry (`?? api/lib/`), which a naive is_file() filter then discards —
    silently excluding every file inside it. That is how config.js and the whole
    of api/lib/ escaped the first scan. `git ls-files --others
    --exclude-standard` returns real paths and honours .gitignore, which is
    precisely the contract we need to test.
    """
    def git(args: list[str]) -> list[str]:
        r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
        return [l for l in r.stdout.splitlines() if l.strip()]

    tracked = git(["ls-files"])
    untracked = git(["ls-files", "--others", "--exclude-standard"])
    modified = [ln[3:].strip().split(" -> ")[-1]
                for ln in subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                                         capture_output=True, text=True).stdout.splitlines()
                if ln[:2] in (" M", "M ", "A ", "MM")]
    return sorted({f for f in tracked + untracked + modified
                   if f and not f.endswith("/") and not Path(ROOT / f).is_dir()})


def read(p: Path) -> str | None:
    if p.suffix.lower() in BINARY_EXT:
        return None
    try:
        return p.read_text(encoding="utf-8", errors="strict")
    except Exception:
        try:
            return p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None


def scan_history():
    """Every blob ever committed. .gitignore cannot help here."""
    shas = subprocess.run(["git", "rev-list", "--objects", "--all"], cwd=ROOT,
                          capture_output=True, text=True).stdout.splitlines()
    seen, findings = set(), []
    for entry in shas:
        parts = entry.split(" ", 1)
        sha = parts[0]
        name = parts[1] if len(parts) > 1 else ""
        if sha in seen:
            continue
        seen.add(sha)
        cat = subprocess.run(["git", "cat-file", "-p", sha], cwd=ROOT,
                             capture_output=True)
        if cat.returncode != 0 or len(cat.stdout) > 2_000_000:
            continue
        try:
            text = cat.stdout.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for sev, kind, lineno, _ in scan_text(text, name):
            findings.append((sev, kind, name or sha[:8], lineno))
    return findings


def main() -> int:
    print("=" * 74)
    print("BLNQ PRE-PUSH SECRET SCAN")
    print("=" * 74)

    files = committed_files()
    print(f"\nA) working set — {len(files)} file(s) git would stage\n")

    blocks, warns, noise = [], [], []
    for rel in files:
        p = ROOT / rel
        if not p.is_file():
            continue
        text = read(p)
        if not text:
            continue
        for sev, kind, lineno, src in scan_text(text, rel):
            (blocks if sev == "BLOCK" else warns if sev == "WARN" else noise).append(
                (kind, src, lineno))

    def report(title, items, marker, colour):
        print(f"  {marker} {title}: {len(items)}")
        for kind, src, lineno in items:
            print(f"      \x1b[{colour}m{kind}\x1b[0m  {src}:{lineno}")
        if not items:
            print("      (none)")

    report("BLOCK — do not push until resolved", blocks, "✗", "31")
    report("WARN — review these", warns, "!", "33")
    report("NOISE — infra layout (already gitignored where sensitive)", noise, "·", "36")

    print(f"\nB) git history — {len(list(subprocess.run(['git','rev-list','--all'], cwd=ROOT, capture_output=True, text=True).stdout.split()))} commit(s)\n")
    hist = scan_history()
    # scan_history() yields (sev, kind, src, line); report() expects
    # (kind, src, line) — unflattened, the first history warning crashed the
    # whole scan (ValueError on unpack) and turned a review item into an
    # opaque exit-1 (2026-11-18).
    hblocks = [(k, src, ln) for (sev, k, src, ln) in hist if sev == "BLOCK"]
    hwarns = [(k, src, ln) for (sev, k, src, ln) in hist if sev == "WARN"]
    report("BLOCK — secrets in history", hblocks, "✗", "31")
    report("WARN — review in history", hwarns, "!", "33")

    total = len(blocks) + len(hblocks)
    print("\n" + "=" * 74)
    if total:
        print(f"\x1b[1m\x1b[31m{total} BLOCKING finding(s) — do not push.\x1b[0m")
        return 1
    if warns or hwarns:
        print(f"\x1b[1m\x1b[33m{len(warns) + len(hwarns)} warning(s) — review before pushing.\x1b[0m")
        return 1
    print("\x1b[1m\x1b[32mCLEAN — no blocking or warning findings.\x1b[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
