#!/usr/bin/env python3
"""blnq — the bLNQ.org client CLI / local agent.

Pure stdlib (no pip install). Connects to blnq.org as a CLIENT.

Subcommands (operator / local):
  start              start the local blnq agent (background, heartbeats to hub)
  stop               stop the local blnq agent
  restart            stop + start
  status             pid, uptime, last heartbeat, last error
  logs [N] [-f]      tail ~/.local/share/blnq/agent.log
  free               host mem + swap + disk + per-process RSS
  pct [--watch=N]    live CPU%/MEM% line (refreshes like top)
  info               hub URL, version, install path, hub_health
  update             pull the latest blnq-cli.py from blnq.org
  uninstall [--purge]
              stop agent + disarm respawn + remove code (keeps config/keys/
              logs; --purge removes those too — keys unrecoverable)
  --help, help       list every subcommand

Subcommands (one-shot / talk to blnq.org):
  health              GET /api/stats (cheap liveness check)
  whoami              same as health
  workers list        GET /api/workers/list
  graph               GET /api/graph
  graph stats         GET /api/graph/stats
  graph search Q      GET /api/graph/search?q=Q
  graph timeline      GET /api/graph/timeline
  scripts list        GET /api/scripts
  scripts get ID      GET /api/scripts/:id
  login               prompt for /api/auth/login, save session cookie

Smart default — if argv[0] is a path to an existing local file with a
supported extension, it gets uploaded to blnq.org /api/run, executed
remotely, and stdout/stderr stream back here. So:

  blnq runme.py                       # upload + run, print output
  blnq ./scripts/hello.js arg1 arg2   # also forwards argv after the file as "stdin"

Supported extensions: .py .js .ts .rb .go .rs .c .cpp .java .sh .pl .php

Per-subcommand --help also works.
"""
from __future__ import annotations

import argparse
import ast
import base64
import getpass
import hashlib
import hmac
import http.cookiejar as cookiejar
import io
import json
import os
import re
import secrets
import select
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from queue import Queue, Empty

APP       = "blnq"
HUB       = os.environ.get("BLNQ_HUB",  "https://blnq.org")
HUB_NAME  = "bLNQ.org"
VERSION   = "0.6.4"

# sys.stdlib_module_names is 3.10+; macOS ships python3.9 forever, so without
# a real fallback list EVERY stdlib import looked "third-party" and
# `blnq evaluate` crashed with AttributeError (audit 2026-11-18).
_STDLIB_39 = frozenset("""
abc aifc argparse array ast asynchat asyncio atexit base64 bdb binascii binhex
bisect builtins bz2 calendar cgi cgitb chunk cmd codecs codeop collections
colorsys compileall concurrent configparser contextlib contextvars copy copyreg
crypt csv ctypes curses dataclasses datetime dbm decimal difflib dis doctest
email encodings ensurepip enum errno faulthandler fcntl filecmp fileinput
fnmatch formatter fractions ftplib functools gc getopt getpass gettext glob
graphlib grp gzip hashlib heapq hmac html http imaplib imghdr importlib inspect
io ipaddress itertools json keyword linecache locale logging lzma mailbox
mailcap marshal math mimetypes mmap modulefinder multiprocessing netrc nis
nntplib ntpath nturl2path numbers opcode operator optparse os pathlib pickle
pickletools pipes pkgutil platform plistlib poplib posix posixpath pprint pstats
pty py_compile pyclbr pydoc queue quopri random re reprlib resource rlcompleter
runpy sched secrets select selectors shelve shlex shutil signal site smtpd
smtplib sndhdr socket socketserver sqlite3 ssl stat statistics string stringprep
struct subprocess sunau symbol symtable sys sysconfig syslog tabnanny tarfile
telnetlib tempfile termios textwrap this threading time timeit token tokenize
traceback tracemalloc tty types typing unicodedata unittest urllib uu uuid venv
warnings wave weakref webbrowser wsgiref xdrlib xml xmlrpc zipapp zipfile
zipimport zlib _thread __future__
""".split())

def _stdlib_names():
    """Top-level stdlib module names: the real set on 3.10+, the curated 3.9
    list on the macOS system python (which will never grow past 3.9)."""
    n = getattr(sys, "stdlib_module_names", None)
    return frozenset(n) if n is not None else _STDLIB_39

# `blnq file.py` must behave like `python file.py`: the SCRIPT's output and
# nothing else. Everything blnq says about itself (scan, upload, queue, trust)
# is chatter — useful, but only when asked for. Details live in `blnq last`.
# Set by main() from --verbose / --detailed / -v.
VERBOSE = False


# ── output policy: colour for humans, clean bytes for machines ─────────────
# 103 lines of this CLI emit ANSI escapes. A person watching a terminal wants
# them; `blnq run.py > out.txt` and every AI harness do NOT — they should get
# data, not escape sequences to strip before use. So colour follows the stream,
# not the author, and NO_COLOR (the de-facto standard) is honoured.
class _AnsiFilter:
    _RX = __import__("re").compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

    def __init__(self, real, force: bool):
        self._real = real
        self._strip = (not force) and (bool(__import__("os").environ.get("NO_COLOR"))
                                       or not real.isatty())

    def write(self, s):
        return self._real.write(self._RX.sub("", s) if self._strip else s)

    def flush(self):
        return self._real.flush()

    def isatty(self):
        return self._real.isatty()

    def __getattr__(self, name):
        # buffer/encoding/fileno and friends must reach the real stream untouched
        return getattr(self._real, name)


def _install_stream_policy() -> None:
    force = bool(__import__("os").environ.get("FORCE_COLOR")
                 or __import__("os").environ.get("CLICOLOR_FORCE"))
    for name in ("stdout", "stderr"):
        real = getattr(sys, name, None)
        if real is None or not hasattr(real, "isatty"):
            continue
        try:
            setattr(sys, name, _AnsiFilter(real, force))
        except Exception:
            pass


_install_stream_policy()


# ── presentation: one house style, so no command looks like a stranger ─────
def _title(title: str, sub: str = "") -> None:
    tail = f" \033[2m— {sub}\033[0m" if sub else ""
    print(f"\033[1m{APP} {title}\033[0m{tail}")


def _hdr(text: str) -> str:
    return f"\033[2m{text}\033[0m"


def _kv(label: str, value, width: int = 14) -> None:
    """One aligned key/value row, indented under its section header. Width is
    fixed so columns line up across commands instead of each one inventing its
    own padding."""
    print(f"    {str(label).ljust(width)} {value}")


def _hint(text: str) -> None:
    """Guidance, unified. Warnings stay on stderr via warn(); this is for
    'here is what to do next' so advice never looks like an error."""
    print(f"    \033[2m→ {text}\033[0m")


def _disp_len(s: str) -> int:
    """Printable width of a string in terminal columns.

    Emoji and CJK glyphs occupy TWO columns but are one Python character, so
    len() is wrong for anything we want to right-align. Getting this wrong is
    why rules drift a few characters to the left on lines with emoji in them.
    """
    w = 0
    for ch in str(s):
        w += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return w


def _section(emoji: str, text: str, width: int = 66) -> None:
    """Section header: emoji + label + a dim rule out to the margin.

    Every command builds its output from these three pieces (_section for a
    heading, _kv for a row, _hint for what to do next) so that 'where does one
    topic end' looks identical everywhere instead of each command inventing
    its own separator, indentation and colour.
    """
    label = f"{emoji} {text}"
    pad = max(3, width - _disp_len(label))
    print(f"\n  \033[1;35m{label}\033[0m \033[2m{'─' * pad}\033[0m")


def _rule(width: int = 66) -> None:
    """A plain dim rule — for closing a block without inventing a heading."""
    print(f"  \033[2m{'─' * width}\033[0m")


def _good(text) -> str:
    return f"\033[32m✓ {text}\033[0m"


def _bad(text) -> str:
    return f"\033[31m✗ {text}\033[0m"


def _meh(text) -> str:
    return f"\033[33m⚠ {text}\033[0m"


def _humanize_secs(secs) -> str:
    """47s → '47s', 3700 → '1h 2m', 90000 → '1d 1h'. Short and greppable."""
    try:
        s = max(0, int(secs))
    except (TypeError, ValueError):
        return str(secs)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60}m"
    return f"{s // 86400}d {(s % 86400) // 3600}h"


def _ago(ts) -> str:
    """An epoch (or ISO string) as 'just now' / '3m ago' / '2d ago'.

    Absolute timestamps make a reader do arithmetic to learn whether a
    heartbeat is worrying; relative time is the answer they actually wanted.
    """
    try:
        if isinstance(ts, str):
            ts = time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
        delta = max(0, int(time.time() - int(ts)))
    except (TypeError, ValueError, OverflowError):
        return str(ts)
    if delta < 10:
        return "just now"
    if delta < 60:
        return f"{delta}s ago"
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"

IS_WIN = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"

CONFIG_DIR    = Path(os.environ.get("BLNQ_CONFIG_DIR")  or (Path.home() / ".config" / APP))
STATE_DIR     = Path(os.environ.get("BLNQ_STATE_DIR")   or (Path.home() / ".local" / "share" / APP))
COOKIE_FILE   = CONFIG_DIR  / "cookies.txt"

# Same derivation as hivv: figure out install dir from __file__ if we're under <prefix>/lib/<app>/
_THIS_DIR = Path(__file__).resolve().parent
if _THIS_DIR.name == "blnq" and _THIS_DIR.parent.name == "lib":
    INSTALL_DIR = Path(os.environ.get("BLNQ_INSTALL_DIR") or _THIS_DIR)
    BIN_DIR     = Path(os.environ.get("BLNQ_BIN_DIR")     or _THIS_DIR.parent.parent / "bin")
else:
    _default_prefix = Path(os.environ.get("USERPROFILE", str(Path.home()))) if IS_WIN else Path("/usr/local")
    INSTALL_DIR = Path(os.environ.get("BLNQ_INSTALL_DIR") or (_default_prefix / "lib" / APP))
    BIN_DIR     = Path(os.environ.get("BLNQ_BIN_DIR")     or (_default_prefix / "bin"))

CONFIG_FILE   = CONFIG_DIR  / "config.toml"
STATE_FILE    = STATE_DIR   / "state.json"
LOG_FILE      = STATE_DIR   / "agent.log"
PID_FILE      = STATE_DIR   / "agent.pid"
STOP_FILE     = STATE_DIR   / "stop.request"   # graceful-stop flag (polled; works on Windows too)
AUTH_FILE     = CONFIG_DIR  / "auth.json"   # 0600 — per-install bearer token

HEARTBEAT_S = int(os.environ.get("BLNQ_HEARTBEAT_S", "60"))

# How many DISTINCT validators must agree before code is runnable. Mirrors
# api/lib/trust.js so `blnq who` states the same number the hub enforces —
# a CLI that guesses is a CLI that eventually lies.
_SIGN_THRESHOLD = int(os.environ.get("BLNQ_SIGN_THRESHOLD") or 2)


# ── utilities ──────────────────────────────────────────────────────────
def log(msg: str) -> None:
    print(f"\033[1;34m[{APP}]\033[0m {msg}", file=sys.stderr)
def ok(msg: str) -> None:
    print(f"\033[1;32m[{APP}]\033[0m {msg}")
def warn(msg: str) -> None:
    print(f"\033[1;33m[{APP}]\033[0m {msg}", file=sys.stderr)
def die(msg: str, code: int = 1) -> None:
    print(f"\033[0;31m[{APP}]\033[0m {msg}", file=sys.stderr)
    sys.exit(code)

def ensure_dirs() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)

def read_state() -> dict:
    if not STATE_FILE.exists(): return {}
    try: return json.loads(STATE_FILE.read_text())
    except (OSError, json.JSONDecodeError): return {}

def write_state(d: dict) -> None:
    ensure_dirs()
    STATE_FILE.write_text(json.dumps(d, indent=2, sort_keys=True))


# ── security primitives (Phase A — graceful degrade if hub doesn't support) ──

_SCRUB_RULES = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[\w\-\.]{6,}"), r"\1***REDACTED***"),
    (re.compile(r"""(?i)\b(api[_-]?key|api[_-]?token|secret[_-]?key|access[_-]?token|auth[_-]?token)\b(\s*[:=]\s*)(?:["'])?[\w\-\.]{6,}"""), r"\1\2***REDACTED***"),
    (re.compile(r"(?i)\b(password|passwd|pwd)\b(\s*[:=]\s*)(?:[\"'])?[^\s\"']{6,}"), r"\1\2***REDACTED***"),
    (re.compile(r"([?&])(token|access_token|api_key|apikey|password|secret)=([\w\-\.%]+)"), r"\1\2=***"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"), "***JWT***"),
    (re.compile(r"\b(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9\-]{10,})\b"), "***KEY***"),
]

def _scrub(text: str) -> str:
    if not text: return text
    out = text
    for pat, repl in _SCRUB_RULES:
        out = pat.sub(repl, out)
    return out

def _scrub_lines(text: str) -> str:
    return "\n".join(_scrub(line) for line in text.splitlines())

def _machine_id() -> str | None:
    try:
        p = Path("/etc/machine-id")
        if p.exists():
            mid = p.read_text().strip()
            if mid: return f"linux-{mid[:32]}"
    except OSError: pass
    if sys.platform == "darwin":
        try:
            out = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True, timeout=3)
            if out.returncode == 0:
                m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', out.stdout)
                if m: return f"macos-{m.group(1)}"
        except (subprocess.SubprocessError, OSError): pass
    if IS_WIN:
        # winreg first: wmic is deprecated/removed on recent Windows 11 builds.
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Cryptography") as k:
                v, _ = winreg.QueryValueEx(k, "MachineGuid")
                if v: return f"windows-{v}"
        except (OSError, ImportError): pass
        try:
            out = subprocess.run(
                ["wmic", "csproduct", "get", "uuid"],
                capture_output=True, text=True, timeout=3)
            if out.returncode == 0:
                m = re.search(r"[0-9A-Fa-f\-]{36}", out.stdout)
                if m: return f"windows-{m.group(0)}"
        except (subprocess.SubprocessError, OSError, FileNotFoundError): pass
    return None

def _get_or_create_auth_token() -> str:
    ensure_dirs()
    f = AUTH_FILE
    if f.exists():
        try:
            d = json.loads(f.read_text())
            tok = d.get("token")
            if isinstance(tok, str) and len(tok) >= 32:
                return tok
        except (OSError, json.JSONDecodeError): pass
    tok = secrets.token_hex(32)
    fd = os.open(str(f), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps({
            "token": tok, "created_at": int(time.time()), "version": 1,
        }, indent=2).encode())
    finally:
        os.close(fd)
    return tok

def _signed_headers(method: str, path: str, body_bytes: bytes | None,
                    token: str | None = None) -> dict:
    if not token: return {}
    ts = str(int(time.time()))
    nonce = secrets.token_hex(8)
    body_hash = hashlib.sha256(body_bytes or b"").hexdigest()
    msg = f"{ts}\n{nonce}\n{method.upper()}\n{path}\n{body_hash}"
    sig = hmac.new(token.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return {
        "X-Auth-Timestamp": ts,
        "X-Auth-Nonce":     nonce,
        "X-Auth-Signature": sig,
    }


# ── trust layer: Ed25519 attestations ───────────────────────────────────
# Pure-stdlib Ed25519 so a signature made here verifies identically on the
# Node hub and on any stranger's machine. The canonicalization rules MUST stay
# byte-identical to api/lib/attest.js — see docs/TRUST-PLAN.md §2.
#
# NOTE: this is the reference-form implementation (affine coordinates), which is
# not constant-time. It signs occasional small attestations on the signer's own
# machine, where local timing leakage is not in our threat model. Do NOT use it
# for high-volume or adversarial co-tenant signing without moving to extended
# coordinates.

_ED25519_B = 256
_ED25519_Q = 2 ** 255 - 19
_ED25519_L = 2 ** 252 + 27742317777372353535851937790883648493
_ED25519_D = (-121665 * pow(121666, _ED25519_Q - 2, _ED25519_Q)) % _ED25519_Q
_ED25519_I = pow(2, (_ED25519_Q - 1) // 4, _ED25519_Q)


def _ed_xrecover(y: int) -> int:
    q = _ED25519_Q
    xx = (y * y - 1) * pow(_ED25519_D * y * y + 1, q - 2, q) % q
    xx = pow(xx, (q + 3) // 8, q)
    if (xx * xx - (y * y - 1) * pow(_ED25519_D * y * y + 1, q - 2, q)) % q != 0:
        xx = (xx * _ED25519_I) % q
    if xx % 2 != 0:
        xx = q - xx
    return xx


_ED25519_BY = 4 * pow(5, _ED25519_Q - 2, _ED25519_Q) % _ED25519_Q
_ED25519_BASE = (_ed_xrecover(_ED25519_BY), _ED25519_BY)


def _ed_add(p, pq):
    q = _ED25519_Q
    x1, y1 = p
    x2, y2 = pq
    x3 = (x1 * y2 + x2 * y1) * pow(1 + _ED25519_D * x1 * x2 * y1 * y2, q - 2, q) % q
    y3 = (y1 * y2 + x1 * x2) * pow(1 - _ED25519_D * x1 * x2 * y1 * y2, q - 2, q) % q
    return (x3, y3)


def _ed_scalarmult(p, e: int):
    if e == 0:
        return (0, 1)
    qq = _ed_scalarmult(p, e // 2)
    qq = _ed_add(qq, qq)
    if e & 1:
        qq = _ed_add(qq, p)
    return qq


def _ed_bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _ed_encodeint(y: int) -> bytes:
    return bytes(
        sum(((y >> (i * 8 + j)) & 1) << j for j in range(8))
        for i in range(_ED25519_B // 8)
    )


def _ed_encodepoint(p) -> bytes:
    x, y = p
    bits = [(y >> i) & 1 for i in range(_ED25519_B - 1)] + [x & 1]
    return bytes(
        sum(bits[i * 8 + j] << j for j in range(8))
        for i in range(_ED25519_B // 8)
    )


def _ed_decodeint(s: bytes) -> int:
    """Little-endian integer over ALL bytes.

    Ed25519's r and h are SHA-512 outputs — 512 bits — reduced mod L. Slicing
    this to _ED25519_B (256) bits made sign/verify self-consistent locally while
    producing signatures OpenSSL rejects, and it is invisible to any test that
    only checks a signature against itself.
    """
    return int.from_bytes(s, "little")


def _ed_isoncurve(p) -> bool:
    x, y = p
    return (-x * x + y * y - 1 - _ED25519_D * x * x * y * y) % _ED25519_Q == 0


def _ed_decodepoint(s: bytes):
    y = sum(2 ** i * _ed_bit(s, i) for i in range(0, _ED25519_B - 1))
    x = _ed_xrecover(y)
    if x & 1 != _ed_bit(s, _ED25519_B - 1):
        x = _ED25519_Q - x
    p = (x, y)
    if not _ed_isoncurve(p):
        raise ValueError("point not on curve")
    return p


def _ed_secret_expand(sk: bytes):
    if len(sk) != 32:
        raise ValueError("ed25519 secret key must be 32 bytes")
    h = hashlib.sha512(sk).digest()
    a = 2 ** (_ED25519_B - 2) + sum(2 ** i * _ed_bit(h, i) for i in range(3, _ED25519_B - 2))
    return a, h[32:]


def ed25519_public_key(sk: bytes) -> bytes:
    a, _ = _ed_secret_expand(sk)
    return _ed_encodepoint(_ed_scalarmult(_ED25519_BASE, a))


def ed25519_sign(message: bytes, sk: bytes) -> bytes:
    a, prefix = _ed_secret_expand(sk)
    pk = ed25519_public_key(sk)
    r = _ed_decodeint(hashlib.sha512(prefix + message).digest()) % _ED25519_L
    big_r = _ed_scalarmult(_ED25519_BASE, r)
    h = _ed_decodeint(hashlib.sha512(_ed_encodepoint(big_r) + pk + message).digest()) % _ED25519_L
    s = (r + h * a) % _ED25519_L
    return _ed_encodepoint(big_r) + _ed_encodeint(s)


def ed25519_verify(message: bytes, signature: bytes, pk: bytes) -> bool:
    """Verify a 64-byte Ed25519 signature. Never raises on malformed input."""
    try:
        if len(signature) != 64 or len(pk) != 32:
            return False
        a_point = _ed_decodepoint(pk)
        big_r = _ed_decodepoint(signature[:32])
        s = _ed_decodeint(signature[32:])
        if s >= _ED25519_L:
            return False
        h = _ed_decodeint(
            hashlib.sha512(_ed_encodepoint(big_r) + pk + message).digest()
        ) % _ED25519_L
        return _ed_scalarmult(_ED25519_BASE, s) == _ed_add(big_r, _ed_scalarmult(a_point, h))
    except Exception:
        return False


def _principal_id(raw_pk: bytes) -> str:
    # Human-readable namespace + key fingerprint. The prefix names the issuing
    # system family; the 32 hex characters remain cryptographically derived.
    return "hivv_" + hashlib.sha256(raw_pk).hexdigest()[:32]


def _is_known_principal_id(value: str) -> bool:
    """Accept current `hivv_` IDs and legacy `pri_` IDs for read/verify only."""
    return bool(re.fullmatch(r"(?:hivv|pri)_[0-9a-f]{32}", str(value or "")))


# ── canonical JSON (byte-identical to api/lib/attest.js) ───────────────
def _canonical_json(value) -> str:
    """Deterministic JSON: sorted-by-UTF-8-byte keys, no whitespace, ints only."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        # Guard the same range Node rejects (Number.isSafeInteger).
        if abs(value) > 2 ** 53 - 1:
            raise ValueError(f"canonical JSON integer out of range: {value}")
        return str(value)
    if isinstance(value, float):
        raise ValueError(f"canonical JSON allows integers only, got {value!r}")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        # Node only drops `undefined`, so explicit nulls MUST be kept —
        # dropping them here would make {"a":null} and {} hash differently
        # on the two sides and silently break every signature.
        keys = sorted(value.keys(), key=lambda k: str(k).encode("utf-8"))
        return "{" + ",".join(
            json.dumps(str(k), ensure_ascii=False) + ":" + _canonical_json(value[k])
            for k in keys
        ) + "}"
    raise ValueError(f"canonical JSON cannot serialize type {type(value).__name__}")


_ENVELOPE_KINDS = ("source.review", "run.request", "io.record", "run.record")


def build_envelope(kind: str, subject: str, issuer: str, body: dict,
                   nonce: str | None = None, issued_at: int | None = None) -> dict:
    if kind not in _ENVELOPE_KINDS:
        raise ValueError(f"unknown attestation kind: {kind}")
    if not re.fullmatch(r"[0-9a-f]{64}", str(subject)):
        raise ValueError("subject must be 64 hex chars")
    if not re.fullmatch(r"hivv_[0-9a-f]{32}", str(issuer)):
        raise ValueError("issuer must be hivv_<32 hex>")
    return {
        "v": 2,
        "kind": kind,
        "subject": subject,
        "issuer": issuer,
        "issued_at": int(time.time()) if issued_at is None else int(issued_at),
        "nonce": nonce or secrets.token_hex(8),
        "body": body or {},
    }


def sign_envelope(envelope: dict, sk: bytes) -> str:
    import base64
    return base64.b64encode(
        ed25519_sign(_canonical_json(envelope).encode("utf-8"), sk)
    ).decode("ascii")


def verify_envelope(envelope: dict, signature_b64: str, raw_pk: bytes) -> tuple[bool, list]:
    """Mirror of attest.js verifyEnvelope: signature AND issuer derivation."""
    import base64
    problems = []
    if not isinstance(envelope, dict):
        return False, ["malformed envelope"]
    if envelope.get("v") not in (1, 2):
        problems.append(f"unsupported version {envelope.get('v')!r}")
    if envelope.get("kind") not in _ENVELOPE_KINDS:
        problems.append(f"unknown kind {envelope.get('kind')!r}")
    if not re.fullmatch(r"[0-9a-f]{64}", str(envelope.get("subject", ""))):
        problems.append("bad subject")
    if not _is_known_principal_id(envelope.get("issuer", "")):
        problems.append("bad issuer")
    if not isinstance(envelope.get("issued_at"), int) or isinstance(envelope.get("issued_at"), bool):
        problems.append("bad issued_at")
    if len(raw_pk) != 32:
        problems.append("public key must be 32 bytes")
        return False, problems
    if (str(envelope.get("issuer", "")).startswith("hivv_") and
            _principal_id(raw_pk) != envelope.get("issuer")):
        problems.append("issuer does not derive from public key")
    if problems:
        return False, problems
    try:
        sig = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return False, ["unparseable signature"]
    if not ed25519_verify(_canonical_json(envelope).encode("utf-8"), sig, raw_pk):
        return False, ["signature mismatch"]
    return True, []


# ── P2P crypto: X25519 + HKDF-SHA256 + HMAC-SHA256 AEAD ───────────────
#
# Why this construction and not AES-GCM / ChaCha20-Poly1305:
# the blnq CLI must stay pure-stdlib, and Python's stdlib has NO AEAD. Node and
# the browser both have AES-GCM, but Python does not — so using them would force
# a `cryptography` dependency onto every machine that installs blnq.
#
# HMAC-SHA256 IS in every one of the three implementations (stdlib hashlib,
# node:crypto, WebCrypto), so the suite is built entirely from it:
#
#   key agreement : X25519      (pure-python Montgomery ladder, RFC 7748)
#   KDF           : HKDF-SHA256 (RFC 5869)
#   confidentiality : HMAC-SHA256 in counter mode  (HMAC as a PRF keystream)
#   integrity     : HMAC-SHA256, encrypt-then-MAC with a SEPARATE key
#
# Encrypt-then-MAC means a ciphertext is authenticated BEFORE any of it is
# decrypted, and the AAD covers who it is for and what kind of message it is,
# so a hub that reorders, replays or re-addresss an envelope cannot make either
# side act on it.
#
# The three implementations must produce byte-identical results — that is what
# tests/test_p2p_cross.py enforces.

_X_P = 2 ** 255 - 19
_X_A24 = 121665


def _x25519_clamp(k: bytearray) -> bytearray:
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return k


def x25519(scalar: bytes, u: bytes) -> bytes:
    """RFC 7748 X25519 — Montgomery ladder over 25519."""
    if len(scalar) != 32 or len(u) != 32:
        raise ValueError("x25519 operands must be 32 bytes")
    k = _x25519_clamp(bytearray(scalar))
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)   # mask the high bit
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k[t >> 3] >> (t & 7)) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _X_P
        aa = (a * a) % _X_P
        b = (x2 - z2) % _X_P
        bb = (b * b) % _X_P
        e = (aa - bb) % _X_P
        c = (x3 + z3) % _X_P
        d = (x3 - z3) % _X_P
        da = (d * a) % _X_P
        cb = (c * b) % _X_P
        x3 = ((da + cb) ** 2) % _X_P
        z3 = (x1 * ((da - cb) ** 2)) % _X_P
        x2 = (aa * bb) % _X_P
        z2 = (e * ((aa + _X_A24 * e) % _X_P)) % _X_P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, _X_P - 2, _X_P)) % _X_P).to_bytes(32, "little")


def x25519_public_key(seed32: bytes) -> bytes:
    """Public key from a 32-byte seed (clamped as the scalar)."""
    if len(seed32) != 32:
        raise ValueError("x25519 seed must be 32 bytes")
    return x25519(seed32, (9).to_bytes(32, "little"))


def p2p_seed_from_signing_key(ed_seed32: bytes) -> bytes:
    """Derive a SEPARATE X25519 seed from the Ed25519 seed.

    Deliberately not a curve conversion of the signing key: reusing one key
    material for both signing and key agreement is a cross-protocol hazard, so
    the encryption identity is domain-separated away from it with HMAC.
    """
    return hmac.new(b"blnq-x25519-v1", ed_seed32, hashlib.sha256).digest()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256 (extract then expand)."""
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t, prev = b"", b"", 0
    while len(out) < length:
        prev += 1
        t = hmac.new(prk, t + info + bytes([prev]), hashlib.sha256).digest()
        out += t
    return out[:length]


P2P_INFO = b"blnq-p2p-v1"


def p2p_session_keys(shared: bytes, session_id: bytes) -> tuple[bytes, bytes]:
    """Split an X25519 shared secret into independent enc + mac keys.

    Standard RFC 5869 HKDF with `P2P_INFO` as the salt and the session id mixed
    into the info label, so the same shared secret yields different keys for
    different sessions (no key reuse across conversations).
    """
    k_enc = hkdf_sha256(shared, P2P_INFO, b"enc|" + session_id, 32)
    k_mac = hkdf_sha256(shared, P2P_INFO, b"mac|" + session_id, 32)
    return k_enc, k_mac


def aead_encrypt(k_enc: bytes, k_mac: bytes, nonce: bytes, plaintext: bytes,
                 aad: bytes) -> bytes:
    """Encrypt-then-MAC. Returns nonce(16) || tag(32) || ciphertext."""
    if len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")
    # HMAC-SHA256 as a PRF in counter mode → keystream blocks.
    ks = b""
    ctr = 0
    while len(ks) < len(plaintext):
        ks += hmac.new(k_enc, nonce + ctr.to_bytes(4, "big"), hashlib.sha256).digest()
        ctr += 1
    ct = bytes(p ^ q for p, q in zip(plaintext, ks))
    tag = hmac.new(k_mac, nonce + aad + ct, hashlib.sha256).digest()
    return nonce + tag + ct


def aead_decrypt(k_enc: bytes, k_mac: bytes, blob: bytes, aad: bytes) -> bytes | None:
    """Verify the tag FIRST, then decrypt. Returns None on any failure."""
    if len(blob) < 48:
        return None
    nonce, tag, ct = blob[:16], blob[16:48], blob[48:]
    expect = hmac.new(k_mac, nonce + aad + ct, hashlib.sha256).digest()
    # Constant-time compare: a timing channel here would leak byte-by-byte
    # whether a forged tag is on the right track.
    if not hmac.compare_digest(tag, expect):
        return None
    ks = b""
    ctr = 0
    while len(ks) < len(ct):
        ks += hmac.new(k_enc, nonce + ctr.to_bytes(4, "big"), hashlib.sha256).digest()
        ctr += 1
    return bytes(p ^ q for p, q in zip(ct, ks))


# ── local key storage ──────────────────────────────────────────────────
def key_dir() -> Path:
    """Derived at call time from CONFIG_DIR so tests/moves can redirect it."""
    return CONFIG_DIR / "keys"


def load_or_create_key(role: str) -> tuple[bytes, bytes]:
    """Return (private_key_32, raw_public_key_32) for a principal role.

    Roles: requester | runner | validator
    """
    ensure_dirs()
    kdir = key_dir()
    kdir.mkdir(parents=True, exist_ok=True)
    priv_path = kdir / f"{role}.key"
    pub_path = kdir / f"{role}.pub"
    if priv_path.exists():
        try:
            raw = bytes.fromhex(priv_path.read_text().strip())
            if len(raw) == 32:
                pub = ed25519_public_key(raw)
                if pub_path.exists() and pub_path.read_bytes().strip() != pub.hex().encode():
                    pub_path.write_bytes(pub.hex().encode() + b"\n")
                return raw, pub
        except (ValueError, OSError):
            pass
    raw = secrets.token_bytes(32)
    pub = ed25519_public_key(raw)
    # Atomic-ish write with restrictive perms: this is the signing key.
    fd = os.open(str(priv_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (raw.hex() + "\n").encode())
    finally:
        os.close(fd)
    os.chmod(str(priv_path), 0o600)
    pub_path.write_text(pub.hex() + "\n")
    os.chmod(str(pub_path), 0o644)
    return raw, pub


def _ensure_principal(role: str) -> tuple[bytes, bytes, str]:
    """Load a local key and publish its public keys to the hub (once).

    Publishes BOTH the Ed25519 signing key and the X25519 encryption key used by
    the P2P relay — without the latter nobody can encrypt to this principal and
    messages would silently fail to decrypt much later. Registration is
    idempotent (the principal id derives from the key), so we cache it.
    """
    priv, pub = load_or_create_key(role)
    pid = _principal_id(pub)
    # The cache value records that the P2P key went up too; an older cache entry
    # from before this feature existed must trigger a re-register.
    cache_val = f"{pid}|p2p"
    st = read_state()
    if st.get(f"principal_{role}") != cache_val:
        code, resp = do_http("POST", "/api/attest/principal",
                             body={"public_key": base64.b64encode(pub).decode(),
                                   "p2p_public_key": base64.b64encode(
                                       x25519_public_key(p2p_seed_from_signing_key(priv))).decode(),
                                   "role": role, "name": socket.gethostname(),
                                   "source": "blnq-cli"}, timeout=20)
        if code in (200, 201):
            st[f"principal_{role}"] = cache_val
            write_state(st)
        elif code == 409 and role != "validator":
            # 409 here means "the key already exists on the hub" (old hubs
            # answered this before the server became idempotent-by-key). We
            # HOLD the private key that proves it's ours, so proceed and
            # sign — otherwise one stale row blocks every speed report from
            # this node forever. Validator roles still fail hard: their 409
            # means one-account-one-vote, which must never be waved through.
            st[f"principal_{role}"] = cache_val
            write_state(st)
        else:
            # Registration failing must not silently skip the attestation —
            # surface it so the caller can log why no run record was filed.
            raise RuntimeError(f"principal registration failed: http {code} {resp}")
    return priv, pub, pid


def submit_run_record(run_id: str, status: str, exit_code, duration_ms: int,
                      cpu_ms: int = 0, bytes_in: int = 0, bytes_out: int = 0,
                      peak_rss_kb: int = 0, source_sha256: str | None = None) -> dict | None:
    """Sign and file a run.record — the runner's own account of what happened.

    Signed with THIS machine's runner key, so the hub can relay the claim but
    cannot author it. Filing it is what meters compute into the leaderboard and
    the lyrz ledger; the hub dedupes on run_id, so a retry cannot double-pay.
    """
    try:
        priv, pub, pid = _ensure_principal("runner")
    except Exception as e:
        warn(f"run record skipped (no runner principal): {e}")
        return None
    subject = hashlib.sha256(str(run_id).encode("utf-8")).hexdigest()
    envelope = build_envelope(
        "run.record", subject, pid,
        {
            "run_id": str(run_id),
            "status": status,
            "exit_code": 0 if exit_code is None else int(exit_code),
            "duration_ms": max(0, int(duration_ms)),
            "cpu_ms": max(0, int(cpu_ms)),
            "peak_rss_kb": max(0, int(peak_rss_kb)),
            "bytes_in": max(0, int(bytes_in)),
            "bytes_out": max(0, int(bytes_out)),
            "reported_at": int(time.time()),
            # WHICH code ran. Without this a signed "a run happened" proves nothing
            # about the content — and ranking runners by "safe scripts" would be
            # a guess dressed up as a metric.
            "source_sha256": source_sha256 or None,
        },
    )
    signature = sign_envelope(envelope, priv)
    code, resp = do_http("POST", "/api/attest",
                         body={"envelope": envelope, "signature": signature,
                               "run_id": str(run_id)}, timeout=20)
    if code == 409:
        # Already attested by this runner — that is the idempotency guard
        # working, not a failure. Return quietly so retries stay calm.
        return {"attestation_id": None, "lyrz": None, "run_id": str(run_id), "already": True}
    if code not in (200, 201):
        warn(f"run record rejected: http {code}")
        return None
    if isinstance(resp, dict):
        d = resp.get("data", resp)
        led = d.get("ledger") or {}
        return {"attestation_id": d.get("attestation_id"),
                "lyrz": led.get("lyrz_delta"), "run_id": led.get("run_id")}
    return None


def _child_cpu_ms(cpu0) -> int:
    """CPU consumed by child processes since cpu0 (os.times snapshot).

    cutime/cstime are the cumulative child user+system seconds; taking the
    delta gives the CPU this job actually burned rather than a wall-clock guess.
    """
    try:
        now = os.times()
        delta = ((now[2] - cpu0[2]) + (now[3] - cpu0[3])) * 1000.0
        return max(0, int(delta))
    except Exception:
        return 0


# ── P2P client (end-to-end encrypted relay) ────────────────────────────
def _p2p_aad(env: dict) -> bytes:
    """AAD binding a ciphertext to its routing metadata.

    Uses _canonical_json so the bytes match api/lib/p2pCrypto.js aadFor() — if
    these ever differ, every message fails to decrypt rather than silently
    decrypting the wrong thing.
    """
    return _canonical_json({
        "v": 1, "from": env["from"], "to": env["to"], "type": env["type"],
        "ts": env["ts"], "nonce": env["nonce"],
    }).encode("utf-8")


def _p2p_headers(method: str, path: str, role: str = "requester") -> dict:
    """Stateless proof of identity for inbox reads (Ed25519, no session).

    The public key identifies the principal (it derives the id), and the
    signature over (method, path, ts, nonce) proves possession of the private
    key — so the hub learns who is reading without being able to impersonate
    them, and no session or shared secret is involved.
    """
    priv, pub, _ = _ensure_principal(role)
    ts = str(int(time.time()))
    nonce = secrets.token_hex(8)
    msg = f"{method.upper()}\n{path}\n{ts}\n{nonce}"
    sig = base64.b64encode(ed25519_sign(msg.encode("utf-8"), priv)).decode("ascii")
    return {"X-P2P-Public": base64.b64encode(pub).decode("ascii"),
            "X-P2P-Ts": ts, "X-P2P-Nonce": nonce, "X-P2P-Sig": sig}


def _peer_p2p_key(peer_pid: str) -> str:
    code, resp = do_http("GET", f"/api/p2p/key/{peer_pid}", timeout=15)
    if code != 200 or not isinstance(resp, dict):
        die(f"cannot fetch P2P key for {peer_pid}: http {code} {resp}")
    return resp["data"]["p2p_public_key"]


def cmd_dm(args) -> None:
    """Send an end-to-end encrypted message to another principal.

    The hub stores only ciphertext plus routing metadata — it cannot read the
    body, re-address it (AAD), forge one (Ed25519) or replay one (nonce).
    """
    peer = str(args.principal).strip()
    if not _is_known_principal_id(peer):
        die(f"recipient must be a principal id (hivv_…), got {peer!r}")

    if getattr(args, "file", None):
        text = Path(args.file).read_text(errors="replace")
    elif args.message:
        text = " ".join(args.message)
    else:
        text = sys.stdin.read()
    if not text:
        die("empty message")

    role = getattr(args, "role", None) or "requester"
    priv, _, pid = _ensure_principal(role)
    shared = x25519(p2p_seed_from_signing_key(priv),
                    base64.b64decode(_peer_p2p_key(peer)))
    sid = "|".join(sorted([pid, peer])).encode("utf-8")
    k_enc, k_mac = p2p_session_keys(shared, sid)

    ts = int(time.time())
    nonce = secrets.token_hex(8)
    env = {"v": 1, "from": pid, "to": peer, "type": "dm", "ts": ts, "nonce": nonce}
    # 16 random bytes per message: with a per-message nonce the HMAC-CTR
    # keystream never repeats for a given key.
    env["ct"] = base64.b64encode(
        aead_encrypt(k_enc, k_mac, secrets.token_bytes(16), text.encode("utf-8"), _p2p_aad(env))
    ).decode("ascii")
    sig = base64.b64encode(
        ed25519_sign(_canonical_json(env).encode("utf-8"), priv)
    ).decode("ascii")
    full = {**env, "sig": sig}

    # Preferred: talk straight to the peer. Only the hub's rendezvous sees any
    # traffic at all, and it carries addresses — never this message.
    if not getattr(args, "relay_only", False) and _p2p_try_direct(role, peer, full):
        ok(f"sent {len(full['ct'])}B to {peer[:16]}… "
           f"\033[32mDIRECT\033[0m (peer online; hub only matched addresses)")
        return

    code, resp = do_http("POST", "/api/p2p/send", body=full, timeout=20)
    if code not in (200, 201) or not isinstance(resp, dict):
        _print(resp, code)
        sys.exit(1)
    d = resp.get("data", resp)
    ok(f"sent {d.get('bytes')}B to {peer[:16]}… (msg {d.get('msg_id')})")
    log("hub holds ciphertext only — it cannot read this message")
    log("direct path unavailable (peer offline or UDP blocked) → used the relay")


def cmd_inbox(args) -> None:
    """Receive and decrypt P2P messages addressed to this principal.

    Listens on BOTH paths at once — a direct UDP socket for peers that are online
    right now, and the relay long-poll for everything else — then deduplicates on
    (from, nonce), because the same message can legitimately arrive either way.

    A message that fails to decrypt is reported and NOT acked: better to leave it
    visible in the inbox than to silently lose it.
    """
    role = getattr(args, "role", None) or "requester"
    wait = max(0, min(int(getattr(args, "wait", 0) or 0), 50))
    relay_only = bool(getattr(args, "relay_only", False))
    _, _, pid = _ensure_principal(role)

    inbox_q: list = []          # messages arriving on the direct path
    listener = None
    if not relay_only:
        listener = _DirectListener(role, lambda env, text: inbox_q.append((env, text)),
                                   log_path=sys.stderr)
        listener.start()
        listener.ready.wait(timeout=3)

    path = f"/api/p2p/inbox?wait={wait}&limit=50"
    hdrs = _p2p_headers("GET", path, role)
    t0 = time.time()
    code, resp = do_http("GET", path, timeout=wait + 30, extra_headers=hdrs)
    if code != 200 or not isinstance(resp, dict):
        if listener:
            listener.stop()
        _print(resp, code)
        sys.exit(1)

    # Hold the direct listener for the REST of the requested window.
    #
    # The relay long-poll returns immediately when there is backlog, and the old
    # code tore the listener down right after — so with any message already
    # queued, direct was never up long enough for the other side to reach us and
    # every send silently fell back to the relay.
    if listener and wait:
        deadline = time.time() + max(0.0, wait - (time.time() - t0))
        while time.time() < deadline:
            if inbox_q:
                break                     # direct delivered — nothing to wait for
            time.sleep(0.2)

    priv, _ = load_or_create_key(role)
    xseed = p2p_seed_from_signing_key(priv)
    seen: set = set()
    got_ids: list = []
    shown = 0

    def emit(env: dict, text: str) -> None:
        nonlocal shown
        key = (env.get("from"), env.get("nonce"))
        if key in seen:
            return
        seen.add(key)
        if getattr(args, "json", False):
            print(json.dumps({"from": env.get("from"), "type": env.get("type"),
                              "ts": env.get("ts"), "text": text}))
        else:
            print(f"\033[36m[{time.strftime('%H:%M:%S')}] "
                  f"{(env.get('from') or '?')[:18]}…\033[0m {text}")
        shown += 1

    for m in (resp.get("data") or {}).get("messages") or []:
        env = m.get("envelope") or {}
        got_ids.append(m.get("msg_id"))
        try:
            peer_x = m.get("from_p2p_key")
            if not peer_x:
                warn(f"{m.get('msg_id')}: sender published no P2P key")
                continue
            shared = x25519(xseed, base64.b64decode(peer_x))
            # Same sorted-pair session id as cmd_dm, so both sides agree without
            # either having to say who started the conversation.
            sid = "|".join(sorted([pid, env.get("from", "")])).encode("utf-8")
            k_enc, k_mac = p2p_session_keys(shared, sid)
            pt = aead_decrypt(k_enc, k_mac, base64.b64decode(env.get("ct") or ""),
                              _p2p_aad(env))
            if pt is None:
                # Do NOT ack: an undecryptable message staying in the inbox is
                # better than one silently vanishing.
                warn(f"{m.get('msg_id')}: DECRYPT FAILED from {env.get('from')} "
                     f"(not acked — left in inbox)")
                continue
            emit(env, pt.decode("utf-8", "replace"))
        except Exception as e:
            warn(f"{m.get('msg_id')}: handle failed: {e}")

    for env, text in inbox_q:
        emit(env, text)

    if listener:
        listener.stop()

    if got_ids:
        do_http("POST", "/api/p2p/ack", body={"ids": got_ids}, timeout=15,
                extra_headers=_p2p_headers("POST", "/api/p2p/ack", role))
    if shown or got_ids:
        log(f"{shown} message(s) shown, {len(got_ids)} relay message(s) acked")
    elif wait:
        log("no messages (waited)")
    else:
        log("inbox empty")


# ── direct transport (UDP hole punch, relay fallback) ──────────────────
# Preferred path: the two peers talk to each other and the hub carries nothing
# but a few address-matching datagrams. If the rendezvous times out — restrictive
# NAT, closed UDP port, peer offline — we fall back to the E2E relay, so a
# failure here degrades the *route*, never the delivery or the confidentiality.
P2P_UDP_PORT = int(os.environ.get("BLNQ_P2P_UDP_PORT", "3094"))
# One datagram must survive base64 + JSON overhead and a conservative MTU.
P2P_DIRECT_MAX = 1100
P2P_DIRECT_TIMEOUT = float(os.environ.get("BLNQ_P2P_DIRECT_TIMEOUT", "3"))


def _hub_host() -> str | None:
    try:
        return urllib.parse.urlparse(HUB).hostname or None
    except Exception:
        return None


def _rendezvous_endpoint(role: str = "requester") -> tuple[str, int] | None:
    """Where the UDP rendezvous actually lives.

    Never derived from HUB: blnq.org is Cloudflare-fronted and Cloudflare does
    not carry our UDP port, so resolving HUB would point every peer at a black
    hole. The hub tells us the origin address instead, cached so the common case
    costs no extra round trip.
    """
    # Operator/test override wins over everything, and is deliberately not
    # cached — a test that points at a different rendezvous must not poison the
    # hour-long cache for the real one.
    env_host = os.environ.get("BLNQ_P2P_RENDEZVOUS_HOST")
    if env_host:
        return env_host, int(os.environ.get("BLNQ_P2P_UDP_PORT", str(P2P_UDP_PORT)))

    cache_key = "p2p_rendezvous"
    st = read_state()
    cached = st.get(cache_key)
    if isinstance(cached, dict) and cached.get("host") and time.time() - cached.get("at", 0) < 3600:
        return cached["host"], int(cached["port"])
    host, port = None, P2P_UDP_PORT
    try:
        code, resp = do_http("GET", "/api/p2p/config", timeout=10)
        if code == 200 and isinstance(resp, dict):
            d = resp.get("data") or {}
            host = d.get("rendezvous_host") or None
            port = int(d.get("rendezvous_port") or P2P_UDP_PORT)
    except Exception:
        pass
    if not host:
        return None
    st[cache_key] = {"host": host, "port": port, "at": int(time.time())}
    write_state(st)
    return host, port


def _p2p_conn_id(recipient_pid: str) -> str:
    """Rendezvous connection id.

    It has to be derivable by the SENDER alone, because the listener cannot know
    in advance who will contact it — so it is the recipient's principal id, which
    the sender already knows. Consequence (documented, not hidden): a third party
    can squat someone's rendezvous slot and force that pair back onto the relay.
    They cannot read or inject anything — the data plane is still AEAD + Ed25519.
    """
    return recipient_pid


def _udp_rendezvous(conn_id: str, pid: str, timeout_s: float, sock) -> str | None:
    """Ask the hub who we can reach directly. Returns 'ip:port' or None."""
    ep = _rendezvous_endpoint()
    if not ep:
        return None
    hub, port = ep
    msg = json.dumps({"t": "bind", "c": conn_id, "p": pid, "v": 1}).encode("utf-8")
    deadline = time.time() + timeout_s
    sent_at = 0.0
    while time.time() < deadline:
        if time.time() - sent_at > 1.0:      # re-send: UDP drops datagrams
            try:
                sock.sendto(msg, (hub, port))
            except OSError:
                return None
            sent_at = time.time()
        try:
            sock.settimeout(max(0.2, min(1.0, deadline - time.time())))
            data, _ = sock.recvfrom(2048)
        except (socket.timeout, TimeoutError, OSError):
            continue
        try:
            m = json.loads(data.decode("utf-8"))
        except Exception:
            continue
        t = m.get("t")
        if t == "peer":
            peer = m.get("peer")
            if isinstance(peer, str) and ":" in peer:
                return peer
        elif t == "err":
            return None
    return None


def _p2p_try_direct(role: str, peer_pid: str, envelope: dict,
                    timeout_s: float | None = None) -> bool:
    """Deliver over a direct UDP path. Returns True only if the peer ACKed.

    Returning False is not an error — the caller falls back to the relay. We only
    claim success on an explicit application-level ack, because UDP delivery
    provides no signal of its own.
    """
    timeout_s = P2P_DIRECT_TIMEOUT if timeout_s is None else timeout_s
    if len(json.dumps(envelope)) > P2P_DIRECT_MAX:
        return False                      # too big for one datagram → relay
    try:
        _, _, pid = _ensure_principal(role)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except Exception:
        return False
    try:
        sock.bind(("", 0))
        sock.settimeout(0.3)
        peer_addr = _udp_rendezvous(_p2p_conn_id(peer_pid), pid, timeout_s, sock)
        if not peer_addr:
            return False
        host, _, port = peer_addr.rpartition(":")
        if not host or not port.isdigit():
            return False
        target = (host, int(port))
        payload = json.dumps({"t": "msg", "e": envelope}).encode("utf-8")

        for _ in range(2):                 # at most two attempts
            try:
                sock.sendto(payload, target)
            except OSError:
                return False
            deadline = time.time() + 1.0
            while time.time() < deadline:
                try:
                    data, _ = sock.recvfrom(2048)
                except (socket.timeout, TimeoutError, OSError):
                    continue
                try:
                    m = json.loads(data.decode("utf-8"))
                except Exception:
                    continue
                if m.get("t") == "ack" and m.get("n") == envelope.get("nonce"):
                    return True
        return False
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


class _DirectListener(threading.Thread):
    """Holds a UDP socket open so peers can reach us directly.

    Runs alongside the relay long-poll; `cmd_inbox` drains both and dedupes on
    (from, nonce), since a message could in principle arrive both ways.
    """

    daemon = True

    def __init__(self, role: str, on_message, log_path=None):
        super().__init__(name="blnq-p2p-direct")
        self.role = role
        self.on_message = on_message
        self.log_path = log_path
        self._stop_event = threading.Event()
        self.sock = None
        self.peer_addr = None
        self.ready = threading.Event()

    def stop(self):
        self._stop_event.set()

    def _say(self, msg):
        if self.log_path:
            try:
                print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=self.log_path, flush=True)
            except Exception:
                pass

    def run(self):
        try:
            priv, _, pid = _ensure_principal(self.role)
        except Exception as e:
            self._say(f"direct listener not started: {e}")
            return
        xseed = p2p_seed_from_signing_key(priv)
        ep = _rendezvous_endpoint(self.role)
        if not ep:
            self._say("direct listener not started: no rendezvous endpoint")
            return
        hub, port = ep
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(("", 0))
            self.sock.settimeout(1.0)
        except OSError as e:
            self._say(f"direct socket failed: {e}")
            return
        if os.environ.get("BLNQ_P2P_DEBUG"):
            self._say(f"listener local socket = {self.sock.getsockname()} rendezvous={hub}:{port}")
        self.ready.set()
        last_bind = 0.0
        try:
            while not self._stop_event.is_set():
                if time.time() - last_bind > 15:   # keep the NAT mapping alive
                    try:
                        self.sock.sendto(
                            json.dumps({"t": "bind", "c": _p2p_conn_id(pid),
                                        "p": pid, "v": 1}).encode("utf-8"),
                            (hub, port))
                    except OSError:
                        pass
                    last_bind = time.time()
                try:
                    data, addr = self.sock.recvfrom(4096)
                except (socket.timeout, TimeoutError):
                    continue
                except OSError:
                    break
                try:
                    m = json.loads(data.decode("utf-8"))
                except Exception:
                    continue
                t = m.get("t")
                if os.environ.get("BLNQ_P2P_DEBUG"):
                    self._say(f"recv t={t} from={addr} payload={ {k: v for k, v in m.items() if k != 'peer'} }")
                if t == "peer":
                    self.peer_addr = m.get("peer")
                    continue
                if t != "msg":
                    continue
                env = m.get("e")
                if not isinstance(env, dict):
                    continue
                try:
                    peer_x = _peer_p2p_key(env.get("from", ""))
                    shared = x25519(xseed, base64.b64decode(peer_x))
                    sid = "|".join(sorted([pid, env.get("from", "")])).encode("utf-8")
                    k_enc, k_mac = p2p_session_keys(shared, sid)
                    pt = aead_decrypt(k_enc, k_mac,
                                      base64.b64decode(env.get("ct") or ""),
                                      _p2p_aad(env))
                except Exception:
                    pt = None
                if pt is None:
                    # Never ack something we could not authenticate: that would
                    # let a forged datagram suppress a real one.
                    self._say(f"direct: dropped undecryptable datagram from {env.get('from')}")
                    continue
                try:
                    self.sock.sendto(
                        json.dumps({"t": "ack", "n": env.get("nonce")}).encode("utf-8"),
                        addr)
                except OSError:
                    pass
                try:
                    self.on_message(env, pt.decode("utf-8", "replace"))
                except Exception as e:
                    self._say(f"direct: handler error: {e}")
        finally:
            try:
                self.sock.close()
            except Exception:
                pass

def cmd_p2p(args) -> None:
    """Diagnose the direct transport and show this machine's P2P identity."""
    action = getattr(args, "action", None) or "status"
    role = getattr(args, "role", None) or "requester"

    try:
        priv, pub, pid = _ensure_principal(role)
    except Exception as e:
        die(f"cannot load identity: {e}")
    xpub = x25519_public_key(p2p_seed_from_signing_key(priv))

    _title("p2p doctor", "identity + direct-transport diagnosis")
    print()
    print(f"  {_hdr('identity')}")
    _kv("principal", pid)
    _kv("signing", f"ed25519   {_key_fingerprint(pub)}")
    _kv("encryption", f"x25519    {_key_fingerprint(xpub)}")
    _kv("pubkey sign", base64.b64encode(pub).decode())
    _kv("pubkey p2p", base64.b64encode(xpub).decode())

    print()
    print(f"  {_hdr('endpoint')}")
    _kv("hub", HUB)

    ep = _rendezvous_endpoint(role)
    if not ep:
        _kv("rendezvous", "\033[31mnot published by the hub\033[0m")
        _hint("set BLNQ_P2P_RENDEZVOUS_HOST or api/.p2p.json on the hub")
        return
    hub, rport = ep
    _kv("rendezvous", f"udp/{rport} at {hub}   (timeout {P2P_DIRECT_TIMEOUT}s)")

    if action not in ("status", "doctor"):
        return

    print()
    print(f"  {_hdr('diagnosis')}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("", 0))
        sock.settimeout(3.0)
        # Self-rendezvous: nobody else is bound to a conn named after our own id,
        # so we only expect {t:"you"} back. Getting it at all proves the UDP path
        # to the hub works end to end.
        got_you = None
        t0 = time.time()
        deadline = t0 + 3.0
        while time.time() < deadline:
            try:
                sock.sendto(json.dumps({"t": "bind", "c": pid, "p": pid,
                                        "v": 1}).encode("utf-8"), (hub, rport))
            except OSError as e:
                _kv("verdict", f"\033[31m✗ cannot send\033[0m")
                _hint(f"socket error: {e}")
                return
            try:
                data, _ = sock.recvfrom(2048)
            except (socket.timeout, TimeoutError, OSError):
                continue
            try:
                m = json.loads(data.decode("utf-8"))
            except Exception:
                continue
            if m.get("t") == "you":
                got_you = (m.get("addr"), int((time.time() - t0) * 1000))
                break
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if got_you:
        _kv("verdict", f"\033[32m✓ reachable in {got_you[1]} ms\033[0m  observed as {got_you[0]}")
        _hint("direct peering available — the other peer must be online at the same time")
        _hint("relay still works either way, and stays end-to-end encrypted")
    else:
        _kv("verdict", "\033[31m✗ rendezvous not reachable\033[0m")
        _hint("traffic uses the E2E relay — messages stay end-to-end encrypted")
        _hint(f"open UDP {rport} inbound to {hub} to enable direct peering")
        _hint(f"check with: {APP} p2p doctor   (from another machine)")


# ── HTTP helper (with optional cookie jar + bearer token) ──────────────
def _hub_is_loopback_http() -> bool:
    """True when the CLI points at a PLAIN-HTTP loopback origin — the local
    hub setup (tests/cli_smoke.sh sets BLNQ_HUB=http://127.0.0.1:3099).

    Production hubs mark session cookies `Secure` (isSecureCookie() =
    isProduction()), and express-session then refuses to emit Set-Cookie
    unless it believes the connection is TLS. Behind the real proxy that
    belief comes from X-Forwarded-Proto; against a loopback origin we
    declare it ourselves (do_http) and treat Secure cookies as sendable
    (the policy in _opener) — otherwise `blnq login` against the local hub
    can never complete: the cookie is either never issued or http.cookiejar
    declines to send it back over http.

    Remote plaintext origins are NOT included: auth there must fail loudly,
    and we never claim TLS to a host we don't control."""
    return HUB.startswith(("http://127.0.0.1", "http://localhost", "http://[::1]"))


class _LoopbackSecureCookiePolicy(cookiejar.DefaultCookiePolicy):
    """Return Secure-flagged cookies on loopback http. Attached exclusively
    when _hub_is_loopback_http(). Receiving already works (set_ok has no
    secure check — CookieJar stores the cookie; only SENDING refuses a
    Secure cookie over http, via return_ok_secure, which is what this
    overrides). See _hub_is_loopback_http for why that is safe here."""

    def return_ok_secure(self, cookie, request=None):
        return True


def _opener() -> urllib.request.OpenerDirector:
    cj = cookiejar.MozillaCookieJar(str(COOKIE_FILE))
    if COOKIE_FILE.exists():
        try: cj.load(ignore_discard=True, ignore_expires=True)
        except OSError: pass
    if _hub_is_loopback_http():
        cj.set_policy(_LoopbackSecureCookiePolicy())
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

_OPENER = None
def opener() -> urllib.request.OpenerDirector:
    global _OPENER
    if _OPENER is None:
        ensure_dirs()
        _OPENER = _opener()
    return _OPENER

def _auth_rejected() -> bool:
    try:
        return bool((read_state() or {}).get("auth_rejected"))
    except Exception:
        return False

def _mark_auth_rejected(v: bool = True) -> None:
    try:
        st = read_state() or {}
        st["auth_rejected"] = bool(v)
        st["auth_rejected_at"] = int(time.time())
        write_state(st)
    except OSError:
        pass

def do_http(method: str, path: str, *, body=None, token: str | None = None,
         timeout: float = 15.0, save_cookies: bool = True, sign: bool = True,
         allow_degrade: bool = True, content_type: str | None = None,
         extra_headers: dict | None = None) -> tuple[int, dict | str]:
    """Auth + signed request with graceful degrade.
    If the hub returns 401/403 for Authorization, retry once without auth and
    remember via state.auth_rejected=True so we don't re-send every call."""
    url = HUB.rstrip("/") + path
    headers = {"user-agent": f"{APP}/{VERSION}", "accept": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    if _hub_is_loopback_http():
        # See _hub_is_loopback_http: production hubs only issue the session
        # cookie when Express believes the connection is TLS. The real
        # proxy supplies X-Forwarded-Proto; the loopback origin has no proxy,
        # so we supply it (trust proxy = 1 hop on the hub).
        headers.setdefault("X-Forwarded-Proto", "https")
    if token is None:
        try: token = _get_or_create_auth_token()
        except OSError: token = None
    use_auth = bool(token) and not _auth_rejected() and sign
    data = None
    if body is not None:
        if isinstance(body, (bytes, bytearray)):
            data = bytes(body)
            headers["content-type"] = content_type or "application/gzip"
        elif isinstance(body, dict) and all(isinstance(v, str) for v in body.values()) and not use_auth:
            data = urllib.parse.urlencode(body).encode()
            headers["content-type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode()
            headers["content-type"] = "application/json"
    if use_auth:
        headers["authorization"] = f"Bearer {token}"
        headers.update(_signed_headers(method, path, data, token))

    def _do() -> tuple[int, dict | str]:
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with opener().open(req, timeout=timeout) as r:
                raw = r.read().decode("utf-8", errors="replace")
                try: return r.status, json.loads(raw)
                except json.JSONDecodeError: return r.status, raw
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace") if e.fp else ""
            try: return e.code, json.loads(raw)
            except json.JSONDecodeError: return e.code, raw
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
            return 0, f"network error: {e}"

    code, payload = _do()
    if allow_degrade and use_auth and code in (401, 403):
        # one-shot retry without auth headers (some proxies strip Authorization).
        # NOTE: we deliberately do NOT persist auth_rejected anymore — the hub
        # now verifies worker signatures, and a degraded global flag would
        # silently break claims forever.
        headers.pop("authorization", None)
        for h in ("X-Auth-Timestamp", "X-Auth-Nonce", "X-Auth-Signature"):
            headers.pop(h, None)
        return _do()
    return code, payload


# ── pid / metrics ──────────────────────────────────────────────────────
def _pid_alive_win(pid: int) -> bool:
    # os.kill(pid, 0) TERMINATES the process on Windows (TerminateProcess),
    # so probe with an OpenProcess handle instead.
    try:
        import ctypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h: return False
        try:
            code = ctypes.c_ulong()
            if k32.GetExitCodeProcess(h, ctypes.byref(code)):
                return code.value == STILL_ACTIVE
            return True
        finally:
            k32.CloseHandle(h)
    except Exception:
        return False

def pid_alive(pid: int) -> bool:
    if pid <= 0: return False
    if IS_WIN: return _pid_alive_win(pid)
    try: os.kill(pid, 0); return True
    except (ProcessLookupError, PermissionError): return False

def read_pid() -> int | None:
    if not PID_FILE.exists(): return None
    try: pid = int(PID_FILE.read_text().strip())
    except ValueError: return None
    return pid if pid_alive(pid) else None

def _spawn_detached_agent(log_fh) -> subprocess.Popen:
    """Launch the agent as a background process, cross-platform.
    POSIX: new session (detaches from the controlling tty).
    Windows: DETACHED_PROCESS + new process group (start_new_session raises there)."""
    argv = [sys.executable, str(Path(__file__).resolve()), "_agent"]
    kw = {"stdout": log_fh, "stderr": subprocess.STDOUT, "stdin": subprocess.DEVNULL}
    if IS_WIN:
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        kw["creationflags"] = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    return subprocess.Popen(argv, **kw)

def _terminate_pid(pid: int, graceful_timeout_s: float = 5.0) -> bool:
    """Stop a pid cross-platform. POSIX: SIGTERM → wait → SIGKILL.
    Windows: no SIGTERM delivery, so write the stop-file the loop polls,
    wait, then taskkill /T /F the tree as fallback."""
    if not pid_alive(pid): return True
    if IS_WIN:
        try: STOP_FILE.write_text(str(int(time.time())))
        except OSError: pass
        deadline = time.time() + graceful_timeout_s
        while time.time() < deadline and pid_alive(pid): time.sleep(0.1)
        if not pid_alive(pid): return True
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True, timeout=10)
        except Exception: pass
        return not pid_alive(pid)
    try: os.kill(pid, signal.SIGTERM)
    except ProcessLookupError: return True
    deadline = time.time() + graceful_timeout_s
    while time.time() < deadline and pid_alive(pid): time.sleep(0.1)
    if pid_alive(pid):
        try: os.kill(pid, signal.SIGKILL)
        except ProcessLookupError: pass
    return not pid_alive(pid)


# ── update helpers (atomic swap + rollback + healthcheck) ───────────────
def _parse_ver(s) -> tuple:
    """Parse '0.2.3' (or any string with embedded numbers) into (0,2,3).
    Tolerant of prefixes/suffixes. Returns (0,) on empty/no-digits."""
    if not s: return (0,)
    parts = re.findall(r"\d+", str(s))
    return tuple(int(p) for p in parts[:3]) if parts else (0,)

def _atomic_write(path: Path, data: bytes) -> None:
    """Atomic write: tempfile + fsync + chmod + os.replace into place.
    (shutil.move errors on Windows when dest exists; os.replace is atomic.)"""
    tmp = tempfile.NamedTemporaryFile("wb", delete=False, dir=str(path.parent))
    try:
        tmp.write(data); tmp.flush(); os.fsync(tmp.fileno()); tmp.close()
        os.chmod(tmp.name, 0o644); os.replace(tmp.name, path)
    finally:
        if os.path.exists(tmp.name):
            try: os.unlink(tmp.name)
            except OSError: pass

def _apply_update(data: bytes, expected_sha256=None, source: str = "") -> tuple:
    """Atomic swap with rollback. Returns (ok: bool, msg: str, target: Path).

    Steps:
      1. Verify SHA256 (if provided).
      2. Backup current → <target>.bak (only if .bak doesn't already exist;
         preserve the last known-good across re-attempts).
      3. Write new → <target>.new.
      4. Healthcheck: spawn `python3 <target>.new --healthcheck` (timeout 10s).
         Exit 0 → atomic rename .new → target.
         Non-zero / timeout → rename .new → .bad, restore .bak → target.
    Never raises.
    """
    target = INSTALL_DIR / f"{APP}-cli.py"
    if not target.exists(): target = Path(__file__).resolve()
    bak = target.with_suffix(target.suffix + ".bak")
    bad = target.with_suffix(target.suffix + ".bad")
    new = target.with_suffix(target.suffix + ".new")
    try:
        if expected_sha256:
            actual = hashlib.sha256(data).hexdigest()
            if actual.lower() != expected_sha256.lower():
                return (False, f"sha256 mismatch (got {actual[:12]}…, want {expected_sha256[:12]}…)", target)
        if target.exists() and not bak.exists():
            shutil.copy2(target, bak)
        _atomic_write(new, data)
        proc = subprocess.run(
            [sys.executable, str(new), "--healthcheck"],
            capture_output=True, timeout=10,
        )
        if proc.returncode != 0:
            # Preserve the FAILED new file as .bad for inspection.
            try: shutil.move(str(new), str(bad))
            except OSError: pass
            if bak.exists():
                try: shutil.copy2(bak, target)
                except OSError: pass
            return (False, f"healthcheck failed (rc={proc.returncode}, source={source})", target)
        os.replace(new, target)
        return (True, f"applied (source={source})", target)
    except Exception as e:
        return (False, f"unexpected: {e}", target)

def _http_get_bytes(url: str, timeout: float = 30.0) -> bytes:
    """GET a URL and return raw bytes. Stdlib only; sets user-agent.
    Resolves relative URLs (e.g. '/blnq-cli.py') against HUB."""
    from urllib.parse import urljoin
    full = url if "://" in url else urljoin(HUB.rstrip("/") + "/", url.lstrip("/"))
    req = urllib.request.Request(full, headers={"user-agent": f"{APP}/{VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

_VERSION_TTL_S = 6 * 3600   # don't re-ask a working hub on every command
_VERSION_FAIL_TTL_S = 60    # …but retry a failing one soon, without hammering


def _hub_version() -> tuple:
    """(version, sha256) from the hub, cached. Returns (None, None) on failure.

    Uses _http_get_bytes, NOT bare urlopen: Cloudflare returns 403 to the
    default `Python-urllib/3.11` agent, and the old implementation swallowed
    that in `except: pass` — so the version nag had never fired for anyone.

    A version check must never be able to break a command, hence the (None, None)
    contract rather than raising.
    """
    st = read_state()
    now = int(time.time())
    cached_ver = st.get("hub_version")
    ttl = _VERSION_TTL_S if cached_ver else _VERSION_FAIL_TTL_S
    if now - int(st.get("version_check_at") or 0) < ttl:
        return cached_ver, st.get("hub_sha256")
    try:
        meta = json.loads(_http_get_bytes(f"{HUB.rstrip('/')}/api/version", timeout=3))
        if not isinstance(meta, dict):
            raise ValueError("not an object")
        ver, sha = meta.get("version"), meta.get("sha256")
    except Exception:
        ver, sha = None, None
    st["version_check_at"], st["hub_version"], st["hub_sha256"] = now, ver, sha
    try:
        write_state(st)
    except Exception:
        pass
    return ver, sha


def _nag_if_behind(async_ok: bool = True) -> None:
    """Tell the user a newer CLI exists. Never blocks, never raises.

    Runs on a daemon thread by default so latency-sensitive commands (run,
    status, doctor) don't pay for it — and so the nag itself can't fail them.
    Auto-update deliberately does NOT happen here: see _maybe_auto_update().
    """
    def _go() -> None:
        try:
            hub_ver, _ = _hub_version()
            if not hub_ver or _parse_ver(hub_ver) <= _parse_ver(VERSION):
                return
            hint = ("" if os.environ.get("BLNQ_AUTO_UPDATE")
                    else f" — run: \033[1;36m{APP} update\033[0m"
                         f" (or set BLNQ_AUTO_UPDATE=1 to do it automatically)")
            sys.stderr.write(
                f"\033[1;33m[{APP}]\033[0m hub v{hub_ver} is available "
                f"(you're on v{VERSION}){hint}\n"
            )
        except Exception:
            pass
    if async_ok:
        try:
            threading.Thread(target=_go, daemon=True, name=f"{APP}-version").start()
            return
        except Exception:
            pass
    _go()


def _maybe_auto_update(argv: list) -> None:
    """Opt-in self-update (BLNQ_AUTO_UPDATE=1), checked BEFORE any command runs.

    Opt-in on purpose. Silently swapping executable code on someone else's
    machine is exactly the kind of unchecked change the trust layer exists to
    prevent — so the default is to TELL you, not to do it. Two guards keep it
    sane: it never fights the command you asked for, and BLNQ_AUTO_UPDATED stops
    a broken hub from putting us in a re-exec loop.
    """
    if not os.environ.get("BLNQ_AUTO_UPDATE") or os.environ.get("BLNQ_AUTO_UPDATED"):
        return
    if not argv or argv[0] in ("update", "upgrade", "uninstall", "_agent",
                               "healthcheck", "--healthcheck", "--version",
                               "-h", "--help", "help"):
        return
    try:
        hub_ver, hub_sha = _hub_version()
        if not hub_ver or _parse_ver(hub_ver) <= _parse_ver(VERSION):
            return
        log(f"auto-update: hub v{hub_ver} > local v{VERSION} — updating")
        data = _http_get_bytes(f"{HUB.rstrip('/')}/{APP}-cli.py", timeout=30)
        updated, msg, target = _apply_update(data, expected_sha256=hub_sha,
                                             source="auto")
        if not updated:
            warn(f"auto-update skipped: {msg} — continuing on v{VERSION}")
            return
        ok(f"{msg} → restarting as v{hub_ver}")
        env = dict(os.environ); env["BLNQ_AUTO_UPDATED"] = "1"
        os.execve(sys.executable, [sys.executable] + sys.argv, env)
    except SystemExit:
        raise
    except Exception as e:
        # Never let a failed upgrade take the user's actual command down with it.
        warn(f"auto-update failed ({e}) — continuing on v{VERSION}")


def _meminfo_kb() -> dict:
    out = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, _, v = line.partition(":"); out[k.strip()] = v.strip().split()[0]
    except OSError: pass
    return out

def _disk(path: str) -> str:
    try:
        du = shutil.disk_usage(path)
        total, used = du.total, du.used
        def h(b): return f"{b/1024/1024/1024:.1f}G"
        return f"{h(used)}/{h(total)} ({(used*100/max(1,total)):.0f}%)"
    except OSError: return "?"

def _win_mem_mb() -> tuple[int, int] | None:
    """(total_mb, avail_mb) via kernel32.GlobalMemoryStatusEx — stdlib ctypes."""
    try:
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_uint32), ("dwMemoryLoad", ctypes.c_uint32),
                        ("ullTotalPhys", ctypes.c_uint64), ("ullAvailPhys", ctypes.c_uint64),
                        ("ullTotalPageFile", ctypes.c_uint64), ("ullAvailPageFile", ctypes.c_uint64),
                        ("ullTotalVirtual", ctypes.c_uint64), ("ullAvailVirtual", ctypes.c_uint64),
                        ("ullAvailExtendedVirtual", ctypes.c_uint64)]
        st = MEMORYSTATUSEX(); st.dwLength = ctypes.sizeof(st)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)): return None
        return (st.ullTotalPhys // (1024 * 1024), st.ullAvailPhys // (1024 * 1024))
    except Exception:
        return None

def _win_uptime_s() -> int | None:
    try:
        import ctypes
        return int(ctypes.windll.kernel32.GetTickCount64() // 1000)
    except Exception:
        return None

def _process_rss_kb(pid: int) -> int | None:
    if IS_WIN:
        try:
            import ctypes
            class PMC(ctypes.Structure):
                _fields_ = [("cb", ctypes.c_uint32), ("PageFaultCount", ctypes.c_uint32),
                            ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
            k32 = ctypes.windll.kernel32
            get_info = getattr(k32, "GetProcessMemoryInfo", None) or ctypes.windll.psapi.GetProcessMemoryInfo
            h = k32.OpenProcess(0x1400, False, pid)  # QUERY_LIMITED | VM_READ
            if not h: return None
            try:
                pmc = PMC(); pmc.cb = ctypes.sizeof(PMC)
                if get_info(h, ctypes.byref(pmc), pmc.cb):
                    return pmc.WorkingSetSize // 1024
                return None
            finally:
                k32.CloseHandle(h)
        except Exception:
            return None
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"): return int(line.split()[1])
    except OSError: return None
    return None

def _gpu_info(timeout: float = 3.0) -> list:
    """Return [{index, name, mem_total_mb, mem_used_mb, util_pct, temp_c}] via nvidia-smi.
    Empty list if no NVIDIA GPU or nvidia-smi missing. Never raises."""
    try:
        import subprocess
        r = subprocess.run(
            ["nvidia-smi",
             "--query-gpu=index,name,memory.total,memory.used,utilization.gpu,temperature.gpu",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []
    if r.returncode != 0 or not r.stdout.strip():
        return []
    gpus = []
    for line in r.stdout.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 6: continue
        try:
            gpus.append({"index": int(parts[0]), "name": parts[1],
                         "mem_total_mb": int(parts[2]), "mem_used_mb": int(parts[3]),
                         "util_pct": int(parts[4]), "temp_c": int(parts[5])})
        except ValueError: continue
    return gpus

def _collect_metrics() -> dict:
    """Single-pass snapshot of system state for the heartbeat payload. Stdlib only."""
    m = {"ts": int(time.time()), "sandbox": _sandbox_tier()}
    try:
        la = os.getloadavg()
        m["load_1"], m["load_5"], m["load_15"] = (round(x, 2) for x in la)
    except (OSError, AttributeError): pass
    try: m["cpu_count"] = os.cpu_count()
    except Exception: pass
    try:
        mi = _meminfo_kb()
        total = int(mi.get("MemTotal", 0)); avail = int(mi.get("MemAvailable", 0))
        if not total and IS_WIN:
            wm = _win_mem_mb()
            if wm: total, avail = wm[0] * 1024, wm[1] * 1024
        if total:
            m["mem_total_mb"] = total // 1024
            m["mem_avail_mb"] = avail // 1024
            m["mem_used_mb"] = (total - avail) // 1024
            m["mem_pct"] = round((total - avail) * 100 / total, 1)
        swap_total = int(mi.get("SwapTotal", 0)); swap_free = int(mi.get("SwapFree", 0))
        if swap_total:
            m["swap_total_mb"] = swap_total // 1024
            m["swap_used_mb"] = (swap_total - swap_free) // 1024
    except (OSError, ValueError): pass
    try:
        du = shutil.disk_usage("/")
        total = du.total; free = du.free
        if total:
            m["disk_total_gb"] = round(total / 1024**3, 1)
            m["disk_free_gb"] = round(free / 1024**3, 1)
            m["disk_used_gb"] = round((total - free) / 1024**3, 1)
            m["disk_pct"] = round((total - free) * 100 / total, 1)
    except (OSError, AttributeError): pass
    try:
        with open("/proc/uptime") as f:
            m["uptime_s"] = int(float(f.read().split()[0]))
    except (OSError, ValueError, IndexError): pass
    if "uptime_s" not in m and IS_WIN:
        up = _win_uptime_s()
        if up is not None: m["uptime_s"] = up
    gpus = _gpu_info()
    if gpus:
        m["gpus"] = gpus
        m["gpu_count"] = len(gpus)
        m["gpu_mem_used_mb"] = sum(g["mem_used_mb"] for g in gpus)
        m["gpu_util_pct"] = round(sum(g["util_pct"] for g in gpus) / len(gpus), 1)
    return m

def _print_metrics_local(m: dict) -> None:
    def pct(v): return f"{v}%" if v is not None else "?"
    def mb(v):  return f"{v} MB" if v is not None else "?"
    print(f"\033[1m{APP} bee metrics\033[0m — local snapshot (ts={m.get('ts')})")
    print(f"  cpu:    {m.get('cpu_count','?')} cores   load: {m.get('load_1','?')} / {m.get('load_5','?')} / {m.get('load_15','?')}")
    print(f"  mem:    {mb(m.get('mem_used_mb'))} / {mb(m.get('mem_total_mb'))} ({pct(m.get('mem_pct'))})")
    if m.get("swap_total_mb"):
        print(f"  swap:   {mb(m.get('swap_used_mb'))} / {mb(m.get('swap_total_mb'))}")
    print(f"  disk:   {m.get('disk_used_gb','?')}G / {m.get('disk_total_gb','?')}G ({pct(m.get('disk_pct'))})")
    if m.get("uptime_s") is not None:
        up = m["uptime_s"]; days, rem = divmod(up, 86400); hrs, rem = divmod(rem, 3600); mins, _ = divmod(rem, 60)
        print(f"  uptime: {days}d {hrs}h {mins}m ({up}s)")
    gpus = m.get("gpus") or []
    if gpus:
        print(f"  gpus:   {len(gpus)}")
        for g in gpus:
            print(f"    [{g['index']}] {g['name']}  util={g['util_pct']}%  mem={g['mem_used_mb']}/{g['mem_total_mb']} MB  temp={g.get('temp_c','?')}°C")
    else:
        print(f"  gpus:   (none detected)")


# ── job runner (volunteer bees execute approved jobs here) ─────────────
_LANG_EXE = {"node": "node", "ruby": "ruby", "perl": "perl",
             "php": "php", "go": "go", "bash": "bash", "sh": "sh"}
_SCRIPT_EXT = {"python": ".py", "node": ".js", "javascript": ".js", "ruby": ".rb",
               "perl": ".pl", "php": ".php", "bash": ".sh", "sh": ".sh",
               "go": ".go", "c": ".c", "cpp": ".cpp", "c++": ".cpp"}
_MAX_OUTPUT_LINES = 5000
_MAX_ARTIFACT_BYTES = 50 * 1024 * 1024
# bwrap/docker fail instantly with these when the jail itself can't start
# (userns exhausted, daemon down…) — distinct from the job's own failure.
_SANDBOX_BOOT_RE = re.compile(
    r"bwrap:|Creating new namespace|Unknown option|"
    r"docker: |Cannot connect to the Docker|no such image|error while loading shared", re.I)

def _platform_tag() -> str:
    return "windows" if IS_WIN else ("macos" if IS_MAC else "linux")

def _os_user() -> str:
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"

def _find_exe(*names) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p: return p
    return None

def _available_languages() -> list:
    """Languages this machine can actually execute right now."""
    langs = ["python"]  # we're literally running a python interpreter
    for lang, exe in _LANG_EXE.items():
        if _find_exe(exe): langs.append(lang)
    if _find_exe("cc", "gcc", "clang", "tcc"): langs.append("c")
    if _find_exe("c++", "g++", "clang++"): langs.append("cpp")
    return sorted(set(langs))

def _job_command(lang: str, script_name: str, code_text: str, jobdir: Path):
    """Resolve (argv, compile_argv|None) for a job, or None if unsupported.
    Code is written to a real file in jobdir (no shell escaping anywhere)."""
    lang = (lang or "python").lower()
    ext = _SCRIPT_EXT.get(lang, ".txt")
    safe = re.sub(r"[^\w.\-]", "_", script_name or "job")
    src = jobdir / (safe if safe.lower().endswith(ext) else safe + ext)
    src.write_text(code_text, encoding="utf-8")
    out = jobdir / ("a.exe" if IS_WIN else "a.out")
    if lang == "python":
        return [sys.executable, "-u", str(src)], None
    if lang in ("c", "cpp"):
        cc = _find_exe("cc", "gcc", "clang", "tcc") if lang == "c" else _find_exe("c++", "g++", "clang++")
        if not cc: return None, None
        return [str(out)], [cc, str(src), "-o", str(out)]
    if lang == "go":
        go = _find_exe("go")
        return ([go, "run", str(src)], None) if go else (None, None)
    exe = _find_exe(_LANG_EXE.get(lang, ""))
    if not exe: return None, None
    return [exe, str(src)], None

def _clean_env() -> dict:
    keep = ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP",
            "HOME", "USERPROFILE", "LANG", "LC_ALL", "PYTHONIOENCODING")
    env = {k: v for k, v in os.environ.items() if k in keep and v}
    env["PYTHONUNBUFFERED"] = "1"   # stream job output even through pipes
    return env

def _redact_secrets(text: str, values: list) -> str:
    """Scrub secret substrings from anything we log/upload (longest first)."""
    for v in values:
        if v and len(v) >= 4:
            text = text.replace(v, "***REDACTED***")
    return text

_SANDBOX_CACHE: dict = {}

# ── bwrap filesystem jail ──────────────────────────────────────────────────
# Audit 2026-11-19: `_BWRAP_BASE` started with `--ro-bind / /`, and jobs run
# as the agent's own uid — so 0600 bought nothing. A job read
# ~/.config/blnq/auth.json and keys/runner.key straight out of the jail and
# printed them; stdout already goes to whoever requested the run, so any
# user's job could exfiltrate this node's hub credentials with no network at
# all (file:// never opens a socket, so the egress proxy would never see it).
#
# The fix inverts the model: bwrap's new root starts EMPTY, and every path a
# job can see is mounted deliberately —
#
#   1. system roots (/usr, /etc, usr-merge links, /dev, /proc, tmpfs /tmp)
#   2. the interpreter's paths, computed from the ACTUAL interpreter the job
#      will exec (python sysconfig/sys.path; other langs: their install
#      prefix) — read-only, and never anything under a secret location
#   3. the job's own directory (read-write), bound LAST so it wins over any
#      tmpfs that covers its path
#   4. surgical tmpfs over any secret dir inside a bound tree (e.g. a
#      ~/.local prefix bind gets ~/.local/share blanked)
#
# $HOME itself is never mounted: the secret dirs list is the belt on top of
# that, for prefix binds that sit inside a home directory.

_BWRAP_SYSTEM = ("/usr", "/etc")
# usr-merged distros (Debian/Ubuntu/Fedora): these are symlinks INTO /usr.
# Recreate the link inside the jail instead of bind-mounting through it.
_BWRAP_USR_MERGE = ("/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32")

def _bwrap_static_args() -> list:
    """Namespaces + system roots. Probed by _bwrap_works() with the SAME
    flags a real job gets (the runtime/jobdir binds are added by
    _bwrap_wrap on top of these)."""
    cached = _SANDBOX_CACHE.get("bwrap_static")
    if cached: return list(cached)
    args = []
    for src in _BWRAP_SYSTEM:
        if os.path.isdir(src) and not os.path.islink(src):
            args += ["--ro-bind", src, src]
        elif os.path.islink(src):
            args += ["--symlink", os.readlink(src), src]
    for src in _BWRAP_USR_MERGE:
        if os.path.islink(src):
            args += ["--symlink", os.readlink(src), src]
        elif os.path.isdir(src):
            args += ["--ro-bind", src, src]
    args += ["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
             "--unshare-all", "--die-with-parent"]
    _SANDBOX_CACHE["bwrap_static"] = list(args)
    return args

def _bwrap_secret_dirs() -> list:
    """Secret locations inside the agent's home. A bound tree that CONTAINS
    one of these gets a tmpfs over it. ($HOME itself is never bound — these
    cover prefix binds like ~/.local or a venv that lives beside them.)"""
    home = os.path.expanduser("~")
    rels = (".config", ".ssh", ".aws", ".gnupg", ".kube", ".docker", ".cache",
            ".local/share", ".local/state", ".npm", ".pki", ".password-store",
            ".mozilla", ".thunderbird", ".vault", ".ansible",
            ".git-credentials", ".netrc", ".npmrc", ".gitconfig")
    return [os.path.join(home, r) for r in rels]

def _p_bind_ok(p: str) -> bool:
    """May this path be mounted into the jail? Deny wins; unknown → deny for
    the sensitive roots, allow for ordinary software prefixes (nvm, /opt
    toolchains, venvs) — their secret subdirs are blanked by tmpfs hides."""
    try:
        p = os.path.abspath(os.path.expanduser(str(p)))
    except Exception:
        return False
    if p == "/" or len(p) < 4:
        return False
    deny_top = ("/var", "/root", "/run", "/srv", "/boot", "/mnt", "/media",
                "/snap", "/proc", "/sys", "/dev", "/tmp", "/etc")
    if any(p == d or p.startswith(d + "/") for d in deny_top):
        return False
    home = os.path.expanduser("~")
    if p == home:
        return False
    # the CLI's own tree (blnq state, job logs, the module we are inside)
    cli_dir = os.path.dirname(os.path.abspath(__file__))
    if p == cli_dir or p.startswith(cli_dir + "/"):
        return False
    state = os.environ.get("BLNQ_STATE_DIR") \
        or os.path.join(home, ".local", "share", "blnq")
    if p == state or p.startswith(state + "/"):
        return False
    for frag in ("/.ssh/", "/.aws/", "/.gnupg/", "/.docker/", "/.config/",
                 "/.git/", "/vhosts/", "/blnq.org/"):
        if (p + "/").find(frag) >= 0:
            return False
    return True

def _bwrap_runtime_args(lang: str, argv: list) -> list:
    """Read-only mounts for the interpreter the job will actually exec, plus
    tmpfs hides for any secret dir that sits inside them. Cached per
    (lang, realpath(exe))."""
    exe = ""
    try:
        exe = os.path.realpath(argv[0]) if argv else ""
    except Exception:
        exe = ""
    key = f"bwrap_rt:{lang}:{exe}"
    cached = _SANDBOX_CACHE.get(key)
    if cached: return list(cached)

    args: list = []
    hides: set = set()
    bound_dirs: set = set()

    def covered(p: str) -> bool:
        """p is inside a path the static args already mount."""
        p = os.path.abspath(p)
        if p == "/usr" or p.startswith("/usr/"): return True
        if p == "/etc" or p.startswith("/etc/"): return True
        return any(p == s or p.startswith(s + "/")
                   for s in ("/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"))

    def add_dir(p: str) -> None:
        try:
            p = os.path.abspath(os.path.expanduser(p))
        except Exception:
            return
        if not p or covered(p) or p in bound_dirs: return
        if not os.path.isdir(p) or not _p_bind_ok(p): return
        args.extend(["--ro-bind", p, p])
        bound_dirs.add(p)
        for s in _bwrap_secret_dirs():
            if (s == p or s.startswith(p + "/")) and os.path.isdir(s):
                hides.add(s)

    if lang == "python" or (exe and exe == os.path.realpath(sys.executable)):
        # Jobs run [sys.executable, …] — the SAME interpreter doing this
        # computation, so its sysconfig/sys.path is exactly what the job
        # will import from.
        import sysconfig
        import site as _site
        cands = set()
        for k in ("stdlib", "platstdlib", "purelib", "platlib", "include",
                  "platinclude", "scripts", "data"):
            try:
                p = sysconfig.get_path(k)
                if p: cands.add(p)
            except Exception:
                pass
        for p in (sys.base_prefix, sys.prefix, sys.exec_prefix,
                  getattr(_site, "USER_BASE", None),
                  getattr(_site, "USER_SITE", None)):
            if p: cands.add(p)
        for p in list(sys.path):          # import roots, NOT '' / relative:
            if p and os.path.isabs(p):    # the job's own cwd is jobdir
                cands.add(p)
        for p in sorted(cands, key=len):
            add_dir(p)
        if exe and not covered(exe) and os.path.isfile(exe) and _p_bind_ok(exe):
            if not any(exe.startswith(d + "/") for d in bound_dirs):
                args.extend(["--ro-bind", exe, exe])
    elif exe and os.path.isfile(exe) and not covered(exe) and _p_bind_ok(exe):
        # node/perl/ruby/php/go outside system roots (nvm, ~/sdk, /opt/nodejs):
        # walk up out of bin/sbin and bind that install prefix.
        pre = os.path.dirname(exe)
        for _ in range(3):
            if os.path.basename(pre) in ("bin", "sbin"):
                pre = os.path.dirname(pre)
            else:
                break
        if os.path.isdir(pre) and _p_bind_ok(pre):
            add_dir(pre)
        else:
            add_dir(os.path.dirname(exe))
        if not any(exe.startswith(d + "/") for d in bound_dirs) \
                and _p_bind_ok(exe):
            args.extend(["--ro-bind", exe, exe])

    # Surgical hides AFTER the binds they redact (bwrap mounts in arg order).
    for h in sorted(hides, key=len, reverse=True):
        args.extend(["--tmpfs", h])

    _SANDBOX_CACHE[key] = list(args)
    return args

def _bwrap_works() -> bool:
    """One-time probe: can unprivileged user namespaces + bwrap run here?
    Uses the SAME static flags as _bwrap_wrap so a pass means the real job's
    namespace setup works."""
    if "bwrap" in _SANDBOX_CACHE: return _SANDBOX_CACHE["bwrap"]
    ok = False
    exe = _find_exe("bwrap")
    if exe:
        try:
            r = subprocess.run([exe, *_bwrap_static_args(), "true"], capture_output=True, timeout=8)
            ok = (r.returncode == 0)
        except Exception:
            ok = False
    _SANDBOX_CACHE["bwrap"] = ok
    return ok

_DOCKER_IMAGES = {"python": "python:3.12-alpine", "node": "node:22-alpine",
                  "ruby": "ruby:3.3-alpine", "perl": "perl:5.38",
                  "php": "php:8.3-cli", "bash": "bash:5.2"}

def _ensure_docker_path() -> None:
    """Docker Desktop may put its CLI where only LOGIN shells look
    (~/.docker/bin via .zprofile — interactive shells source .zshrc and miss
    it, and the agent inherits whatever it was started with). Probe the known
    locations and prepend them: one process-local fix instead of depending on
    every user's shell rc files being right."""
    if shutil.which("docker"):
        return
    for d in (Path.home() / ".docker" / "bin",
              Path.home() / ".docker" / "desktop" / "bin",
              Path("/Applications/Docker.app/Contents/Resources/bin")):
        if (d / "docker").exists():
            os.environ["PATH"] = f"{d}{os.pathsep}{os.environ.get('PATH', '')}"
            return

def _docker_cli_ok() -> bool:
    _ensure_docker_path()
    if "docker" in _SANDBOX_CACHE: return _SANDBOX_CACHE["docker"]
    ok = False
    if _find_exe("docker"):
        try:
            ok = subprocess.run(["docker", "info"], capture_output=True, timeout=8).returncode == 0
        except Exception:
            ok = False
    _SANDBOX_CACHE["docker"] = ok
    return ok

def _docker_has_image(img: str) -> bool:
    key = "img:" + img
    if key in _SANDBOX_CACHE: return _SANDBOX_CACHE[key]
    try:
        ok = subprocess.run(["docker", "image", "inspect", img],
                            capture_output=True, timeout=8).returncode == 0
    except Exception:
        ok = False
    _SANDBOX_CACHE[key] = ok
    return ok

def _pick_sandbox(pref: str, lang: str, has_compile: bool):
    """Tier selection: 'bwrap' | 'docker' | 'subprocess'. Never worse than the
    rlimit'd subprocess baseline; docker only for interpreted langs with a
    locally-present image; explicit 'docker' degrades gracefully.
    BLNQ_SANDBOX_TIER=docker|bwrap|subprocess forces a tier (testing only —
    set on the AGENT, never by job code)."""
    pref = os.environ.get("BLNQ_SANDBOX_TIER") or pref
    if IS_WIN: return "subprocess"
    if pref == "subprocess": return "subprocess"
    if pref == "bwrap":       return "bwrap" if _bwrap_works() else "subprocess"
    if pref == "docker":
        if (not has_compile and lang in _DOCKER_IMAGES
                and _docker_cli_ok() and _docker_has_image(_DOCKER_IMAGES[lang])):
            return "docker"
        return "bwrap" if _bwrap_works() else "subprocess"
    # auto
    if _bwrap_works(): return "bwrap"
    if (not has_compile and lang in _DOCKER_IMAGES
            and _docker_cli_ok() and _docker_has_image(_DOCKER_IMAGES[lang])):
        return "docker"
    return "subprocess"

def _sandbox_tier() -> str:
    """Strongest jail this machine can offer: 'bwrap' | 'docker' | 'rlimit'.
    'rlimit' is the NO-JAIL tier — on macOS Darwin ignores RLIMIT_AS (so the
    memory cap is decorative) and there are no namespaces at all, meaning
    rlimit'd code keeps full network and filesystem access. Foreign code must
    never run there."""
    if _bwrap_works():   return "bwrap"
    if _docker_cli_ok(): return "docker"
    return "rlimit"

def _sandbox_caps() -> list:
    """sandbox-* capability tags advertised at register time. No tag at all
    means a legacy (pre-tier) client; 'sandbox-rlimit-v1' means the node
    KNOWS it has no jail — the hub refuses to nudge it, and it refuses to
    claim (fail closed on both sides).

    v2 = the bwrap jail also isolates the FILESYSTEM (audit 2026-11-19:
    v1's `--ro-bind / /` ran jobs with $HOME readable at our own uid, so
    auth.json and the worker key were one print() away from any submitter).
    v1 is still sent as an ALIAS during rollout: hubs checking the exact
    v1 string keep nudging updated nodes until every hub runs the
    BLNQ_REQUIRE_FS_JAIL-aware jobs.js. The hub can tell them apart by the
    PRESENCE of v2."""
    caps = []
    if _bwrap_works():   caps.append("sandbox-bwrap-v2"); caps.append("sandbox-bwrap-v1")
    if _docker_cli_ok(): caps.append("sandbox-docker-v1")
    if not caps:         caps.append("sandbox-rlimit-v1")
    return caps

def _declared_sandbox(w: dict) -> str:
    """Tier a worker ROW declares: prefer the hub's derived `sandbox` field
    (present once the hub is redeployed), fall back to the raw sandbox-*
    capability tag the client already sends — so the display is correct even
    against an older hub that doesn't know the field yet."""
    sb = w.get("sandbox")
    if sb:
        return str(sb)
    caps = w.get("capabilities") or []
    if "sandbox-docker-v1" in caps: return "docker"
    if "sandbox-bwrap-v2" in caps:  return "bwrap"   # fs-jailed (post audit)
    if "sandbox-bwrap-v1" in caps:  return "bwrap"
    if any(str(c).startswith("sandbox-rlimit") for c in caps): return "rlimit"
    return "legacy"

def _sandbox_ok_for(lang: str) -> bool:
    """True when `lang` can run inside a real jail here (docker or bwrap).
    Mirrors _pick_sandbox('auto', lang, False): a docker box whose image is
    not pulled yet counts as OK — the claim thread pulls it before claiming
    and aborts if the pull fails."""
    if _pick_sandbox("auto", lang, False) in ("bwrap", "docker"):
        return True
    return bool(lang in _DOCKER_IMAGES and _docker_cli_ok())

def _bwrap_wrap(argv: list, jobdir: Path, lang: str = "python") -> list:
    """Full bwrap argv. Mount order is the security: system roots →
    interpreter paths (+ secret tmpfs hides) → the jobdir LAST so a job can
    always reach its own files even when its path sits under a hidden tree."""
    return ["bwrap", *_bwrap_static_args(), *_bwrap_runtime_args(lang, argv),
            "--bind", str(jobdir), str(jobdir),
            "--setenv", "HOME", str(jobdir), "--setenv", "TMPDIR", "/tmp",
            "--hostname", "blnq-jail", "--", *argv]

def _docker_wrap(argv: list, jobdir: Path, lang: str, mem_mb: int,
                 env_map: dict, cname: str) -> list:
    """Docker argv for interpreted langs: job dir mounted at /job, no network,
    hard caps, secrets forwarded as -e (never logged)."""
    img = _DOCKER_IMAGES[lang]
    inner = [a.replace(str(jobdir), "/job") if isinstance(a, str) else a for a in argv]
    cmd = ["docker", "run", "--rm", "-i", "--name", cname,
           "--network", "none", "--memory", f"{mem_mb}m", "--memory-swap", f"{mem_mb}m",
           "--cpus", "0.5", "--pids-limit", "64",
           "-u", f"{os.getuid()}:{os.getgid()}",
           "-v", f"{jobdir}:/job", "-w", "/job", "-e", "HOME=/job"]
    for k in env_map:
        cmd += ["-e", k]
    cmd += [img, *inner]
    return cmd

def _collect_artifacts(jobdir: Path, exclude_names: set, cap_bytes: int) -> "bytes | None":
    """tar.gz of every file the job produced in its workdir (excl. inputs/binaries).
    None if nothing new or over cap. Paths are relative (safe to extract)."""
    buf = io.BytesIO()
    count = 0
    try:
        with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.GNU_FORMAT) as tf:
            for p in sorted(jobdir.rglob("*")):
                if p.is_symlink(): continue           # never archive symlinks (host-path smuggling)
                if not p.is_file(): continue
                if p.name in exclude_names or p.name.startswith("."): continue
                try:
                    if p.stat().st_size > cap_bytes: continue
                    tf.add(str(p), arcname=p.relative_to(jobdir).as_posix())
                    count += 1
                except OSError:
                    continue
                if buf.tell() > cap_bytes: return None
    except Exception:
        return None
    return buf.getvalue() if count else None

def _posix_preexec(cpu_s: int, mem_mb: int):
    """rlimits + own process group for POSIX job children."""
    def _apply():
        os.setsid()
        try:
            import resource
            def clamp(rid, soft):
                hard = resource.getrlimit(rid)[1]
                if hard == resource.RLIM_INFINITY: hard = soft
                resource.setrlimit(rid, (min(soft, hard), hard))
            clamp(resource.RLIMIT_CPU, cpu_s)
            clamp(resource.RLIMIT_AS, mem_mb * 1024 * 1024)
            clamp(resource.RLIMIT_FSIZE, 64 * 1024 * 1024)
            try: clamp(resource.RLIMIT_NPROC, 128)
            except Exception: pass
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            pass
    return _apply

class _WinJob:
    """Kernel Job Object: memory cap + guaranteed tree-kill on close.
    Best-effort — if anything fails we degrade to taskkill /T."""
    def __init__(self, mem_mb: int, active_proc_limit: int = 64):
        self.h = None
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            self._k32 = k32
            self.h = k32.CreateJobObjectW(None, None)
            if not self.h: return
            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [(n, ctypes.c_uint64) for n in
                            ("ReadOperationCount","WriteOperationCount","OtherOperationCount",
                             "ReadTransferCount","WriteTransferCount","OtherTransferCount")]
            class BASIC(ctypes.Structure):
                _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                            ("PerJobUserTimeLimit", ctypes.c_int64),
                            ("LimitFlags", ctypes.c_uint32),
                            ("MinimumWorkingSetSize", ctypes.c_size_t),
                            ("MaximumWorkingSetSize", ctypes.c_size_t),
                            ("ActiveProcessLimit", ctypes.c_uint32),
                            ("Affinity", ctypes.c_size_t),
                            ("PriorityClass", ctypes.c_uint32),
                            ("SchedulingClass", ctypes.c_uint32)]
            class EXT(ctypes.Structure):
                _fields_ = [("BasicLimitInformation", BASIC), ("IoInfo", IO_COUNTERS),
                            ("ProcessMemoryLimit", ctypes.c_size_t),
                            ("JobMemoryLimit", ctypes.c_size_t),
                            ("PeakProcessMemoryUsed", ctypes.c_size_t),
                            ("PeakJobMemoryUsed", ctypes.c_size_t)]
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS   = 0x00000008
            JOB_OBJECT_LIMIT_PROCESS_MEMORY   = 0x00000100
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE= 0x00002000
            info = EXT()
            info.BasicLimitInformation.LimitFlags = (
                JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY |
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
            info.BasicLimitInformation.ActiveProcessLimit = active_proc_limit
            info.ProcessMemoryLimit = mem_mb * 1024 * 1024
            ok = k32.SetInformationJobObject(
                self.h, 9, ctypes.byref(info), ctypes.sizeof(info))  # 9 = ExtendedLimitInformation
            if not ok: k32.CloseHandle(self.h); self.h = None
        except Exception:
            self.h = None

    def assign(self, proc_handle) -> bool:
        if not self.h: return False
        try:
            import ctypes
            return bool(self._k32.AssignProcessToJobObject(self.h, ctypes.c_void_p(proc_handle)))
        except Exception:
            return False

    def close(self):
        if not self.h: return
        try:
            self._k32.TerminateJobObject(self.h, 1)
            self._k32.CloseHandle(self.h)
        except Exception:
            pass
        self.h = None

def _kill_proc_tree(proc, win_job: "_WinJob | None", container: str | None = None) -> None:
    if win_job and win_job.h:
        win_job.close()          # KILL_ON_JOB_CLOSE takes the whole tree out
    if container:
        # docker run client is NOT in its own session (no setsid preexec); killpg
        # would signal the agent's own group. Kill the client + the container.
        try: proc.kill()
        except Exception: pass
        try:
            subprocess.run(["docker", "kill", container], capture_output=True, timeout=10)
        except Exception:
            pass
        return
    try:
        if IS_WIN:
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           capture_output=True, timeout=10)
        else:
            # rlimit/bwrap children are session leaders (preexec setsid) → safe killpg
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try: proc.kill()
        except Exception: pass

_ACTIVE_JOBS: dict = {}          # job_id -> proc (for cancel + load reporting)
_ACTIVE_META: dict = {}          # job_id -> {started, lang, tier, pid} for `blnq tasks`
_ACTIVE_LOCK = threading.Lock()

def _jobs_inflight() -> int:
    with _ACTIVE_LOCK:
        return len(_ACTIVE_JOBS)

def run_job(worker_id: str, job: dict, log_path) -> None:
    """Claimed job → sandboxed subprocess → stream output lines to hub."""
    job_id  = job.get("job_id") or ""
    lang    = (job.get("language") or "python").lower()
    code    = job.get("script_content") or ""
    stdin_s = job.get("stdin_data") or ""
    interactive = bool(job.get("interactive"))
    try:
        timeout_s = int(job.get("timeout_seconds") or 30)
    except (TypeError, ValueError):
        timeout_s = 30
    timeout_s = max(1, min(timeout_s, 300))
    vol = _volunteer_load()
    mem_mb = max(64, int(vol.get("max_mem_mb", 1024)))
    sec_map = job.get("secrets") or {}
    if not isinstance(sec_map, dict): sec_map = {}
    sec_map = {str(k): str(v) for k, v in sec_map.items() if isinstance(v, (str, int, float))}
    redact_vals = sorted({str(v) for v in sec_map.values() if v}, key=len, reverse=True)
    ts = lambda: time.strftime("%H:%M:%S")

    def api(method, path, body=None, tmo=10, content_type=None, extra_headers=None):
        return do_http(method, path, body=body, timeout=tmo, content_type=content_type,
                       extra_headers=extra_headers, allow_degrade=False)

    _completed = {"v": False}
    authz_dec = None   # set by the authorization gate below; read inside
                       # complete() so EVERY outcome — including refusals —
                       # lands in authz-history with its identity and mode
    def complete(status, exit_code=None, output="", error=""):
        if _completed["v"]: return
        _completed["v"] = True
        api("POST", f"/api/jobs/{job_id}/complete",
            {"worker_id": worker_id, "status": status,
             "output": _redact_secrets(output[:1_000_000], redact_vals),
             "exit_code": exit_code, "duration_ms": duration_ms,
             "error": _redact_secrets(error[:4000], redact_vals)})
        # File our own signed account of the run. Best-effort: a ledger hiccup
        # must never turn a completed job into a failed one.
        try:
            rec = submit_run_record(
                job_id, status, exit_code, duration_ms,
                cpu_ms=_child_cpu_ms(cpu0),
                bytes_out=len(output.encode("utf-8", "replace")),
                bytes_in=len(code.encode("utf-8", "replace")),
                source_sha256=_subject_of(code),
            )
            if rec and rec.get("lyrz") is not None:
                print(f"[{ts()}] job {job_id}: run recorded, +{rec['lyrz']} LYRz",
                      file=log_path)
        except Exception as e:
            print(f"[{ts()}] job {job_id}: run record failed: {e}", file=log_path)
        # ── audit: EVERY outcome, refusals included ───────────────────────
        # An audit that only lists the runs you allowed is a story; this one
        # records who asked, what mode they were in, and why it ended.
        try:
            _authz_history_append({
                "ts": time.time(), "job_id": job_id,
                "identity": (authz_dec or {}).get("identity")
                            or str(job.get("username") or job.get("user_id") or "unknown"),
                "mode": (authz_dec or {}).get("mode"),
                "script": job.get("script_name") or "?",
                "sha": _subject_of(code)[:16],
                "status": status, "exit": exit_code,
                "ms": duration_ms,
                "detail": (error or "").strip()[:180]
                          or (authz_dec or {}).get("reason") or "ok",
            })
        except Exception:
            pass    # the audit never breaks a completion

    with _ACTIVE_LOCK:
        if job_id in _ACTIVE_JOBS: return
        _ACTIVE_JOBS[job_id] = None
        _ACTIVE_META[job_id] = {"started": time.time(),
                                "lang": job.get("language") or "?"}
    start = time.time()
    cpu0 = os.times()          # baseline for the run.record's cpu_ms
    duration_ms = 0
    print(f"[{ts()}] job {job_id} ({lang}) starting — timeout {timeout_s}s", file=log_path)

    # ── local authorization: THIS machine decides who may run what here ──
    # Identity is jobs.username (NOT NULL at the hub, delivered in the claim
    # response), so no display-name trust is needed. Default-allow keeps the
    # fleet exactly as permissive as it is today; `blnq auth default deny`
    # flips this node to whitelist mode. Probation ("maybe") is ALLOW-with-
    # a-strict-scan: the run only proceeds if the local scanner finds no
    # CRITICAL/WARN — "test the user out" with evidence, not vibes.
    authz_dec = _authz_decision(
        _authz_load(),
        bool(vol.get("allow_network_jobs", True)),
        str(job.get("username") or job.get("user_id") or "unknown"),
        has_secrets=bool(sec_map),
        wants_network=bool(job.get("want_network") or job.get("network")),
    )
    print(f"[{ts()}] job {job_id}: authz identity={authz_dec['identity']} "
          f"mode={authz_dec['mode']} caps={','.join(authz_dec['caps']) or '-'}",
          file=log_path)
    if not authz_dec["ok"]:
        print(f"[{ts()}] job {job_id}: AUTHZ DENIED — {authz_dec['reason']}",
              file=log_path)
        complete("failed", exit_code=None, error=f"authz denied: {authz_dec['reason']}")
        with _ACTIVE_LOCK:
            _ACTIVE_JOBS.pop(job_id, None)
        _ACTIVE_META.pop(job_id, None)
        return
    if authz_dec.get("strict"):
        # Probation gate: local scan of the exact source; CRITICAL/WARN refuse
        # with the rule ids in the error so the requester knows what to fix.
        _suffix = os.path.splitext(job.get("script_name") or "job.py")[1] or ".py"
        _scan_path = None
        try:
            import tempfile as _tf_authz
            with _tf_authz.NamedTemporaryFile("w", suffix=_suffix, delete=False,
                                              encoding="utf-8") as _sf:
                _sf.write(code)
                _scan_path = _sf.name
            _findings = _security_scan_file(Path(_scan_path))
            _bad = [f for f in _findings if f.get("severity") in ("CRITICAL", "WARN")]
        except Exception as _e:
            # fail closed under probation: if we cannot scan, we cannot vouch
            _bad = [{"rule_id": f"scan-error:{_e}"}]
        finally:
            if _scan_path:
                try: os.unlink(_scan_path)
                except OSError: pass
        if _bad:
            _rules = ", ".join(sorted({str(f.get("rule_id") or "?") for f in _bad}))[:200]
            print(f"[{ts()}] job {job_id}: PROBATION REFUSED by scan — {_rules}",
                  file=log_path)
            complete("failed", exit_code=None,
                     error=f"authz maybe-mode: refused by strict scan ({_rules}) — "
                           f"approve fully with `{APP} auth {authz_dec['identity']} all`")
            with _ACTIVE_LOCK:
                _ACTIVE_JOBS.pop(job_id, None)
            _ACTIVE_META.pop(job_id, None)
            return

    try:
        with tempfile.TemporaryDirectory(prefix="blnq-job-") as td:
            jobdir = Path(td)
            argv, compile_argv = _job_command(lang, job.get("script_name") or "job", code, jobdir)
            if argv is None:
                duration_ms = int((time.time() - start) * 1000)
                print(f"[{ts()}] job {job_id}: no {lang} toolchain here — reporting skipped", file=log_path)
                complete("failed", error=f"worker cannot run {lang}: toolchain not installed")
                return
            # build the job env: scrubbed base + injected secrets
            job_env = _clean_env()
            for k, v in sec_map.items():
                job_env[k] = str(v)
            if compile_argv:
                cr = subprocess.run(compile_argv, capture_output=True, text=True,
                                    timeout=min(timeout_s, 60), env=_clean_env(), cwd=str(jobdir))
                if cr.returncode != 0:
                    duration_ms = int((time.time() - start) * 1000)
                    msg = _redact_secrets((cr.stderr or cr.stdout or "")[:4000], redact_vals)
                    complete("failed", exit_code=cr.returncode, error=f"compile error:\n{msg}")
                    print(f"[{ts()}] job {job_id}: compile failed", file=log_path)
                    return
            def _attempt(name):
                """Launch under one sandbox tier. Buffers output for a short grace
                period so an instant sandbox-bootstrap failure (bwrap userns EAGAIN,
                docker daemon down) is detected and NOT streamed to the hub, letting
                us cleanly retry a weaker tier. Returns a result dict."""
                docker_container = None
                popen_kw = dict(stdin=(subprocess.PIPE if (stdin_s or interactive) else subprocess.DEVNULL),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, cwd=str(jobdir),
                                encoding="utf-8", errors="replace")
                win_job = None
                if name == "docker":
                    docker_container = f"blnq-{job_id}-{int(time.time())}"
                    run_argv = _docker_wrap(argv, jobdir, lang, mem_mb, sec_map, docker_container)
                    popen_kw["env"] = job_env
                elif name == "bwrap":
                    run_argv = _bwrap_wrap(argv, jobdir, lang)
                    popen_kw["env"] = job_env
                    if not IS_WIN:
                        popen_kw["preexec_fn"] = _posix_preexec(timeout_s + 5, mem_mb)
                else:  # subprocess (rlimit'd)
                    run_argv = argv
                    popen_kw["env"] = job_env
                    if IS_WIN:
                        popen_kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
                        win_job = _WinJob(mem_mb)
                    else:
                        popen_kw["preexec_fn"] = _posix_preexec(timeout_s + 5, mem_mb)
                print(f"[{ts()}] job {job_id}: sandbox={name}" +
                      (f" secrets={len(sec_map)}" if sec_map else ""), file=log_path)
                proc = subprocess.Popen(run_argv, **popen_kw)
                try: proc._blnq_container = docker_container
                except Exception: pass
                with _ACTIVE_LOCK:
                    _ACTIVE_JOBS[job_id] = proc
                _ACTIVE_META.setdefault(job_id, {"started": time.time(), "lang": lang})
                _ACTIVE_META[job_id].update({"pid": proc.pid, "tier": name})
                if win_job:
                    try: win_job.assign(int(getattr(proc, "handle", None) or proc._handle))
                    except Exception: pass
                stdin_stop = threading.Event()
                if interactive:
                    # keep stdin open and feed typed input until eof
                    if stdin_s:
                        try: proc.stdin.write(stdin_s); proc.stdin.flush()
                        except Exception: pass
                    def feeder():
                        while not stdin_stop.is_set():
                            try:
                                c_, p_ = api("GET", f"/api/jobs/{job_id}/stdin?wait=3000", tmo=8,
                                             extra_headers={"X-Worker-Id": worker_id})
                            except Exception:
                                time.sleep(1); continue
                            if c_ != 200 or not isinstance(p_, dict):
                                time.sleep(1); continue
                            for ch in (p_.get("chunks") or []):
                                try:
                                    proc.stdin.write(ch.get("data", "")); proc.stdin.flush()
                                except Exception:
                                    return
                            if p_.get("eof"):
                                try: proc.stdin.close()
                                except Exception: pass
                                return
                    threading.Thread(target=feeder, daemon=True).start()
                elif stdin_s:
                    try: proc.stdin.write(stdin_s); proc.stdin.close()
                    except Exception: pass
                lines_q: Queue = Queue()
                def reader():
                    try:
                        for ln in proc.stdout:
                            lines_q.put(_redact_secrets(ln, redact_vals) if redact_vals else ln)
                    except Exception:
                        pass
                    finally:
                        lines_q.put(None)
                threading.Thread(target=reader, daemon=True).start()

                out_lines: list = []
                sent = 0

                timed_out = False
                grace = time.time() + 1.5
                deadline = start + timeout_s
                flush_at = time.time() + 1.0
                hb_at = time.time() + 10.0
                done_reading = False
                # Phase 1: buffer briefly to catch an instant bootstrap failure.
                while time.time() < grace and not done_reading:
                    try:
                        item = lines_q.get(timeout=0.1)
                    except Exception:
                        item = ""
                    if item is None:
                        done_reading = True
                    elif item:
                        out_lines.append(item)
                # If stdout already closed during the grace window, reap the exit
                # code now (poll() can still be None for a hair after EOF).
                rc_now = proc.poll()
                if rc_now is None and done_reading:
                    try:
                        rc_now = proc.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        rc_now = None
                if rc_now not in (None, 0) and len(out_lines) < 6:
                    head = "".join(out_lines).lower()
                    if name != "subprocess" and _SANDBOX_BOOT_RE.search(head):
                        # the JAIL failed to start — discard this output, retry weaker
                        try:
                            _kill_proc_tree(proc, win_job, docker_container)
                        except Exception:
                            pass
                        if win_job: win_job.close()
                        with _ACTIVE_LOCK:
                            _ACTIVE_JOBS.pop(job_id, None); _ACTIVE_META.pop(job_id, None)
                        stdin_stop.set()
                        return {"bootstrap_fail": True, "rc": rc_now,
                                "out_lines": [], "timed_out": False}
                # looks like a real run → commit to this tier, stream from here on
                api("POST", f"/api/jobs/{job_id}/start", {"worker_id": worker_id})

                # flush anything already buffered
                while sent < len(out_lines):
                    chunk = out_lines[sent:sent + 50]
                    api("POST", f"/api/jobs/{job_id}/output",
                        {"worker_id": worker_id, "line": "".join(chunk), "line_number": sent})
                    sent += len(chunk)
                # Phase 2: normal streaming
                pending: list = []
                while True:
                    if not done_reading:
                        try:
                            item = lines_q.get(timeout=0.25)
                            if item is None: done_reading = True
                            elif len(out_lines) + len(pending) < _MAX_OUTPUT_LINES:
                                pending.append(item)
                        except Exception:
                            pass
                    if not timed_out and time.time() > deadline:
                        timed_out = True
                        print(f"[{ts()}] job {job_id}: deadline hit — killing tree", file=log_path)
                        _kill_proc_tree(proc, win_job, docker_container)
                    if time.time() >= hb_at and not done_reading:
                        api("POST", f"/api/jobs/{job_id}/heartbeat", {"worker_id": worker_id})
                        hb_at = time.time() + 10.0
                    if pending and (len(pending) >= 20 or done_reading or time.time() >= flush_at):
                        out_lines.extend(pending); pending.clear(); flush_at = time.time() + 1.0
                    while sent < len(out_lines):
                        chunk = out_lines[sent:sent + 50]
                        code_, _ = api("POST", f"/api/jobs/{job_id}/output",
                                       {"worker_id": worker_id,
                                        "line": "".join(chunk), "line_number": sent})
                        sent += len(chunk)
                        if code_ in (409, 410) and not timed_out:
                            timed_out = True
                            _kill_proc_tree(proc, win_job, docker_container)
                            break
                    if done_reading and not pending: break
                try:
                    rc = proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    _kill_proc_tree(proc, win_job, docker_container)
                    rc = proc.wait()
                finally:
                    stdin_stop.set()
                    if win_job: win_job.close()
                return {"bootstrap_fail": False, "rc": rc,
                        "out_lines": out_lines, "timed_out": timed_out}

            chosen = _pick_sandbox(vol.get("sandbox", "auto"), lang, compile_argv is not None)
            tiers = [chosen] if chosen == "subprocess" else [chosen, "subprocess"]
            result = None
            for tier in tiers:
                result = _attempt(tier)
                if not result["bootstrap_fail"]:
                    break
                print(f"[{ts()}] job {job_id}: {tier} sandbox unavailable "
                      f"(bootstrap failed) — falling back", file=log_path)
            duration_ms = int((time.time() - start) * 1000)
            output = "".join(result["out_lines"])
            rc = result["rc"]
            timed_out = result["timed_out"]
            status = "timeout" if timed_out else ("success" if rc == 0 else "failed")
            complete(status, exit_code=rc, output=output)
            print(f"[{ts()}] job {job_id} → {status} (rc={rc}, {duration_ms}ms)", file=log_path)
            # artifacts: upload anything the job wrote into its workdir
            try:
                excl = {p.name for p in jobdir.glob("*")} & \
                       {Path(a).name for a in (argv + (compile_argv or [])) if isinstance(a, str)}
                # exclude the source file(s) we created, keep program outputs
                data = _collect_artifacts(jobdir, excl, _MAX_ARTIFACT_BYTES)
                if data:
                    ac, _ = api("POST", f"/api/jobs/{job_id}/artifact", body=data,
                                content_type="application/gzip", tmo=60,
                                extra_headers={"X-Worker-Id": worker_id})
                    print(f"[{ts()}] job {job_id}: artifact {len(data)}B -> http {ac}", file=log_path)
            except Exception as e:
                print(f"[{ts()}] job {job_id}: artifact upload failed: {e}", file=log_path)
    except Exception as e:
        duration_ms = int((time.time() - start) * 1000)
        print(f"[{ts()}] job {job_id} runner exception: {e}", file=log_path)
        try: complete("failed", error=_redact_secrets(str(e)[:4000], redact_vals))
        except Exception: pass
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE_JOBS.pop(job_id, None); _ACTIVE_META.pop(job_id, None)

# ── agent (daemon) ─────────────────────────────────────────────────────
def cmd_agent(stop_event) -> None:
    ensure_dirs()
    try: STOP_FILE.unlink()
    except OSError: pass
    PID_FILE.write_text(str(os.getpid()))
    write_state({"started_at": int(time.time()), "pid": os.getpid(),
                 "worker_id": None, "last_heartbeat": None, "last_error": None,
                 "transport": "heartbeat-only"})
    log_path = LOG_FILE.open("a", buffering=1)
    print(f"[{time.strftime('%H:%M:%S')}] agent started (pid={os.getpid()}, hub={HUB})", file=log_path)

    def shutdown(*_a): stop_event.set()
    signal.signal(signal.SIGINT, shutdown)
    try: signal.signal(signal.SIGTERM, shutdown)   # not deliverable on Windows; stop-file covers it
    except (ValueError, OSError, AttributeError): pass

    try:
        auth_token = _get_or_create_auth_token()
    except OSError as e:
        auth_token = None
        print(f"[{time.strftime('%H:%M:%S')}] WARN could not create auth token: {e}", file=log_path)

    hostname = socket.gethostname()
    hw_id = _machine_id()

    # 1. register once (with auth_token + hw_id + capabilities)
    vol = _volunteer_load()
    langs = _available_languages() if vol.get("share_cpu") else []
    capabilities = ["heartbeat", "cli", "metrics", "signed-requests", "long-poll", "scan",
                    "lan-discovery"]
    if vol.get("share_cpu"):
        capabilities.append("exec-jobs-v1")
    # Which jail we run foreign code in (sandbox-bwrap-v2 = fs-jailed, its
    # v1 alias, sandbox-docker-v1 / sandbox-rlimit-v1). The hub filters
    # nudges on this; we also refuse to claim without a jail — both sides
    # fail closed.
    capabilities += _sandbox_caps()
    max_parallel = max(1, int(vol.get("max_parallel", 1))) if vol.get("share_cpu") else 0
    body = {"hostname": hostname, "version": VERSION,
            "max_parallel": max(1, max_parallel), "tags": ["cli", "v"+VERSION] + capabilities,
            "hw_id": hw_id, "auth_token": auth_token,
            "client": f"{APP}/{VERSION}",
            "platform": _platform_tag(),
            "os_user": _os_user(),
            "capabilities": capabilities,
            "languages": langs,
            "metrics": _collect_metrics()}
    code, payload = do_http("POST", "/api/workers/register", body=body)
    st = read_state()
    if code == 200 and isinstance(payload, dict) and payload.get("worker_id"):
        st["worker_id"] = payload["worker_id"]
        st["hw_id"] = hw_id
        print(f"[{time.strftime('%H:%M:%S')}] registered as {st['worker_id']} (hw={hw_id or 'soft'})", file=log_path)
    else:
        st["last_error"] = f"register failed: http {code}: {str(payload)[:200]}"
        print(f"[{time.strftime('%H:%M:%S')}] register failed {code}: {str(payload)[:120]}", file=log_path)
    write_state(st)

    # 2. heartbeat + inbox-poll loop
    inbox_supported = True
    last_inbox_at = 0
    job_threads: list = []
    while not stop_event.is_set():
        if STOP_FILE.exists():
            print(f"[{time.strftime('%H:%M:%S')}] stop.request seen — shutting down", file=log_path)
            stop_event.set(); break
        job_threads = [t for t in job_threads if t.is_alive()]
        st = read_state()
        worker_id = st.get("worker_id")
        if worker_id:
            code, payload = do_http("POST", "/api/workers/heartbeat",
                                    body={"worker_id": worker_id,
                                          "current_load": _jobs_inflight(),
                                          "hostname": hostname,
                                          "version": VERSION,
                                          "ts": int(time.time()),
                                          "metrics": _collect_metrics()})
            if code == 404:
                print(f"[{time.strftime('%H:%M:%S')}] hb 404, re-registering", file=log_path)
                st["worker_id"] = None
                write_state(st)
                continue
        else:
            code, payload = do_http("POST", "/api/workers/register", body=body)
            if code == 200 and isinstance(payload, dict) and payload.get("worker_id"):
                st = read_state() or {}
                st["worker_id"] = payload["worker_id"]
                write_state(st)

        st = read_state()
        st["last_heartbeat"] = int(time.time())
        st["last_status"]    = code
        if code and code >= 400:
            st["last_error"] = f"http {code}: {str(payload)[:120]}"
        elif code == 0:
            st["last_error"] = str(payload)[:120]
        write_state(st)
        print(f"[{time.strftime('%H:%M:%S')}] hb={code} worker={st.get('worker_id')}", file=log_path)

        # 3. inbox poll — graceful degrade on 404
        if inbox_supported and worker_id and code == 200:
            wait_s = max(2, HEARTBEAT_S - 5)
            ic, ipayload = do_http("GET", f"/api/agents/{worker_id}/inbox?wait={wait_s}",
                                   timeout=wait_s + 10)
            last_inbox_at = int(time.time())
            if ic == 404:
                inbox_supported = False
                st["transport"] = "heartbeat-only"
                write_state(st)
                print(f"[{time.strftime('%H:%M:%S')}] inbox 404 → heartbeat-only mode", file=log_path)
            elif ic == 200 and isinstance(ipayload, dict):
                msgs = ipayload.get("messages") or []
                if msgs:
                    print(f"[{time.strftime('%H:%M:%S')}] inbox: {len(msgs)} message(s)", file=log_path)
                    for msg in msgs:
                        t = _dispatch_inbox_message(msg, st, log_path, job_threads)
                        if t is not None: job_threads.append(t)
                    ack_ids = [m.get("id") for m in msgs if isinstance(m, dict) and m.get("id")]
                    if ack_ids and worker_id:
                        do_http("POST", f"/api/agents/{worker_id}/inbox/ack",
                                body={"ids": ack_ids}, timeout=10)
                    st["transport"] = "long-poll"
                else:
                    st["transport"] = "long-poll"
                write_state(st)
            elif ic and ic >= 400:
                print(f"[{time.strftime('%H:%M:%S')}] inbox http {ic}: {str(ipayload)[:80]}", file=log_path)

        elapsed = max(0, int(time.time()) - last_inbox_at) if last_inbox_at else 0
        sleep_for = max(1, HEARTBEAT_S - elapsed)
        deadline = time.time() + sleep_for
        while not stop_event.is_set() and time.time() < deadline:
            stop_event.wait(min(1.0, max(0.05, deadline - time.time())))
            if STOP_FILE.exists(): stop_event.set(); break
        if stop_event.is_set(): break

    print(f"[{time.strftime('%H:%M:%S')}] agent stopping", file=log_path)
    # Kill in-flight jobs first: they run in their own sessions and would
    # otherwise outlive us and keep running unattended. STOP_FILE is left
    # IN PLACE — it is now the durable "user stopped" intent that keeps
    # keepalive/autostart from respawning us; only `blnq start` clears it.
    with _ACTIVE_LOCK:
        _jobs = list(_ACTIVE_JOBS.values())
    for _p in _jobs:
        if _p is None: continue
        try: _kill_proc_tree(_p, None, getattr(_p, "_blnq_container", None))
        except Exception: pass
    log_path.close()
    try: PID_FILE.unlink()
    except OSError: pass


def _dispatch_inbox_message(msg: dict, st: dict, log_path, job_threads: list) -> "threading.Thread | None":
    """Dispatch a single inbox message from the hub.
    Returns a Thread when one was spawned for async work (jobs)."""
    if not isinstance(msg, dict): return None
    kind = msg.get("type") or msg.get("kind") or "unknown"
    ts = time.strftime("%H:%M:%S")
    payload = msg.get("payload") or msg.get("data") or {}
    print(f"[{ts}] inbox[{kind}]: {str(payload)[:200]}", file=log_path)
    log_path.flush()

    if kind == "update_available":
        new_ver = payload.get("version")
        sha     = payload.get("sha256")
        url     = payload.get("url") or f"{HUB.rstrip('/')}/{APP}-cli.py"
        if new_ver and _parse_ver(new_ver) <= _parse_ver(VERSION):
            print(f"[{ts}] update_available ignored: already on v{VERSION} or newer", file=log_path)
        else:
            try:
                print(f"[{ts}] pulling new client from {url}…", file=log_path)
                data = _http_get_bytes(url, timeout=30)
                updated, msg, target = _apply_update(data, expected_sha256=sha, source="inbox")
                print(f"[{ts}] {msg}", file=log_path)
                if updated:
                    print(f"[{ts}] updated → {target}; restarting agent", file=log_path)
                    if IS_WIN:
                        # os.execv doesn't reliably replace a running process on
                        # Windows: spawn the new detached agent, then exit clean.
                        try:
                            with LOG_FILE.open("a", buffering=1) as lf:
                                _spawn_detached_agent(lf)
                            try: STOP_FILE.unlink()
                            except OSError: pass
                            os._exit(0)
                        except Exception as e:
                            print(f"[{ts}] restart-spawn failed: {e}", file=log_path)
                    else:
                        os.execv(sys.executable, [sys.executable, str(target), "_agent"])
                else:
                    print(f"[{ts}] auto-update FAILED: {msg}", file=log_path)
            except Exception as e:
                print(f"[{ts}] auto-update exception: {e}", file=log_path)

    elif kind == "shutdown_requested":
        print(f"[{ts}] hub requested shutdown", file=log_path)
        if IS_WIN:
            try: STOP_FILE.write_text(str(int(time.time())))
            except OSError: pass
        else:
            os.kill(os.getpid(), signal.SIGTERM)

    elif kind == "log":
        print(f"[{ts}] [hub-log] {payload}", file=log_path)

    elif kind == "job_available":
        worker_id = st.get("worker_id")
        if not worker_id:
            print(f"[{ts}] job_available ignored: not registered yet", file=log_path)
            return None
        vol = _volunteer_load()
        if not vol.get("share_cpu"):
            print(f"[{ts}] job_available ignored: volunteer is OFF (blnq volunteer on)", file=log_path)
            return None
        # Foreign code needs a real jail. The rlimit tier has no isolation on
        # macOS (Darwin ignores RLIMIT_AS; no namespaces) — fail closed HERE,
        # on the node, even if the hub mis-routes a job to us.
        lang = (payload.get("language") or "python").lower()
        if not _sandbox_ok_for(lang):
            print(f"[{ts}] job_available REFUSED: no jail for {lang} on this machine "
                  f"(sandbox={_sandbox_tier()}) — install docker or bubblewrap, "
                  f"then `blnq restart`", file=log_path)
            return None
        cap = max(1, int(vol.get("max_parallel", 1)))
        if _jobs_inflight() >= cap:
            print(f"[{ts}] job_available ignored: at capacity ({cap})", file=log_path)
            return None
        def _claim_and_run():
            try:
                # The docker tier is one `docker pull` away on a fresh host:
                # fetch the image once (best effort) so a docker-only box does
                # not silently degrade to the rlimit tier — and abort, rather
                # than run unjailed, if the image never arrives.
                if _pick_sandbox("auto", lang, False) == "subprocess" \
                        and lang in _DOCKER_IMAGES and _docker_cli_ok():
                    img = _DOCKER_IMAGES[lang]
                    print(f"[{ts}] sandbox: pulling {img} (first run)", file=log_path)
                    try:
                        subprocess.run(["docker", "pull", img], capture_output=True,
                                       timeout=300, check=False)
                    except Exception as e:
                        print(f"[{ts}] docker pull failed: {e}", file=log_path)
                    _SANDBOX_CACHE.pop("img:" + img, None)
                    if not _docker_has_image(img):
                        print(f"[{ts}] claim aborted: {img} unavailable — refusing to "
                              f"run {lang} outside a jail", file=log_path)
                        return
                code, resp = do_http("POST", "/api/jobs/claim",
                                     body={"worker_id": worker_id, "max_claims": 1,
                                           "langs": _available_languages()},
                                     timeout=20, allow_degrade=False)
                if code != 200 or not isinstance(resp, dict):
                    print(f"[{ts}] claim failed: http {code} {str(resp)[:120]}", file=log_path)
                    if code in (401, 404):
                        # legacy row without auth_token (or purged) — force re-register
                        st2 = read_state() or {}
                        st2["worker_id"] = None
                        write_state(st2)
                    return
                job = resp.get("job")
                if not job:
                    print(f"[{ts}] claim: nothing left for my languages", file=log_path)
                    return
                run_job(worker_id, job, log_path)
            except Exception as e:
                print(f"[{ts}] claim/run exception: {e}", file=log_path)
        t = threading.Thread(target=_claim_and_run, daemon=True, name=f"blnq-job-{payload.get('job_id','?')}")
        t.start()
        return t

    elif kind == "job_cancel":
        job_id = payload.get("job_id")
        with _ACTIVE_LOCK:
            proc = _ACTIVE_JOBS.get(job_id)
        if proc:
            print(f"[{ts}] hub cancelled job {job_id} — killing", file=log_path)
            _kill_proc_tree(proc, None, getattr(proc, "_blnq_container", None))
        return None

    return None


# ── operator subcommands ───────────────────────────────────────────────
def cmd_start(args) -> None:
    _nag_if_behind()
    if read_pid(): die(f"already running (pid={read_pid()}) — try: {APP} restart")
    ensure_dirs()
    try: STOP_FILE.unlink()
    except OSError: pass
    log_path = LOG_FILE.open("a")
    proc = _spawn_detached_agent(log_path)
    PID_FILE.write_text(str(proc.pid))
    ok(f"started (pid={proc.pid}, log={LOG_FILE})")
    for _ in range(20):
        time.sleep(0.1)
        st = read_state()
        if st.get("worker_id"):
            ok(f"registered with {HUB_NAME} as worker {st['worker_id']}"); return
    warn("registered heartbeat not yet received; check `blnq status` in a moment")

def _child_pids(pid: int) -> list:
    """Direct children of pid (POSIX best-effort; [] when unknowable)."""
    try:
        out = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True,
                             text=True, timeout=5)
        return [int(x) for x in out.stdout.split() if x.strip().isdigit()]
    except Exception:
        return []

def _kill_descendants(pid: int) -> int:
    """TERM every descendant of pid (jobs run in their own sessions, so they
    would otherwise outlive the agent, get reparented to init, and keep
    burning CPU with nobody left to cancel them). Returns the count."""
    stack, seen = [pid], set()
    while stack:
        for c in _child_pids(stack.pop()):
            if c not in seen:
                seen.add(c); stack.append(c)
    n = 0
    for p in seen:
        try:
            os.kill(p, signal.SIGTERM); n += 1
        except OSError:
            pass
    time.sleep(0.5)
    for p in seen:
        try: os.kill(p, signal.SIGKILL)
        except OSError: pass
    return n

def cmd_stop(args, quiet: bool = False) -> None:
    pid = read_pid()
    if not pid: die("not running")
    # The stop intent, written FIRST and left in place afterwards: this is
    # what keeps keepalive/autostart from respawning the agent behind our
    # back (and it survives a reboot). `blnq start` clears it.
    try: STOP_FILE.write_text(str(int(time.time())))
    except OSError: pass
    killed = _kill_descendants(pid)
    alive = _terminate_pid(pid)
    if not alive:
        warn("did not exit; see blnq logs")
    try: PID_FILE.unlink()
    except OSError: pass
    ok(f"stopped (was pid={pid})" + (f" — {killed} job process(es) killed" if killed else ""))
    # quiet = part of a restart: the start line follows immediately, so the
    # "will respawn" warning would only confuse ("but I just started it…").
    if not quiet:
        print(f"  nothing will respawn until: {APP} start")

def cmd_restart(args) -> None:
    if read_pid(): cmd_stop(args, quiet=True)
    cmd_start(args)

def cmd_docker(args) -> None:
    """`blnq docker` = `blnq install docker` — one word to get the runtime."""
    cmd_install(argparse.Namespace(what="docker"))


def cmd_install(args) -> None:
    """Install a jail so volunteer mode can run. `blnq install sandbox` picks
    the best jail for this OS (bubblewrap on Linux, colima+docker on macOS);
    `blnq install docker` targets the docker runtime specifically. Probes
    after every step — success is only claimed when the jail WORKS."""
    what = getattr(args, "what", None) or "sandbox"
    _title("install", f"{what} — the jail that protects this machine")
    print()

    def _finish(msg: str) -> None:
        ok(msg)
        print(f"\n  next: {APP} security      # verdict for this machine")
        print(f"        {APP} volunteer on   # then start taking jailed jobs")
        sys.exit(0)

    # ── already have a working jail? ───────────────────────────────────
    if _docker_cli_ok():
        img = _DOCKER_IMAGES.get("python")
        if img and not _docker_has_image(img):
            print(f"  pulling {img} for the docker sandbox…")
            subprocess.run(["docker", "pull", img], check=False)
        _finish(f"docker runtime already works — sandbox tier: {_sandbox_tier()}")
    if what == "sandbox" and _bwrap_works():
        _finish("bubblewrap already installed — sandbox tier: bwrap")

    if IS_WIN:
        die("on Windows, install Docker Desktop (docker.com) or run blnq under WSL2,\n"
            "    then re-run: blnq docker")

    if sys.platform == "darwin":
        # Fastest reliable route on macOS — ESPECIALLY Intel Macs, where
        # Homebrew is Tier 3 (no bottles) so colima would build from source —
        # is Docker Desktop itself: download the dmg, copy the app, launch it.
        # No brew, no sudo. System-wide when /Applications is writable,
        # user-local (~/Applications) otherwise.
        #
        # IDEMPOTENT BY DESIGN: re-running this command resumes from wherever
        # a previous attempt stopped — broken copy → removed and reinstalled,
        # good copy → just started, partial download → re-fetched, stale
        # mount → detached. `blnq install docker` is always the fix.
        #
        # Copy with `ditto`, NEVER shutil.copytree: copytree flattens the
        # bundle's internal symlinks (Frameworks/Versions/Current → A), which
        # breaks the code signature — macOS then reports "app is damaged".
        dest, dmg = None, None
        for _app in (Path("/Applications/Docker.app"),
                     Path.home() / "Applications" / "Docker.app"):
            if not _app.exists() or _docker_cli_ok():
                continue
            # Self-repair: a stray quarantine bit or a broken previous copy
            # explains most "corrupt install" complaints.
            subprocess.run(["xattr", "-dr", "com.apple.quarantine", str(_app)],
                           check=False)
            _v = subprocess.run(["codesign", "--verify", "--deep", "--strict",
                                 str(_app)], capture_output=True)
            if _v.returncode != 0:
                print(f"  found a broken copy from a previous attempt ({_app}) — removing it…")
                shutil.rmtree(_app, ignore_errors=True)
                continue
            dest = _app   # previous attempt finished the install — just start it
            break

        if dest is None:
            # Keep the 600MB installer across retries — a flaky first download
            # should not cost another 15 minutes.
            _cache = Path.home() / "Library" / "Caches" / "blnq"
            _cache.mkdir(parents=True, exist_ok=True)
            dmg = _cache / "Docker.dmg"
            if dmg.exists() and dmg.stat().st_size >= 500_000_000:
                print("  reusing cached installer…")
            else:
                url = "https://desktop.docker.com/mac/main/amd64/Docker.dmg"
                print("  downloading Docker Desktop for Mac (Intel)…")
                if subprocess.run(["curl", "-fL", "--connect-timeout", "15",
                                   "-o", str(dmg), url]).returncode != 0 \
                        or not dmg.exists() or dmg.stat().st_size < 500_000_000:
                    dmg.unlink(missing_ok=True)
                    die(f"download failed — fix your connection and re-run: {APP} docker "
                        f"(it resumes from here)\n    {url}")
            dest = Path("/Applications/Docker.app")
            if not os.access("/Applications", os.W_OK):
                dest = Path.home() / "Applications" / "Docker.app"
                dest.parent.mkdir(parents=True, exist_ok=True)
            print(f"  installing to {dest.parent}…")
            mnt = _cache / "mnt"
            subprocess.run(["hdiutil", "detach", str(mnt), "-quiet"], check=False)
            mnt.mkdir(exist_ok=True)   # a killed previous run can leave it mounted
            att = subprocess.run(["hdiutil", "attach", "-nobrowse", "-readonly",
                                  "-mountpoint", str(mnt), str(dmg)],
                                 capture_output=True, text=True)
            if att.returncode != 0:
                dmg.unlink(missing_ok=True)
                die(f"could not mount the installer (cached copy removed — re-run "
                    f"{APP} docker to re-download): {(att.stderr or '').strip()[:160]}")
            try:
                if dest.exists(): shutil.rmtree(dest)
                if subprocess.run(["ditto", str(mnt / "Docker.app"), str(dest)]).returncode != 0:
                    die(f"copy failed → {dest} — re-run: {APP} docker (it resumes from here)")
                subprocess.run(["xattr", "-dr", "com.apple.quarantine", str(dest)],
                               check=False)
                print("  verifying code signature…")
                _v = subprocess.run(["codesign", "--verify", "--deep", "--strict",
                                     str(dest)], capture_output=True)
                if _v.returncode != 0:
                    die(f"the copy failed its signature check — re-run: {APP} docker "
                        f"(it will remove the bad copy and redo it)")
            finally:
                subprocess.run(["hdiutil", "detach", str(mnt), "-quiet"], check=False)
            print("  launching Docker Desktop — ACCEPT its license window when it appears…")
        else:
            print(f"  resuming a previous attempt — starting {dest.name} "
                  "(accept its license if the window appears)…")

        subprocess.run(["open", str(dest)], check=False)
        for _ in range(90):                        # up to ~3 min: first boot + EULA click
            _SANDBOX_CACHE.pop("docker", None)      # never trust a cached False
            if _docker_cli_ok(): break
            time.sleep(2)
        if not _docker_cli_ok():
            die("Docker Desktop has not come up yet:\n"
                "    • click Accept in its license window\n"
                "    • wait for the whale 🐳 in the menu bar\n"
                "    • macOS says 'damaged'? run:  xattr -dr com.apple.quarantine "
                f"{dest}\n"
                "    • running but `docker` missing? Docker Desktop → Settings → "
                "Install command line tools (then re-open your terminal)\n"
                f"    then re-run: {APP} docker   ← it detects and resumes from here")
        if dmg is not None:
            dmg.unlink(missing_ok=True)            # success — drop the 600MB cache
        img = _DOCKER_IMAGES.get("python")
        if img and not _docker_has_image(img):
            print(f"  pulling {img} for the sandbox…")
            subprocess.run(["docker", "pull", img], check=False)
        _finish(f"Docker Desktop is up — sandbox tier: {_sandbox_tier()}")

    # ── Linux ──────────────────────────────────────────────────────────
    if what == "sandbox":
        # bubblewrap: tiny, unprivileged, no daemon — the preferred Linux jail
        pkg = None
        if   _find_exe("apt-get"): pkg = ["sudo", "apt-get", "install", "-y", "bubblewrap"]
        elif _find_exe("dnf"):      pkg = ["sudo", "dnf", "install", "-y", "bubblewrap"]
        elif _find_exe("pacman"):   pkg = ["sudo", "pacman", "-S", "--noconfirm", "bubblewrap"]
        elif _find_exe("zypper"):   pkg = ["sudo", "zypper", "-n", "install", "bubblewrap"]
        if not pkg:
            die("no supported package manager — install bubblewrap manually:\n"
                "    https://github.com/containers/bubblewrap  (or: blnq install docker)")
        print(f"  running: {' '.join(pkg)}   (sudo will ask your password)\n")
        rc = subprocess.run(pkg).returncode
        _SANDBOX_CACHE.pop("bwrap", None)
        if rc == 0 and _bwrap_works():
            _finish("bubblewrap installed — sandbox tier: bwrap")
        warn("bubblewrap installed but the probe failed (unprivileged user namespaces disabled?)")
        die("    Ubuntu 24.04+: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0\n"
            "    …or use docker instead: blnq install docker")

    if   _find_exe("apt-get"): pkg = ["sudo", "apt-get", "install", "-y", "docker.io"]
    elif _find_exe("dnf"):      pkg = ["sudo", "dnf", "install", "-y", "docker"]
    elif _find_exe("pacman"):   pkg = ["sudo", "pacman", "-S", "--noconfirm", "docker"]
    elif _find_exe("zypper"):   pkg = ["sudo", "zypper", "-n", "install", "docker"]
    else:
        die("no supported package manager for docker")
    print(f"  running: {' '.join(pkg)}   (sudo will ask your password)\n")
    subprocess.run(pkg, check=False)
    subprocess.run(["sudo", "systemctl", "enable", "--now", "docker"], check=False)
    _SANDBOX_CACHE.pop("docker", None)
    if not _docker_cli_ok():
        die("docker installed but the daemon is not answering.\n"
            "    try: sudo systemctl start docker\n"
            "    non-root user?  sudo usermod -aG docker $USER   (then re-login)")
    _finish(f"docker ready — sandbox tier: {_sandbox_tier()}")


def cmd_suggest(args) -> None:
    """Send a suggestion/report to the hub — for humans AND AIs.
    Humans:  blnq suggest "your idea"     (bare `blnq suggest` prompts you)
    AIs:     blnq suggest --kind bug --json "..."   (stable JSON on stdout)"""
    msg = " ".join(getattr(args, "message", None) or []).strip()
    if not msg and sys.stdin.isatty():
        print("what would you like to tell us? (blank line cancels)")
        try: msg = input("  > ").strip()
        except EOFError: msg = ""
    if not msg:
        die(f"need a message: {APP} suggest \"your idea\"   "
            f"(alias: {APP} report \"…\" — same thing)")
    body = {"message": msg[:5000],
            "kind": getattr(args, "kind", None) or "idea",
            "source": "cli",
            "cli_version": VERSION,
            "platform": sys.platform,
            "contact": getattr(args, "contact", None) or ""}
    code, p = do_http("POST", "/api/suggest", body=body, timeout=15)
    if code in (200, 201) and isinstance(p, dict) and p.get("ok"):
        if getattr(args, "json", False):
            _print(p, code)
        else:
            ok(f"suggestion recorded — #{p.get('id')} · status "
               f"{p.get('status', 'new')} (thanks 🙏)")
    else:
        die(f"could not send (HTTP {code}): {str(p)[:160]}")


def cmd_security(args) -> None:
    """Security posture: is THIS machine safe to run code on, and does the
    hub's view agree? Local (jail, secrets-at-rest perms) + remote
    (registered tier, version, deactivation). Exit 1 = FAIL."""
    _title("security", "local machine + network posture — user safety & network safety")
    print()
    fails, warns = [], []

    # ── local ──────────────────────────────────────────────────────────
    _section("\U0001f512", "this machine")
    tier = _sandbox_tier()
    vol = _volunteer_load()
    if tier == "rlimit":
        _kv("sandbox", _bad("rlimit — NO jail (docker/bwrap not found)"))
        if vol.get("share_cpu"):
            fails.append("volunteer ON but no jail — foreign code would run unjailed. "
                         "Fix: `blnq volunteer off`, or install docker/bubblewrap then `blnq restart`")
        else:
            warns.append("no jail — this machine cannot run volunteer jobs until you "
                         "install docker or bubblewrap")
    else:
        _kv("sandbox", _good(f"{tier} — foreign code only runs jailed"))
    _kv("volunteer", ("ON  " if vol.get("share_cpu") else "OFF ") +
        f"· {int(vol.get('max_parallel', 1))} job(s) max · {int(vol.get('max_mem_mb', 1024))} MB")
    pid = read_pid()
    if pid and pid_alive(pid):
        _kv("agent", _good(f"running (pid {pid})"))
    else:
        _kv("agent", _meh("stopped"))
        if vol.get("share_cpu"):
            warns.append("volunteer is ON but the agent is stopped — nothing is being done (`blnq start`)")

    # Secrets at rest: config/state must not be readable by other accounts.
    # Auto-hardens (this is a security command — fix what is safe to fix),
    # and reports what it could not.
    for label, d in (("config", Path.home() / ".config" / APP),
                     ("state",  Path.home() / ".local" / "share" / APP)):
        if not d.exists():
            continue
        fixed = 0
        try:
            if d.stat().st_mode & 0o077:
                os.chmod(d, 0o700); fixed += 1
            for f in d.rglob("*"):
                if f.is_file() and (f.stat().st_mode & 0o077):
                    os.chmod(f, 0o600); fixed += 1
        except OSError as e:
            warns.append(f"could not harden {label} ({e}) — run: chmod 700 {d}")
        _kv(f"{label} perms", _good("private (700/600)" if not fixed
            else f"hardened {fixed} path(s) → 700/600"))
    if STOP_FILE.exists():
        _kv("stop intent", _meh("set — nothing respawns until `blnq start`"))

    # ── network ────────────────────────────────────────────────────────
    _section("\U0001f310", "this node on the network")
    st = read_state() or {}
    wid = st.get("worker_id")
    code, ver = do_http("GET", "/api/version", timeout=6, sign=False)
    hub_v = ver.get("version") if (code == 200 and isinstance(ver, dict)) else None
    if hub_v:
        if _parse_ver(VERSION) >= _parse_ver(hub_v):
            _kv("version", _good(f"{VERSION} ✓ current"))
        else:
            _kv("version", _warn(f"{VERSION} — hub ships {hub_v}"))
            warns.append("you are behind: `blnq update` (security fixes ship here)")
    else:
        _kv("version", _meh(f"{VERSION} (hub unreachable — cannot verify)"))
    if wid:
        _kv("worker", wid)
        code2, pl = do_http("GET", "/api/workers/list", timeout=8, sign=False)
        w = None
        if code2 == 200 and isinstance(pl, dict):
            for x in (pl.get("workers") or []):
                if x.get("worker_id") == wid:
                    w = x; break
        if w:
            reg = _declared_sandbox(w)
            local_strong = tier in ("docker", "bwrap")
            _kv("registered tier", _good(reg) if reg in ("docker", "bwrap") else _bad(reg))
            if w.get("is_active") is False:
                _kv("hub state", _bad("deactivated by an operator"))
                fails.append("an operator deactivated this node — it cannot claim until "
                             "re-activated (POST /api/workers/<id>/activate)")
            else:
                _kv("hub state", _good("active"))
            if local_strong and reg in ("rlimit", "legacy"):
                warns.append("hub still shows the old tier — `blnq restart` to re-register")
            if (not local_strong) and reg in ("docker", "bwrap"):
                fails.append(f"hub believes this node is '{reg}' but it has no jail — "
                             "stale or false registration (`blnq restart` to correct)")
            _kv("reputation", f"{w.get('reputation', 0)} · "
                f"{w.get('success_count', 0)} ok / {w.get('fail_count', 0)} failed")
        else:
            _kv("registered tier", _warn("not in worker list (registered elsewhere?)"))
    else:
        _kv("worker", _meh("not registered yet (`blnq start`)"))

    # ── verdict ────────────────────────────────────────────────────────
    print()
    if fails:
        _title("verdict", _fail(f"FAIL — {len(fails)} problem(s)"))
        for f in fails: print(f"      \033[31m✗\033[0m {f}")
        for w in warns: print(f"      \033[33m!\033[0m {w}")
        print()
        sys.exit(1)
    if warns:
        _title("verdict", _warn(f"PASS with {len(warns)} warning(s)"))
        for w in warns: print(f"      \033[33m!\033[0m {w}")
    else:
        _title("verdict", _ok("PASS — jailed, private, current, registered"))
    print()
    _hint(f"full health report: {APP} doctor   ·   change something? {APP} status")
    sys.exit(0)


def cmd_emergency(args) -> None:
    """The big red button: ONE command that actually STOPS work on this box.

    `blnq stop` alone is not an emergency stop — on a keepalive/autostart box
    systemd respawns the agent within 5 minutes, with volunteer mode still on.
    This leaves volunteer mode FIRST (so even a respawn claims nothing),
    disables both respawn mechanisms, then stops the agent."""
    red, rst = "\033[1;31m", "\033[0m"
    print(f"\n{red}■ EMERGENCY STOP{rst} — {socket.gethostname()}")
    print(f"  jobs, respawn and volunteering on THIS machine\n")

    # 1. leave volunteer mode first: share_cpu=false means even an agent that
    #    somehow comes back claims nothing.
    try:
        cfg = _volunteer_load()
        if cfg.get("share_cpu"):
            cfg["share_cpu"] = False
            cfg["opted_in_at"] = None
            _VOLUNTEER_FILE.write_text(json.dumps(cfg, indent=2))
            print("  ✓ volunteer mode → OFF  (no jobs will be claimed)")
        else:
            print("  ✓ volunteer mode was already OFF")
    except Exception as e:
        warn(f"volunteer config not updated: {e}")

    # 2. disable respawn — keepalive timer + autostart entries. Best effort:
    #    an absent unit is the normal case, not a failure (they print their
    #    own 'not installed' line, and die() there must not abort us).
    for _fn in (cmd_keepalive, cmd_autostart):
        try:
            _fn(argparse.Namespace(action="off"))
        except (SystemExit, Exception):
            pass
    print("  ✓ respawn disabled (keepalive/autostart)")

    # 3. stop the agent. In-flight jobs end at their own wall/CPU rlimit; the
    #    hub can also cancel anything left (see below).
    pid = read_pid()
    if pid and pid_alive(pid):
        try:
            cmd_stop(argparse.Namespace())
        except (SystemExit, Exception) as e:
            warn(f"agent did not stop cleanly ({e}) — check: {APP} logs")
    else:
        print("  ✓ agent was not running")

    print(f"\n  {rst}this machine stays stopped until you say otherwise:")
    print(f"    {APP} volunteer on        # rejoin the corps (auto-restarts the agent)")
    print(f"    {APP} start               # …or just start the agent")
    print(f"    {APP} keepalive on / {APP} autostart on   # re-enable respawn")
    print(f"  hub-side kill switch for ONE or ALL nodes (admin token):")
    print(f"    POST /api/control/shutdown-workers   # pushes shutdown_requested")
    print()

def cmd_status(args) -> None:
    pid = read_pid(); st = read_state()
    _nag_if_behind()

    # ── agent ────────────────────────────────────────────────────────────
    _section("🤖", "agent")
    if pid:
        _kv("state", _good("running"))
        _kv("pid", pid)
        up = int(time.time()) - st.get("started_at", int(time.time()))
        _kv("uptime", _humanize_secs(up))
        rss = _process_rss_kb(pid)
        if rss:
            _kv("memory", f"{rss/1024:.1f} MB")
        _kv("worker", st.get("worker_id") or "(not registered yet)")
        if st.get("last_heartbeat"):
            age = int(time.time()) - int(st["last_heartbeat"])
            _kv("heartbeat", f"{_ago(st['last_heartbeat'])}"
                + (_meh("stale") if age > HEARTBEAT_S * 3 else _good("fresh")))
        _kv("last status", st.get("last_status", "?"))
        if st.get("last_error"):
            _kv("last error", _bad(str(st.get("last_error"))[:70]))
    else:
        _kv("state", _bad("stopped"))
        _hint(f"start it: {APP} start")

    # ── volunteer mode ──────────────────────────────────────────────────
    # This decides whether the node can be handed anyone else's work. It used
    # to be invisible here, which is how a node ends up registered,
    # heartbeating, and silently claiming nothing — the hub only nudges nodes
    # advertising `exec-jobs-v1`, which the CLI adds only when share_cpu is on.
    _section("🤝", "volunteer mode")
    vol = _volunteer_load()
    tier = _sandbox_tier()
    _kv("sandbox", _good(f"{tier} ✓") if tier != "rlimit"
        else _bad("rlimit — NO jail (docker/bwrap not found)"))
    if vol.get("share_cpu"):
        _kv("sharing", _good("ON"))
        _kv("limits", f"{int(vol.get('max_parallel', 1))} job(s) at once · "
                      f"{int(vol.get('max_cpu_pct', 25))}% cpu · "
                      f"{int(vol.get('max_mem_mb', 1024))} MB")
        if tier == "rlimit":
            _hint("⚠ foreign jobs are REFUSED until you install a sandbox "
                  "(docker or bubblewrap), then: blnq restart")
        else:
            _hint("the hub may send you other people's code to run")
    else:
        _kv("sharing", _meh("OFF"))
        _kv("effect", "runs only your own code — no jobs from the hub")
        _hint(f"opt in: {APP} volunteer on")

    # ── hub ─────────────────────────────────────────────────────────────
    _section("🌐", "hub")
    _kv("url", HUB)
    t0 = time.time()
    code, payload = do_http("GET", "/api/stats", timeout=5)
    ms = int((time.time() - t0) * 1000)
    if code != 200 or not isinstance(payload, dict):
        _kv("reachable", _bad(f"HTTP {code} ({ms}ms)"))
        _hint(f"is the hub up? {APP} debug \"cannot reach the hub\"")
        return
    _kv("reachable", _good(f"yes · {ms}ms"))

    # A raw key dump reads like a JSON blob fell over. These are the numbers
    # people actually come here for, so name them and drop the rest — the full
    # set is one request away in `blnq health --json`.
    _section("📊", f"{HUB_NAME} network")
    interesting = [
        ("runs",        "totalRuns",        "🏃"),
        ("users",       "totalUsers",       "👥"),
        ("machines",    "workersOnline",    "🖥️ "),
        ("scripts",     "scripts",          "📜"),
        ("attestations","attestations",     "🛡️ "),
        ("jobs",        "jobsFinished",     "✅"),
        ("quorum",      "quorumThreshold",  "🔐"),
    ]
    shown = 0
    for label, key, emo in interesting:
        if key in payload:
            v = payload[key]
            print(f"    {emo} {label:<13} {v}")
            shown += 1
    if not shown:
        _hint(f"full payload: {APP} health --json")

    print()

def cmd_logs(args) -> None:
    n = args.n or 50
    if not LOG_FILE.exists(): die(f"no log file at {LOG_FILE} — start the agent first")
    if args.follow:
        with LOG_FILE.open() as f:
            data = f.readlines()[-n:]
            sys.stdout.write("".join(data)); sys.stdout.flush()
            while True:
                line = f.readline()
                if not line: time.sleep(0.2); continue
                sys.stdout.write(line); sys.stdout.flush()
    else:
        with LOG_FILE.open("rb") as f:
            try: f.seek(0, os.SEEK_END); size = f.tell()
            except OSError: size = 0
            f.seek(max(0, size - 64*1024))
            data = f.read().decode("utf-8", errors="replace")
        sys.stdout.write("\n".join(data.splitlines()[-n:]) + "\n")

def cmd_free(args) -> None:
    print(f"  hub:           {HUB}")
    mi = _meminfo_kb()
    if not mi and IS_WIN:
        wm = _win_mem_mb()
        if wm:
            total_mb, avail_mb = wm
            print(f"  mem:           {(total_mb-avail_mb)/1024:.1f}G used / {total_mb/1024:.1f}G total ({avail_mb/1024:.1f}G avail)")
    elif mi:
        total = int(mi.get("MemTotal", 0)); free = int(mi.get("MemAvailable", mi.get("MemFree", 0))); used = total - free
        print(f"  mem:           {used/1024/1024:.1f}G used / {total/1024/1024:.1f}G total ({free/1024/1024:.1f}G avail)")
        sw_total = int(mi.get("SwapTotal", 0)); sw_free = int(mi.get("SwapFree", 0))
        if sw_total:
            print(f"  swap:          {(sw_total-sw_free)/1024/1024:.1f}G used / {sw_total/1024/1024:.1f}G total")
    print(f"  disk (~):      {_disk(str(STATE_DIR))}  on {STATE_DIR}")
    pid = read_pid()
    print(f"\n  agent:         {'running (pid '+str(pid)+')' if pid else 'stopped'}")
    if pid:
        rss = _process_rss_kb(pid)
        if rss: print(f"  rss:           {rss/1024:.1f} MB")

def cmd_pct(args) -> None:
    def sample():
        pid = read_pid()
        if not pid: return f"{time.strftime('%H:%M:%S')}  blnq:  not running"
        rss = _process_rss_kb(pid) or 0
        try:
            with open(f"/proc/{pid}/stat"): pass
            cpu_pct = _quick_cpu_pct(pid)
        except OSError: cpu_pct = 0.0
        return f"{time.strftime('%H:%M:%S')}  blnq:  cpu={cpu_pct:5.1f}%  mem={rss/1024:6.1f}MB  pid={pid}"
    if args.watch <= 0: print(sample()); return
    try:
        while True: print(sample(), flush=True); time.sleep(args.watch)
    except KeyboardInterrupt: return

def _quick_cpu_pct(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/stat") as f: s = f.read().split()
        with open("/proc/stat")     as f: t = f.readline().split()
        return max(0.0, min(100.0, (int(s[13]) + int(s[14])) / max(1, sum(int(x) for x in t[1:])) * 100))
    except (OSError, ValueError, IndexError): return 0.0

def cmd_info(args) -> None:
    _nag_if_behind()
    print(f"  app:           {APP}")
    print(f"  version:       {VERSION}")
    print(f"  hub:           {HUB} ({HUB_NAME})")
    print(f"  install:       {INSTALL_DIR / (APP + '-cli.py')}")
    print(f"  bin:           {BIN_DIR / APP}")
    print(f"  config:        {CONFIG_DIR}")
    print(f"  state:         {STATE_DIR}")
    print(f"  log:           {LOG_FILE}")
    print(f"  pid:           {PID_FILE}")
    print(f"  heartbeat_s:   {HEARTBEAT_S}")
    st = read_state()
    print(f"  transport:     {st.get('transport', 'heartbeat-only')}   {'(Phase A 2-way comms active)' if st.get('transport') == 'long-poll' else '(1-way only — hub does not support inbox)'}")
    print(f"  hw_id:         {_machine_id() or '(unavailable)'}")
    code, payload = do_http("GET", "/api/stats", timeout=5)
    print(f"  auth_token:    {'set (in ' + str(AUTH_FILE) + ', mode 0600)' if AUTH_FILE.exists() else 'NOT SET'}")
    print(f"  signed:        {'yes' if not (read_state() or {}).get('auth_rejected') else 'no (hub does not support auth headers)'}")
    print(f"  hub_stats:     {code} {payload if code != 200 else ''}")

def _rc_file() -> Path:
    """The rc file this shell family reads. Mirrors install-blnq.sh."""
    sh = os.environ.get("SHELL", "")
    if sh.endswith("/zsh"):
        return Path.home() / ".zshrc"
    if sh.endswith("/fish"):
        return Path.home() / ".config" / "fish" / "config.fish"
    return Path.home() / ".bashrc"


def _path_line(bin_dir: str) -> str:
    """Idempotent PATH entry — the case-guard means re-running never duplicates it."""
    if os.environ.get("SHELL", "").endswith("/fish"):
        return f"fish_add_path {bin_dir}"
    return (f'case ":$PATH:" in *":{bin_dir}:"*) ;; '
            f'*) export PATH="{bin_dir}:$PATH" ;; esac')


def ensure_path(persist: bool = True) -> str:
    """Make sure this install's bin dir is reachable, repairing the rc if not.

    Lives in `update` because machines installed before the installer learned to
    persist PATH can NEVER be fixed by reinstalling the old way — so `blnq update`
    (and its `upgrade` alias) repairs PATH for them instead.

    A child process cannot change its parent shell's PATH; only the rc file can.
    So the honest return value always says which of the two is still needed —
    callers must tell the user to `source` rather than imply it already happened.
    """
    bin_dir = str(BIN_DIR)
    if bin_dir in os.environ.get("PATH", "").split(os.pathsep):
        return "on PATH"
    if not persist:
        return "NOT on PATH"
    rc = _rc_file()
    try:
        rc.parent.mkdir(parents=True, exist_ok=True)
        existing = rc.read_text(encoding="utf-8") if rc.exists() else ""
        if bin_dir in existing:
            return f"already recorded in {rc} (not on PATH in this shell)"
        with rc.open("a", encoding="utf-8") as fh:
            fh.write(f"\n# {APP} CLI - added by `{APP} update`\n{_path_line(bin_dir)}\n")
        return f"added to {rc}"
    except Exception as e:
        return f"NOT on PATH, and could not write {rc}: {e}"


def _fetch_changelog() -> list:
    """Fetch /changelog.json — newest-first list of versions.

    Best-effort by design: the changelog is printed AFTER a successful update,
    so a missing or malformed file must never turn a good update into a
    failure. Every failure path returns [].
    """
    try:
        code, p = do_http("GET", "/changelog.json", sign=False, timeout=8)
        if code == 200 and isinstance(p, dict) and isinstance(p.get("versions"), list):
            return [e for e in p["versions"] if isinstance(e, dict)]
    except Exception:
        pass
    return []


_KIND_MARK = {"added": "+", "fixed": "\u2713", "changed": "~", "removed": "-",
              "security": "!", "docs": "\u00b7", "improved": "~"}
_KIND_COL = {"added": "32", "fixed": "36", "changed": "33", "removed": "31",
             "security": "31", "docs": "2", "improved": "33"}


def _render_changelog(entries: list, from_ver: str = "", head: str = "") -> None:
    """Print entries with their rationale. House style: title, then rows."""
    if not entries:
        return
    width = max(58, min(100, shutil.get_terminal_size((80, 20)).columns - 2))
    newest = str(entries[0].get("version") or "?")
    # _title() already prefixes APP, so the title must not repeat it.
    title = "changelog"
    if from_ver:
        title = f"{title}  {from_ver} \u2192 {newest}"
    _title(title, head or "what changed, and why")
    print()

    for e in entries:
        ver = str(e.get("version") or "?")
        date = str(e.get("date") or "")
        stamp = f"  \033[2m{date}\033[0m" if date else ""
        print(f"  {_hdr('v' + ver)}{stamp}")
        summary = str(e.get("summary") or "").strip()
        if summary:
            for line in textwrap.wrap(summary, width - 4):
                print(f"    \033[2m{line}\033[0m")
        for c in (e.get("changes") or []):
            if not isinstance(c, dict):
                continue
            kind = str(c.get("kind") or "changed").lower()
            mark = _KIND_MARK.get(kind, "~")
            col = _KIND_COL.get(kind, "33")
            what = str(c.get("what") or "").strip()
            why = str(c.get("why") or "").strip()
            body = textwrap.wrap(what, width - 8) if what else []
            if body:
                print(f"    \033[{col}m{mark}\033[0m {body[0]}")
                for line in body[1:]:
                    print(f"      {line}")
            if why:
                wrapped = textwrap.wrap(why, width - 14)
                if wrapped:
                    print(f"      \033[2mwhy: {wrapped[0]}\033[0m")
                    for line in wrapped[1:]:
                        print(f"            \033[2m{line}\033[0m")
            # Optional verbatim example: real commands and real output, shown
            # as a dim ruled block. "What changed" lands better with "here is
            # exactly what it looks like."
            ex = str(c.get("example") or "").rstrip()
            if ex:
                for line in ex.split("\n"):
                    print(f"      \033[2m│ {line}\033[0m")
        print()


def _print_changelog_since(old_version: str, head: str = "") -> bool:
    """Show entries NEWER than old_version. Returns True if anything printed."""
    entries = [e for e in _fetch_changelog()
               if _parse_ver(str(e.get("version") or "0")) > _parse_ver(old_version)]
    if not entries:
        return False
    _render_changelog(entries, from_ver=old_version, head=head)
    return True


def cmd_changelog(args) -> None:
    """Show what changed and why — newest first, or since a version."""
    as_json = bool(getattr(args, "json", False))
    since = getattr(args, "since", None)
    limit = int(getattr(args, "limit", 0) or 3)

    entries = _fetch_changelog()
    if not entries:
        # Never pretend: an unreachable changelog is reported, not skipped.
        warn("changelog unavailable — could not reach the hub")
        die(f"  fetch it yourself: {HUB.rstrip('/')}/changelog.json", code=2)

    if since:
        entries = [e for e in entries
                   if _parse_ver(str(e.get("version") or "0")) > _parse_ver(since)]
    elif limit > 0:
        entries = entries[:limit]

    if as_json:
        print(json.dumps({"versions": entries}, indent=2))
        return
    if not entries:
        ok(f"nothing newer than {since} — you are current at v{VERSION}")
        return
    _render_changelog(entries, from_ver=str(since or ""),
                      head=f"you are on v{VERSION}")


def cmd_update(args) -> None:
    url = getattr(args, "from_url", None) or f"{HUB.rstrip('/')}/blnq-cli.py"
    sha = getattr(args, "sha256", None)
    if not sha:
        # Default to the hub's published digest of the artifact it serves. The
        # whole point of the trust layer is that code is checked before it runs —
        # and this is the one path that REPLACES the code, so it used to be the
        # single place nothing was checked. It cannot defend against a fully
        # compromised hub (that would serve its own digest too) but it does catch
        # truncation, stale CDN/mirror copies and bit-rot in transit.
        try:
            code, meta = do_http("GET", "/api/version", timeout=8, sign=False)
            if code == 200 and isinstance(meta, dict):
                sha = meta.get("sha256") or None
        except Exception:
            sha = None
        if not sha:
            warn("hub published no digest — falling back to TLS only")
    else:
        log(f"expecting sha256 {sha[:16]}…")
    log(f"fetching {url}")
    try:
        data = _http_get_bytes(url, timeout=30)
    except Exception as e:
        # The updater is the thing that just failed, so its advice must not
        # depend on the updater working. Give the raw download instead.
        die(f"download failed: {e}\n"
            f"  escape hatch (does not use this updater):\n"
            f"    curl -fsSL {url} -o {Path(__file__).resolve()}")
    # `ok` must NOT be reused as a variable name: it shadows the ok() printer
    # defined at module scope, so the very next line (`ok(...)`) raised
    # TypeError: 'bool' object is not callable — after the update had already
    # been applied, leaving the user with a traceback and no success message.
    updated, msg, target = _apply_update(data, expected_sha256=sha, source="cli")
    if not updated:
        die(f"{msg}\n"
            f"  escape hatch (does not use this updater):\n"
            f"    curl -fsSL {url} -o {Path(__file__).resolve()}", code=20)
    ok(f"{msg} → {target}")
    # Tell the user what they just installed. VERSION here belongs to the
    # RUNNING process — the pre-update code — so it is exactly the version to
    # diff from. Best-effort: a missing changelog must not fail a good update.
    if not _print_changelog_since(VERSION, head="just installed"):
        log(f"hub published no changelog entry newer than v{VERSION}")

    # PATH repair: this is how installs made before the installer persisted PATH
    # get fixed — they cannot benefit from reinstalling the old way.
    _pstate = ensure_path()
    if _pstate == "on PATH":
        ok(f"path: {_pstate}")
    else:
        warn(f"path: {_pstate}")
        print(f"      then: source {_rc_file()}     # a child process can't change the shell that started it")
    if read_pid(): log("restarting agent"); cmd_stop(args, quiet=True); cmd_start(args)

def cmd_uninstall(args) -> None:
    """Stop the agent, disable everything that would RESPAWN it, remove the
    code — credentials/logs kept by default, `--purge` for the lot.

    Two bugs the first version had (found 2026-11-19):
      * keepalive/autostart were left armed → the timer happily respawned a
        NOW-MISSING script every ≤5min forever (an error loop nobody sees);
      * stale update artifacts stayed behind — `blnq-cli.py.bak` (111KB of a
        PREVIOUS version's code) was still on disk after "uninstall".
    Default keeps: config (auth/session/contribute/authz), KEYS, state, logs
    and authz-history — a reinstall should find your identity, not lose it.
    `--purge` removes those too, only after an explicit confirmation,
    because the private keys are UNRECOVERABLE: attestations signed with
    them stay valid forever, but this machine can never sign again.
    """
    purge = bool(getattr(args, "purge", False))
    yes = bool(getattr(args, "yes", False))

    # ── 1. stop the agent, then disarm EVERY respawn path ──────────────────
    try:
        if read_pid():
            cmd_stop(args)
    except SystemExit:
        pass
    except Exception as e:
        warn(f"stop reported: {e}")
    try:
        PID_FILE.unlink()
    except OSError:
        pass
    for fn, label in ((cmd_keepalive, "keepalive"), (cmd_autostart, "autostart")):
        try:
            fn(argparse.Namespace(action="off"))
        except SystemExit as e:
            if e.code not in (0, None):
                warn(f"{label} disable exited {e.code} — check `{APP} {label} status`")
        except Exception as e:
            warn(f"could not disable {label}: {e} — check `{APP} {label} status`")

    # ── 2. remove the CODE (installed client, wrapper, update leftovers) ───
    targets = [INSTALL_DIR / f"{APP}-cli.py", BIN_DIR / APP,
               BIN_DIR / f"{APP}.cmd"]           # windows wrapper, if present
    for suffix in (".bak", ".new", ".bad"):      # update rollback artifacts
        targets.append(INSTALL_DIR / f"{APP}-cli.py{suffix}")
    pyc = INSTALL_DIR / "__pycache__"
    try:
        if pyc.is_dir():
            targets.extend(pyc.iterdir())
            targets.append(pyc)
    except OSError:
        pass
    for p in targets:
        try:
            if p.exists():
                p.unlink() if p.is_file() else shutil.rmtree(p, ignore_errors=True)
                log(f"removed {p}")
        except OSError as e:
            warn(f"could not remove {p}: {e}")
    try:
        INSTALL_DIR.rmdir()   # only if now empty — never deletes strangers' files
    except OSError:
        pass

    # ── 3. purge (opt-in, confirmed): config + keys + state + history ──────
    if purge:
        victims = [d for d in (CONFIG_DIR, STATE_DIR) if d.exists()]
        if victims and not yes:
            if not sys.stdin.isatty():
                die("--purge needs --yes when there is no TTY to confirm on")
            print("\033[33mThis removes EVERYTHING local:\033[0m")
            for d in victims:
                for f in sorted(d.rglob("*")):
                    if f.is_file():
                        print(f"    {f}")
            print("\n\033[33mThe private keys among them are UNRECOVERABLE — "
                  "past attestations stay valid, but this machine can never "
                  "sign again, and a reinstall gets a NEW identity.\033[0m")
            if input("type PURGE to continue: ").strip() != "PURGE":
                die("purge aborted — nothing was removed")
        for d in victims:
            try:
                shutil.rmtree(d)
                log(f"purged {d}")
            except OSError as e:
                warn(f"could not remove {d}: {e}")
        ok(f"uninstalled + PURGED (config, keys, state, logs, history gone)")
        return

    kept = [str(d) for d in (CONFIG_DIR, STATE_DIR) if d.exists()]
    ok(f"uninstalled (code removed"
       + (f"; kept {', '.join(kept)}" if kept else "")
       + ")")
    _hint(f"remove credentials/history too: {APP} uninstall --purge "
          f"(the private keys are unrecoverable once purged)")


# ── one-shot commands ──────────────────────────────────────────────────
def _print(payload, code):
    if isinstance(payload, (dict, list)):
        print(json.dumps(payload, indent=2))
    else:
        print(payload)
    sys.exit(0 if code == 200 else 2)

def cmd_health(args) -> None:
    code, p = do_http("GET", "/api/stats"); _print(p, code)

def cmd_whoami(args) -> None:
    code, me = do_http("GET", "/api/user/me", timeout=10, sign=False)
    if code == 200 and isinstance(me, dict) and me.get("id"):
        cc, cred = do_http("GET", "/api/user/credits", timeout=10, sign=False)
        print(f"  hub:     {HUB}")
        print(f"  account: {me.get('name') or me.get('email')}  ({me.get('email')})")
        print(f"  provider:{me.get('provider')}  id: {me.get('id')}")
        if cc == 200 and isinstance(cred, dict):
            print(f"  credits: {cred.get('credits')}")
        sys.exit(0)
    code, p = do_http("GET", "/api/stats", timeout=5)
    warn("not logged in (hub liveness instead) — `blnq login` to see your account")
    print(f"hub={HUB}  status={code}  payload={p}"); sys.exit(0 if code == 200 else 2)

def cmd_metrics(args) -> None:
    if getattr(args, "local", False):
        _print_metrics_local(_collect_metrics())
        return
    code, p = do_http("GET", "/api/stats"); _print(p, code)

def _ok(s): return f"\033[32m✓\033[0m {s}"
def _warn(s): return f"\033[33m!\033[0m {s}"
def _fail(s): return f"\033[31m✗\033[0m {s}"


# ── evaluate: study a codebase and find where blnq can run it ───────────────
_EVAL_SKIP = frozenset({
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".eggs",
    ".next", "target", "site-packages", ".artifacts", ".deploy-backups",
    "backups", "logs",
})

# modules that mean "this wants the network" / "a database" / "a display"
_EVAL_NET = frozenset({"urllib", "httpx", "requests", "aiohttp", "socket",
                       "ssl", "http", "ftplib", "smtplib", "telnetlib",
                       "xmlrpc"})
_EVAL_DB = frozenset({"psycopg2", "psycopg", "sqlalchemy", "pymongo", "redis",
                      "pymysql", "mysql", "asyncpg"})
_EVAL_WEB = frozenset({"flask", "django", "fastapi", "starlette"})
_EVAL_UI = frozenset({"tkinter", "pygame", "PyQt5", "PySide6", "wx"})
_EVAL_PAR = frozenset({"multiprocessing", "concurrent", "joblib", "ray", "dask"})

# severity order — the first blocker present becomes the file's verdict
_EVAL_ORDER = ("package", "netwrite", "network", "database", "web", "ui", "deps")
_EVAL_WHY = {
    "package":  "relative imports — give it a __main__ entry point",
    "netwrite": "sends data (POST/PUT/…) — the egress proxy allows GET/HEAD "
                "only, so this would be refused at the socket",
    "network":  "wants the network — routed through the gated egress proxy "
                "(GET/HEAD, mission list, robots.txt, audited) when egress is "
                "enabled; with no egress the sandbox has no network at all",
    "database": "wants a database — unreachable from the sandbox",
    "web":      "is a web service — long-running, not a job",
    "ui":       "has a GUI — no display in the sandbox",
    "deps":     "third-party imports — needs the container tier",
}
_EVAL_LIMIT = 3000

# ── network evidence: imports are NOT the only door ────────────────────────
# Audit 2026-11-19: B04 ran `curl` through subprocess and B07 did
# `importlib.import_module("urllib.request")` — both came back RUNNABLE and
# 0-finding from every import-based gate, because facts["network"] only read
# import statements. These sniffers look for the *behaviour shapes*: URL
# literals, shell network binaries, module names as strings, and write
# methods (POST/PUT/…) that the egress proxy will refuse outright.
#
# They are deliberately conservative (a false "needs network" is annoying; a
# false "clear" is a gate that waves evil through) and every match is carried
# forward as human-readable EVIDENCE so the verdict always says why.

_NET_MODULES = frozenset({
    "urllib", "urllib2", "requests", "httpx", "aiohttp", "socket", "ssl",
    "http", "ftplib", "smtplib", "telnetlib", "xmlrpc", "websocket",
    "websockets", "urllib3", "paramiko", "pycurl", "dns", "httpie",
})

_URL_RE = re.compile(r"\b(?:https?|ftp|wss?)://[^\s'\"<>)\]}]*", re.I)
# a quoted string that is ONLY a scheme — the classic `u = "https://" + host`
# concat, and the split form `base = "https:"; u = base + "//" + host`
_SCHEME_CONCAT_RE = re.compile(r"""["']https?:/{0,2}["']""")
_NET_CMD_RE = re.compile(
    r"(?<![\w./-])(?:curl|wget|ncat|netcat|socat|aria2c|axel|scp|sftp|nmap|"
    r"telnet|ping)(?![\w-])")
# module names appearing as STRINGS (importlib, __import__, shelve…)
_NET_MODSTR_RE = re.compile(
    r"""['"](?:urllib(?:\.[\w]+)*|requests|httpx|aiohttp|socket|http\.client|"""
    r"""httplib|ftplib|smtplib|telnetlib|xmlrpc(?:\.[\w]+)*|websockets?|"""
    r"""paramiko|pycurl|scrapy|httpie)['"]""")

# per-family read-network signatures (the family's own idioms)
_FAM_NET_RE = {
    "node": re.compile(r"(?<![.\w])(?:fetch|axios)\s*\(|https?\.(?:get|post|request|"
                       r"createServer)\s*\(|require\s*\(\s*['\"]node:?(?:http|https|"
                       r"net|dns|dgram|tls)['\"]|\bWebSocket\s*\(|XMLHttpRequest"),
    "c":    re.compile(r"#\s*include\s*<(?:sys/socket|netdb\.h|curl/)|"
                       r"\b(?:getaddrinfo|gethostbyname|curl_easy\w*)\s*\("),
    "go":   re.compile(r'"net/http"|"net/url"|http\.(?:Get|Post|ListenAndServe)\b|'
                       r'\bnet\.Dial\b'),
    "php":  re.compile(r"\b(?:fsockopen|curl_init|curl_exec|stream_socket_client)\s*\(|"
                       r"file_get_contents\s*\(\s*['\"]https?://", re.I),
    "perl": re.compile(r"\b(?:LWP::|IO::Socket|HTTP::Request|WWW::Mechanize)\b"),
    "ruby": re.compile(r"require\s*['\"](?:net/http|socket|open-uri)['\"]|"
                       r"\b(?:Net::HTTP|TCPSocket|open-uri)\b"),
}

# per-family WRITE-method signatures — the proxy refuses everything that is
# not GET/HEAD (egressPolicy.evaluate: `method not allowed — jobs may only
# read`), so these are a guaranteed-to-fail-remotely shape, not a style note.
_FAM_WRITE_RE = {
    "python": re.compile(r"\.post\s*\(|\.put\s*\(|\.patch\s*\(|\.delete\s*\(|"
                         r"method\s*=\s*[\"'](?:POST|PUT|PATCH|DELETE)[\"']"),
    "node":   re.compile(r"method\s*:\s*[\"'](?:POST|PUT|PATCH|DELETE)[\"']|"
                         r"\.(?:post|put|patch)\s*\("),
    "shell":  re.compile(r"-X\s*(?:POST|PUT|PATCH|DELETE)\b|--data(?:-binary|-raw|-urlencode)?"
                         r"[=\s]|--form[=\s]|\s-d\s+[\"']|--upload-file|\s-T\s"),
    "c":      re.compile(r"CURLOPT_(?:POST|PUT|UPLOAD|CUSTOMREQUEST)\b"),
    "go":     re.compile(r"http\.(?:Post|Put|Patch|NewRequest)\s*\(\s*[\"'](?:POST|PUT|PATCH)"),
    "php":    re.compile(r"CURLOPT_(?:POST|PUT|UPLOAD)\b|"
                         r"['\"](?:POST|PUT|PATCH)['\"]\s*,\s*\$"),
    "perl":   re.compile(r"HTTP::Request::Common::(?:POST|PUT)\b|->post\b"),
    "ruby":   re.compile(r"\bNet::HTTP(?:::Post|::Put)?\b.*\bpost\b|\.post\s*\("),
}

def _lang_family(lang: str) -> str:
    """Map a declared language to a sniffing family."""
    lang = (lang or "python").lower()
    if lang in ("python",): return "python"
    if lang in ("node", "javascript", "js"): return "node"
    if lang in ("bash", "sh"): return "shell"
    if lang in ("c", "cpp", "c++"): return "c"
    if lang == "go": return "go"
    if lang == "php": return "php"
    if lang == "perl": return "perl"
    if lang == "ruby": return "ruby"
    return "other"

def _lang_of(pathname: str) -> str:
    """Language for a file path (reverse of _SCRIPT_EXT; default python)."""
    ext = os.path.splitext(str(pathname))[1].lower()
    if not ext:
        return "python"
    for lang, e in _SCRIPT_EXT.items():
        if e == ext:
            return lang
    return "python" if ext in (".py", ".pyw") else "unknown"

def _net_evidence(text: str, lang: str = "python") -> list:
    """Why this code wants the network (import-independent). Empty = no
    signal found. Text-level on purpose: it runs on files that do not parse
    and on languages we cannot AST-walk."""
    ev = []
    m = _URL_RE.search(text)
    if m:
        ev.append(f"URL literal ({m.group(0)[:40]})")
    if not m and _SCHEME_CONCAT_RE.search(text):
        ev.append("URL scheme built by concatenation")
    m = _NET_CMD_RE.search(text)
    if m:
        ev.append(f"network command ({m.group(0)})")
    m = _NET_MODSTR_RE.search(text)
    if m:
        ev.append(f"module name as string ({m.group(0)})")
    fam = _lang_family(lang)
    fam_re = _FAM_NET_RE.get(fam)
    if fam_re:
        m = fam_re.search(text)
        if m:
            ev.append(f"{fam} network API ({m.group(0)[:40]})")
    return ev

def _net_write_evidence(text: str, lang: str = "python") -> list:
    """Why this code would be REFUSED by the proxy (non-GET/HEAD)."""
    ev = []
    fam = _lang_family(lang)
    for family in ({fam} | ({"shell"} if fam != "shell" else set())):
        r = _FAM_WRITE_RE.get(family)
        if not r:
            continue
        m = r.search(text)
        if m:
            ev.append(f"write method {m.group(0).strip()[:30]} ({family})")
            break
    return ev


def _eval_file(path: Path, root: Path) -> dict | None:
    """Static analysis of one file: can blnq run it, and if not, why?"""
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    imports, relative = set(), 0
    has_main = has_argparse = side_effects = False
    tree = None
    try:
        tree = ast.parse(src)
    except SyntaxError:
        pass

    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    relative += 1
                elif node.module:
                    imports.add(node.module.split(".")[0])
            elif isinstance(node, ast.If):
                t = node.test
                if (isinstance(t, ast.Compare) and isinstance(t.left, ast.Name)
                        and t.left.id == "__name__"
                        and any(isinstance(c, ast.Constant) and c.value == "__main__"
                                for c in t.comparators)):
                    has_main = True
        # unguarded top-level calls: importing this module runs code
        side_effects = any(isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                           for n in tree.body)
        has_argparse = "argparse" in imports or "click" in imports
    else:
        # unparsable (py2, truncated, generated) — fall back to text sniffing
        has_main = "__main__" in src
        has_argparse = "argparse" in src or "click" in src
        for m in re.findall(r"^\s*(?:import|from)\s+([A-Za-z_][\w.]*)", src, re.M):
            imports.add(m.split(".")[0])

    third = sorted(m for m in imports
                   if m not in _stdlib_names() and m != "__future__")

    # ── network, WITHOUT trusting imports (audit 2026-11-19) ─────────────
    # B04 (`subprocess curl`) and B07 (`importlib.import_module("urllib…")`)
    # both imported nothing on this list. Evidence carries the why; write
    # methods (POST/…) get their own verdict because the proxy REFUSES them.
    file_lang = _lang_of(path.name)
    net_ev = _net_evidence(src, file_lang)
    write_ev = _net_write_evidence(src, file_lang)
    if imports & _EVAL_NET:
        net_ev.append("import " + ", ".join(sorted(imports & _EVAL_NET)))

    blockers = []
    if relative:            blockers.append("package")
    if write_ev:            blockers.append("netwrite")
    if net_ev:              blockers.append("network")
    if imports & _EVAL_NET and not net_ev: blockers.append("network")
    if imports & _EVAL_DB:  blockers.append("database")
    if imports & _EVAL_WEB: blockers.append("web")
    if imports & _EVAL_UI:  blockers.append("ui")
    if third:               blockers.append("deps")
    blockers = list(dict.fromkeys(blockers))   # keep order, drop dupes
    verdict = "ready" if not blockers else _EVAL_ORDER[
        min(_EVAL_ORDER.index(b) for b in blockers)]

    name = path.name.lower()
    is_test = name.startswith("test_") or name.endswith("_test.py") \
        or "tests" in path.parts
    is_service = any(t in src for t in
                     ("serve_forever", "HTTPServer", "app.run(", "uvicorn.run"))
    if is_test:                     pattern = "test"
    elif is_service:                pattern = "service"
    elif has_main and has_argparse: pattern = "cli"
    elif has_main:                  pattern = "pipeline"
    else:                           pattern = "library"

    return {
        "path": str(path.relative_to(root)),
        "loc": src.count("\n") + 1,
        "verdict": verdict,
        "blockers": blockers,
        "pattern": pattern,
        "third_party": third,
        "main": has_main,
        "args": has_argparse,
        "stdin": "sys.stdin" in src or "input(" in src,
        "stdout": "sys.stdout" in src or "print(" in src,
        "parallel": bool(imports & _EVAL_PAR),
        "side_effects": side_effects,
        "parsed": tree is not None,
        "net_evidence": net_ev[:4],
        "net_write_evidence": write_ev[:4],
    }


def _eval_walk(root: Path, limit: int) -> tuple:
    """Walk the tree, skipping vendor/VCS dirs. Returns (files, truncated)."""
    out, seen, truncated = [], 0, False
    try:
        paths = sorted(root.rglob("*.py"))
    except OSError:
        return out, False
    for p in paths:
        if seen >= limit:
            truncated = True
            break
        try:
            rel = p.relative_to(root)
            if any(seg in _EVAL_SKIP for seg in rel.parts):
                continue
            if p.is_symlink() or not p.is_file():
                continue
        except (ValueError, OSError):
            continue
        seen += 1
        r = _eval_file(p, root)
        if r:
            out.append(r)
    return out, truncated


def cmd_evaluate(args) -> None:
    """Study a codebase: where can blnq run it, and what blocks the rest?"""
    from collections import Counter

    raw = getattr(args, "path", None) or "."
    root = Path(raw).expanduser().resolve()
    if not root.exists():
        die(f"no such path: {root}")
    if root.is_file():
        root = root.parent
    limit = int(getattr(args, "limit", 0) or _EVAL_LIMIT)

    files, truncated = _eval_walk(root, limit)
    if not files:
        die(f"no Python files found under {root}")

    verdicts = Counter(f["verdict"] for f in files)
    patterns = Counter(f["pattern"] for f in files)
    ready = sorted((f for f in files if f["verdict"] == "ready"),
                   key=lambda f: -f["loc"])
    total_loc = sum(f["loc"] for f in files)
    pct = (100 * len(ready)) // len(files)

    if getattr(args, "json", False):
        print(json.dumps({
            "root": str(root),
            "files": len(files),
            "truncated": truncated,
            "lines": total_loc,
            "ready": len(ready),
            "ready_pct": pct,
            "verdicts": dict(verdicts),
            "patterns": dict(patterns),
            "blockers": {k: _EVAL_WHY[k] for k in _EVAL_ORDER if verdicts.get(k)},
            "candidates": ready,
            "blocked": [{k: f[k] for k in ("path", "loc", "verdict",
                                           "blockers", "third_party")}
                        for f in files if f["verdict"] != "ready"],
        }, indent=2))
        return

    _title("evaluate", str(root))
    print()
    print(f"  {_hdr('scope')}")
    _kv("python files",
        f"{len(files)}{'   (truncated at limit)' if truncated else ''}")
    _kv("lines", f"{total_loc:,}")
    _kv("patterns", "  ".join(f"{k}={v}" for k, v in patterns.most_common()))

    print()
    print(f"  {_hdr('verdict')}")
    _kv("ready now", f"{len(ready)}   ({pct}%)")
    _kv("blocked", f"{len(files) - len(ready)}")
    if ready:
        _hint(f"{len(ready)} file(s) can run on blnq today")
    else:
        _hint("nothing runnable yet — see blockers below")

    blocked = [(k, verdicts[k]) for k in _EVAL_ORDER if verdicts.get(k)]
    if blocked:
        print()
        print(f"  {_hdr('blockers')}")
        for k, n in blocked:
            _kv(k, f"{n:<6}  {_EVAL_WHY[k]}", width=12)

    pipes = sum(1 for f in ready if f["stdin"] or f["stdout"])
    par = sum(1 for f in files if f["parallel"])
    se = sum(1 for f in files if f["side_effects"] and not f["main"])
    if pipes or par or se:
        print()
        print(f"  {_hdr('opportunities')}")
        if pipes:
            _kv("pipeline", f"{pipes:<6}  ready files that read stdin / write stdout")
        if par:
            _kv("parallel", f"{par:<6}  use multiprocessing/threads -> blnq jobs")
        if se:
            _kv("side effects",
                f"{se:<6}  importing them runs code — guard with __main__")

    if ready:
        print()
        print(f"  {_hdr('try these')}")
        for f in ready[:8]:
            print(f"    {APP} {f['path']}")
        if len(ready) > 8:
            _hint(f"...and {len(ready) - 8} more   (--json for the full list)")
    print()


def cmd_doctor(args) -> None:
    """One-glance health report: install + hub + agent + local bee + version.
    Output is pasteable for support — pure text + ANSI colors only."""
    print(f"\033[1m{APP} doctor\033[0m — {time.strftime('%Y-%m-%d %H:%M:%S')}")
    _nag_if_behind(async_ok=False)
    print(f"hub = {HUB}   client = {VERSION}")

    # --- install -----------------------------------------------------------
    print("\n\033[1minstall\033[0m")
    bin_path = Path(__file__).resolve()
    print(f"  wrapper:  {BIN_DIR / APP}   " + (_ok("exists") if (BIN_DIR / APP).exists() else _fail("MISSING")))
    _onpath = str(BIN_DIR) in os.environ.get("PATH", "").split(os.pathsep)
    print(f"  path:     {BIN_DIR}   " + (_ok("on PATH") if _onpath
          else _warn("NOT on PATH — run `blnq update` to repair it")))
    print(f"  client:   {bin_path}   " + (_ok("exists") if bin_path.exists() else _fail("MISSING")))
    cfg = Path.home() / ".config" / APP
    st  = Path.home() / ".local" / "share" / APP
    print(f"  config:   {cfg}   " + (_ok("exists") if cfg.exists() else _warn("missing (will be created on first run)")))
    print(f"  state:    {st}   " + (_ok("exists") if st.exists() else _warn("missing")))

    # --- sandbox ------------------------------------------------------------
    # The jail that protects THIS machine from other people's code. Without
    # one, volunteer mode is refused (fail closed) — that is a feature.
    print("\n\033[1msandbox\033[0m")
    tier = _sandbox_tier()
    if tier == "rlimit":
        print(f"  {_fail('rlimit only — NO jail')}   volunteer jobs: {_fail('refused')}")
        print("  install one, then `blnq restart`:")
        print("    Linux:  sudo apt install bubblewrap   (or docker.io)")
        print("    macOS:  Docker Desktop · OrbStack · colima (brew install colima docker)")
    else:
        print(f"  {_ok(tier + ' jail')}   volunteer jobs: {_ok('allowed')}")

    # --- hub ---------------------------------------------------------------
    print("\n\033[1mhub\033[0m")
    try:
        t0 = time.time()
        code, p = do_http("GET", "/api/stats", timeout=5)
        ms = int((time.time() - t0) * 1000)
        if code == 200:
            users = (p or {}).get("totalUsers", "?") if isinstance(p, dict) else "?"
            print(f"  {_ok(f'{HUB} reachable ({ms}ms)')}   total users: {users}")
            if isinstance(p, dict):
                # AI endpoint chain health (one line per configured endpoint)
                ai = p.get("ai")
                if isinstance(ai, dict) and ai.get("endpoints"):
                    for ep in ai["endpoints"]:
                        stt = ep.get("state")
                        sym = _ok if stt == "ok" else (
                            _warn if stt in ("unknown", "cooling-down") else _fail)
                        label = f"ai {ep.get('url')} {stt}"
                        err = f"  {ep.get('lastError')}" if (
                            stt != "ok" and ep.get("lastError")) else ""
                        print(f"  {sym(label)}{err}")
                elif ai is None:
                    print(f"  {_warn('ai health: unknown (hub build predates it)')}")
                # Safety ladder: how the last 7 days were actually decided
                saf = p.get("safety")
                if isinstance(saf, dict) and saf.get("sources"):
                    srcs = saf["sources"]
                    line = ", ".join(f"{k}={v}" for k, v in sorted(srcs.items()))
                    fb = saf.get("fallback_runs") or 0
                    print(f"  ladder 7d: {line}" + (f"   \033[33m← {fb} on fallback\033[0m" if fb else ""))
        else:
            print(f"  {_fail(f'{HUB} returned HTTP {code}')}")
    except Exception as e:
        print(f"  {_fail(f'{HUB} unreachable: {e}')}")

    # --- egress (gated network for docker jobs) ----------------------------
    try:
        ce, pe = do_http("GET", "/api/egress/status", timeout=4)
        if ce == 200 and isinstance(pe, dict):
            ready = bool(pe.get("on") and pe.get("ready"))
            state = "on/ready" if ready else (
                "off" if not pe.get("on") else f"on but NOT ready ({pe.get('detail')})")
            lan = ", ".join(pe.get("allow_lan") or []) or "none"
            print(f"  {_ok('egress ' + state) if ready else _warn('egress ' + state)}"
                  f"   allow-lan: {lan}")
        else:
            print(f"  {_warn('egress: not available on this hub (old build)')}")
    except Exception:
        print(f"  {_warn('egress: could not fetch status')}")

    # --- agent -------------------------------------------------------------
    print("\n\033[1magent\033[0m")
    pid = read_pid()
    if pid and pid_alive(pid):
        st_data = read_state() or {}
        wid = st_data.get("worker_id") or "?"
        hb = st_data.get("last_heartbeat") or 0
        hb_age = int(time.time()) - hb if hb else -1
        hb_str = f"{hb_age}s ago" if hb_age >= 0 else "never"
        print(f"  {_ok(f'running (pid {pid}, worker {wid})')}   last heartbeat: {hb_str}")
    else:
        print(f"  {_warn('not running')}   start with `{APP} start`")

    # --- local bee ---------------------------------------------------------
    print("\n\033[1mlocal bee\033[0m")
    m = _collect_metrics()
    print(f"  cpu:  {m.get('cpu_count','?')} cores, load {m.get('load_1','?')}/{m.get('load_5','?')}/{m.get('load_15','?')}")
    print(f"  mem:  {m.get('mem_used_mb','?')}/{m.get('mem_total_mb','?')} MB ({m.get('mem_pct','?')}%)")
    print(f"  disk: {m.get('disk_used_gb','?')}/{m.get('disk_total_gb','?')} GB ({m.get('disk_pct','?')}%)")
    gpus = m.get("gpus") or []
    if gpus:
        for g in gpus:
            print(f"  gpu:  [{g['index']}] {g['name']}  util={g['util_pct']}%  mem={g['mem_used_mb']}/{g['mem_total_mb']} MB  temp={g.get('temp_c','?')}°C")
    else:
        print(f"  gpu:  (none detected — nvidia-smi missing or no NVIDIA GPU)")

    # --- update check ------------------------------------------------------
    print("\n\033[1mupdate\033[0m")
    try:
        req = urllib.request.Request(f"{HUB.rstrip('/')}/{APP}-cli.py", headers={"user-agent": f"{APP}/{VERSION}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = r.read().decode("utf-8", errors="replace")
        import re as _re
        match = _re.search(r'VERSION\s*=\s*"([^"]+)"', data)
        hub_ver = match.group(1) if match else "unknown"
        if hub_ver == VERSION:
            print(f"  {_ok(f'up to date (client {VERSION} = hub {hub_ver})')}")
        else:
            arrow = "↑ newer on hub" if hub_ver > VERSION else "↓ local is newer"
            print(f"  {_warn(f'client {VERSION} vs hub {hub_ver}')}   {arrow}   run `{APP} update`")
    except Exception as e:
        print(f"  {_warn(f'could not check hub version: {e}')}")

    print()  # trailing newline

def _num(v, cap: int = 120):
    """Make a measurement safe for the trust layer's canonical JSON.

    That canonicalizer deliberately forbids floats — it is exactly WHY Node,
    Python and the browser produce byte-identical signatures — so a speed report
    must not smuggle one in. Fractions therefore travel as ASCII strings; Postgres
    casts them to numeric for sorting and medians, so no consumer loses precision.
    """
    if v is None or isinstance(v, bool) or isinstance(v, int):
        return v
    if isinstance(v, str):
        return v[:cap]
    try:
        f = float(v)
    except (TypeError, ValueError):
        return str(v)[:cap]
    if f != f or f in (float("inf"), float("-inf")):   # NaN / inf
        return None
    out = f"{f:.3f}".rstrip("0").rstrip(".")
    return out if out else "0"


def _key_fingerprint(raw_pub: bytes) -> str:
    """OpenSSH-style fingerprint: SHA256:<unpadded base64 of sha256(pub)>.

    Deliberately the exact format ssh-keygen prints, so it reads as a real key
    and can be compared by eye against one. A fingerprint a human can eyeball is
    worth more than a hex blob nobody looks at twice.
    """
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw_pub).digest()).decode().rstrip("=")


def _measure_bandwidth(timeout: float = 30.0) -> dict:
    """Throughput to the hub — the path a job's code and output actually travel.

    Deliberately NOT a generic speed-test server: a fast link to some CDN and a
    bad link to blnq still runs slowly here. This measures the real hop,
    Cloudflare included, because that hop is in the real path.
    """
    out = {}
    try:
        t0 = time.perf_counter()
        data = _http_get_bytes(f"{HUB.rstrip('/')}/api/nodes/blob?bytes=2000000", timeout=timeout)
        dt = max(time.perf_counter() - t0, 1e-9)
        mbps = round(len(data) * 8 / dt / 1e6, 1)
        out["download_bytes"], out["download_mbps"] = len(data), mbps
        _rate = f"{mbps} Mbps"
        print(f"  down  {len(data)/1e6:.1f} MB   {_ok(_rate)}   ({dt*1000:.0f}ms)")
    except Exception as e:
        print(f"  down  {_fail(str(e)[:70])}")
    try:
        buf = bytes(1_000_000)
        t0 = time.perf_counter()
        code, _r = do_http("POST", "/api/nodes/echo", body=buf,
                           content_type="application/octet-stream", timeout=timeout)
        dt = max(time.perf_counter() - t0, 1e-9)
        if code == 200:
            mbps = round(len(buf) * 8 / dt / 1e6, 1)
            out["upload_bytes"], out["upload_mbps"] = len(buf), mbps
            _rate = f"{mbps} Mbps"
            print(f"  up    {len(buf)/1e6:.1f} MB   {_ok(_rate)}   ({dt*1000:.0f}ms)")
        else:
            print(f"  up    {_fail(f'HTTP {code}')}")
    except Exception as e:
        print(f"  up    {_fail(str(e)[:70])}")
    return out


def _report_speed(dns_ms, tcp_ms, pings, bench, bw) -> None:
    """Sign this machine's speed profile and print the receipt.

    The signature makes the numbers AUTHORED and tamper-evident — it does NOT
    make them true, and we should never imply it does. What it does buy: the hub
    cannot quietly edit the figures, and anyone can check they came from this key.
    """
    try:
        priv, pub, pid = _ensure_principal("runner")
    except Exception as e:
        warn(f"cannot sign speed report: {e}")
        return
    b = bench or {}
    # GPU is often a dict/list (vendor, name, vram). Keep it STRUCTURED — str() it
    # and the report ships a Python repr nobody can parse:
    # "{'vendor': 'nvidia', …}". One level deep is plenty for a GPU record.
    _gpu = b.get("gpu")
    if isinstance(_gpu, dict):
        _gpu = {str(k)[:32]: _num(v) for k, v in _gpu.items()}
    elif isinstance(_gpu, (list, tuple)):
        _gpu = [(x if not isinstance(x, dict)
                 else {str(k)[:32]: _num(v) for k, v in x.items()}) for x in _gpu[:8]]
    else:
        _gpu = _num(_gpu)
    _hw = {k: _num(b.get(k)) for k in ("system", "arch", "python", "cpus", "ram_gb")}
    _hw["gpu"] = _gpu
    payload = {
        "from": pid,
        "node_id": _machine_id() or pid,
        "hardware": _hw,
        "bench": {k: _num(b.get(k))
                  for k in ("cpu_mbs", "mem_gbs", "disk_write_mbs", "disk_read_mbs")},
        "bandwidth": {k: _num(bw.get(k))
                      for k in ("download_mbps", "upload_mbps", "download_bytes", "upload_bytes")},
        "latency": {
            "dns_ms": _num(dns_ms), "tcp_ms": _num(tcp_ms),
            "ping_min_ms": _num(min(pings) if pings else None),
            "ping_avg_ms": _num(sum(pings) // len(pings) if pings else None),
            "ping_max_ms": _num(max(pings) if pings else None),
        },
        "peers": [],
        "ts": int(time.time()),
    }
    try:
        sig = base64.b64encode(
            ed25519_sign(_canonical_json(payload).encode("utf-8"), priv)).decode("ascii")
    except Exception as e:
        warn(f"could not sign the report: {e}")
        return
    code, resp = do_http("POST", "/api/nodes/speed",
                         body={**payload, "sig": sig}, timeout=20)

    print()
    print(f"  signed report")
    print(f"    principal    {pid}")
    print(f"    fingerprint  {_key_fingerprint(pub)}")
    print(f"    signature    {sig[:44]}…")
    if code in (200, 201):
        print(f"    {_ok('verified by the hub')}  →  {HUB}/api/nodes/speed")
    else:
        warn(f"hub rejected the report: HTTP {code} {str(resp)[:160]}")


def cmd_speed(args) -> None:
    """Latency benchmark: DNS, TCP, hub ping, run upload+execute."""
    print(f"\033[1m{APP} speed\033[0m — latency benchmark")
    hub_host = HUB.replace("https://", "").replace("http://", "").split("/")[0]
    hub_scheme = "https" if HUB.startswith("https://") else "http"

    t0 = time.time()
    try:
        ip = socket.gethostbyname(hub_host)
        dns_ms = int((time.time() - t0) * 1000)
        print(f"  dns   {hub_host:30s} → {ip:15s}   {dns_ms:4d}ms")
    except Exception as e:
        print(f"  dns   {hub_host:30s} → \033[31mFAIL\033[0m ({e})"); return

    t0 = time.time()
    try:
        s = socket.create_connection((hub_host, 443 if hub_scheme == "https" else 80), timeout=5); s.close()
        tcp_ms = int((time.time() - t0) * 1000)
        print(f"  tcp   {hub_host}:443                      {tcp_ms:4d}ms")
    except Exception as e:
        print(f"  tcp   {hub_host}:443                      \033[31mFAIL\033[0m ({e})"); return

    pings = []
    for i in range(3):
        t0 = time.time()
        try:
            code, _ = do_http("GET", "/api/stats", timeout=5)
            ms = int((time.time() - t0) * 1000); pings.append(ms)
            mark = _ok(f"{ms}ms") if code == 200 else _fail(f"{ms}ms HTTP {code}")
            print(f"  ping  GET /api/stats         #{i+1}            {mark}")
        except Exception as e:
            print(f"  ping  GET /api/stats         #{i+1}            \033[31mFAIL\033[0m ({e})")
    if pings:
        print(f"  ping  min/avg/max = {min(pings)}/{sum(pings)//len(pings)}/{max(pings)}ms")

    print()
    print(f"  bench CPU/RAM/disk:")
    bench = {}
    try:
        bench = cmd_llm_bench(args) or {}
    except Exception as e:
        print(f"        \033[31mFAIL\033[0m ({e})")

    print()
    print(f"  bandwidth (the path a job's code actually travels):")
    bw = _measure_bandwidth()

    _report_speed(dns_ms, tcp_ms, pings, bench, bw)

def cmd_tasks(args) -> None:
    """`blnq tasks [kill <job_id>]` — what THIS node is running right now.

    The humans' missing window into the agent (SANDBOX.md's open
    nice-to-have): job id, tier, language, pid, elapsed. `kill` is an
    OPERATOR stop for one in-flight job — it only ever looks the id up in
    this agent's own _ACTIVE_JOBS table, so a mistyped id is a no-op, never
    a pid-exec primitive. Completion reporting stays with the run loop (it
    observes the exit and tells the hub), same as the hub's own job_cancel.
    """
    verb = getattr(args, "verb", None)
    jid = getattr(args, "job_id", None)
    if verb == "kill":
        if not jid:
            die(f"usage: {APP} tasks kill <job_id>")
        with _ACTIVE_LOCK:
            proc = _ACTIVE_JOBS.get(jid)
        if proc is None:
            # None = claimed but not yet spawned (still valid to cancel):
            # clear the slot so the spawner's launch becomes a no-op is NOT
            # safe here (race with Popen) — only kill spawned processes.
            if jid in _ACTIVE_JOBS:
                die(f"job {jid} is still starting — retry in a moment")
            die(f"no active job {jid} on this node (finished jobs leave the list)")
        container = getattr(proc, "_blnq_container", None)
        _kill_proc_tree(proc, None, container)
        print(f"  {_ok('signalled')} {jid} (pid {getattr(proc, 'pid', '?')})"
              f" — the run loop reports the result to the hub")
        return
    if verb:
        die(f"unknown tasks verb: {verb} (only `kill`)")

    with _ACTIVE_LOCK:
        items = dict(_ACTIVE_JOBS)
    rows = []
    for jid, proc in items.items():
        meta = _ACTIVE_META.get(jid, {})
        elapsed = int(time.time() - (meta.get("started") or time.time()))
        if proc is None:
            state = "starting"
        else:
            rc = proc.poll()
            state = "running" if rc is None else f"exited rc={rc}"
        rows.append({
            "job_id": jid,
            "tier": meta.get("tier") or ("pending" if proc is None else "?"),
            "lang": meta.get("lang", "?"),
            "pid": meta.get("pid"),
            "elapsed_s": elapsed,
            "state": state,
        })
    if getattr(args, "json", False):
        print(json.dumps(rows, indent=2))
        return
    _title("tasks", f"in-flight on this node — {len(rows)} running")
    print()
    if not rows:
        print("  none — this node is idle")
        _hint(f"kill a stuck one with: {APP} tasks kill <job_id>")
        return
    print(f"    {'job_id':<26} {'tier':<10} {'lang':<8} {'pid':>7} {'elapsed':>8}  state")
    for r in rows:
        el = r["elapsed_s"]
        el_s = f"{el // 60}m{el % 60:02d}s" if el >= 60 else f"{el}s"
        col = "\033[32m" if r["state"] == "running" else "\033[33m"
        print(f"    {r['job_id']:<26} {r['tier']:<10} {r['lang']:<8} "
              f"{str(r['pid'] or '-'):>7} {el_s:>8}  {col}{r['state']}\033[0m")
    _hint(f"operator stop: {APP} tasks kill <job_id>")


def cmd_test(args) -> None:
    """End-to-end smoke test: doctor + speed + a small run upload+execute."""
    print(f"\033[1m{APP} test\033[0m — full end-to-end smoke test\n")
    cmd_doctor(args)
    print()
    cmd_speed(args)
    print()
    # ── remote-run preflight ────────────────────────────────────────────
    # Ask the safety ladder FIRST who would decide this exact script. If the
    # answer is "blocked right now" (AI down, no fallback qualifies), a remote
    # run is EXPECTED to fail — report the availability reason and pass the
    # local sections instead of crying FAIL over an outage we were told about.
    import hashlib as _hl
    _tiny_code = 'print("blnq test ok")\n'
    _subj = _hl.sha256(_tiny_code.encode()).hexdigest()
    skip_remote = None
    try:
        _cs, _ps = do_http("GET", f"/api/run/safety/{_subj}?danger=clear", timeout=6)
        if _cs == 200 and isinstance(_ps, dict):
            _dw = str(_ps.get("would_decide_by") or "")
            if _dw.startswith("blocked"):
                skip_remote = _dw
    except Exception:
        pass   # old hub without the endpoint → just attempt the run as before

    if skip_remote:
        print(f"  run   \033[33mSKIP\033[0m remote run — {skip_remote}")
        print(f"\n\033[1m{APP} test\033[0m — \033[33mPASS (local)\033[0m"
              f"\033[2m  install ✓  hub ✓  speed ✓  remote run skipped (availability, not a defect)\033[0m")
        sys.exit(0)

    print(f"  run   tiny script upload+execute:")
    import tempfile as _tf
    with _tf.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(_tiny_code)
        tmp_path = f.name
    # cmd_run_file ends with sys.exit() on success — SystemExit is NOT an
    # Exception, so the old `except Exception` let it straight past and the
    # final verdict line never printed. Catch it, turn it into a result.
    rc = 1
    try:
        cmd_run_file(args, Path(tmp_path), [])
        rc = 0
    except SystemExit as e:
        rc = 0 if (e.code in (0, None)) else int(e.code)
    except Exception as e:
        print(f"        \033[31mFAIL\033[0m ({e})")
        rc = 1
    finally:
        try: os.unlink(tmp_path)
        except OSError: pass

    if rc == 0:
        print(f"\n\033[1m{APP} test\033[0m — \033[32mPASS\033[0m"
              f"\033[2m  install ✓  hub ✓  speed ✓  remote run ✓\033[0m")
    else:
        print(f"\n\033[1m{APP} test\033[0m — \033[31mFAIL\033[0m (remote run exited {rc})")
    sys.exit(rc)


def cmd_workers_list(args) -> None:
    code, p = do_http("GET", "/api/workers/list"); _print(p, code)


def cmd_nodes(args) -> None:
    """`blnq nodes` — who's out there, rendered for humans. Same data as
    `blnq workers list` (raw JSON), but as a table: online state, the jail
    each node runs, volunteering, reputation, freshness."""
    code, p = do_http("GET", "/api/workers/list", timeout=8)
    if code != 200 or not isinstance(p, dict):
        die(f"cannot reach the hub (HTTP {code}) — is {HUB} up?")
    if getattr(args, "json", False):
        _print(p, code)   # raw for scripts/AIs — same data, no table, no emoji
        return
    ws = p.get("workers") or []
    _title("nodes", f"who's out there — {HUB}")
    print()
    if not ws:
        print("  no nodes registered yet.")
        return

    def _since(sec) -> str:
        try: sec = int(float(sec))
        except Exception: return "?"
        if sec < 60:    return f"{sec}s ago"
        if sec < 3600:  return f"{sec // 60}m ago"
        if sec < 86400: return f"{sec // 3600}h ago"
        return f"{sec // 86400}d ago"

    hosts = [str(w.get("hostname") or w.get("worker_id") or "?") for w in ws]
    hw = min(30, max(len(h) for h in hosts))
    print(f"    {'hostname'.ljust(hw)}  {'platform':<9} {'sandbox':<9} {'vol':<3} {'rep':>4}  last seen")
    online = volunteering = jailed = 0
    for w, h in zip(ws, hosts):
        # Own freshness window: the hub's is_online flag uses a 30s threshold
        # but agents heartbeat ~every 50s (inbox long-poll sits between
        # heartbeats) — so the flag flips "offline" for healthy nodes. 90s
        # = two missed heartbeats before we call it gone.
        try:
            on = float(w.get("seconds_since_seen") or 1e9) < 90
        except (TypeError, ValueError):
            on = bool(w.get("is_online"))
        vol = bool(w.get("volunteers"))
        online += 1 if on else 0
        volunteering += 1 if vol else 0
        # raw escapes: the _good()/_meh() helpers PREFIX their own symbol,
        # which would double up with a mark we also pass in
        mark = "\033[32m✓\033[0m" if on else "\033[2m✗\033[0m"
        # sandbox: docker|bwrap (jailed) · rlimit (no jail) · legacy (old
        # client, unknown) — derived from the capability tag when the hub
        # predates the derived field
        sb = _declared_sandbox(w)[:8]
        if sb in ("docker", "bwrap"):
            jailed += 1
            sb_col = f"\033[32m{sb}\033[0m"
        elif sb == "rlimit":
            sb_col = f"\033[31m{sb}\033[0m"
        else:
            sb_col = f"\033[2m{sb}\033[0m"
        print(f"  {mark} {h[:hw].ljust(hw)}  {str(w.get('platform') or '?'):<9} "
              f"{sb_col:<17} {'✓' if vol else '–':<3} {str(w.get('reputation', 0)):>4}  "
              f"{_since(w.get('seconds_since_seen'))}")
    print()
    print(f"    🐝 {online}/{len(ws)} online · {volunteering} volunteering · {jailed} jailed")
    print(f"    {_meh('for scripts & AIs: blnq nodes --json  ·  for this machine: blnq security')}")
    print()

def cmd_graph(args) -> None:
    code, p = do_http("GET", "/api/graph"); _print(p, code)

def cmd_graph_stats(args) -> None:
    code, p = do_http("GET", "/api/graph/stats"); _print(p, code)

def cmd_graph_search(args) -> None:
    q = " ".join(args.query)
    if not q: die("graph search needs a query (blnq graph search 'climate')")
    code, p = do_http("GET", f"/api/graph/search?q={urllib.parse.quote(q)}"); _print(p, code)

def cmd_graph_timeline(args) -> None:
    code, p = do_http("GET", "/api/graph/timeline"); _print(p, code)


# ── friendly / fun commands ────────────────────────────────────────────
_VOLUNTEER_FILE = CONFIG_DIR / "contribute.json"

def _volunteer_default() -> dict:
    return {"share_cpu": False, "max_cpu_pct": 25, "pause_on_battery": True,
            "sandbox": "auto", "max_parallel": 1, "max_mem_mb": 1024,
            "opted_in_at": None, "tags": [],
            "allow_network_jobs": True}   # claim-time gate: `blnq network off`

def _volunteer_load() -> dict:
    if not _VOLUNTEER_FILE.exists():
        return _volunteer_default()
    try:
        d = json.loads(_VOLUNTEER_FILE.read_text())
        base = _volunteer_default()
        base.update({k: v for k, v in d.items() if k in base})
        return base
    except (OSError, json.JSONDecodeError):
        return _volunteer_default()

def _auto_apply_volunteer_change(stopped_hint: str = "") -> None:
    """Volunteer settings are read at register time (capabilities + limits), so
    a running agent must cycle for the hub to see the change. Do it FOR the
    user — one command, not two."""
    pid = read_pid()
    if pid and pid_alive(pid):
        print(f"\napplying — restarting agent (pid {pid})…")
        try:
            cmd_restart(None)
            return
        except (SystemExit, Exception) as e:
            warn(f"automatic restart failed ({e or 'see blnq logs'}) — run it manually:")
            print(f"  {APP} restart")
        return
    if stopped_hint:
        print(stopped_hint)
        print(f"  {APP} start")

def cmd_volunteer(args) -> None:
    """Opt in/out of contributing compute (running other people's jobs) to the network."""
    action = getattr(args, "action", None) or "status"
    ensure_dirs()
    cfg = _volunteer_load()

    if action == "on":
        # Fail closed: foreign code needs a real jail. rlimit tier = no
        # isolation on macOS (Darwin ignores RLIMIT_AS; no namespaces).
        tier = _sandbox_tier()
        if tier == "rlimit" and not getattr(args, "unsafe", False):
            die(f"no sandbox on this machine — volunteer jobs would run UNJAILED\n"
                f"  install a jail first, then retry:\n"
                f"    Linux:  sudo apt install bubblewrap   (or docker)\n"
                f"    macOS:  Docker Desktop · OrbStack · colima (brew install colima docker)\n"
                f"  to opt in without protection anyway: {APP} volunteer on --unsafe")
        cfg["share_cpu"] = True
        cfg["opted_in_at"] = int(time.time())
        _VOLUNTEER_FILE.write_text(json.dumps(cfg, indent=2))
        print(f"\033[1;32m{APP} volunteer\033[0m — \033[32m✓ you're now a volunteer bee!\033[0m\n")
        print(f"When {HUB_NAME} has a job that fits your CPU/memory budget, your bee will run it.")
        print(f"You can leave the volunteer corps anytime with \033[1m{APP} volunteer off\033[0m.\n")
        print(f"settings (in {_VOLUNTEER_FILE}):")
        for k, v in cfg.items():
            if k == "opted_in_at" and v: v = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(v))
            print(f"  {k:18s} {v}")
        _auto_apply_volunteer_change("\n\033[1;34m>\033[0m start your bee to begin contributing:")
        return

    if action == "off":
        cfg["share_cpu"] = False
        cfg["opted_in_at"] = None
        _VOLUNTEER_FILE.write_text(json.dumps(cfg, indent=2))
        print(f"\033[1;32m{APP} volunteer\033[0m — \033[33m✓ thanks for the help — you've left the volunteer corps.\033[0m")
        print(f"Your bee will no longer accept jobs from {HUB_NAME}.")
        print(f"Run \033[1m{APP} volunteer on\033[0m to rejoin anytime.")
        _auto_apply_volunteer_change()
        return

    print(f"\033[1m{APP} volunteer\033[0m — status")
    if cfg.get("share_cpu"):
        since = cfg.get("opted_in_at")
        since_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(since)) if since else "?"
        print(f"  state:    \033[1;32m✓ volunteering\033[0m  (since {since_str})")
    else:
        print(f"  state:    \033[2mnot volunteering\033[0m")
    print(f"  config:   {_VOLUNTEER_FILE}")
    for k, v in cfg.items():
        if k == "opted_in_at":
            v = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(v)) if v else "(never)"
        print(f"    {k:18s} {v}")
    if not cfg.get("share_cpu"):
        print(f"\n  to join:   \033[1m{APP} volunteer on\033[0m")



# ── autostart: start the agent on boot / at login ─────────────────────────
# Four tiers, because "start on boot" has to work for someone with root AND
# for someone on a shared box who has none. The second group is larger, and
# answering it with "install a system unit" is the same as answering "you
# cannot have this."
#
#   systemd-system   survives logout; needs sudo          (best)
#   systemd-user     survives within a login session; no sudo
#   xdg-autostart    GNOME / KDE / XFCE / MATE at login; no sudo
#   profile          a guarded ~/.profile line; no sudo, works on bare SSH
#
# Every tier runs the SAME command — `keepalive run` — which is already the
# proven path: it no-ops if the agent is alive, self-updates first so a reboot
# comes back on the latest CLI, and only then spawns. Four installers, one
# behaviour, so the tiers cannot drift apart.

AST_SYSTEMD_SYS = "/etc/systemd/system/blnq-autostart.service"
AST_SYSTEMD_USER_DIR = Path.home() / ".config" / "systemd" / "user"
AST_SYSTEMD_USER = AST_SYSTEMD_USER_DIR / "blnq-autostart.service"
AST_XDG_DIR = Path.home() / ".config" / "autostart"
AST_XDG = AST_XDG_DIR / "blnq.desktop"
AST_TIERS = ("systemd-system", "systemd-user", "xdg", "profile")


def _ast_boot_cmd() -> str:
    """The single command every tier runs. Full paths: at boot there is no
    guaranteed PATH, and at login `blnq` may not be on PATH either."""
    return f"{sys.executable} {Path(__file__).resolve()} keepalive run"


def _ast_systemd_user_unit() -> str:
    return (
        "[Unit]\nDescription=bLNQ agent (start at login)\n"
        "After=network-online.target\nWants=network-online.target\n\n"
        "[Service]\nType=oneshot\n"
        f"ExecStart={_ast_boot_cmd()}\n"
        "# keepalive run returns once the agent is spawned detached, so this\n"
        "# unit must not be treated as a long-lived main process.\n"
        "RemainAfterExit=no\n\n"
        "[Install]\nWantedBy=default.target\n"
    )


def _ast_xdg_desktop() -> str:
    return (
        "[Desktop Entry]\nType=Application\nName=bLNQ\n"
        "Comment=Start the bLNQ agent at login\n"
        f"Exec={_ast_boot_cmd()}\n"
        "NoDisplay=true\nHidden=false\n"
        "X-GNOME-Autostart-enabled=true\n"
        "X-KDE-autostart-after=panel\n"
    )


def _ast_profile_line() -> str:
    # Guarded three ways: only if blnq exists, never twice, never in a
    # non-interactive shell where a stray `&` would surprise a script.
    return (
        "\n# bLNQ: start the agent at login (added by `blnq autostart on`)\n"
        "case $- in *i*)\n"
        f"  [ -f {Path(__file__).resolve()} ] && "
        "command -v blnq >/dev/null 2>&1 && "
        "( blnq keepalive run >/dev/null 2>&1 & )\n"
        "  ;;\n"
        "esac\n"
    )


def _ast_installed() -> dict:
    """Which tiers are currently in place."""
    found = {}
    found["systemd-system"] = Path(AST_SYSTEMD_SYS).exists()
    found["systemd-user"] = AST_SYSTEMD_USER.exists()
    found["xdg"] = AST_XDG.exists()
    try:
        prof = Path.home() / ".profile"
        found["profile"] = prof.exists() and "blnq autostart on" in prof.read_text(
            errors="replace")
    except OSError:
        found["profile"] = False
    return found


def _ast_preferred_tier() -> str:
    """Pick the best tier this machine can actually use."""
    if not IS_WIN and Path("/etc/systemd/system").is_dir() and _sudo(["true"]):
        return "systemd-system"
    if not IS_WIN and shutil.which("systemctl"):
        # `systemctl --user` needs a session bus; it fails cleanly when absent,
        # which is exactly when we should fall through to xdg/profile.
        return "systemd-user"
    if not IS_WIN:
        return "xdg"
    return "profile"


def cmd_autostart(args) -> None:
    """on|off|status — start the blnq agent automatically at boot/login."""
    action = getattr(args, "action", None) or "status"
    want = getattr(args, "tier", None)

    if action == "status":
        found = _ast_installed()
        _title("autostart", "does the agent start on its own?")
        print()
        for t in AST_TIERS:
            mark = "\033[32minstalled\033[0m" if found.get(t) else "\033[2mnot set\033[0m"
            print(f"    {t:<16} {mark}")
        print()
        on = [t for t in AST_TIERS if found.get(t)]
        if on:
            ok(f"the agent will start automatically ({', '.join(on)})")
            _hint(f"check it is actually running: {APP} status")
        else:
            warn("the agent will NOT start after reboot or login")
            _hint(f"turn it on: {APP} autostart on")
        if not on and _ast_preferred_tier() not in AST_TIERS:
            _hint(f"this box would use: {_ast_preferred_tier()}")
        sys.exit(0 if on else 1)

    if action == "off":
        removed = []
        if Path(AST_SYSTEMD_SYS).exists():
            _sudo(["systemctl", "disable", "--now", "blnq-autostart.service"])
            _sudo(["rm", "-f", AST_SYSTEMD_SYS])
            _sudo(["systemctl", "daemon-reload"])
            removed.append("systemd-system")
        if AST_SYSTEMD_USER.exists():
            try:
                subprocess.run(["systemctl", "--user", "disable", "--now",
                                "blnq-autostart.service"],
                               capture_output=True, timeout=15)
            except Exception:
                pass
            try:
                AST_SYSTEMD_USER.unlink()
                (AST_SYSTEMD_USER_DIR / "blnq-autostart.service-wants").mkdir(
                    exist_ok=True)
            except OSError:
                pass
            removed.append("systemd-user")
        if AST_XDG.exists():
            try:
                AST_XDG.unlink(); removed.append("xdg")
            except OSError:
                pass
        try:
            prof = Path.home() / ".profile"
            if prof.exists():
                txt = prof.read_text(errors="replace")
                if "blnq autostart on" in txt:
                    # Remove only OUR block: from our marker to the next blank
                    # line that follows the closing `esac`. Never rewrite the
                    # rest of someone's profile — that file is theirs.
                    lines = txt.splitlines(keepends=True)
                    out, i, dropping = [], 0, False
                    while i < len(lines):
                        if "blnq autostart on" in lines[i]:
                            dropping = True
                        if dropping and lines[i].strip() == "esac":
                            dropping = False; i += 1; continue
                        if not dropping:
                            out.append(lines[i])
                        i += 1
                    prof.write_text("".join(out))
                    removed.append("profile")
        except OSError:
            pass
        if removed:
            ok(f"autostart removed from: {', '.join(removed)}")
            _hint("the agent keeps running until you stop it: "
                  f"{APP} stop")
        else:
            warn("nothing was installed")
        sys.exit(0)

    # ── on ────────────────────────────────────────────────────────────────
    tier = want or _ast_preferred_tier()
    if tier not in AST_TIERS:
        die(f"unknown tier {tier!r} — choose one of: {', '.join(AST_TIERS)}")

    if tier == "systemd-system":
        if not Path("/etc/systemd/system").is_dir():
            die("no systemd here — try: "
                f"{APP} autostart on --tier xdg  (or --tier profile)")
        svc = ("[Unit]\nDescription=bLNQ agent (start at boot)\n"
               "After=network-online.target\nWants=network-online.target\n\n"
               "[Service]\nType=oneshot\n"
               f"ExecStart={_ast_boot_cmd()}\n\n"
               "[Install]\nWantedBy=multi-user.target\n")
        if _sudo(["tee", AST_SYSTEMD_SYS], svc.encode()):
            _sudo(["systemctl", "daemon-reload"])
            _sudo(["systemctl", "enable", "--now", "blnq-autostart.service"])
            ok("autostart installed as a SYSTEM service — starts at boot, "
               "survives logout")
            _hint(f"unit: {AST_SYSTEMD_SYS}")
            return
        warn("need sudo for a system service. Either run with sudo, or use "
             "a tier that needs none:")
        import shlex
        print(f"  printf %s {shlex.quote(svc)} | sudo tee {AST_SYSTEMD_SYS} >/dev/null")
        print("  sudo systemctl daemon-reload && sudo systemctl enable --now "
              "blnq-autostart.service")
        print(f"\n  or, no root at all:\n    {APP} autostart on --tier systemd-user"
              f"\n    {APP} autostart on --tier xdg")
        sys.exit(1)

    if tier == "systemd-user":
        if not shutil.which("systemctl"):
            die("no systemctl here — try: "
                f"{APP} autostart on --tier profile")
        try:
            AST_SYSTEMD_USER_DIR.mkdir(parents=True, exist_ok=True)
            AST_SYSTEMD_USER.write_text(_ast_systemd_user_unit())
            r = subprocess.run(["systemctl", "--user", "daemon-reload"],
                               capture_output=True, timeout=15)
            if r.returncode != 0:
                raise RuntimeError(r.stderr.decode(errors="replace")[:120])
            subprocess.run(["systemctl", "--user", "enable", "--now",
                            "blnq-autostart.service"],
                           capture_output=True, timeout=15)
            ok("autostart installed as a USER service — starts at login, "
               "no root needed")
            _hint(f"unit: {AST_SYSTEMD_USER}")
            _hint("note: starts when YOU log in, not at machine boot — "
                  "for boot, use --tier systemd-system with sudo")
            return
        except Exception as e:
            AST_SYSTEMD_USER.unlink(missing_ok=True)
            die(f"systemd user session unavailable ({str(e)[:90]}).\n"
                f"  try a tier that needs no session bus:\n"
                f"    {APP} autostart on --tier xdg\n"
                f"    {APP} autostart on --tier profile", code=1)

    if tier == "xdg":
        if IS_WIN:
            die("xdg autostart is a Linux/desktop thing — use "
                f"{APP} autostart on --tier profile")
        AST_XDG_DIR.mkdir(parents=True, exist_ok=True)
        AST_XDG.write_text(_ast_xdg_desktop())
        AST_XDG.chmod(0o644)
        ok("autostart installed via XDG — starts when you log into your "
           "desktop session")
        _hint(f"file: {AST_XDG}")
        _hint("works on GNOME / KDE / XFCE / MATE; a headless SSH box will "
              f"ignore it — use --tier profile there")
        return

    # profile — the universal fallback
    prof = Path.home() / ".profile"
    if not prof.exists():
        for cand in (".bash_profile", ".bashrc", ".zprofile", ".zshrc"):
            p = Path.home() / cand
            if p.exists():
                prof = p
                break
    try:
        existing = prof.read_text(errors="replace") if prof.exists() else ""
        if "blnq autostart on" in existing:
            ok(f"already installed in {prof.name}")
            return
        with prof.open("a") as f:
            f.write(_ast_profile_line())
        ok(f"autostart appended to {prof} — starts at the next login")
        _hint("the block is guarded: interactive shells only, and only once")
        _hint(f"remove it later with: {APP} autostart off")
    except OSError as e:
        die(f"cannot write {prof}: {e}", code=1)

# ── keep-alive (reboot/crash-proofing via systemd) ─────────────────────
KA_UNIT  = "blnq-keepalive.service"
KA_TIMER = "blnq-keepalive.timer"

def _ka_unit_text():
    user, home = _os_user(), str(Path.home())
    svc = (
        f"[Unit]\nDescription=bLNQ volunteer keep-alive check (user {user})\n"
        f"After=network-online.target\nWants=network-online.target\n\n"
        f"[Service]\nType=oneshot\nUser={user}\nEnvironment=HOME={home}\n"
        f"ExecStart={sys.executable} {Path(__file__).resolve()} keepalive run\n\n"
        f"[Install]\nWantedBy=multi-user.target\n"
    )
    tmr = (
        "[Unit]\nDescription=bLNQ keep-alive check every 5 minutes\n\n"
        "[Timer]\nOnBootSec=30\nOnUnitActiveSec=5min\nAccuracySec=1min\n\n"
        "[Install]\nWantedBy=timers.target\n"
    )
    return svc, tmr

def _sudo(args, input_bytes=None) -> bool:
    try:
        r = subprocess.run(["sudo", "-n"] + list(args), input=input_bytes,
                           capture_output=True, timeout=20)
        return r.returncode == 0
    except Exception:
        return False

def cmd_keepalive(args) -> None:
    """on|off|status|run — install a systemd timer that respawns the blnq agent
    after reboot/crash (and auto-updates it from the hub before respawn)."""
    action = getattr(args, "action", None) or "status"

    if action in ("run", "ensure"):
        if read_pid():
            return                                   # already alive → nothing to do
        st = read_state()
        if not st.get("worker_id") and not _VOLUNTEER_FILE.exists():
            return                                   # never joined the collective → nothing to keep
        # self-update first so the reboot comes back on the latest CLI
        try:
            code, ver = do_http("GET", "/api/version", timeout=6, sign=False)
            hub_v = ver.get("version") if isinstance(ver, dict) else None
            if hub_v and _parse_ver(hub_v) > _parse_ver(VERSION):
                data = _http_get_bytes(f"{HUB.rstrip('/')}/blnq-cli.py", timeout=30)
                _apply_update(data, source="keepalive")
        except Exception:
            pass
        ensure_dirs()
        # Respect the user's stop: STOP_FILE is the durable "stopped" intent
        # (`blnq stop` leaves it, `blnq start` clears it) — never unlink it
        # here, or every timer tick would undo the stop it just honoured.
        if STOP_FILE.exists():
            print(f"[{APP} keepalive] stopped by user — not respawning ({APP} start to resume)")
            return
        with LOG_FILE.open("a") as lf:
            proc = _spawn_detached_agent(lf)
        print(f"[{APP} keepalive] respawned agent pid={proc.pid}")
        return

    if action == "on":
        if not Path("/etc/systemd/system").is_dir():
            die("keepalive currently supports systemd boxes (Linux) only")
        svc, tmr = _ka_unit_text()
        a = _sudo(["tee", f"/etc/systemd/system/{KA_UNIT}"], svc.encode())
        b = _sudo(["tee", f"/etc/systemd/system/{KA_TIMER}"], tmr.encode())
        if a and b:
            _sudo(["systemctl", "daemon-reload"])
            _sudo(["systemctl", "enable", "--now", KA_TIMER])
            ok(f"keep-alive installed — the agent now respawns ≤5 min after reboot/crash"
               f"\n  units: /etc/systemd/system/{KA_UNIT} + {KA_TIMER}")
        else:
            warn("need sudo to write units. Run:")
            import shlex
            print(f"  printf %s {shlex.quote(svc)} | sudo tee /etc/systemd/system/{KA_UNIT} >/dev/null")
            print(f"  printf %s {shlex.quote(tmr)} | sudo tee /etc/systemd/system/{KA_TIMER} >/dev/null")
            print(f"  sudo systemctl daemon-reload && sudo systemctl enable --now {KA_TIMER}")
        return

    if action == "off":
        if Path(f"/etc/systemd/system/{KA_TIMER}").exists():
            _sudo(["systemctl", "disable", "--now", KA_TIMER])
            _sudo(["rm", "-f", f"/etc/systemd/system/{KA_TIMER}", f"/etc/systemd/system/{KA_UNIT}"])
            _sudo(["systemctl", "daemon-reload"])
            ok("keep-alive removed")
        else:
            print("keep-alive not installed")
        return

    # status
    installed = Path(f"/etc/systemd/system/{KA_TIMER}").exists()
    pid = read_pid()
    enabled = ""
    if installed:
        r = subprocess.run(["systemctl", "is-enabled", KA_TIMER], capture_output=True, text=True)
        enabled = "enabled" if r.stdout.strip() == "enabled" else "disabled"
    print(f"  agent:      " + (f"\033[32malive (pid {pid})\033[0m" if pid else "\033[2mnot running\033[0m"))
    if installed:
        col = "\033[32m" if enabled == "enabled" else "\033[33m"
        print(f"  keep-alive: \033[32minstalled\033[0m, timer {col}{enabled}\033[0m")
    else:
        print(f"  keep-alive: \033[2mnot installed\033[0m  →  {APP} keepalive on")

def cmd_help_bang(args) -> None:
    """Panic button — show how to get help."""
    print(f"\033[1;31m{APP} help!\033[0m — emergency help\n")
    print(f"  \033[1mstep 1: what does your bee say?\033[0m")
    print(f"    {APP} doctor       \033[2m# pasteable health report\033[0m")
    print(f"    {APP} logs 30      \033[2m# last 30 lines of the agent log\033[0m")
    print(f"    {APP} status       \033[2m# agent pid + heartbeat state\033[0m")
    print(f"    {APP} scan FILE    \033[2m# check a script before uploading\033[0m")
    print()
    print(f"  \033[1mstep 2: stop the bleeding (if needed)\033[0m")
    print(f"    {APP} stop         \033[2m# stop the local agent\033[0m")
    print(f"    {APP} uninstall    \033[2m# full removal (keeps ~/.config/{APP}/)\033[0m")
    print()
    print(f"  \033[1mstep 3: get human help\033[0m")
    print(f"    bug/issue:  https://github.com/{APP}/issues  (paste `doctor` output)")
    print(f"    email:      support@{HUB.replace('https://','').rstrip('/')}")
    print()
    print(f"  \033[1mstep 4: re-run safely\033[0m")
    print(f"    {APP} FILE        \033[2m# auto-scans + uploads + runs\033[0m")
    print(f"    {APP} FILE --no-scan  \033[2m# skip the local scan (still gets server-side filter)\033[0m")

def cmd_hi(args) -> None:
    """Friendly greeter — no chat here (blnq executes code, doesn't talk)."""
    print(f"\033[1m{APP}\033[0m hi! 👋  ready to run some code?\n")
    print(f"  try:")
    print(f"    {APP} --help               \033[2m# all subcommands\033[0m")
    print(f"    {APP} doctor               \033[2m# full health check\033[0m")
    print(f"    {APP} speed                \033[2m# latency benchmark\033[0m")
    print(f"    {APP} myscript.py          \033[2m# scan + upload + run remotely\033[0m")
    print(f"    {APP} scan myscript.py     \033[2m# just scan, no upload\033[0m")
    print()
    print(f"  drop a tiny test file:")
    print(f"    echo 'print(\"hello from blnq!\")' > /tmp/hi.py && {APP} /tmp/hi.py")


def cmd_support(args) -> None:
    """Get help. blnq doesn't have an AI chat endpoint (it runs code, doesn't talk),
    so `support` collects your full context (doctor + last 10 log lines + bee metrics)
    and prints it ready-to-paste for human support — plus a quick FAQ for common issues."""
    print(f"\033[1m{APP} support\033[0m — gathering context for human support...\n")

    # --- gather context (mirrors hivv's support, minus the AI call) -----
    log_tail = ""
    if LOG_FILE.exists():
        try:
            lines = LOG_FILE.read_text(errors="replace").splitlines()[-10:]
            log_tail = "\n".join(lines)
        except OSError:
            pass

    m = _collect_metrics()
    pid = read_pid()
    st = read_state() or {}
    hb = st.get("last_heartbeat") or 0
    hb_age = int(time.time()) - hb if hb else -1
    hb_str = f"{hb_age}s ago" if hb_age >= 0 else "never"

    ctx_lines = [
        f"[bLNQ.org CLI support session — client v{VERSION}]",
        f"hub       = {HUB}",
        f"hostname  = {socket.gethostname()}",
        f"hw_id     = {_machine_id() or '(unavailable)'}",
        f"agent     = {'running (pid ' + str(pid) + ', worker_id ' + str(st.get('worker_id','?')) + ')' if pid else 'NOT RUNNING'}",
        f"heartbeat = {hb_str}",
        f"transport = {st.get('transport', 'heartbeat-only')}",
        f"signed    = {'no (hub does not support)' if st.get('auth_rejected') else 'yes'}",
        f"bee       = {m.get('cpu_count','?')} cores, {m.get('mem_pct','?')}% mem, {m.get('disk_pct','?')}% disk",
    ]
    for g in (m.get("gpus") or []):
        ctx_lines.append(f"  gpu[{g['index']}] {g['name']} util={g['util_pct']}% temp={g.get('temp_c','?')}°C")
    if log_tail:
        ctx_lines += ["", "--- recent agent log (last 10 lines, scrubbed) ---", log_tail]
    ctx_lines = [_scrub_lines(line) for line in ctx_lines]

    print("\033[1;7m  paste-ready support bundle (copy everything below)  \033[0m")
    print(f"  ```\n  {chr(10).join(ctx_lines)}\n  ```\n")

    # --- quick FAQ for the most common blnq issues -----------------------
    print(f"\033[1mquick FAQ:\033[0m")
    print()
    print(f"  \033[1;33mQ: my script got rejected by the server\033[0m")
    print(f"     blnq.org has its own server-side risk filter that blocks")
    print(f"     patterns like `import os`, `eval`, network calls, etc.")
    print(f"     even if `blnq scan` says it's clean. (defense in depth.)")
    print(f"     try:  blnq FILE --no-scan   and look at the server's error")
    print(f"     or:   set BLNQ_TOKEN=...    (logged-in users have fewer limits)")
    print()
    print(f"  \033[1;33mQ: my agent keeps going offline\033[0m")
    print(f"     blnq restart && blnq logs 20 -f")
    print(f"     look for connection errors / 403 / 5xx in the log")
    print()
    print(f"  \033[1;33mQ: how do I get human help?\033[0m")
    print(f"     github issues : https://github.com/{APP}/issues")
    print(f"     (paste the bundle above + what you were trying to do)")
    print(f"     email         : support@{HUB.replace('https://','').rstrip('/')}")
    print()
    print(f"  \033[1;33mQ: where's the AI chat? (you're running code, not chatting)\033[0m")
    print(f"     blnq runs code. If you want AI chat, install hivv:")
    print(f"       curl -sSL https://hivv.org/install-hivv.sh | bash")
    print(f"     Then `hivv support` will stream an actual AI diagnosis.")





def cmd_scripts_list(args) -> None:
    code, p = do_http("GET", "/api/scripts"); _print(p, code)

def cmd_scripts_get(args) -> None:
    code, p = do_http("GET", f"/api/scripts/{args.id}"); _print(p, code)

def cmd_love(args) -> None:
    """Show love for a script. Authors earn credits when others love their work."""
    undo = getattr(args, "undo", False)
    if undo:
        code, p = do_http("DELETE", f"/api/scripts/{args.id}/love", sign=False, timeout=15)
        if code == 200 and isinstance(p, dict):
            ok(f"[love] removed your love for {args.id} — {p.get('love_count', '?')} love(s) remain")
        else:
            _print(p, code)
        return
    code, p = do_http("POST", f"/api/scripts/{args.id}/love", body={}, sign=False, timeout=15)
    if code in (401, 403) and isinstance(p, dict) and "Authentication" in str(p.get("error", "")):
        die("login first: blnq login")
    if code != 200 or not isinstance(p, dict):
        _print(p, code); return
    if p.get("already"):
        ok(f"[love] you already love {args.id} — {p.get('love_count', '?')} love(s) total")
        return
    msg = f"[love] loved {args.id} — {p.get('love_count', '?')} love(s) total"
    if p.get("earned"):
        msg += f"  ·  author +{p['earned']} credit(s) ❤️"
    ok(msg)

def cmd_catalog(args) -> None:
    """Browse what the network actually runs: categorised, searchable, code-only.

    The catalog deliberately carries CODE and counters and nothing else — the
    data a script ran on (stdin/stdout) never leaves `runs`. `show` re-hashes
    the source locally so you can confirm the row matches its own key without
    taking the hub's word for it.
    """
    action = getattr(args, "catalog_cmd", None) or "list"
    as_json = bool(getattr(args, "json", False))

    if action == "categories":
        code, p = do_http("GET", "/api/catalog/categories", sign=False)
        if code != 200 or not isinstance(p, dict):
            _print(p, code); return
        rows = p.get("data") or []
        if as_json:
            print(json.dumps(p, indent=2)); return
        _title("catalog", "categories")
        print()
        print(f"  {_hdr('browse by type')}")
        for r in rows:
            _kv(r.get("category", "?"),
                f"{r.get('entries', 0)} entries    {r.get('total_runs', 0)} runs")
        _hint(f"blnq catalog search <word> --category <name>")
        return

    if action == "show":
        subj = (getattr(args, "subject", None) or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", subj):
            die("subject must be a 64-hex sha256 (from `blnq catalog`)")
        code, p = do_http("GET", f"/api/catalog/{subj}", sign=False)
        if code != 200 or not isinstance(p, dict):
            _print(p, code); return
        row = p.get("data") or {}
        src = row.get("code") or ""
        # Verify LOCALLY: the key is the hash of the bytes, so the hub cannot
        # hand back altered source without the mismatch being visible here.
        actual = hashlib.sha256(src.encode("utf-8")).hexdigest()
        intact = actual == subj
        if as_json:
            out = dict(row)
            out["verified_locally"] = intact
            print(json.dumps(out, indent=2))
            if not intact: sys.exit(3)
            return
        _title("catalog", row.get("name") or subj[:16])
        print()
        print(f"  {_hdr('entry')}")
        _kv("category", f"{row.get('category', '?')}   tags: {', '.join(row.get('tags') or []) or '-'}")
        _kv("language", row.get("language", "?"))
        _kv("runs", f"{row.get('run_count', 0)}")
        _kv("bytes", f"{len(src)}")
        _kv("subject", subj)
        print()
        print(f"  {_hdr('integrity')}")
        _kv("sha256(code)", actual[:24] + "…")
        _kv("matches key", "\033[32m✓ yes\033[0m" if intact
            else "\033[31m✗ NO — source altered\033[0m")
        _hint("the key IS the hash, so this row is self-verifying")
        print()
        print(f"  {_hdr('source')}")
        for line in src.splitlines()[:60]:
            print(f"    {line}")
        if len(src.splitlines()) > 60:
            _hint(f"… {len(src.splitlines()) - 60} more line(s)")
        print()
        _hint(f"run it: {APP} /dev/stdin  (pipe the source) or copy it out")
        if not intact:
            sys.exit(3)
        return

    # list / search
    q = (getattr(args, "query", None) or "").strip()
    params = []
    if q:
        params.append("q=" + urllib.parse.quote(q))
    cat = getattr(args, "category", None)
    if cat:
        params.append("category=" + urllib.parse.quote(str(cat)))
    sort = getattr(args, "sort", None)
    if sort:
        params.append("sort=" + urllib.parse.quote(str(sort)))
    if action == "search" and not sort:
        params.append("sort=relevance")
    params.append("limit=" + str(int(getattr(args, "limit", 0) or 15)))
    path = "/api/catalog?" + "&".join(params)

    code, p = do_http("GET", path, sign=False)
    if code != 200 or not isinstance(p, dict):
        _print(p, code); return
    rows = p.get("data") or []
    if as_json:
        print(json.dumps(p, indent=2)); return

    label = "search" if (action == "search" or q) else "most run"
    _title("catalog", f"{label}  {('— ' + q) if q else ''}".rstrip())
    print()
    if not rows:
        _hint("no matches — try `blnq catalog categories` to see what exists")
        return
    print(f"  {_hdr('rank  runs  category   name')}")
    for i, r in enumerate(rows, 1):
        nm = r.get("name") or (r.get("subject") or "")[:12]
        print(f"    {str(i):>2}. {str(r.get('run_count', 0)):>4}  "
              f"{str(r.get('category', '?')):<10} {nm[:52]}")
    tot = (p.get("totals") or {})
    print()
    _hint(f"{tot.get('entries', '?')} entries / {tot.get('total_runs', '?')} runs "
          f"across {tot.get('categories', '?')} categories")
    _hint(f"inspect one: {APP} catalog show <subject>")
    _hint(f"the catalog holds CODE only — never the data it ran on")


def cmd_leaderboard(args) -> None:
    code, p = do_http("GET", "/api/scripts/leaderboard/love", sign=False)
    if code != 200 or not isinstance(p, dict):
        _print(p, code); return
    ts, ta = p.get("top_scripts") or [], p.get("top_authors") or []
    print(f"\033[1m  ♥ blnq love board ♥\033[0m   {HUB}")
    print("\n  \033[1mmost-loved approved scripts\033[0m")
    if not ts:
        print("    (no loves yet — be the first: blnq love scr_xxxxx)")
    for i, s in enumerate(ts[:10], 1):
        print(f"    {i:>2}. {'❤ ' + str(s['love_count']):<6} {s['name'][:40]:<42} by {s.get('username') or 'anon'}  [{s['language']}]")
    print("\n  \033[1mmost-loved authors\033[0m")
    if not ta:
        print("    (nobody loved yet)")
    for i, a in enumerate(ta[:10], 1):
        print(f"    {i:>2}. ♥ {int(a['loves']):<5} {str(a['name'])[:30]:<32} ({a['scripts']} script(s))")
    print()

def cmd_jobs_list(args) -> None:
    status = getattr(args, "status", None) or "all"
    code, p = do_http("GET", f"/api/jobs/list?limit=50&status={status}", sign=False)
    _print(p, code)

def cmd_jobs_submit(args) -> None:
    secrets_map = {}
    for item in args.secret or []:
        k, _, v = item.partition("=")
        if not k or not v: die(f"--secret needs KEY=VALUE, got {item!r}")
        secrets_map[k] = v
    body: dict = {}
    script_id = getattr(args, "script", None)
    file_arg = getattr(args, "file", None)
    node = getattr(args, "node", None)
    if file_arg and script_id:
        die("give EITHER a script id or --file, not both")
    if file_arg:
        # Inline path: ships the file's code directly (hub safety-scans it;
        # no library/approval round-trip) — the "get it on MY node NOW" route.
        p = Path(file_arg)
        if not p.exists():
            die(f"file not found: {p}")
        lang = _EXT_TO_LANG.get(p.suffix.lower())
        if not lang:
            die(f"unsupported file type {p.suffix!r} — supported: "
                f"{', '.join(sorted(_EXT_TO_LANG))}")
        try:
            code_text = p.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError) as e:
            die(f"cannot read {p}: {e}")
        body.update(script_name=p.name, script_content=code_text, language=lang)
    elif script_id:
        body["script_id"] = script_id
    else:
        die(f"usage: {APP} jobs submit <script_id> | --file <local.py> "
            f"[--node <hostname>] [--stdin=…] [--timeout=N] [--secret K=V]")
    if node:
        body["node"] = str(node).strip().lower()
    if args.stdin is not None: body["stdin_data"] = args.stdin
    if args.timeout: body["timeout_seconds"] = args.timeout
    if getattr(args, "interactive", False): body["interactive"] = True
    if secrets_map: body["secrets"] = secrets_map
    code, p_resp = do_http("POST", "/api/jobs/submit", body=body, sign=False, timeout=30)
    if code in (401, 403) and isinstance(p_resp, dict) and "log in" in str(p_resp.get("error", "")).lower():
        die("login first: blnq login --username=... --password=...")
    if code == 201 and isinstance(p_resp, dict):
        job = p_resp.get("job") or {}
        ok(f"queued job {job.get('job_id')} (credits left: {p_resp.get('credits_left')}"
          + (f", {len(secrets_map)} secret(s) encrypted" if secrets_map else "") + ")")
        if node:
            print(f"  targeted at node: {node} (only that worker may claim it)")
        if file_arg:
            print(f"  inline code: {len(body.get('script_content',''))} bytes "
                  "— hub safety scan applied, no library approval needed")
        if getattr(args, "interactive", False):
            print(f"  interactive: send input with  {APP} send {job.get('job_id')} \"your text\"")
        print(f"  watch it live:  {APP} watch {job.get('job_id')}")
    else:
        _print(p_resp, code)

def cmd_send(args) -> None:
    """Type input into a running interactive job."""
    body = {}
    if args.eof:
        body = {"eof": True}
    else:
        text = args.text if args.text is not None else ""
        if not sys.stdin.isatty() and args.text is None:
            text = sys.stdin.read()
        body = {"data": text if text.endswith("\n") or not text else text + "\n"}
    code, p = do_http("POST", f"/api/jobs/{args.id}/stdin", body=body, sign=False, timeout=15)
    if code == 200: ok(f"[send] → {args.id}" + (" (eof)" if args.eof else ""))
    else: _print(p, code)

def cmd_jobs_status(args) -> None:
    code, p = do_http("GET", f"/api/jobs/{args.id}", sign=False); _print(p, code)

def cmd_login(args) -> None:
    user = args.username or input("username/email: ")
    pw   = args.password or getpass.getpass("password: ")
    # local passport strategy is configured with usernameField:'email'
    code, p = do_http("POST", "/api/auth/login", body={"email": user, "username": user, "password": pw})
    if code == 200:
        jar = next((h.cookiejar for h in opener().handlers
                    if isinstance(h, urllib.request.HTTPCookieProcessor)), None)
        if jar is not None:
            try: jar.save(ignore_discard=True, ignore_expires=True)
            except OSError: pass
        ok("logged in (cookie saved)")
    else:
        _print(p, code)


# Map file extensions → blnq /api/run language codes (must match blnq's LANGUAGES table)
_EXT_TO_LANG = {
    ".py":   "python",
    ".js":   "node",         # blnq uses "node", not "javascript"
    ".mjs":  "node",
    ".ts":   "node",         # blnq doesn't yet support TS — try node first
    ".rb":   "ruby",
    ".rs":   "rust",
    ".sh":   "bash",
    ".pl":   "perl",
    ".php":  "php",
    ".c":    "c",
    ".cpp":  "cpp",
    ".cc":   "cpp",
    ".cxx":  "cpp",
    ".go":   "go",
}

# ── trust layer: local keys + offline verification ─────────────────────
def _subject_of(code_text: str) -> str:
    return hashlib.sha256(code_text.encode("utf-8")).hexdigest()


def cmd_keys(args) -> None:
    """List / inspect this machine's Ed25519 principal keys.

    Trust roles: requester (this human), runner (this worker), validator
    (the scanners) — and list mode enumerates EVERY *.key on the box, so
    odd names (validator2, old experiments) are visible too.

    Public material only. The private key's BYTES are never printed by any
    mode or flag — instead you get what people actually need to answer:
    the file path, its REAL permissions (stat'ed, never assumed — a printed
    "(mode 0600)" that ignores reality would be the confident-wrong-reason
    bug all over again), a backup digest (a hash of a file is useless to
    someone who does not hold the file, and worthless to someone who does —
    it lets YOU match a backup without revealing anything), the derived
    principal id, and hub registration state.
    """
    role = getattr(args, "role", None)
    kdir = key_dir()
    files = sorted(kdir.glob("*.key")) if kdir.exists() else []
    have = {f.stem for f in files}

    def _mode(p: Path) -> str:
        try:
            return f"{p.stat().st_mode & 0o777:04o}"   # '0600', not '0o600'
        except OSError:
            return "????"

    def _fp(b: bytes, n: int = 16) -> str:
        import hashlib as _hl
        return _hl.sha256(b).hexdigest()[:n]

    def _file_digest(p: Path) -> str:
        import hashlib as _hl
        try:
            return _hl.sha256(p.read_bytes()).hexdigest()
        except OSError:
            return "?"

    def _hub_state(r: str, pid: str) -> str:
        cached = (read_state() or {}).get(f"principal_{r}")
        if not cached:
            return "not yet"
        return "registered ✓" if str(cached) == f"{pid}|p2p" \
            else "stale — next use re-registers"

    if not role:
        # ── inventory ────────────────────────────────────────────────────
        _title("keys", f"this machine's principals — {kdir}")
        print()
        if not files:
            print("  no keys yet — one is created on first use")
            _hint(f"e.g. `{APP} keys requester` (then --register to publish it)")
            return
        print(f"    {'role':<16} {'principal':<44} {'mode':>6} {'hub':<26} fingerprint")
        for f in files:
            r = f.stem
            try:
                _priv, _pub = load_or_create_key(r)
                pid = _principal_id(_pub)
                row = (f"  {r:<16} {pid:<44} {_mode(f):>6} "
                       f"{_hub_state(r, pid):<26} {_fp(_pub)}")
                print(row)
            except Exception as e:
                print(f"  {r:<16} {'(unreadable: ' + str(e)[:40] + ')':<44} {_mode(f):>6}")
            if _mode(f) not in ("0600", "0400"):
                print(f"    \033[33m⚠ {r}.key is mode {_mode(f)} — run `{APP} security` to harden\033[0m")
        print()
        _hint(f"details: {APP} keys <role>   ·   publish: {APP} keys <role> --register")
        _hint("the private key's bytes are never printed — its path, real perms and "
              "backup digest are shown in detail mode")
        return

    # ── single key ───────────────────────────────────────────────────────
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", str(role)):
        die(f"invalid role name: {role!r}")
    if role not in have and role not in ("requester", "runner", "validator"):
        die(f"no key '{role}' on this machine (have: "
            f"{', '.join(sorted(have)) or 'none'})")

    priv, pub = load_or_create_key(role)
    pid = _principal_id(pub)
    priv_path = kdir / f"{role}.key"
    mode = _mode(priv_path)
    ok(f"{role} principal {pid}")
    print(f"  public key : {base64.b64encode(pub).decode()}")
    print(f"  fingerprint: {_fp(pub, 24)}  (sha256 of the PUBLIC key — quote this "
          f"when comparing across channels)")
    try:
        p2p = base64.b64encode(
            x25519_public_key(p2p_seed_from_signing_key(priv))).decode()
        print(f"  p2p key    : {p2p}  (relay encryption — published on --register)")
    except Exception:
        pass
    print(f"  key file   : {priv_path} (mode {mode})"
          + ("" if mode in ("0600", "0400")
             else f"  \033[33m⚠ NOT 0600 — run `{APP} security`\033[0m"))
    print(f"  backup tag : {_file_digest(priv_path)[:32]}…  "
          "(sha256 of the FILE — matches a backup without revealing the key)")
    print("  private    : never printed by any command; it exists only in that file")
    print(f"  hub        : {_hub_state(role, pid)}")

    if getattr(args, "register", False):
        # Route through _ensure_principal so this publishes the X25519 P2P key as
        # well — registering only the signer would leave the principal unable to
        # receive encrypted messages.
        try:
            _, _, reg_pid = _ensure_principal(role)
            ok(f"registered with hub as {reg_pid} (signing + P2P encryption keys)")
        except Exception as e:
            warn(f"registration failed: {e}")
            sys.exit(1)


# ── local authorization: identity → caps → mode → audit ──────────────────────
# `blnq auth` / `blnq authorize` — a node-local permission layer, because
# "volunteer: on/off" is a light switch and people want a breaker panel:
# grant machines/accounts specific CAPABILITIES, put unknown ones on
# PROBATION, flip the whole node to WHITELIST mode, and see WHO did WHAT.
#
# Three pieces, kept apart on purpose:
#   * store      ~/.config/blnq/authz.json  (default + entries + caps)
#   * decision   _authz_decision()          PURE — the whole permission
#                 matrix is testable with no hub, job or filesystem
#                 (tests/test_authz.py)
#   * audit      ~/.local/share/blnq/authz-history.jsonl — EVERY outcome,
#                 refusals included (an audit of only the runs you allowed
#                 is a story, not evidence)
#
# Identity is jobs.username — NOT NULL at the hub, delivered in the claim
# response (RETURNING *), so the node never has to trust a display name it
# cannot see. "unknown" identity only passes under default-allow.

_AUTHZ_FILE = CONFIG_DIR / "authz.json"
try:
    _AUTHZ_HISTORY = LOG_FILE.parent / "authz-history.jsonl"
except Exception:
    _AUTHZ_HISTORY = CONFIG_DIR / "authz-history.jsonl"

_AUTHZ_STORED_MODES = ("allow", "maybe", "deny")   # modes an entry may HOLD
# 'delete' is parse-only: revoke/remove ERASE the entry (identity returns to
# the node default). `deny`/`block`/`off` stay distinct — an explicit block
# is a different promise than an absent grant.
_AUTHZ_MODES = {"allow": "allow", "on": "allow", "maybe": "maybe",
                "deny": "deny", "block": "deny", "off": "deny",
                "revoke": "delete", "remove": "delete", "forget": "delete"}
_AUTHZ_CAPS = {"all": "all", "run": "run", "network": "network",
               "net": "network", "secrets": "secrets", "secret": "secrets"}
_AUTHZ_VERBS = {"who": "who", "list": "who", "show": "show",
                "logs": "logs", "log": "logs", "history": "logs"}
_AUTHZ_IDENT_RE = re.compile(r"^[a-z0-9_@.+-]{1,64}$")


def _authz_load() -> dict:
    base = {"version": 1, "default": "allow", "entries": {}}
    if not _AUTHZ_FILE.exists():
        return base
    try:
        d = json.loads(_AUTHZ_FILE.read_text())
        base["default"] = "deny" if d.get("default") == "deny" else "allow"
        ent = d.get("entries")
        if isinstance(ent, dict):
            for k, v in ent.items():
                if not isinstance(v, dict) or not _AUTHZ_IDENT_RE.match(str(k).lower()):
                    continue    # skip malformed identities — they can only fail closed
                # Fail CLOSED on corrupt entries: a junk/missing mode is
                # read as 'deny', never as 'allow' — a mangled authz file
                # must refuse, not open. Deny entries hold NO caps (an empty
                # list must not coerce into a default cap on display).
                _m = v.get("mode") if v.get("mode") in _AUTHZ_STORED_MODES else "deny"
                base["entries"][str(k).lower()] = {
                    "mode": _m,
                    "caps": [c for c in (v.get("caps") or []) if c in _AUTHZ_CAPS.values()]
                            or (["run"] if _m != "deny" else []),
                    "granted_at": v.get("granted_at"),
                }
        return base
    except (OSError, json.JSONDecodeError):
        return base


def _authz_save(cfg: dict) -> None:
    _AUTHZ_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(_AUTHZ_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(cfg, indent=2).encode())
    finally:
        os.close(fd)
    os.chmod(str(_AUTHZ_FILE), 0o600)


def _authz_decision(cfg: dict, allow_network: bool, identity: str,
                    has_secrets: bool, wants_network: bool) -> dict:
    """PURE permission gate. All inputs are plain data — tests/test_authz.py
    walks the whole matrix without a hub, a job or a filesystem.

    Order matters and is deliberate:
      1. entry mode deny  → out (explicit beats everything)
      2. default deny + no entry → out (whitelist mode; the message names
         the exact command that grants access)
      3. network requested → needs node `blnq network on` AND the cap
      4. secrets present  → needs the secrets cap ('all' implies both)
      5. mode maybe → ALLOW but strict (caller applies the probation scan)
    """
    ident = str(identity or "").strip().lower() or "unknown"
    entries = (cfg or {}).get("entries") or {}
    default_mode = "deny" if (cfg or {}).get("default") == "deny" else "allow"
    ent = entries.get(ident)
    mode = (ent or {}).get("mode") or (default_mode if not ent else "allow")
    if not ent:
        mode = default_mode
    if mode not in _AUTHZ_STORED_MODES:
        mode = "deny"    # hand-edited garbage in an entry fails closed
    caps = list((ent or {}).get("caps") or (["all"] if mode != "deny" else []))

    def _no(reason):
        return {"ok": False, "identity": ident, "mode": mode, "caps": caps,
                "reason": reason, "strict": False}

    if mode == "deny":
        if ent:
            return _no(f"'{ident}' is denied on this node "
                       f"(restore: blnq auth allow {ident})")
        return _no(f"node default is DENY and '{ident}' has no entry "
                   f"(grant: blnq auth {ident} all …)")
    if wants_network:
        if not allow_network:
            return _no("this node has network jobs OFF (blnq network on)")
        if not ("all" in caps or "network" in caps):
            return _no(f"'{ident}' lacks the network cap "
                       f"(grant: blnq auth {ident} network)")
    if has_secrets and not ("all" in caps or "secrets" in caps):
        return _no(f"'{ident}' lacks the secrets cap "
                   f"(grant: blnq auth {ident} secrets)")
    if mode == "maybe":
        return {"ok": True, "identity": ident, "mode": "maybe", "caps": caps,
                "reason": "probation — strict local scan gate applies",
                "strict": True}
    return {"ok": True, "identity": ident, "mode": "allow", "caps": caps,
            "reason": "authorized", "strict": False}


def _authz_parse(tokens) -> dict:
    """FLEXIBLE token parser — order never matters:
    `blnq auth yalla network` == `blnq auth network yalla` ==
    `blnq authorize all yalla run`. Unknown tokens are identities; verbs,
    modes and caps are recognized anywhere; numbers are log counts."""
    spec = {"identities": [], "mode": None, "caps": [], "verbs": [],
            "count": None, "default": None, "errors": []}
    seen_caps = []
    toks = [str(t) for t in tokens]
    i = 0
    while i < len(toks):
        t = toks[i].lower()
        if t in ("default",):
            spec["verbs"].append("default")
            nxt = toks[i + 1].lower() if i + 1 < len(toks) else ""
            if nxt in ("allow", "deny"):
                spec["default"] = nxt
                i += 1
            else:
                spec["errors"].append("`default` needs allow|deny "
                                      "(e.g. `blnq auth default deny`)")
        elif t in _AUTHZ_VERBS:
            v = _AUTHZ_VERBS[t]
            if v not in spec["verbs"]:
                spec["verbs"].append(v)
        elif t in _AUTHZ_MODES:
            canon = _AUTHZ_MODES[t]
            if spec["mode"] and spec["mode"] != canon:
                spec["errors"].append(f"conflicting modes: {spec['mode']} vs {canon}")
            spec["mode"] = canon
        elif t in _AUTHZ_CAPS:
            c = _AUTHZ_CAPS[t]
            if c not in seen_caps:
                seen_caps.append(c)
        elif t.isdigit():
            spec["count"] = min(500, int(t))
        elif t in ("authorize", "auth"):
            pass    # harmless repeats of the command word itself
        else:
            if not _AUTHZ_IDENT_RE.match(t):
                spec["errors"].append(f"not a valid identity: {toks[i]!r} "
                                      "(letters, digits, . _ @ + - only)")
            elif t not in spec["identities"]:
                spec["identities"].append(t)
        i += 1
    spec["caps"] = seen_caps
    if "all" in seen_caps:
        spec["caps"] = ["all"]
    return spec


def _authz_history_append(entry: dict) -> None:
    """Append-only JSONL, capped — the audit must survive many jobs without
    ever becoming the thing that fills the disk (it is written from the
    completion path of EVERY job, including authz refusals)."""
    try:
        _AUTHZ_HISTORY.parent.mkdir(parents=True, exist_ok=True)
        with open(_AUTHZ_HISTORY, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        # cheap cap: trim only when the file grows past ~1500 lines
        if _AUTHZ_HISTORY.stat().st_size > 400_000:
            lines = _AUTHZ_HISTORY.read_text(encoding="utf-8").splitlines()[-1000:]
            _AUTHZ_HISTORY.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        pass    # the audit never breaks a run


def _authz_history(limit: int = 20, identity: str | None = None) -> list:
    if not _AUTHZ_HISTORY.exists():
        return []
    try:
        rows = []
        for line in _AUTHZ_HISTORY.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if identity and str(r.get("identity", "")).lower() != identity:
                continue
            rows.append(r)
        return rows[-max(1, min(500, limit)):]
    except OSError:
        return []


def _authz_grant(cfg: dict, ident: str, mode: str, caps: list) -> None:
    now = int(time.time())
    prev = cfg["entries"].get(ident) or {}
    if mode == "deny":
        cfg["entries"][ident] = {"mode": "deny", "caps": [], "granted_at": now}
        return
    # caps MERGE on purpose: `blnq auth yalla network` ADDS the network cap to
    # an existing grant instead of silently replacing what was there.
    base_caps = set() if prev.get("mode") == "deny" else set(prev.get("caps") or [])
    merged = sorted(base_caps | set(caps or [])) or ["run"]
    cfg["entries"][ident] = {"mode": mode, "caps": merged, "granted_at": now}


def cmd_auth(args) -> None:
    """`blnq auth|authorize` — grant, inspect and audit local authorizations.

    Order-free by design (the parser above): who/logs/show/default are verbs,
    allow/maybe/deny are modes, all/run/network/secrets are caps, everything
    else is an identity. `blnq auth` alone = inventory. --json everywhere for
    humans who are machines. The PRIVATE decision this feeds runs in
    run_job via _authz_decision(); the audit is authz-history.jsonl.
    """
    tokens = [str(t) for t in (getattr(args, "tokens", None) or [])]
    as_json = bool(getattr(args, "json", False))
    spec = _authz_parse(tokens)
    if spec["errors"]:
        die("; ".join(spec["errors"]))
    cfg = _authz_load()

    if spec["default"]:
        cfg["default"] = spec["default"]
        _authz_save(cfg)
        msg = (f"node default → DENY (whitelist: only listed identities run)"
               if spec["default"] == "deny" else
               f"node default → ALLOW (any identity runs unless denied)")
        ok(msg)
        if as_json:
            print(json.dumps({"ok": True, "default": cfg["default"]}, indent=2))
        if spec["default"] == "deny":
            _hint(f"listed: {', '.join(cfg['entries']) or '(none yet)'} — "
                  f"grant with `{APP} auth <identity> [caps]`")
        return

    if "logs" in spec["verbs"]:
        rows = _authz_history(spec["count"] or 20,
                              spec["identities"][0] if spec["identities"] else None)
        if as_json:
            print(json.dumps(rows, indent=2, default=str))
            return
        _title("auth logs", f"last {len(rows)} job decisions"
              + (f" — {spec['identities'][0]}" if spec["identities"] else ""))
        print()
        if not rows:
            print("  no history yet — entries appear as jobs complete "
                  f"(file: {_AUTHZ_HISTORY})")
            return
        print(f"    {'when':<16} {'identity':<16} {'mode':<8} {'status':<10} {'ms':>7}  script / detail")
        for r in rows:
            when = time.strftime("%m-%d %H:%M", time.localtime(r.get("ts") or 0))
            detail = str(r.get("script") or "?")
            extra = str(r.get("detail") or "")[:44]
            if extra:
                detail += f" · {extra}"
            print(f"    {when:<16} {str(r.get('identity','?')):<16} "
                  f"{str(r.get('mode') or '-'):<8} {str(r.get('status','?')):<10} "
                  f"{str(r.get('ms') or '-'):>7}  {detail}")
        return

    # show / inventory / grant
    if "show" in spec["verbs"] and spec["identities"]:
        ident = spec["identities"][0]
        ent = cfg["entries"].get(ident)
        rows = _authz_history(5, ident)
        probe = {k: _authz_decision(cfg, True, ident, k == "secrets",
                                    k == "network")
                 for k in ("run", "secrets", "network")}
        if as_json:
            print(json.dumps({"identity": ident, "entry": ent,
                              "default": cfg["default"], "would_allow": probe,
                              "recent": rows}, indent=2, default=str))
            return
        _title("auth", f"{ident} on this machine")
        print()
        if ent:
            _kv("mode", str(ent.get("mode")))
            _kv("caps", ", ".join(ent.get("caps") or []))
            _kv("granted", time.strftime("%Y-%m-%d %H:%M",
                time.localtime(ent.get("granted_at") or 0)) or "?")
        else:
            _kv("entry", f"(none — node default applies: {cfg['default']})")
        _kv("node default", cfg["default"])
        for k, d in probe.items():
            sym = "\033[32m✓\033[0m" if d["ok"] else "\033[31m✗\033[0m"
            print(f"    {sym} {k:<8} {d['reason']}")
        if rows:
            print()
            print(f"  {_hdr('recent')}")
            for r in rows:
                print(f"    {time.strftime('%m-%d %H:%M', time.localtime(r.get('ts') or 0))}"
                      f"  {str(r.get('status','?')):<10} {str(r.get('script') or '?')[:40]}")
        return

    if spec["identities"]:
        # ── GRANT / REVOKE ────────────────────────────────────────────────
        mode = spec["mode"] or "allow"
        caps = spec["caps"] or (["run"] if mode == "maybe" else ["all"])
        changed = {}
        removed = []
        for ident in spec["identities"]:
            if not _AUTHZ_IDENT_RE.match(ident):
                die(f"not a valid identity: {ident!r}")
            if mode == "delete":
                # revoke/remove = ERASE the entry (identity returns to the
                # node default) — distinct from `deny`, which blocks even
                # under default-allow.
                if cfg["entries"].pop(ident, None) is not None:
                    removed.append(ident)
                continue
            _authz_grant(cfg, ident, mode, caps)
            changed[ident] = cfg["entries"][ident]
        _authz_save(cfg)
        if as_json:
            print(json.dumps({"ok": True, "entries": changed, "removed": removed,
                              "default": cfg["default"]}, indent=2, default=str))
            return
        for ident in removed:
            ok(f"{ident} → entry removed (node default '{cfg['default']}' now applies)")
        for ident, ent in changed.items():
            ok(f"{ident} → {ent['mode']}  caps: {', '.join(ent['caps'])}")
        if mode == "maybe":
            _hint("probation: their jobs run ONLY through the strict local "
                  "scan — CRITICAL/WARN findings refuse the run, every "
                  "outcome lands in `blnq auth logs`")
        if mode == "delete" and not removed:
            warn("nothing to remove — no entry for "
                 + ", ".join(spec["identities"]))
        return

    # ── INVENTORY (bare `blnq auth` or `blnq auth who`) ────────────────────
    vol = _volunteer_load()
    out = {"default": cfg["default"], "entries": cfg["entries"],
           "network_jobs": bool(vol.get("allow_network_jobs", True)),
           "history_file": str(_AUTHZ_HISTORY)}
    if as_json:
        print(json.dumps(out, indent=2, default=str))
        return
    _title("auth", f"authorization on this machine — default: {cfg['default']}")
    print()
    if not cfg["entries"]:
        print("  no entries — every identity follows the default"
              + (" (DENY: grant with `blnq auth <identity> [caps]`)"
                 if cfg["default"] == "deny" else
                 " (ALLOW: deny trouble with `blnq auth deny <identity>`)"))
    else:
        print(f"    {'identity':<24} {'mode':<8} caps")
        for ident, ent in sorted(cfg["entries"].items()):
            print(f"    {ident:<24} {str(ent.get('mode')):<8} "
                  f"{', '.join(ent.get('caps') or [])}")
    print()
    _kv("network jobs", "on" if out["network_jobs"] else "off")
    _kv("history", f"{len(_authz_history(500))} entries — `{APP} auth logs [N]`")
    print()
    _hint(f"grant: {APP} auth <who> [all|run|network|secrets] · probation: "
          f"{APP} auth <who> maybe · inspect: {APP} auth show <who> · "
          f"whitelist: {APP} auth default deny")


def cmd_network(args) -> None:
    """`blnq network on|off|status` — may THIS node run jobs that ask for
    egress? Enforced in run_job via _authz_decision (a job declaring network
    is refused when off, with the command that fixes it in the message).
    Honest scope note printed on status: the hub's containers execute
    today's network runs; this flag governs this node claiming them — and
    becomes a socket-level gate when node-side egress ships."""
    action = (getattr(args, "action", None) or "status").lower()
    as_json = bool(getattr(args, "json", False))
    cfg = _volunteer_load()
    if action in ("on", "off"):
        cfg["allow_network_jobs"] = (action == "on")
        try:
            _VOLUNTEER_FILE.write_text(json.dumps(cfg, indent=2))
        except OSError as e:
            die(f"cannot write {_VOLUNTEER_FILE}: {e}")
        ok(f"network jobs on this node → {action.upper()}")
        if as_json:
            print(json.dumps({"ok": True, "allow_network_jobs": action == "on"},
                             indent=2))
        if action == "off":
            _hint("jobs that request the network are now refused at claim-time "
                  "with this reason; everything else is unaffected")
        return
    allowed = bool(cfg.get("allow_network_jobs", True))
    if as_json:
        print(json.dumps({"allow_network_jobs": allowed,
                          "file": str(_VOLUNTEER_FILE)}, indent=2))
        return
    _title("network", "egress permission for jobs on this machine")
    print()
    _kv("state", "\033[32mON\033[0m — jobs requesting network may run here"
        if allowed else "\033[33mOFF\033[0m — such jobs are refused with a reason")
    _kv("toggle", f"{APP} network on | {APP} network off")
    _hint("today the hub's own containers execute network runs through the "
          "gated proxy; this flag is this node's claim-time gate for them "
          "and becomes socket-level when node-side egress ships")
    _hint(f"per-identity network permission sits on top: {APP} auth <who> network")


def _verify_one(envelope, signature, public_key_b64) -> tuple[bool, list]:
    """Verify a single attestation entirely locally — no hub round trip."""
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
    except Exception as e:
        return False, [f"bad public key: {e}"]
    return verify_envelope(envelope, signature, raw)


def cmd_verify(args) -> None:
    """Verify signed attestations and report quorum for a piece of code.

    Signatures are checked HERE, with the issuer's public key, so "it says
    verified" is never taken on the hub's word.
    """
    subject = getattr(args, "subject", None)
    attestation_id = getattr(args, "attestation", None)

    if attestation_id:
        code, resp = do_http("GET", f"/api/attest/{attestation_id}")
        if code != 200 or not isinstance(resp, dict):
            _print(resp, code); return
        d = resp.get("data", resp)
        env, sig = d.get("envelope"), d.get("signature")
        pub = (d.get("issuer") or {}).get("public_key")
        okk, probs = _verify_one(env, sig, pub)
        (ok if okk else warn)(f"{attestation_id}: {'VALID' if okk else 'INVALID ' + '; '.join(probs)}")
        print(f"  issuer : {(d.get('issuer') or {}).get('name')} ({d.get('issuer', {}).get('principal_id')})")
        print(f"  kind   : {env.get('kind')}")
        st = (env.get("body") or {}).get("statement")
        if st: print(f"  says   : {st}")
        body = env.get("body") or {}
        score = body.get("risk_score")
        level = body.get("risk_level") or body.get("risk") or "?"
        if isinstance(score, int):
            print(f"  risk   : {score}/100 ({level})")
        reviewed = body.get("reviewed_date") or body.get("reviewed_at")
        if reviewed:
            if isinstance(reviewed, int):
                reviewed = time.strftime('%Y-%m-%d', time.gmtime(reviewed))
            print(f"  date   : {reviewed}")
        if body.get("reviewer_name"):
            print(f"  reviewer: {body['reviewer_name']}"
                  + (f" / {body.get('reviewer_system')}" if body.get("reviewer_system") else ""))
        sys.exit(0 if okk else 2)

    if getattr(args, "script", None):
        code, resp = do_http("GET", f"/api/scripts/{args.script}/quorum")
        if code != 200 or not isinstance(resp, dict):
            _print(resp, code); return
        subject = resp.get("data", {}).get("subject")
        if not subject:
            die("hub returned no subject for that script")

    if not subject:
        # Default: verify a local file, exactly like `blnq scan FILE`.
        if not getattr(args, "path", None):
            die("give a file, --subject <64-hex>, --script <scr_id>, or --attestation <att_id>")
        p = Path(args.path)
        if not p.exists() or not p.is_file():
            die(f"file not found: {p}")
        subject = _subject_of(p.read_text(errors="replace"))

    code, resp = do_http("GET", f"/api/attest/subject/{subject}")
    if code != 200 or not isinstance(resp, dict):
        _print(resp, code); return
    data = resp.get("data", {})
    rows = data.get("attestations") or []
    if not rows:
        warn(f"no attestations recorded for subject {subject[:16]}…")
        print("  run `blnq review <file>` (or POST /api/scripts/:id/scan) to get validators to sign it")
        sys.exit(1)

    good = bad = 0
    print(f"subject {subject}")
    print(f"  {'attestation':<22}{'kind':<16}{'issuer':<22}{'verdict'}")
    for row in rows:
        env = row.get("envelope") or {}
        # envelope is TEXT in the DB; the hub now returns it as JSON, but an
        # older hub would hand us a string — parse rather than crash.
        if isinstance(env, str):
            try: env = json.loads(env)
            except ValueError: env = {}
        okk, probs = _verify_one(env, row.get("signature"), row.get("issuer_public_key"))
        good += okk
        bad += (not okk)
        verdict = (env.get("body") or {}).get("verdict", "-")
        mark = "\033[32mOK \033[0m" if okk else "\033[31mBAD\033[0m"
        name = (row.get("issuer_name") or row.get("issuer") or "?")[:21]
        score = (env.get("body") or {}).get("risk_score")
        level = (env.get("body") or {}).get("risk_level") or (env.get("body") or {}).get("risk") or "-"
        risk = f"{score}/100 {level}" if isinstance(score, int) else str(level)
        print(f"  {mark}  {row.get('attestation_id',''):<22}{row.get('kind',''):<16}{name:<22}{verdict:<8}{risk}")
        if not okk:
            print(f"        reason: {'; '.join(probs)}")

    q = data.get("quorum") or {}
    # Precomputed: Python <3.12 forbids backslashes inside f-string expressions.
    runnable_txt = "\033[32mRUNNABLE\033[0m" if q.get("runnable") else "\033[33mNOT YET\033[0m"
    print(f"\n  quorum: {q.get('approvals', 0)}/{q.get('required', 0)} distinct validators"
          f"  → {runnable_txt}")
    print(f"  verified locally: {good} valid, {bad} invalid")
    sys.exit(0 if bad == 0 and q.get("runnable") else 2)


def cmd_review(args) -> None:
    """Run the multi-validator signed scan on a local file.

    Registers this file as a script (needs `blnq login`) and asks every
    configured validator to sign a verdict. Quorum is how many DISTINCT
    validators said "safe".
    """
    p = Path(args.path)
    if not p.exists() or not p.is_file():
        die(f"file not found: {p}")
    code_text = p.read_text(errors="replace")
    lang = _EXT_TO_LANG.get(p.suffix.lower())
    if not lang:
        die(f"unsupported file type {p.suffix!r}")

    log(f"submitting {p.name} ({len(code_text)} bytes) for multi-validator scan")
    c, resp = do_http("POST", "/api/scripts",
                      body={"name": p.name, "code": code_text,
                            "language": lang, "description": args.description or ""})
    # `verify` points people here, so a missing login must not be a dead end:
    # say the one command that fixes it (audit 2026-11-18).
    if c == 401:
        die(f"review needs an account — log in first: {APP} login\n"
            f"    (verify needs no account and works right now: {APP} verify {args.path})")
    if c not in (200, 201) or not isinstance(resp, dict):
        _print(resp, c); return
    script_id = (resp.get("script") or {}).get("id")
    if not script_id:
        die(f"hub returned no script id: {resp!r}")
    ok(f"script {script_id}")

    log("asking validators to scan + sign (this can take a minute)…")
    c, resp = do_http("POST", f"/api/scripts/{script_id}/scan", timeout=240)
    if c != 200 or not isinstance(resp, dict):
        _print(resp, c); return
    data = resp.get("data", {})

    for r in data.get("results", []):
        if r.get("signed"):
            ext = " (relayed, signed by hivv itself)" if r.get("external") else ""
            mark = "\033[32mSIGNED\033[0m"
            score = r.get("risk_score")
            level = r.get("risk_level") or r.get("risk") or "?"
            risk_text = f"risk={score}/100 {level}" if isinstance(score, int) else f"risk={level}"
            print(f"  {mark} {r.get('name') or r.get('source'):<20} {r.get('verdict'):<8} "
                  f"{risk_text}{ext}")
            st = r.get("statement")
            if st: print(f"         {st}")
            cmds = r.get("commands") or r.get("most_used_commands") or []
            if cmds:
                top = ", ".join(f"{c.get('name')} ({c.get('count')}x)" for c in cmds[:5])
                print(f"         commands: {top}")
            files = r.get("files") or {}
            if files.get("paths"):
                print(f"         files: {', '.join(files['paths'][:6])}")
            net = r.get("network") or {}
            if net.get("domains"):
                print(f"         network: {', '.join(net['domains'][:6])}")
        else:
            print(f"  \033[31mFAILED\033[0m {r.get('name') or r.get('source'):<20} {r.get('error','')} "
                  f"(no signature — fail-closed)")

    q = data.get("quorum") or {}
    approved, required = q.get("approvals", 0), q.get("required", 0)
    if q.get("runnable"):
        ok(f"quorum {approved}/{required} → RUNNABLE")
    else:
        warn(f"quorum {approved}/{required} → not yet runnable")
    print(f"\n  verify offline: blnq verify --subject {data.get('subject')}")
    print(f"  view           : {HUB}/trust.html?subject={data.get('subject')}")
    sys.exit(0 if q.get("runnable") else 2)



# ── human verdicts: blnq approve / blnq reject ────────────────────────────
# Quorum is counted from DISTINCT active validators. Until now every validator
# was hub-seeded (hivv-scan, hivv-chat, local-llama) — so "the validators
# agreed" always meant "the models agreed". A person could not have an opinion
# that the hub was bound to respect.
#
# This is the human half of that. Two properties make a vote worth counting:
#   1. it is SIGNED with a key this machine holds, so it cannot be forged
#      afterwards and cannot be attributed to anyone else;
#   2. it is ISSUED BY an account, because registering a validator now
#      requires being signed in — so a vote costs an identity rather than a
#      fresh keypair.
#
# Note what this does NOT do: it does not bypass the sandbox, and it does not
# override an objection. run.js fails closed on ANY objection, so `reject` is
# a veto and `approve` only ever adds to the approval count. That asymmetry is
# deliberate — it is cheap to say "this is fine" and expensive to unblock
# something someone else flagged.

def _logged_in() -> bool:
    try:
        c, me = do_http("GET", "/api/user/me", timeout=10, sign=False)
        return c == 200 and isinstance(me, dict) and bool(me.get("id"))
    except Exception:
        return False


def cmd_vote(args) -> None:
    """`blnq approve|reject FILE` — file a signed human verdict on source."""
    verdict = "safe" if getattr(args, "verdict", "approve") == "approve" else "unsafe"
    word = "approve" if verdict == "safe" else "reject"
    fp = Path(getattr(args, "path", "") or "")
    if not fp.exists() or not fp.is_file():
        die(f"file not found: {fp}")
    code_text = fp.read_text(errors="replace")
    subject = _subject_of(code_text)

    # A vote must be attributable. Say so plainly rather than failing later
    # with an opaque 401 from deep inside principal registration.
    if not _logged_in():
        die(f"to {word} you need an account — a validator vote gates execution "
            f"for everyone, so it has to be attributable:\n"
            f"    {APP} login --username=you --password=…\n"
            f"  then re-run: {APP} {word} {fp.name}", code=3)

    try:
        priv, _pub, pid = _ensure_principal("validator")
    except RuntimeError as e:
        if "401" in str(e):
            die(f"the hub refused validator registration: {e}\n"
                f"  are you logged in?  {APP} whoami", code=3)
        raise

    note = (getattr(args, "note", None) or "").strip()[:400]
    lang = _EXT_TO_LANG.get(fp.suffix.lower(), "python")
    envelope = build_envelope(
        "source.review", subject, pid,
        {"source_sha256": subject,
         "verdict": verdict,
         # Plain English, because this string is what a human reads on the
         # trust page when deciding whether to agree with the vote.
         "statement": note or (f"{word}d by {socket.gethostname()} "
                               f"({APP} {word})"),
         "risk_level": "low" if verdict == "safe" else "high",
         "reviewer_name": socket.gethostname(),
         "reviewer_system": APP,
         "reviewer_version": VERSION,
         "reviewed_by": "human",
         "language": lang,
         "bytes": len(code_text.encode("utf-8")),
         "lines": code_text.count("\n") + 1,
         "reviewed_at": int(time.time())})
    signature = sign_envelope(envelope, priv)

    if not getattr(args, "json", False):
        log(f"filing your {word} verdict on {fp.name} …")
    c, resp = do_http("POST", "/api/attest",
                      body={"envelope": envelope, "signature": signature},
                      timeout=20)
    if c not in (200, 201):
        _print(resp, c)
        return

    q = ((resp.get("data") or {}).get("quorum") or {}) if isinstance(resp, dict) else {}
    if getattr(args, "json", False):
        print(json.dumps({"subject": subject, "verdict": verdict,
                          "issuer": pid, "quorum": q}, indent=2))
        sys.exit(0 if q.get("runnable") else 2)

    print()
    ok(f"your {word} is signed and recorded as {pid}")
    _kv("subject", subject[:32] + "…")
    approved, required = q.get("approvals", 0), q.get("required", 0)
    obj = q.get("objections") or []
    if q.get("runnable"):
        _kv("quorum", f"\033[32m✓ {approved}/{required} → RUNNABLE\033[0m")
    elif obj:
        _kv("quorum", f"\033[31m✗ {approved}/{required}, "
                      f"{len(obj)} objection(s) → blocked\033[0m")
        _hint("the hub fails closed on any objection — an approve cannot "
              "override a reject")
    else:
        _kv("quorum", f"\033[33m… {approved}/{required} "
                      f"(needs {max(0, required - approved)} more)\033[0m")
    for s in (q.get("signers") or [])[:6]:
        _hint(f"signed by {s.get('name') or s.get('issuer')} "
              f"({s.get('source') or '?'})")
    print()
    _hint(f"see it: {HUB}/trust.html?subject={subject}")
    _hint(f"undo is a new verdict: {APP} {'reject' if verdict == 'safe' else 'approve'} {fp.name}")
    sys.exit(0 if q.get("runnable") else 2)


def cmd_approve(args) -> None:
    """`blnq approve FILE` — file a signed HUMAN 'safe' verdict."""
    args.verdict = "approve"
    cmd_vote(args)


def cmd_reject(args) -> None:
    """`blnq reject FILE` — file a signed HUMAN objection (a veto)."""
    args.verdict = "reject"
    cmd_vote(args)


def _show_trust(code_text: str) -> None:
    """Best-effort quorum line for `blnq FILE.py`. Never blocks the run."""
    try:
        code, resp = do_http("GET", f"/api/attest/subject/{_subject_of(code_text)}", timeout=6)
    except Exception:
        return
    if code != 200 or not isinstance(resp, dict):
        return
    q = (resp.get("data") or {}).get("quorum") or {}
    n = q.get("approvals", 0)
    if not n:
        return
    req = q.get("required", 0)
    obj = q.get("objections") or []
    if q.get("runnable"):
        ok(f"trust: {n}/{req} validators signed this exact source → runnable")
    elif obj:
        # The hub fails closed on ANY objection, so say that here rather than
        # letting the run fail later with a message that does not explain why.
        warn(f"trust: {n}/{req} signed safe, but {len(obj)} validator(s) "
             f"reported this source as UNSAFE")
        _hint("the hub fails closed on any objection — re-scan with "
              f"`{APP} review <file>` to collect fresh verdicts")
    else:
        warn(f"trust: {n}/{req} validators signed this exact source "
             f"(needs {req - n} more)")


def _preflight_static(code: str, lang: str = "python") -> dict:
    """Local static facts for the duh/check gates. No network, no execution.

    Deliberately cheap and offline: this runs BEFORE every upload, so it must
    never be the thing that makes `blnq file.py` feel slow. It answers three
    questions the hub cannot:
      * is there enough work here to justify a round trip at all?
      * what shape is the I/O (stdin / stdout / argv / files)?
      * does the script need something the sandbox does not have?

    2026-11-19 audit changes:
      * `lang` aware — `parses` is now tri-state (True/False/None). ast.parse
        ran on EVERYTHING, so .js/.c/.sh files got a confident false
        "does not parse — it will fail remotely" (11 of 34 files). None means
        "not verified locally" and never becomes a blocker; python keeps the
        hard False, and bash/node are verified with their own `-n`/`--check`
        when present.
      * `network` no longer trusts import statements alone (B04 subprocess
        curl, B07 importlib-imported urllib both walked through it). Every
        signal carries `net_evidence` text so a verdict always says WHY.
      * `net_write` — POST/PUT/… shapes the egress proxy refuses outright
        (GET/HEAD only), reported as its own blocker instead of the generic
        "needs the network".
      * `opaque` — eval/exec means static analysis cannot vouch for the file.
    """
    lang = (lang or "python").lower()
    f = {
        "bytes": len(code.encode("utf-8")),
        "loc": 0, "imports": [], "third_party": [],
        "stdin": False, "stdout": False, "argv": False, "files": False,
        "network": False, "db": False, "heavy": False,
        "complexity": 0, "has_main": False, "parses": None,
        "lang": lang, "parse_lang": None,
        "net_evidence": [], "net_write_evidence": [],
        "net_write": False, "opaque": False,
    }
    lines = [l for l in code.splitlines() if l.strip() and not l.strip().startswith("#")]
    f["loc"] = len(lines)

    NET = {"socket", "urllib", "requests", "httpx", "aiohttp", "http", "ftplib",
           "smtplib", "telnetlib", "xmlrpc", "websocket"}
    DB = {"psycopg", "psycopg2", "sqlalchemy", "pymongo", "redis", "pymysql",
          "asyncpg", "mysql"}
    HEAVY = {"numpy", "pandas", "scipy", "torch", "tensorflow", "multiprocessing",
             "concurrent", "joblib", "ray", "dask"}

    # ── syntax verdict: only claim what we actually checked ───────────────
    tree = None
    if lang == "python":
        try:
            tree = ast.parse(code)
            f["parses"] = True
            f["parse_lang"] = "python ast"
        except SyntaxError:
            f["parses"] = False
            f["parse_lang"] = "python ast"
    elif lang in ("bash", "sh") and _find_exe("bash"):
        ok = _sh_syntax_ok(code, lang)
        if ok is not None:
            f["parses"] = ok
            f["parse_lang"] = "bash -n"
    elif _lang_family(lang) == "node" and _find_exe("node"):
        ok = _sh_syntax_ok(code, lang)
        if ok is not None:
            f["parses"] = ok
            f["parse_lang"] = "node --check"
    # else: parses stays None — "not verified", NEVER a failure.

    imports, depth = set(), 0

    def walk(node, d):
        nonlocal depth
        depth = max(depth, d)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.For, ast.While, ast.AsyncFor)):
                walk(child, d + 1)
            elif isinstance(child, (ast.If, ast.Try, ast.With, ast.FunctionDef,
                                    ast.AsyncFunctionDef, ast.ClassDef)):
                walk(child, d)
            else:
                walk(child, d)

    if tree is not None:
        walk(tree, 0)
        f["complexity"] = min(3, depth)

        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    imports.add(a.name.split(".")[0])
            elif isinstance(n, ast.ImportFrom):
                if n.level:
                    f["package_import"] = True     # relative import: needs its package
                elif n.module:
                    imports.add(n.module.split(".")[0])
            elif isinstance(n, ast.Attribute):
                if isinstance(n.value, ast.Name) and n.value.id == "sys" and n.attr == "argv":
                    f["argv"] = True
                if (isinstance(n.value, ast.Attribute) and n.value.attr == "stdin"
                        and isinstance(n.value.value, ast.Name)
                        and n.value.value.id == "sys"):
                    f["stdin"] = True
            elif isinstance(n, ast.Name):
                if n.id == "input":
                    f["stdin"] = True
                elif n.id == "print":
                    f["stdout"] = True
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                if n.func.id == "open":
                    f["files"] = True
                elif n.func.id in ("eval", "exec"):
                    f["opaque"] = True

        f["has_main"] = any(isinstance(n, ast.If) and isinstance(n.test, ast.Compare)
                            and "__main__" in ast.dump(n.test)
                            for n in ast.walk(tree))
    else:
        # Non-python, or python that does not parse: text sniffing only.
        # (This is also where a .js file's `import … from`/require and an
        # unparsable python file's imports come from.)
        if lang == "python":
            f["has_main"] = "__main__" in code
        for m in re.findall(r"^\s*(?:import|from)\s+([A-Za-z_][\w.]*)", code, re.M):
            imports.add(m.split(".")[0])
        for m in re.findall(r"""\brequire\s*\(\s*['"]([^'"]+)['"]""", code):
            imports.add(m.split("/")[0].replace("node:", ""))
        # family-shaped I/O detection so a .js file's shape is not blank
        if re.search(r"\b(?:console\.log|puts|echo |printf|alert\()\b", code):
            f["stdout"] = True
        if re.search(r"\b(?:process\.stdin|readline|STDIN|prompt\()\b", code):
            f["stdin"] = True
        if re.search(r"\b(?:process\.argv|ARGV|\$1\b)", code):
            f["argv"] = True
        if re.search(r"\b(?:readFileSync|open\(|fopen\s*\()", code):
            f["files"] = True

    stdlib = set(_stdlib_names())
    f["imports"] = sorted(imports)
    f["third_party"] = sorted(m for m in imports
                              if m not in stdlib and m != "__future__")
    f["db"] = bool(imports & DB)
    f["heavy"] = bool(imports & HEAVY)

    # ── network evidence: imports are one signal, not the verdict ─────────
    ev = _net_evidence(code, lang)
    if imports & NET:
        ev.insert(0, "import " + ", ".join(sorted(imports & NET)))
    # importlib/__import__ with a COMPUTED name cannot be verified — the
    # literal case (B07: import_module("urllib.request")) is already caught
    # by the module-name-as-string sniff above.
    if re.search(r"(?:importlib\.import_module|(?<![.\w])__import__)\s*\(", code) \
            and not re.search(r"""(?:importlib\.import_module|(?<![.\w])__import__)\s*\(\s*['"]""", code):
        ev.append("dynamic import with computed name (unverifiable)")
    f["net_evidence"] = ev[:6]
    f["network"] = bool(ev)

    wev = _net_write_evidence(code, lang)
    f["net_write_evidence"] = wev[:6]
    f["net_write"] = bool(wev)

    # argparse/sys.argv means the script expects arguments, not stdin
    if f["argv"]:
        f["argv"] = True
    return f


def _sh_syntax_ok(code: str, lang: str) -> "bool | None":
    """Cheap native syntax check for non-python files (bash -n / node
    --check). Returns None when the toolchain is absent or the check could
    not run — None must never read as failure."""
    exe = _find_exe("bash" if lang in ("bash", "sh") else "node")
    if not exe:
        return None
    suffix = ".sh" if lang in ("bash", "sh") else ".js"
    tmp = None
    try:
        import tempfile as _tf
        with _tf.NamedTemporaryFile("w", suffix=suffix, delete=False,
                                    encoding="utf-8") as tf:
            tf.write(code)
            tmp = tf.name
        cmd = [exe, "-n", tmp] if suffix == ".sh" else [exe, "--check", tmp]
        r = subprocess.run(cmd, capture_output=True, timeout=4)
        return r.returncode == 0
    except Exception:
        return None
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except Exception:
                pass


def _duh_call(facts: dict, subject: str | None, stdin_bytes: int = 0,
              argv_count: int = 0, danger: str | None = None) -> dict | None:
    """Ask the hub what a remote run costs — and (with `danger`) who would
    decide its safety right now. Never raises — offline is fine."""
    q = [f"bytes={facts['bytes']}", f"loc={facts['loc']}",
         f"stdin_bytes={stdin_bytes}", f"argv={argv_count}",
         f"complexity={facts['complexity']}"]
    if subject:
        q.append(f"subject={subject}")
    if danger in ("clear", "low", "medium", "high"):
        q.append(f"danger={danger}")
    try:
        code, p = do_http("GET", "/api/run/duh?" + "&".join(q),
                          sign=False, timeout=8)
        if code == 200 and isinstance(p, dict):
            return p.get("data") or {}
    except Exception:
        pass
    return None


# Egress status of THIS hub, probed only when a file actually references the
# network (so the common duh/check path stays the single hub call it was).
# None = unknown / older hub / unreachable → every caller must fail CLOSED
# (treat network as unavailable), never optimistically open.
_EGRESS_CACHE: dict = {}


def _hub_egress_status() -> "dict | None":
    if "egress" in _EGRESS_CACHE:
        return _EGRESS_CACHE["egress"]
    st = None
    try:
        code, p = do_http("GET", "/api/egress/status", timeout=3, sign=False)
        if code == 200 and isinstance(p, dict):
            st = p
    except Exception:
        st = None
    _EGRESS_CACHE["egress"] = st
    return st


def _preflight_blockers(facts: dict, egress: "dict | None" = None) -> tuple:
    """(blockers, notes) from preflight facts — the ONE place duh and check
    agree on what the sandbox can give a script.

    The network verdict is policy-carrying (audit 2026-11-19: "the local
    network verdict is a boolean, but only the proxy can tell GET from POST —
    the CLI must carry which policy applies"). So instead of a bare "needs the
    network":

      * egress OFF / unknown     → blocker: the sandbox has no network.
      * egress ON + ready        → NOTE, not blocker: reads work through the
                                   gated proxy — GET/HEAD only, mission list,
                                   robots.txt, every request audited.
      * WRITE methods (POST/PUT…)→ ALWAYS a blocker: egressPolicy refuses
                                   non-GET/HEAD at the socket ('jobs may only
                                   read'), so egress being on does not help.

    `egress` is the parsed GET /api/egress/status; None means unknown → fail
    closed. parses is tri-state: only an actual False is a blocker (None =
    'not verified locally', e.g. a language we have no parser for).
    """
    blockers, notes = [], []

    if facts["parses"] is False:
        blockers.append(
            f"does not parse ({facts.get('parse_lang') or 'local check'}) — it "
            "will fail remotely exactly as it fails here, so the round trip "
            "buys nothing")
    if facts.get("opaque"):
        blockers.append("exec()/eval() — dynamic code cannot be verified "
                        "statically (the scan flags it CRITICAL)")
    if facts.get("package_import"):
        blockers.append("uses a relative import — needs its package, which the "
                        "sandbox will not have")

    egress_on = bool(egress and egress.get("on") and egress.get("ready"))
    ev = "; ".join((facts.get("net_evidence") or [])[:3]) or "network imports"
    wev = "; ".join((facts.get("net_write_evidence") or [])[:3]) or "non-GET method"
    if facts.get("net_write"):
        blockers.append(
            f"sends data ({wev}) — the egress proxy allows GET/HEAD only, so "
            "this would be refused at the socket"
            + (" (egress is ON — refused by policy, not by unavailability)"
               if egress_on else ""))
    elif facts.get("network"):
        if egress_on:
            notes.append(
                f"network via gated egress ({ev}) — GET/HEAD only, mission "
                "list, robots.txt honoured, every request audited")
        else:
            blockers.append(
                f"needs the network ({ev}) — the sandbox runs with "
                "--network=none (egress not enabled on this hub)")

    if facts["db"]:
        blockers.append("needs a database — none is reachable from the sandbox")
    if facts["third_party"]:
        blockers.append("third-party imports not in the sandbox: "
                        + ", ".join(facts["third_party"][:6]))
    return blockers, notes


def cmd_duh(args) -> None:
    """`blnq duh [FILE]` — is it dumb to run this remotely?

    The pre-pre check: static analysis happens here, offline, before anything
    is uploaded. A 10-line script is almost never worth a 20-second safety
    review, and finding that out AFTER the upload is the wrong order.
    """
    path = getattr(args, "file", None)
    as_json = bool(getattr(args, "json", False))

    if not path:
        # no file: judge the piped/typed stdin instead
        code_text = sys.stdin.read() if not sys.stdin.isatty() else ""
        if not code_text:
            die(f"usage: {APP} duh <file.py>   (or pipe code on stdin)")
        src_label = "<stdin>"
    else:
        p = Path(path)
        if not p.exists():
            die(f"file not found: {p}")
        try:
            code_text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            die(f"cannot read {p}: {e}")
        src_label = str(p)

    facts = _preflight_static(code_text, _lang_of(src_label))
    subject = _subject_of(code_text)
    stdin_bytes = 0
    argv_count = len(getattr(args, "argv", None) or [])
    # Pattern verdict for the ladder preview: CRITICAL→high, WARN→medium,
    # INFO-only→low, none→clear (mirrors how the hub's gate ranks them).
    danger = None
    _dp = Path(path) if path else None
    if _dp and _dp.exists():
        try:
            _sev = [f.get("severity") for f in _security_scan_file(_dp)]
            danger = ("high" if "CRITICAL" in _sev else
                      "medium" if "WARN" in _sev else
                      "low" if "INFO" in _sev else "clear")
        except Exception:
            danger = None
    remote = _duh_call(facts, subject, stdin_bytes, argv_count, danger=danger)

    # ── local sanity: things the sandbox cannot give this script ──
    # Network verdict needs to know the hub's egress policy state (one extra
    # probe, only when the file references the network at all).
    egress = _hub_egress_status() if (facts["network"] or facts.get("net_write")) else None
    blockers, notes = _preflight_blockers(facts, egress)

    if as_json:
        out = {"file": src_label, "subject": subject, "facts": facts,
               "remote": remote, "blockers": blockers, "notes": notes,
               "egress": egress,
               "dumb": bool(blockers or (remote or {}).get("dumb"))}
        print(json.dumps(out, indent=2))
        sys.exit(3 if blockers else 0)

    _title("duh", "is it dumb to run this remotely?")
    print()
    print(f"  {_hdr('code')}")
    _kv("file", src_label)
    _kv("size", f"{facts['bytes']} bytes · {facts['loc']} lines · "
                f"{len(facts['imports'])} import(s)")
    shape = []
    if facts["stdin"]:  shape.append("reads stdin")
    if facts["stdout"]: shape.append("writes stdout")
    if facts["argv"]:   shape.append("takes argv")
    if facts["files"]:  shape.append("opens files")
    _kv("shape", " · ".join(shape) or "no I/O detected")
    _kv("deps", (", ".join(facts["third_party"][:4]) + " …")
                if facts["third_party"] else "stdlib only ✓")
    _kv("work", ("straight-line" if facts["complexity"] == 0 else
                 f"{facts['complexity']} nested loop(s)")
                + (" · heavy libs" if facts["heavy"] else ""))
    if notes:
        print()
        print(f"  {_hdr('policy')}")
        for n in notes:
            print(f"    \033[36m•\033[0m {n}")

    if blockers:
        print()
        print(f"  {_hdr('cannot run remotely')}")
        for b in blockers:
            print(f"    \033[31m✗\033[0m {b}")
        _hint("fix these locally first — the sandbox gives code no network, "
              "no database and only the standard library")
        sys.exit(3)

    if not remote:
        print()
        print(f"  {_hdr('verdict')}")
        _kv("hub", "\033[33m unreachable\033[0m")
        _hint("static checks passed; rerun with the hub up for the cost comparison")
        sys.exit(0)

    est = remote.get("estimates") or {}
    net = remote.get("network") or {}
    remote_ms = int(est.get("remote_ms") or 0)
    local_ms = int(est.get("local_ms") or 0)
    dumb = bool(remote.get("dumb"))
    ratio = round(remote_ms / max(1, local_ms))

    print()
    print(f"  {_hdr('network')}")
    _kv("hub rtt", f"{net.get('ping_ms', '?')} ms")
    if net.get("up_mbps"):
        _kv("uplink", f"{net['up_mbps']} Mbps")
    for note in (net.get("notes") or []):
        _hint(note)

    safety = (remote or {}).get("safety") or {}
    if safety:
        print()
        print(f"  {_hdr('safety')}")
        _kv("decides", str(safety.get("would_decide_by", "?")))
        if safety.get("pattern"):
            _kv("pattern", f"{safety['pattern']}"
                + (f"  → gate: {safety['pattern_ok']}" if safety.get("pattern_ok")
                   else "  → gate NOT qualified (AI-or-nothing for this file)"))
        _qu = safety.get("quorum")
        if _qu:
            _kv("quorum", f"{_qu.get('approvals')}/{_qu.get('required')}"
                + ("  signed ✓ (review skipped)" if _qu.get("runnable") else "")
                + (f"  · {_qu.get('objections')} objection(s)" if _qu.get("objections") else ""))
        _cv = safety.get("cached")
        if _cv:
            _kv("cached", f"{'safe' if _cv.get('safe') else 'rejected'}"
                f" by {_cv.get('source')} · {_cv.get('created_at')}")
        _ai = safety.get("ai")
        if isinstance(_ai, dict) and _ai.get("endpoints"):
            _kv("ai", " · ".join(f"{e.get('url')}={e.get('state')}"
                                 for e in _ai["endpoints"]))

    print()
    print(f"  {_hdr('verdict')}")
    bd = est.get("breakdown") or {}
    if dumb:
        _kv("decision", f"\033[33m⚠ DUMB\033[0m  remote ≈ {remote_ms/1000:.1f}s "
                        f"vs local ≈ {local_ms}ms  ({ratio}×)")
    else:
        _kv("decision", f"\033[32m✓ not dumb\033[0m  remote ≈ {remote_ms/1000:.1f}s "
                        f"vs local ≈ {local_ms}ms  ({ratio}×)")
    _kv("breakdown", f"review {bd.get('safety_ms', 0)} · queue {bd.get('queue_ms', 0)} "
                     f"· exec {bd.get('exec_ms', 0)} · ping {bd.get('ping_ms', 0)} "
                     f"· upload {bd.get('upload_ms', 0)} ms")
    if remote.get("signed"):
        s = remote["signed"]
        _kv("signed", f"{s.get('approvals')}/{s.get('required')} validators → "
                      f"{'runnable' if s.get('runnable') else 'blocked'}")
    for sug in (remote.get("suggestions") or [])[:4]:
        _hint(sug)
    print()



# ── local pre-submission analysis ────────────────────────────────────────
# `blnq check FILE` — everything that can be known about a script BEFORE it
# is uploaded, split into two halves:
#
#   local   static analysis + security + privacy + the sha256 that WILL be
#           signed. No network. Works offline.
#   remote  has this exact hash already been signed? what did it cost last
#           time? one call, and the whole thing still works without it.
#
# Why this exists as its own command rather than being folded into `scan`:
# `scan` answers "is anything dangerous here"; `check` answers "should I run
# this on blnq at all" — including the answers only the hub has.
#
# The credential patterns are mirrored from api/lib/piiScan.js. They were NOT
# in the local scanner before, which meant `aws_secret_access_key = "..."`
# passed `blnq scan` locally and was only caught after upload. A pre-submission
# check that disagrees with the server is worse than no check: it teaches you
# to trust the wrong verdict.

_PII_CREDENTIAL = [
    ("private key block",
     r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----[\sA-Za-z0-9+/=]{40,}?-----END"),
    ("aws access key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("aws secret key", r"(?i)aws_secret_access_key\s*[=:]\s*['\"][A-Za-z0-9/+=]{30,}"),
    ("github token", r"\bgh[pousr]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}"),
    ("stripe key", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}"),
    ("slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ("assigned secret",
     r"(?i)(?:secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token)"
     r"[A-Za-z0-9_-]*['\"]?[ \t]*[:=][ \t]*['\"]?[A-Za-z0-9+/_=-]{16,}"),
    ("connection string",
     r"(?i)\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis|amqp)://"
     r"[^\s:/@]+:[^\s@/]{3,}@"),
]

_PII_PERSONAL = [
    ("email address", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    ("phone number", r"(?:\+?\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?\d{3}[ .-]?\d{4}\b"),
    ("payment card", r"\b(?:\d[ -]?){13,19}\b"),
    ("national id", r"\b\d{3}-\d{2}-\d{4}\b"),
]


def _blank_prose(text: str) -> str:
    """Blank comments and docstrings, preserving offsets.

    A docstring explaining "we scan for passwords" must not trip the password
    scanner — but a password inside an ordinary string MUST be found.
    """
    out = list(text)
    n = len(text)
    i = 0

    def blank(a, b):
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if c == "#":
            j = i
            while j < n and text[j] != "\n":
                j += 1
            blank(i, j); i = j
        elif c in "\"'":
            q = c
            if text.startswith(q * 3, i):
                end = text.find(q * 3, i + 3)
                stop = n if end == -1 else end + 3
                blank(i, stop); i = stop
            else:
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


def _local_pii_scan(text: str) -> list:
    """Credentials (block) + personal data (warn), mirroring api/lib/piiScan.js."""
    src = _blank_prose(text)
    out = []
    for kind, rx in _PII_CREDENTIAL:
        m = re.search(rx, src)
        if m:
            out.append({"severity": "CRITICAL", "kind": kind, "class": "credential",
                        "line": src.count("\n", 0, m.start()) + 1})
    for kind, rx in _PII_PERSONAL:
        m = re.search(rx, src)
        if m:
            out.append({"severity": "WARN", "kind": kind, "class": "personal",
                        "line": src.count("\n", 0, m.start()) + 1})
    return out



# ── outgoing payload scan ─────────────────────────────────────────────────
# `blnq check FILE` scans the SCRIPT. But the script is rarely what leaks:
# `blnq analyse.py customers.csv` uploads the CSV, and `blnq x.py < dump.sql`
# uploads whatever is on stdin. Neither is scanned today, and neither ever
# reaches `blnq check` — because the person running it does not think of a
# data file as "code to be checked".
#
# This is the last gate before bytes leave this machine. Deliberately regex
# only and no network: it runs on every single run, so it must cost nothing.
# Deliberately loud about credentials: a leaked key cannot be un-leaked, while
# a false positive costs one `--allow-secrets`.

def _redact(s) -> str:
    """Show the SHAPE of a hit, never the value. Printing a live credential
    into a terminal that may be scrollbacked, logged or pasted into a chat is
    itself the leak this function exists to prevent."""
    try:
        return f"<{len(str(s))} chars, hidden>"
    except Exception:
        return "<hidden>"


def _scan_outgoing(label: str, text, budget: int = 4_000_000) -> list:
    """Scan a payload about to be uploaded. Returns findings; never raises."""
    if not text:
        return []
    try:
        src = str(text)[:budget]
        out = []
        for kind, rx in _PII_CREDENTIAL:
            m = re.search(rx, src)
            if m:
                out.append({"severity": "CRITICAL", "kind": kind,
                            "class": "credential", "label": label,
                            "line": src.count("\n", 0, m.start()) + 1,
                            "hit": _redact(m.group(0))})
        for kind, rx in _PII_PERSONAL:
            m = re.search(rx, src)
            if m:
                out.append({"severity": "WARN", "kind": kind,
                            "class": "personal", "label": label,
                            "line": src.count("\n", 0, m.start()) + 1,
                            "hit": _redact(m.group(0))})
        return out
    except Exception:
        return []


def _secrets_allowed() -> bool:
    """Explicit opt-out. The env var is the one a CI job can set; the flag is
    the one a person reaches for when they know the file is a test fixture."""
    if os.environ.get("BLNQ_ALLOW_SECRETS") == "1":
        return True
    return bool(globals().get("_ALLOW_SECRETS", False))


def _gate_outgoing(items: list, quiet: bool = False) -> list:
    """items: [(label, text)]. Prints findings to STDERR (stdout belongs to
    the program), blocks on credentials, returns all findings.

    Never raises — this sits on the happy path of every run, and a scanner
    bug must not be able to stop someone working.
    """
    findings = []
    try:
        for label, text in items:
            findings.extend(_scan_outgoing(str(label), text))
    except Exception:
        return []
    if not findings:
        return []

    creds = [f for f in findings if f.get("class") == "credential"]
    personal = [f for f in findings if f.get("class") == "personal"]

    if not quiet:
        err = sys.stderr
        print("", file=err)
        print("\033[1mleak check\033[0m — before anything leaves this machine",
              file=err)
        for f in findings[:12]:
            col = "31" if f["severity"] == "CRITICAL" else "33"
            print(f"  \033[{col}m{f['severity']:<8}\033[0m {f['kind']}"
                  f"  in {f['label']}:{f['line']}", file=err)
        if len(findings) > 12:
            print(f"  … {len(findings) - 12} more", file=err)

    if creds and not _secrets_allowed():
        print("", file=sys.stderr)
        print(f"  \033[31mrefusing to upload {len(creds)} credential(s).\033[0m",
              file=sys.stderr)
        print("  this is the gate working: a key that reaches the hub has "
              "left this machine", file=sys.stderr)
        print("  and cannot be un-sent. options:", file=sys.stderr)
        print("    → remove the value, read it from a file the script gets "
              "on stdin at run time", file=sys.stderr)
        print("    → if it is a fake/test value:  "
              "\033[32m--allow-secrets\033[0m  or  "
              "BLNQ_ALLOW_SECRETS=1", file=sys.stderr)
        print(f"    → see everything first:  {APP} scan <file>", file=sys.stderr)
        die(f"blocked: credential-shaped data in "
            f"{', '.join(sorted({f['label'] for f in creds}))}", code=3)
    return findings


def cmd_scan(args) -> None:
    """`blnq scan [FILE...]` — leak check for anything, before you send it.

    The quick scanner: same patterns that guard a push, run against files,
    a directory, or piped stdin. Exit 3 means credentials were found.
    """
    paths = list(getattr(args, "files", None) or [])
    as_json = bool(getattr(args, "json", False))
    only_creds = not bool(getattr(args, "all", False))

    items = []          # (label, text)
    if paths:
        for raw in paths:
            p = Path(raw)
            if p.is_dir():
                n = 0
                for sub in sorted(p.rglob("*")):
                    if not sub.is_file() or n >= 400:
                        continue
                    if any(part.startswith(".") and part not in (".env",)
                           for part in sub.parts):
                        continue
                    if sub.suffix.lower() in (".png", ".jpg", ".jpeg", ".gif",
                                              ".zip", ".gz", ".pdf", ".ico",
                                              ".woff", ".woff2", ".mp4"):
                        continue
                    try:
                        items.append((str(sub.relative_to(p)),
                                      sub.read_text(errors="replace")))
                        n += 1
                    except (OSError, UnicodeDecodeError):
                        continue
            elif p.is_file():
                try:
                    items.append((p.name, p.read_text(errors="replace")))
                except (OSError, UnicodeDecodeError) as e:
                    warn(f"cannot read {p}: {e}")
            else:
                die(f"not found: {p}")
    elif not sys.stdin.isatty():
        items.append(("stdin", sys.stdin.read()))
    else:
        die(f"nothing to scan — pass a file, a directory, or pipe data in:\n"
            f"    {APP} scan data.csv\n"
            f"    {APP} scan ./project/\n"
            f"    cat dump.sql | {APP} scan")

    findings = []
    for label, text in items:
        findings.extend(_scan_outgoing(label, text))
    if only_creds:
        findings = [f for f in findings if f.get("class") == "credential"]

    if as_json:
        print(json.dumps({"scanned": len(items), "findings": findings},
                         indent=2))
        sys.exit(3 if any(f["severity"] == "CRITICAL" for f in findings) else 0)

    _title("scan", f"{len(items)} item(s) — leak check")
    print()
    if not findings:
        ok("no credential-shaped data found" + (
            "" if not only_creds else " (personal data not shown — "
            "add --all to include it)"))
        _hint(f"this is the same check a push runs: {APP} scan <file>")
        sys.exit(0)

    print(f"  {_hdr('findings')}")
    for f in findings[:40]:
        col = "31" if f["severity"] == "CRITICAL" else "33"
        print(f"    \033[{col}m{f['severity']:<8}\033[0m {f['kind']:<22} "
              f"{f['label']}:{f['line']}")
    if len(findings) > 40:
        print(f"    … {len(findings) - 40} more")
    print()
    creds = [f for f in findings if f.get("class") == "credential"]
    if creds:
        print(f"  \033[31m{len(creds)} credential(s) — do not send these.\033[0m")
        print("  remove the value, or pass --allow-secrets if it is a fixture.")
    else:
        print("  \033[33mpersonal data only — fine to send if you meant to.\033[0m")
    sys.exit(3 if creds else 0)

def _trust_quorum(subject: str) -> dict | None:
    """Has this exact sha256 already been signed? Offline-tolerant."""
    try:
        code, resp = do_http("GET", f"/api/attest/subject/{subject}", timeout=6, sign=False)
        if code == 200 and isinstance(resp, dict):
            return (resp.get("data") or {}).get("quorum") or {}
    except Exception:
        pass
    return None


def cmd_check(args) -> None:
    """`blnq check FILE` — analyse a script before you submit it.

    Local half: static analysis, security scan, privacy scan and the sha256
    that would be signed. Remote half: whether that hash is already signed and
    what a run cost last time. The local half works offline.
    """
    path = getattr(args, "file", None)
    if not path:
        die(f"usage: {APP} check <file.py>")
    fp = Path(path)
    if not fp.exists():
        die(f"file not found: {fp}")
    try:
        code_text = fp.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        die(f"cannot read {fp}: {e}")

    as_json = bool(getattr(args, "json", False))
    facts = _preflight_static(code_text, _lang_of(str(fp)))
    sec = _security_scan_file(fp)
    pii = _local_pii_scan(code_text)
    subject = _subject_of(code_text)
    quorum = _trust_quorum(subject)
    remote = _duh_call(facts, subject, stdin_bytes=0,
                       argv_count=len(getattr(args, "argv", None) or []),
                       danger=("high" if any(f.get("severity") == "CRITICAL" for f in sec)
                               else "medium" if any(f.get("severity") == "WARN" for f in sec)
                               else "low" if sec else "clear"))

    crit = [f for f in sec if f.get("severity") == "CRITICAL"]
    warns = [f for f in sec if f.get("severity") == "WARN"]
    creds = [f for f in pii if f.get("class") == "credential"]
    personal = [f for f in pii if f["class"] == "personal"]
    egress = _hub_egress_status() if (facts["network"] or facts.get("net_write")) else None
    blockers, notes = _preflight_blockers(facts, egress)
    if crit:
        blockers.append(f"{len(crit)} critical security finding(s)")
    if creds:
        blockers.append(f"{len(creds)} credential(s) in the source — never submit these")

    if as_json:
        print(json.dumps({
            "file": str(fp), "subject": subject, "facts": facts,
            "security": sec, "pii": pii, "quorum": quorum, "remote": remote,
            "blockers": blockers, "notes": notes, "egress": egress,
            "personal": personal,
        }, indent=2, default=str))
        sys.exit(3 if blockers else 0)

    _title("check", f"{fp.name} — before you submit")
    print()
    print(f"  {_hdr('local  (offline, instant)')}")
    if facts["parses"] is True:
        _kv("syntax", "\033[32m✓ parses\033[0m"
            + (f" ({facts['parse_lang']})" if facts.get("parse_lang") else ""))
    elif facts["parses"] is False:
        _kv("syntax", "\033[31m✗ does not parse\033[0m"
            + (f" ({facts['parse_lang']})" if facts.get("parse_lang") else ""))
    else:
        # tri-state: no parser for this language here — never claim failure.
        _kv("syntax", "\033[2m… not verified locally\033[0m"
            " (no checker for this language on this machine)")
    _kv("size", f"{facts['bytes']} bytes · {facts['loc']} lines · "
                f"{len(facts['imports'])} import(s)")
    shape = []
    if facts["stdin"]:  shape.append("reads stdin")
    if facts["stdout"]: shape.append("writes stdout")
    if facts["argv"]:   shape.append("takes argv")
    if facts["files"]:  shape.append("opens files")
    _kv("shape", " · ".join(shape) or "no I/O detected")
    _kv("deps", (", ".join(facts["third_party"][:4]) + " …")
                if facts["third_party"] else "stdlib only ✓")
    _kv("work", ("straight-line" if facts["complexity"] == 0
                 else f"{facts['complexity']} nested loop(s)")
                + (" · heavy libs" if facts["heavy"] else ""))
    _kv("sha256", subject[:24] + "…")
    _kv("security", ("\033[32m✓ no critical findings\033[0m"
                     if not crit else
                     f"\033[31m✗ {len(crit)} critical\033[0m")
        + f" · {len(warns)} warning(s)")
    _kv("privacy", ("\033[32m✓ no credentials, no personal data\033[0m"
                    if not creds and not personal else
                    (f"\033[31m✗ {len(creds)} credential(s)\033[0m" if creds else "")
                    + (f" \033[33m{len(personal)} personal-data hit(s)\033[0m"
                       if personal else "")))

    if sec and (crit or warns):
        print()
        print(f"  {_hdr('findings')}")
        shown = (crit + warns)[:8]
        for f in shown:
            sev = f.get("severity", "?")
            col = "31" if sev == "CRITICAL" else "33"
            print(f"    \033[{col}m{sev.lower():<8}\033[0m L{f.get('line', '?')}: "
                  f"{str(f.get('message', ''))[:76]}")
        if len(crit + warns) > len(shown):
            _hint(f"… {len(crit + warns) - len(shown)} more — run `{APP} scan {fp}`")
    if pii:
        print()
        print(f"  {_hdr('privacy hits')}")
        for f in pii[:6]:
            col = "31" if f["class"] == "credential" else "33"
            print(f"    \033[{col}m{f['kind']:<18}\033[0m line {f['line']}")

    print()
    print(f"  {_hdr('remote  (one call)')}")
    if quorum:
        n, req = quorum.get("approvals", 0), quorum.get("required", 0)
        obj = quorum.get("objections") or []
        if quorum.get("runnable"):
            _kv("trust", f"\033[32m✓ {n}/{req} validators signed → runnable\033[0m")
        elif obj:
            _kv("trust", f"\033[31m✗ {n}/{req} signed, {len(obj)} objected\033[0m")
        else:
            _kv("trust", f"\033[33m… {n}/{req} signed (needs {max(0, req - n)} more)\033[0m")
    else:
        _kv("trust", "\033[2mnot signed yet (or hub unreachable)\033[0m")
    if remote:
        est = remote.get("estimates") or {}
        _kv("cost", f"remote ≈ {int(est.get('remote_ms', 0))/1000:.1f}s "
                    f"vs local ≈ {int(est.get('local_ms', 0))}ms"
                    + ("  \033[33m→ dumb to run remotely\033[0m"
                       if remote.get("dumb") else "  \033[32m→ fine remotely\033[0m"))
    else:
        _kv("cost", "\033[2munknown (hub unreachable)\033[0m")

    if notes:
        print()
        print(f"  {_hdr('policy')}")
        for n in notes:
            print(f"    \033[36m•\033[0m {n}")

    print()
    print(f"  {_hdr('verdict')}")
    if blockers:
        for b in blockers:
            print(f"    \033[31m✗\033[0m {b}")
        _hint("fix these before submitting — the sandbox gives code no network, "
              "no database and only the standard library")
        sys.exit(3)
    ok(f"ready to run")
    _hint(f"{APP} {fp.name}          (remote, signed path)")
    _hint(f"python3 {fp.name}       (local, instant)")
    print()



# ── blnq list / who / details ─────────────────────────────────────────────
# Humans reach for different words for the same thing: `list`, `runs`,
# `history`, `last`, `details`. Rather than pick one and make the rest errors,
# they all resolve to the same handler — an unknown command is a worse failure
# than a redundant one.

def _ts(v) -> str:
    try:
        return time.strftime("%m-%d %H:%M", time.localtime(
            int(v) if not isinstance(v, str)
            else __import__("datetime").datetime.fromisoformat(
                v.replace("Z", "+00:00")).timestamp()))
    except Exception:
        return str(v or "")[:16]


def cmd_list(args) -> None:
    """`blnq list [N]` — a table of what has run: who, what, where, when."""
    limit = int(getattr(args, "limit", 0) or 15)
    as_json = bool(getattr(args, "json", False))
    code, p = do_http("GET", f"/api/run?limit={limit}", sign=False, timeout=15)
    if code != 200 or not isinstance(p, dict):
        _print(p, code); return
    rows = p.get("data") or p.get("runs") or []
    if as_json:
        print(json.dumps(rows, indent=2, default=str)); return

    _title("list", f"last {len(rows)} run(s)")
    if not rows:
        _hint("nothing has run yet — try: blnq smoke_hello.py"); return
    print()
    print(f"  {'run':<10} {'when':<12} {'lang':<7} {'status':<11} "
          f"{'exec':>7}  {'by':<16} script")
    print(f"  {'─'*10} {'─'*12} {'─'*7} {'─'*11} {'─'*7}  {'─'*16} {'─'*20}")
    for r in rows:
        rid = str(r.get("id", ""))[:8]
        who = str(r.get("creator_name") or r.get("created_by") or "anonymous")[:16]
        exe = r.get("execution_time_ms")
        exe = f"{int(exe)}ms" if exe is not None else "-"
        script = str(r.get("script") or r.get("subject") or "")[:20]
        print(f"  {rid:<10} {_ts(r.get('created_at')):<12} "
              f"{str(r.get('language',''))[:7]:<7} {str(r.get('status',''))[:11]:<11} "
              f"{exe:>7}  {who:<16} {script}")
    print()
    _hint(f"detail on one: {APP} details <run-id>")
    _hint(f"who can run things: {APP} who")


def cmd_who(args) -> None:
    """`blnq who` — who is available to run things right now."""
    as_json = bool(getattr(args, "json", False))
    code, p = do_http("GET", "/api/workers/list", sign=False, timeout=15)
    workers = (p.get("workers") or []) if code == 200 and isinstance(p, dict) else []
    vc, vp = do_http("GET", "/api/attest/validators", sign=False, timeout=10)
    validators = ((vp.get("data") or {}).get("validators") or []) \
        if vc == 200 and isinstance(vp, dict) else []

    if as_json:
        print(json.dumps({"workers": workers, "validators": validators},
                         indent=2, default=str)); return

    _title("who", "machines and validators")
    print()
    print(f"  {_hdr('machines  (run your code)')}")
    if not workers:
        _hint("no machines registered — start one with: blnq start")
    else:
        print(f"    {'host':<14} {'state':<9} {'volunteer':<10} {'load':>5}  {'last seen':<12} caps")
        for w in workers:
            vol = "yes" if w.get("volunteers") else "no"
            state = ("online" if w.get("is_online")
                     else ("active" if w.get("is_active") else "off"))
            caps = ",".join((w.get("capabilities") or [])[:4])
            print(f"    {str(w.get('hostname',''))[:14]:<14} {state:<9} "
                  f"{vol:<10} {str(w.get('current_load','?')):>5}  "
                  f"{_ts(w.get('last_seen')):<12} {caps}")
        on = sum(1 for w in workers if w.get("is_online"))
        vol = sum(1 for w in workers if w.get("volunteers"))
        _hint(f"{on} online · {vol} volunteering · "
              f"{sum(1 for w in workers if w.get('can_claim'))} can claim now")
    print()
    print(f"  {_hdr('validators  (sign what the code does)')}")
    if not validators:
        _hint("no validators registered")
    else:
        # Split the list the way quorum actually reads it. Printing a
        # suspended validator in the same undifferentiated block as a live one
        # makes the count look bigger than the gate is — the homepage made
        # exactly this mistake and advertised signers that cannot move the
        # number. Suspended keys stay visible below: they are needed to
        # verify signatures made while they were live.
        active = [v for v in validators if v.get("is_active", True)]
        parked = [v for v in validators if not v.get("is_active", True)]
        for v in active:
            print(f"    {v.get('principal_id','')}")
            print(f"      {v.get('name') or v.get('source','')}  "
                  f"role={v.get('role','?')}  \033[32mcounts toward quorum\033[0m")
        if parked:
            print()
            print(f"    \033[2m{len(parked)} suspended "
                  f"(kept so their older signatures still verify)\033[0m")
            for v in parked:
                print(f"      \033[2m{v.get('name') or v.get('source','')}  "
                      f"{v.get('principal_id','')[:24]}…\033[0m")
        _hint(f"{len(active)} active · threshold "
              f"{_SIGN_THRESHOLD} distinct must agree")
    print()
    _hint(f"what they have run: {APP} list")


def cmd_details(args) -> None:
    """`blnq details [run-id]` — everything about the last run (or one run)."""
    rid = getattr(args, "run_id", None)
    token = None
    if not rid:
        st = read_state() or {}
        last = st.get("last_run") or {}
        rid = last.get("id")
        token = last.get("read_token")
    if not rid:
        die(f"no run recorded yet — run something first: {APP} myscript.py")

    # The token exists exactly for this: runs are private by default and the
    # CLI has no session, so the read capability from creation time is what
    # lets the owner see their own output. It was loaded and then dropped,
    # so details of a private run 403'd its own creator (audit 2026-11-18).
    code, p = do_http("GET", f"/api/run/{rid}", sign=False, timeout=15,
                      extra_headers=({"X-Run-Token": token} if token else None))
    if code == 403:
        die(f"run {str(rid)[:8]} is private and its read token isn't stored "
            f"(only the LAST run's is) — open it right after running it, or "
            f"view it in the browser")
    if code != 200 or not isinstance(p, dict):
        _print(p, code); return

    as_json = bool(getattr(args, "json", False))
    if as_json:
        print(json.dumps(p, indent=2, default=str)); return

    status = str(p.get("status", "?"))
    ok_col = "\033[32m" if status == "completed" else "\033[33m"
    _title("details", f"run {str(rid)[:8]}")
    print()
    print(f"  {_hdr('what ran')}")
    _kv("script", str(p.get("script") or "(uploaded source)"))
    _kv("language", str(p.get("language", "?")))
    _kv("status", f"{ok_col}{status}\033[0m"
        + (f"  exit {p.get('exit_code')}" if p.get("exit_code") is not None else ""))
    _kv("subject", str(p.get("subject") or "")[:32] + "…")
    _kv("when", _ts(p.get("created_at")))

    # timings: the row carries review + exec; queue and total come from stamps
    rev = p.get("safety_ms")
    exe = p.get("execution_time_ms")
    try:
        import datetime as _dt
        def _parse(v):
            if not v: return None
            if isinstance(v, str):
                return _dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
            return _dt.datetime.fromtimestamp(v / 1000 if v > 1e12 else v,
                                              tz=_dt.timezone.utc)
        started, created, done = (_parse(p.get("started_at")),
                                  _parse(p.get("created_at")),
                                  _parse(p.get("completed_at")))
        queue_ms = int((started - created).total_seconds() * 1000) \
            if started and created else None
        total_ms = int((done - created).total_seconds() * 1000) \
            if done and created else None
    except Exception:
        queue_ms = total_ms = None

    print()
    print(f"  {_hdr('timing')}")
    if rev is not None:
        _kv("safety review", f"{int(rev)} ms"
            + ("  \033[2m(attestation — model skipped)\033[0m"
               if int(rev) < 50 else ""))
    if queue_ms is not None:
        _kv("queue", f"{queue_ms} ms")
    if exe is not None:
        _kv("execution", f"{int(exe)} ms")
    if total_ms is not None:
        _kv("total", f"{total_ms} ms")

    # who ran it: /api/run always executes in the hub's Docker container
    print()
    print(f"  {_hdr('where')}")
    _kv("executor", "bLNQ hub container (Docker, network=none, read-only)")
    _kv("sandbox", "non-root (uid 65534) · 128 MB · 30 s · 50 pids")

    # trust: was this source signed before it ran?
    subj = p.get("subject")
    if subj:
        q = _trust_quorum(str(subj))
        print()
        print(f"  {_hdr('trust')}")
        if q:
            n, req = q.get("approvals", 0), q.get("required", 0)
            obj = q.get("objections") or []
            if q.get("runnable"):
                _kv("quorum", f"\033[32m✓ {n}/{req} validators signed → runnable\033[0m")
            elif obj:
                _kv("quorum", f"\033[31m✗ {n}/{req} signed, {len(obj)} objected\033[0m")
            else:
                _kv("quorum", f"\033[33m… {n}/{req} (needs {max(0, req-n)} more)\033[0m")
            for sg in (q.get("signers") or [])[:4]:
                _hint(f"signed by {sg.get('name') or sg.get('issuer')}")
        else:
            _kv("quorum", "\033[2mno signatures recorded\033[0m")
    print()
    _hint(f"verify offline: {APP} verify --subject {subj}" if subj
          else "no subject recorded")
    _hint(f"run something else: {APP} myscript.py")



# ── LAN discovery ────────────────────────────────────────────────────────
# Today every introduction goes through the hub: two peers learn each other's
# addresses only because the hub told them. On a LAN — or when the internet is
# down — that means neighbours cannot find each other at all.
#
# This is a plain UDP broadcast, the same idea as a workshop announcing itself.
# It is deliberately NOT a security boundary: anyone on the segment can hear
# it, so it carries only what a stranger could already see from a port scan
# (hostname, p2p port, protocol version) and NEVER a key, a token or a job.
# Trust still comes from the E25519 handshake that follows.

DISCOVERY_PORT = int(os.environ.get("BLNQ_DISCOVERY_PORT", "3095"))
DISCOVERY_MAGIC = "blnq.lan.v1"
_discovery_peers: dict = {}
_discovery_thread = None


def _discovery_payload() -> dict:
    st = read_state() or {}
    return {
        "t": DISCOVERY_MAGIC,
        "name": socket.gethostname(),
        "worker": st.get("worker_id"),
        "p2p_port": P2P_UDP_PORT,
        "version": VERSION,
        "volunteer": bool(_volunteer_load().get("share_cpu")),
        "ts": int(time.time()),
    }


def _discovery_listen(stop: "threading.Event") -> None:
    """Passive listener: record every hello we hear until told to stop."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", DISCOVERY_PORT))
        sock.settimeout(1.0)
    except OSError:
        return                       # port busy (another blnq on this box)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(4096)
        except (socket.timeout, TimeoutError):
            continue
        except OSError:
            break
        try:
            m = json.loads(data.decode("utf-8"))
        except Exception:
            continue
        if not isinstance(m, dict) or m.get("t") != DISCOVERY_MAGIC:
            continue
        if not m.get("name"):
            continue
        _discovery_peers[addr[0]] = {
            "addr": addr[0], "name": m.get("name"), "worker": m.get("worker"),
            "p2p_port": m.get("p2p_port"), "version": m.get("version"),
            "volunteer": bool(m.get("volunteer")),
            "seen": int(time.time()),
        }
    try:
        sock.close()
    except OSError:
        pass


def _discovery_announce() -> bool:
    """Broadcast our presence once. Never raises — discovery is a nicety."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        payload = json.dumps(_discovery_payload()).encode("utf-8")
        for target in ("255.255.255.255", "<broadcast>"):
            try:
                sock.sendto(payload, (target, DISCOVERY_PORT))
            except OSError:
                pass
        sock.close()
        return True
    except Exception:
        return False


def start_discovery() -> None:
    """Start the listener and announce once. Idempotent; safe to call at boot."""
    global _discovery_thread
    if _discovery_thread and _discovery_thread.is_alive():
        return
    _discovery_announce()
    stop = threading.Event()
    _discovery_thread = threading.Thread(
        target=_discovery_listen, args=(stop,), daemon=True, name=f"{APP}-lan")
    _discovery_thread.start()
    # re-announce periodically so peers that started later can hear us
    def _beat():
        while not stop.wait(30):
            _discovery_announce()
    threading.Thread(target=_beat, daemon=True, name=f"{APP}-lan-beat").start()


def _lan_peers(fresh_s: int = 90) -> list:
    """Peers heard within the last `fresh_s` seconds."""
    now = int(time.time())
    return sorted(
        (p for p in _discovery_peers.values() if now - p.get("seen", 0) <= fresh_s),
        key=lambda p: p.get("name") or "")


def cmd_peers(args) -> None:
    """`blnq peers` — who else is on this LAN, without asking the internet."""
    as_json = bool(getattr(args, "json", False))
    _discovery_announce()                 # one probe so the list is current
    time.sleep(1.2)                       # give neighbours a moment to reply
    peers = _lan_peers()

    # also show what the HUB knows, so the two views can be compared
    code, p = do_http("GET", "/api/workers/list", sign=False, timeout=6)
    hub = (p.get("workers") or []) if code == 200 and isinstance(p, dict) else []

    if as_json:
        print(json.dumps({"lan": peers, "hub": hub}, indent=2, default=str))
        return

    _title("peers", "who is on this network")
    print()
    print(f"  {_hdr(f'local network  (udp/{DISCOVERY_PORT} broadcast)')}")
    if not peers:
        _hint(f"none heard in the last 90s — is anything else running {APP} on this LAN?")
    else:
        print(f"    {'host':<16} {'addr':<16} {'p2p':>6} {'ver':<8} {'volunteer':<9} worker")
        for q in peers:
            print(f"    {str(q.get('name',''))[:16]:<16} {str(q.get('addr',''))[:16]:<16} "
                  f"{str(q.get('p2p_port') or '-'):>6} {str(q.get('version') or '-'):<8} "
                  f"{('yes' if q.get('volunteer') else 'no'):<9} "
                  f"{str(q.get('worker') or '-')[:20]}")
    print()
    print(f"  {_hdr('hub  (what blnq.org knows)')}")
    if not hub:
        _hint("hub unreachable or no machines registered")
    else:
        for w in hub:
            print(f"    {str(w.get('hostname',''))[:16]:<16} "
                  f"online={'yes' if w.get('is_online') else 'no':<5} "
                  f"volunteer={'yes' if w.get('volunteers') else 'no':<5} "
                  f"{str(w.get('last_seen') or '')[:16]}")
    print()
    _hint("discovery is unauthenticated by design — it announces hostname and "
          "port only, never keys or jobs")
    _hint(f"connect directly: {APP} p2p doctor")



# ── blnq debug / bugs ────────────────────────────────────────────────────
# Two different questions, two commands:
#
#   blnq debug [TEXT]  "what does THIS error mean and what do I do?"
#                      local knowledge base — works offline, no round trip.
#   blnq bugs          "what is broken on the system right now?"
#                      hub-served known issues + this machine's own recent
#                      failures pulled from the agent log.
#
# The knowledge base is ordered most-likely-first and matched on a score, not
# an exact string: real errors arrive with ids, paths and timestamps glued on.

_DEBUG_KB = [
    # (pattern, title, explanation, fix)
    (r"523|origin is unreachable",
     "hub origin is unreachable (Cloudflare 523)",
     "Cloudflare could not reach blnq.org — the hub is down or restarting, "
     "not you. Nothing is wrong with your machine.",
     "check https://blnq.org/health · wait and retry · blnq doctor"),
    (r"read operation timed out|network error|ENOTFOUND|EAI_AGAIN",
     "cannot reach the hub",
     "the CLI could not complete a request to the hub. Most often a VPN, "
     "captive portal or firewall is in the way.",
     "ping blnq.org · check your proxy/VPN · try again in a minute"),
    (r"401|not logged in|Authentication required",
     "not authenticated",
     "the hub needs an identity for this action (credits, private runs, "
     "or high-risk code).",
     "blnq login --username=you --password=…   or set BLNQ_TOKEN"),
    (r"403|High-risk code|requires authentication",
     "the safety gate wants an identity",
     "the pattern scan rated this high. That is the gate working: it "
     "refuses anonymous execution of anything it is unsure about.",
     "blnq login   ·   or review it first: blnq review <file>"),
    (r"429|rate limit|anonymous run limit|credits",
     "rate limit or out of credits",
     "you have hit a per-IP daily cap or your credit balance.",
     "blnq login (higher limits) · blnq credits · wait for the window to reset"),
    (r"409|Resource already exists",
     "principal already registered",
     "a key is registered under a different id than the one being derived "
     "— usually after a key-format change on the hub.",
     "blnq restart · if it persists, report it: blnq support"),
    (r"sha256 mismatch",
     "downloaded file does not match the published digest",
     "the artifact changed between the digest fetch and the download, or a "
     "mirror served a stale copy. The updater refused to install it.",
     "blnq update   (retry) · if it persists, the hub is serving mixed content"),
    (r"bwrap sandbox unavailable|bootstrap failed",
     "bubblewrap is not usable here",
     "unprivileged user namespaces are disabled or bubblewrap is missing, so "
     "the job fell back to rlimits-only isolation.",
     "sudo apt install bubblewrap · or enable kernel.unprivileged_userns_clone=1"),
    (r"healthcheck failed",
     "the new CLI failed its self-test and was NOT installed",
     "the updater health-checks the new file before swapping it in. It "
     "failed, so your previous version was restored.",
     "blnq update · if it persists, report it: blnq support"),
    (r"pending.*no online volunteer|no online volunteer supports",
     "no machine is available to run it",
     "every registered machine is offline, not volunteering, or does not "
     "advertise this language.",
     "blnq who  ·  on a machine you own: blnq volunteer on && blnq restart"),
    (r"timeout|timed out waiting for run",
     "the run exceeded its time budget",
     "execution is capped (default 30s) so one job cannot hold a machine "
     "hostage.",
     "raise it: blnq run <f> --timeout 120  ·  or optimise the hot loop"),
    (r"EADDRINUSE|address already in use",
     "a port is already bound",
     "another instance (or a previous one that did not exit) holds the port.",
     "blnq stop && blnq start · or kill the stale pid shown by blnq status"),
    (r"permission denied|EACCES",
     "permission denied",
     "the CLI cannot read a file it needs — usually a key or config owned "
     "by another user.",
     "chmod 600 ~/.config/blnq/keys/* · reinstall: curl -sSL https://blnq.org/install-blnq.sh | bash"),
]


def _debug_match(text: str) -> list:
    """Score the knowledge base against an error string. Best matches first."""
    hay = str(text or "")
    low = hay.lower()
    scored = []
    for pat, title, why, fix in _DEBUG_KB:
        m = re.search(pat, hay, re.I)
        if not m:
            continue
        # longer matches are more specific — a 523 beats a bare "403"
        score = len(m.group(0))
        if any(w in low for w in ("error", "failed", "denied")):
            score += 4
        scored.append((score, title, why, fix))
    scored.sort(key=lambda x: -x[0])
    return [(t, w, f) for _s, t, w, f in scored]


def cmd_debug(args) -> None:
    """`blnq debug [ERROR]` — explain an error and say what to do about it."""
    text = getattr(args, "error", None)
    if not text and not sys.stdin.isatty():
        text = sys.stdin.read()
    if not text:
        # no argument: diagnose this machine instead
        return _debug_local(args)

    hits = _debug_match(text)
    as_json = bool(getattr(args, "json", False))
    if as_json:
        print(json.dumps({"input": text[:500], "matches": [
            {"title": t, "why": w, "fix": f} for t, w, f in hits]}, indent=2))
        sys.exit(0 if hits else 2)

    _title("debug", "what that error means")
    print()
    print(f"  {_hdr('you said')}")
    for line in text.strip().splitlines()[:4]:
        print(f"    {line.strip()[:100]}")
    print()
    if not hits:
        print(f"  {_hdr('verdict')}")
        _hint("no known pattern matched — that is worth reporting")
        _hint(f"collect context: {APP} support")
        _hint(f"github: https://github.com/htmlfarmer/blnq/issues")
        sys.exit(2)
    for i, (title, why, fix) in enumerate(hits[:3], 1):
        print(f"  {_hdr(f'{i}. {title}')}")
        for line in textwrap.wrap(why, 74):
            print(f"    {line}")
        print(f"    \033[32m→ {fix}\033[0m")
        print()
    sys.exit(0)


def _debug_local(args) -> None:
    """No error given: diagnose this machine and show what has gone wrong."""
    as_json = bool(getattr(args, "json", False))
    problems = []

    st = read_state() or {}
    pid = read_pid()
    if not pid:
        problems.append(("agent is not running",
                         "nothing is heartbeating, so the hub shows this machine offline",
                         "blnq start"))
    last_err = st.get("last_error") or ""
    if last_err:
        for title, why, fix in _debug_match(last_err)[:2]:
            problems.append((title, why, fix))

    # the agent log is the richest source of recurring failures
    if LOG_FILE.exists():
        try:
            tail = LOG_FILE.read_text(errors="replace").splitlines()[-200:]
            seen = {}
            for line in tail:
                for title, why, fix in _debug_match(line):
                    seen[title] = (why, fix, seen.get(title, (None, None, 0))[2] + 1)
            for title, (why, fix, n) in sorted(seen.items(), key=lambda x: -x[1][2]):
                problems.append((f"{title}  ({n}× in the last {len(tail)} log lines)",
                                 why, fix))
        except OSError:
            pass

    # de-dup by title, keep the most frequent
    uniq, seen = [], set()
    for t, w, f in problems:
        if t in seen:
            continue
        seen.add(t)
        uniq.append((t, w, f))

    if as_json:
        print(json.dumps({"problems": [
            {"title": t, "why": w, "fix": f} for t, w, f in uniq]}, indent=2))
        sys.exit(1 if uniq else 0)

    _title("debug", "this machine")
    if not uniq:
        print()
        ok("nothing obviously wrong")
        _hint(f"full report: {APP} doctor · {APP} support for a pasteable bundle")
        sys.exit(0)
    print()
    for t, w, f in uniq[:6]:
        print(f"  {_hdr(t)}")
        for line in textwrap.wrap(w, 74):
            print(f"    {line}")
        print(f"    \033[32m→ {f}\033[0m")
        print()
    sys.exit(1)


def cmd_bugs(args) -> None:
    """`blnq bugs` — known issues from the hub + what failed on this machine."""
    as_json = bool(getattr(args, "json", False))

    # 1. published known issues (served like the changelog, so the site and
    #    the CLI never tell different stories)
    known = []
    try:
        code, p = do_http("GET", "/known-issues.json", sign=False, timeout=8)
        if code == 200 and isinstance(p, dict):
            known = p.get("issues") or []
    except Exception:
        pass

    # 2. local failures from the agent log
    local = []
    if LOG_FILE.exists():
        try:
            tail = LOG_FILE.read_text(errors="replace").splitlines()[-300:]
            counts = {}
            for line in tail:
                for title, _why, _fix in _debug_match(line):
                    counts[title] = counts.get(title, 0) + 1
            local = [{"title": t, "count": n} for t, n in
                     sorted(counts.items(), key=lambda x: -x[1])]
        except OSError:
            pass

    if as_json:
        print(json.dumps({"known": known, "local": local}, indent=2, default=str))
        sys.exit(0 if not known and not local else 1)

    _title("bugs", "what is broken")
    print()
    print(f"  {_hdr('known issues  (from the hub)')}")
    if not known:
        _hint("none published — https://blnq.org/known-issues.json is empty or unreachable")
    else:
        for it in known[:8]:
            sev = str(it.get("severity", "info"))
            col = {"critical": "31", "high": "31", "medium": "33"}.get(sev, "36")
            print(f"    \033[{col}m{sev.upper():<9}\033[0m {str(it.get('title',''))[:66]}")
            if it.get("detail"):
                for line in textwrap.wrap(str(it["detail"]), 72):
                    print(f"      {line}")
            if it.get("workaround"):
                print(f"      \033[32m→ {it['workaround']}\033[0m")

    print()
    print(f"  {_hdr('this machine  (from the last 300 log lines)')}")
    if not local:
        _hint("no failures recorded")
    else:
        for it in local[:8]:
            print(f"    {it['count']:>4}×  {it['title']}")
    print()
    _hint(f'explain one: {APP} debug "paste the error"')
    _hint(f"full context for a report: {APP} support")



# ── failure advice ────────────────────────────────────────────────────────
# A raw traceback is a puzzle. The same error with a diagnosis is an answer.
#
# This fires AUTOMATICALLY whenever a run fails. Advice that requires you to
# already know the right command (`blnq debug`) is advice you will not get, so
# the knowledge base is applied here without being asked.
#
# Two sources, best first:
#   1. re-parse the file on THIS machine — exact line, real source, a caret,
#      and a diagnosis of that specific line. Free: no round trip at all.
#   2. the generic knowledge base, matched on the error message.

_PY_CAUSES = [
    # (pattern on the message, what it means, what to do about it)
    (r"unexpected character after line continuation",
     "A backslash is not followed by a newline. Python reads it as \"join "
     "this line to the next\", so whatever follows it on that line is a "
     "syntax error.",
     "Find the stray backslash. It is nearly always an escaped quote: the "
     "file holds a backslash before a \" where it should hold none. In "
     "Python source write triple quotes directly, never with backslashes."),
    (r"unexpected EOF while looking for matching|EOL while scanning string literal",
     "A bracket or a quote was opened and never closed.",
     "Check the last lines for a missing ) ] } or an unterminated \" or '."),
    (r"invalid syntax",
     "The parser hit something that is not valid Python where a statement "
     "was expected.",
     "Most common: a missing : after def / if / for / while / class, an "
     "unclosed ( [ {, or a stray character pasted in from a webpage or chat."),
    (r"unindent does not match|expected an indented block",
     "Indentation is inconsistent — tabs and spaces mixed, or a block header "
     "with nothing indented under it.",
     "Use 4 spaces per level. Every line under def / if / for / while must "
     "be indented, even if the body is just pass."),
    (r"TabError",
     "Tabs and spaces are mixed inside the same block.",
     "Re-indent with spaces only — most editors can do this on save."),
    (r"NameError: name .* is not defined",
     "A name is used before it exists.",
     "Check the spelling, and make sure the assignment runs before the line "
     "that reads it."),
    (r"ModuleNotFoundError|ImportError",
     "That module is not in the sandbox (or is misspelled).",
     "The sandbox ships the standard library only — `blnq check <file>` "
     "lists every import it found so you can see which one is missing."),
    (r"FileNotFoundError|IsADirectoryError",
     "The script opened a path that does not exist inside the sandbox.",
     "The sandbox cannot see your disk. Pass data in: blnq script.py data.csv"),
    (r"TypeError",
     "Two types met that do not mix — usually str against int.",
     "Convert at the boundary: int(x) or str(x)."),
    (r"ZeroDivisionError",
     "Division by zero.",
     "Guard the divisor — an empty input making it 0 is the usual cause."),
    (r"KeyError",
     "A dict key that is not present was read.",
     "Use d.get(key, default), or test key in d first."),
    (r"MemoryError|out of memory|Killed",
     "The job passed its memory budget (128 MB in the sandbox).",
     "Stream the input a line at a time instead of reading it all at once."),
    (r"timed out|TimeoutError|deadline exceeded|time limit",
     "The job passed its time budget (30 s by default).",
     "Optimise the hot loop, or ask for longer: blnq run <f> --timeout 120"),
    (r"PermissionError",
     "The sandbox refused a write outside its writable area.",
     "Write to the current directory or /tmp — the root filesystem is "
     "read-only by design."),
]

# A local parse that tells us exactly which line and column broke. Returns
# None when the file parses (or cannot be read) — meaning the failure is NOT
# a local syntax problem and we should not pretend otherwise.
def _syntax_brief(file_path) -> tuple | None:
    try:
        src = file_path.read_text()
    except Exception:
        return None
    if not str(file_path).endswith(".py"):
        return None                      # only Python can be parsed here
    try:
        compile(src, str(file_path), "exec")
        return None                      # it parses locally → not this bug
    except SyntaxError as e:
        lines = src.splitlines()
        n = int(e.lineno or 0)
        return (n, int(e.offset or 1), e.msg or "syntax error",
                lines[n - 1] if 0 < n <= len(lines) else "")
    except Exception:
        return None


def _print_syntax_advice(file_path, brief, out=sys.stderr) -> None:
    """Show the broken line, a caret, and the diagnosis. Never raises."""
    try:
        n, col, msg, src_line = brief
        name = Path(file_path).name
        print(f"\n\033[1m{name}:{n}\033[0m", file=out)
        print(f"    {src_line.rstrip()}", file=out)
        print(f"    {' ' * max(0, col - 1)}\033[31m^\033[0m", file=out)
        print(f"  \033[31mSyntaxError:\033[0m {msg}", file=out)
        low = str(msg).lower()
        cause = fix = None
        for pat, c, f in _PY_CAUSES:
            if re.search(pat, str(msg), re.I):
                cause, fix = c, f
                break
        if cause is None and "line continuation" in low:
            cause, fix = _PY_CAUSES[0][1], _PY_CAUSES[0][2]
        if cause:
            print("\n  what that means", file=out)
            for ln in textwrap.wrap(cause, 72):
                print(f"    {ln}", file=out)
        if fix:
            print("\n  do this", file=out)
            for ln in textwrap.wrap(fix, 72):
                print(f"    {ln}", file=out)
            print(f"    \033[32m-> edit {name} line {n}\033[0m", file=out)
        print(f"\n  \033[2mthis was caught locally — no round trip to blnq.org\033[0m",
              file=out)
        print(f"  \033[2mre-check any time: blnq check {name}\033[0m\n", file=out)
    except Exception:
        return                              # advice must never mask the error


def _advise_on_failure(status: str, output: str, file_path=None) -> None:
    """Print a diagnosis after a failed run. Best-effort, never raises, never
    changes the exit code — it is commentary, not control flow."""
    try:
        text = str(output or "")
        if not text.strip():
            return
        # 1. local file first: exact beats generic
        if file_path is not None:
            brief = _syntax_brief(Path(file_path))
            if brief:
                _print_syntax_advice(file_path, brief)
                return

        # 2. known error shapes, matched on the message
        hits = []
        for pat, cause, fix in _PY_CAUSES:
            if re.search(pat, text, re.I):
                hits.append((cause, fix))
        # 3. fall back to the general knowledge base (523, 401, 409, …)
        if not hits:
            hits = [(w, f) for _t, w, f in _debug_match(text)]

        if not hits:
            return
        print("\n\033[1mwhat went wrong\033[0m", file=sys.stderr)
        cause, fix = hits[0]
        for ln in textwrap.wrap(cause, 72):
            print(f"  {ln}", file=sys.stderr)
        if fix:
            print("\n\033[1mdo this\033[0m", file=sys.stderr)
            for ln in textwrap.wrap(fix, 72):
                print(f"  {ln}", file=sys.stderr)
        if status == "rejected":
            print("\n  \033[2mthis was refused by the safety gate, not by "
                  "Python\033[0m", file=sys.stderr)
            print(f"  \033[2msee why: blnq details  ·  ask for a review: "
                  f"blnq submit <file>\033[0m", file=sys.stderr)
        print(f"\n  \033[2mmore: blnq debug \"paste the error\"\033[0m\n",
              file=sys.stderr)
    except Exception:
        return

# ── blnq about ─────────────────────────────────────────────────────────────
# Who is behind this, and how to reach a human.
#
# Contact details are deliberately PUBLISHED rather than buried in a support
# form: when something breaks at 2am, a form is where enthusiasm goes to die.
# The one thing worth being honest about is that email is not the fast path
# here — saying so saves everyone a week of waiting.

def cmd_about(args) -> None:
    """`blnq about` — what this is, who runs it, and how to reach us."""
    as_json = bool(getattr(args, "json", False))

    if as_json:
        print(json.dumps({
            "name": APP,
            "hub": HUB,
            "version": VERSION,
            "slogan": "everyone working on everything... even with the most distant stars?",
            "mission": ("help all life on earth — physically (health, clean water, food), "
                        "mentally and spiritually (knowledge, wisdom), and leave room for fun"),
            "contact": {
                "name": "Asher",
                "phone": "+1-773-321-8181",
                "phone_preferred": True,
                "email": "ashermartin@gmail.com",
                "email_note": "email is old school — a text gets a faster answer",
                "preferred": ["text message", "stopping by the house"],
            },
            "report_bug": {"text": "+1-773-321-8181", "github": "https://github.com/htmlfarmer/blnq/issues"},
            "docs": {"web": "https://blnq.org/", "api": "https://blnq.org/docs",
                     "network_rules": "https://blnq.org/network.html"},
        }, indent=2))
        return

    _title("about", f"{HUB_NAME} client v{VERSION}")

    print(f"""
  \033[1mbLNQ\033[0m — everyone working on everything...
        even with the most distant stars?

  run code on someone else's machine, and get back proof of what it did.
  independent validators read a script first and \033[1msign\033[0m a plain-English
  description of what it does — so you can check the claim instead of
  taking anyone's word for it. including ours.
""")

    _section("🌿", "why it exists")
    print("""    to help all of life on earth: physically, through health, clean
    water and food; mentally and spiritually, through knowledge and
    wisdom — and to leave room for fun, because a tool nobody enjoys
    using is a tool nobody uses.""")

    _section("📮", "talk to a human")
    _kv("text", "\033[1;36m+1 773-321-8181\033[0m   ← the fast path", width=10)
    _kv("email", "ashermartin@gmail.com", width=10)
    _kv("house", "\"just stop over\" — genuinely offered", width=10)
    print()
    _hint("email is old school around here. it is checked, but a text gets")
    _hint("an answer about a week sooner. seriously. text.")
    _hint("serious bug or something on fire? that is exactly what the number is for.")

    _section("🛠️", "if something is broken")
    _kv("diagnose", f"{APP} debug \"paste the error\"", width=10)
    _kv("known bugs", f"{APP} bugs", width=10)
    _kv("full report", f"{APP} support", width=10)
    _kv("github", "github.com/htmlfarmer/blnq/issues", width=10)

    _section("🗺️", "where things live")
    _kv("website", "https://blnq.org/", width=10)
    _kv("api docs", "https://blnq.org/docs", width=10)
    _kv("net rules", "https://blnq.org/network.html", width=10)
    _kv("verify", f"{APP} verify <file>", width=10)

    print()
    _hint(f"everything this CLI can do: {APP} --help")

def _prescan_numbers(file_path: Path, code_text: str, facts: dict, lang: str) -> dict:
    """Local pre-security as NUMBERS ONLY — counts, danger, parser. This is
    what ships with every submission (the report shows it, the hub cross-
    checks it): never scan text, never source. It is a CLAIM — the hub
    re-scans regardless and reports prescan.match when they disagree."""
    sev = []
    try:
        sev = [f.get("severity") for f in _security_scan_file(file_path)]
    except Exception:
        sev = []
    danger = ("high" if "CRITICAL" in sev else
              "medium" if "WARN" in sev else
              "low" if "INFO" in sev else "clear")
    out = {
        "critical": sev.count("CRITICAL"), "warn": sev.count("WARN"),
        "info": sev.count("INFO"),
        "loc": int(facts.get("loc") or 0),
        "bytes": int(facts.get("bytes") or len(code_text.encode())),
        "danger": danger, "lang": lang,
    }
    if facts.get("parse_lang"):
        out["parser"] = facts["parse_lang"]
    return out


def _evolution_report(file_path: Path, code_text: str, subject: str) -> dict | None:
    """Diff THIS submission against the sender's previous one — computed HERE
    (client side: zero server compute, zero payload bloat) and shipped as
    NUMBERS: lines added/removed, percent changed, base subject. Snapshots are
    gzipped, capped and local-only (5 newest files) — the report says how
    different the code is, not what the old code was."""
    import gzip
    import difflib
    try:
        if not file_path.exists():
            return None     # never block a run over a report about nothing
        idx_path = STATE_DIR / "last-submit.json"
        snap_dir = STATE_DIR / "last-submit-snap"
        idx = {}
        if idx_path.exists():
            idx = json.loads(idx_path.read_text())
        key = str(file_path.resolve())
        prev = idx.get(key) or {}
        base = prev.get("subject")

        out: dict = {}
        if base == subject:
            out = {"base_subject": base, "lines_added": 0, "lines_removed": 0,
                   "pct_changed": 0, "note": "unchanged since your last submit"}
        elif not base:
            out = {"note": "first submit of this file"}
        else:
            out = {"base_subject": base}
            snapf = snap_dir / str(prev.get("snap") or "")
            old = None
            if snapf.name and snapf.exists():
                old = gzip.decompress(snapf.read_bytes()).decode("utf-8", "replace")
            if old is not None:
                old_lines, new_lines = old.splitlines(), code_text.splitlines()
                added = removed = 0
                for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(
                        a=old_lines, b=new_lines).get_opcodes():
                    if tag in ("replace", "insert"):
                        added += j2 - j1
                    if tag in ("replace", "delete"):
                        removed += i2 - i1
                out.update(lines_added=added, lines_removed=removed,
                           pct_changed=min(100, round((added + removed) * 100
                                                      / max(1, len(new_lines)))))

        # refresh the snapshot (capped: only code we can diff cheaply)
        if len(code_text.encode("utf-8", "replace")) <= 512 * 1024:
            snap_dir.mkdir(parents=True, exist_ok=True)
            name = subject[:20] + ".gz"
            (snap_dir / name).write_bytes(
                gzip.compress(code_text.encode("utf-8", "replace")))
            idx[key] = {"subject": subject, "snap": name, "at": int(time.time())}
            if len(idx) > 8:                     # LRU-ish prune (5–8 files)
                for k in sorted(idx, key=lambda k: idx[k].get("at") or 0)[:-5]:
                    old_name = idx.pop(k, {}).get("snap")
                    if old_name:
                        try: (snap_dir / old_name).unlink()
                        except OSError: pass
            idx_path.write_text(json.dumps(idx))
        return out
    except Exception:
        return None      # the report must never block a run


def _render_rejection(p: dict, file_path) -> None:
    """The failure card: WHEN, WHICH id, WHO judged it (endpoint/model/key),
    the FULL reason (never sliced — textwrap, not truncation), the local
    numbers + vs-last-submission, and exact commands to get it running."""
    import textwrap
    s = p.get("safety") or {}
    print()
    hub_at = str(p.get("at") or "")
    local_at = time.strftime("%Y-%m-%d %H:%M:%S %Z")
    print(f"  \033[31m✗ rejected\033[0m  {local_at}"
          + (f"   ·   hub: {hub_at}" if hub_at else ""))
    if p.get("id"):
        _kv("report id", f"{p['id']}  (quote it — full row on hub)")
    if p.get("subject"):
        _kv("subject", str(p["subject"]))

    src = str(s.get("review") or "?")
    rev = s.get("reviewer") or {}
    who = src
    if src == "ai":
        who += f" · {rev.get('model') or '?'} @ {rev.get('endpoint') or '?'}"
    elif src == "attestation" and rev.get("signers"):
        who += " · signed by " + ", ".join(str(x)[:26] for x in (rev["signers"] or [])[:4])
    elif src == "pattern":
        who += f" · {rev.get('scanner', 'safetyCheck')}"
    elif src == "limit":
        who += f" · {rev.get('attempts', '?')}/{rev.get('window_min', '?')} reviews this hour"
    _kv("reviewed by", who)
    if rev.get("principal"):
        pr = rev["principal"]
        print(f"    {'':14}key: {pr.get('principal_id')}  “{pr.get('name') or ''}”")
    if s.get("recheck_note"):
        print(f"    {'':14}recheck: {s['recheck_note']}")
    _kv("level", str(s.get("level") or "?"))

    pc = s.get("prescan")
    if isinstance(pc, dict):
        line = (f"{pc.get('danger', '?')} · critical {pc.get('critical', 0)}"
                f" / warn {pc.get('warn', 0)} / info {pc.get('info', 0)}"
                f" · {pc.get('loc', '?')} loc")
        _kv("local scan", line)
        if pc.get("match") is False:
            print(f"    {'':14}\033[33m⚠ hub scan disagrees with your numbers\033[0m")
    evo = p.get("evolution")
    if isinstance(evo, dict):
        if "lines_added" in evo:
            base = evo.get("base_subject")
            _kv("vs last submit", f"+{evo['lines_added']} −{evo['lines_removed']}"
                f"  ({evo.get('pct_changed', '?')}% changed)"
                + (f"  · base {base[:16]}…" if base else ""))
        elif evo.get("note"):
            _kv("vs last submit", str(evo["note"]))

    reason = str(s.get("reason") or p.get("error") or "no reason given")
    reason_hdr = "\033[33mreason\033[0m"
    print()
    print(f"  {reason_hdr}")
    for line in (textwrap.wrap(reason, 74) or ["(empty)"]):
        print(f"    {line}")
    issues = s.get("issues") or []
    if issues:
        print()
        print("  findings")
        for it in issues[:6]:
            msg = (it or {}).get("message") if isinstance(it, dict) else it
            print(f"    \033[33m•\033[0m {str(msg)[:70]}")
        if len(issues) > 6:
            print(f"    … {len(issues) - 6} more — `blnq scan {file_path}`")

    print()
    print(f"  \033[1mget it running\033[0m")
    print(f"    1. locally, right now:        python3 {file_path}")
    print(f"    2. on YOUR own node (e.g. yalla):")
    print(f"         {APP} jobs submit --file {file_path} --node yalla")
    print(f"       node side once:  ssh yalla '{APP} volunteer on'  "
          f"(status must show a jail ✓)")
    print(f"    3. fresh AI eyes / a different AI:")
    print(f"         {APP} redo {file_path}   (skips the cached verdict)")
    print(f"         {APP} redo {file_path} --endpoint http://other-ai:8080")
    print(f"       identical resubmits are answered from cache (no AI spend);")
    print(f"       3 model calls/hour on one subject → REVIEW_LIMIT: rethink")
    print(f"    4. report this:               quote report id + subject + reviewed-by")
    print()


def cmd_redo(args) -> None:
    """`blnq redo <file> [--endpoint URL]` (alias: `recheck`) — ask again with
    FRESH eyes: the hub skips the verdict cache (identical resubmits normally
    answer from cache with NO AI spend), prefers an endpoint OTHER than the
    previous judge when the chain has two, counts this as a model attempt
    against the 3/hour-per-subject cap (past it: REVIEW_LIMIT — rethink), and
    `--endpoint` pins a configured chain member (the hub rejects URLs that
    are not in BLNQ_AI_ENDPOINTS — it will not fetch a stranger for you)."""
    path = getattr(args, "file", None)
    if not path:
        die(f"usage: {APP} redo <file.py> [--endpoint URL]")
    p = Path(path)
    if not p.exists():
        die(f"file not found: {p}")
    print(f"\033[1m{APP} redo\033[0m — fresh review for {p}"
          + (f"  ·  endpoint pinned: {args.endpoint}" if getattr(args, "endpoint", None) else "")
          + "\n")
    # cmd_run_file reads these via getattr — it never uses `args` otherwise.
    cmd_run_file(argparse.Namespace(recheck=True,
                                    endpoint=getattr(args, "endpoint", None)),
                 p, [])


def cmd_run_file(args, file_path: Path, file_args: list[str]) -> None:
    """Upload a local file to blnq.org /api/run, execute it remotely, stream the output back."""
    _nag_if_behind()          # daemon thread + 6h cache: never delays the run
    if not file_path.exists():
        die(f"file not found: {file_path}")
    if not file_path.is_file():
        die(f"not a regular file: {file_path}")
    ext = file_path.suffix.lower()
    language = _EXT_TO_LANG.get(ext)
    if not language:
        die(f"unsupported file type {ext!r} — supported: {', '.join(sorted(_EXT_TO_LANG))}")
    try:
        code_text = file_path.read_text()
    except (OSError, UnicodeDecodeError) as e:
        die(f"cannot read {file_path}: {e}")
    if len(code_text) > 50_000:
        die(f"file too big ({len(code_text)} bytes; blnq limit is 50 KB)")
    # Parse LOCALLY before spending a request. A file that cannot compile here
    # cannot compile in the sandbox either — sending it buys nothing but a
    # slower error, and it is the single most common failure we see.
    _brief = _syntax_brief(file_path)
    if _brief:
        _print_syntax_advice(file_path, _brief)
        die(f"{file_path.name} does not parse — fix the line above, "
            f"or see it with: {APP} check {file_path.name}", code=2)
    # Two channels, because they are genuinely different things:
    #   argv  <- every argument, with a FILE argument replaced by its basename
    #           (the sandbox has no /home/you/... so the full path is useless)
    #   stdin <- the file's CONTENTS when a file was passed; otherwise the
    #           legacy joined args, so `blnq x.py hello` keeps working
    # Previously the path STRING went to stdin, so `blnq test.py data.csv`
    # handed the script the text "data.csv" instead of the data.
    argv, file_blobs, blob_names = [], [], []
    for a in file_args:
        p = Path(a)
        if p.is_file():
            try:
                file_blobs.append(p.read_text(encoding="utf-8", errors="replace"))
                blob_names.append(p.name)
            except OSError as e:
                warn(f"cannot read {a}: {e}")
            argv.append(p.name)
        else:
            argv.append(a)
    stdin_text = ("\n".join(file_blobs) if file_blobs
                  else (" ".join(file_args) if file_args else ""))

    # Scan EVERYTHING about to leave this machine. The script is the obvious
    # thing to check and the least likely to leak — `blnq analyse.py
    # customers.csv` uploads the CSV, and nobody thinks of a data file as
    # something that needs checking.
    _gate_outgoing([(file_path.name, code_text)]
                   + list(zip(blob_names, file_blobs))
                   + ([("stdin", stdin_text)] if stdin_text else []))

    # Show how many validators have signed this exact source, if any have.
    # Best-effort: a slow or unreachable hub must never block the run.
    if VERBOSE:
        _show_trust(code_text)

    if VERBOSE:
        log(f"uploading {file_path} ({len(code_text)} bytes, language={language}) → blnq.org/api/run")
    token = os.environ.get("BLNQ_TOKEN")
    # Numbers-only local report (pre-scan counts) + the client-side diff vs
    # our previous submit of THIS file — computed here, shipped as numbers,
    # shown in the rejection card and stored with the run on the hub.
    _facts = _preflight_static(code_text, language)
    _prescan = _prescan_numbers(file_path, code_text, _facts, language)
    _evolution = _evolution_report(file_path, code_text, _subject_of(code_text))
    _body = {"language": language, "code": code_text, "stdin": stdin_text,
             "args": argv, "isPublic": False}
    if _prescan:
        _body["prescan"] = _prescan
    if _evolution:
        _body["evolution"] = _evolution
    # `blnq redo` sets these: skip the cached verdict, optionally pin a
    # configured AI endpoint (the hub validates chain membership).
    if getattr(args, "recheck", False):
        _body["recheck"] = True
    if getattr(args, "endpoint", None):
        _body["endpoint"] = str(args.endpoint)
    # /api/run performs the AI safety review SYNCHRONOUSLY before returning
    # (up to AI_STUDY_TIMEOUT=120s), so the default 15s do_http timeout is not
    # enough — locally it squeaked past at ~14.6s and failed outright once the
    # request had to cross Cloudflare.
    submit_code, submit = do_http("POST", "/api/run",
                                  body=_body,
                                  token=token, timeout=180)
    if submit_code not in (200, 201):
        # The rejection card: when, which report id, WHO judged it (endpoint,
        # model, the validator's key), the FULL reason, local numbers, the
        # vs-last diff, and exact commands to get it running elsewhere.
        if isinstance(submit, dict) and (submit.get("safety") or submit.get("id")):
            try:
                _render_rejection(submit, file_path)
            except Exception as _e:
                warn(f"could not render rejection card: {_e}")
            _s = submit.get("safety") or {}
            if _s.get("level") == "high" and not token:
                warn("(high-risk code requires BLNQ_TOKEN — log in via "
                     "`blnq login` or set the env var)")
        _print(submit, submit_code)
        return

    run_id = submit.get("run_id") or submit.get("id")
    if not run_id:
        die(f"blnq returned no run id: {submit!r}")
    # The hub hands back a read capability for this run's private output; without
    # it the requester cannot read back what it just asked to run.
    read_token = submit.get("read_token")
    if not read_token:
        warn("hub returned no read_token — output may be unreadable for private runs")
    # Quiet means QUIET: identical to `python file.py`, so even the good news
    # stays out of the way. Details are one command away (`blnq details`).
    if VERBOSE:
        ok(f"queued run {run_id} (status: {submit.get('status','?')})")
        if isinstance(submit, dict) and submit.get("credits_left") is not None:
            warn(f"credits left: {submit['credits_left']}")

    # Remember it so `blnq details` can show what just happened — including
    # the read token, which the hub returns exactly once and never re-issues.
    try:
        _st = read_state()
        _st["last_run"] = {
            "id": run_id, "script": file_path.name, "language": language,
            "bytes": len(code_text), "read_token": read_token,
            "at": int(time.time()), "argv": argv, "stdin_bytes": len(stdin_text),
        }
        write_state(_st)
    except Exception:
        pass

    # Live-stream over SSE; falls back to polling if the hub has no /stream route.
    if _sse_stream_run(run_id, read_token, file_path=file_path):
        return
    _poll_run_until_done(run_id, read_token)


def _poll_run_until_done(run_id, read_token: str | None = None):
    # Poll until done. blnq's /api/run/:id/logs returns {status, stdout, stderr, exitCode}.
    deadline = time.time() + 300  # 5-minute wall cap
    poll_s = 0.5
    while time.time() < deadline:
        time.sleep(poll_s)
        code, p = do_http("GET", f"/api/run/{run_id}/logs",
                          extra_headers={"X-Run-Token": read_token} if read_token else None)
        if code != 200:
            poll_s = min(poll_s * 1.5, 3.0); continue
        if isinstance(p, dict):
            status = p.get("status")
            if status in ("completed", "failed", "rejected", "error", "timeout"):
                stdout = p.get("stdout", "") or ""
                stderr = p.get("stderr", "") or ""
                exit_code = p.get("exitCode")
                if stdout: sys.stdout.write(stdout)
                if stdout and not stdout.endswith("\n"): sys.stdout.write("\n")
                if stderr: sys.stderr.write(stderr)
                if stderr and not stderr.endswith("\n"): sys.stderr.write("\n")
                if status != "completed":
                    _advise_on_failure(status, stderr or stdout, file_path)
                    die(f"run {run_id} ended with status={status}", code=2 if exit_code is None else 0)
                sys.exit(exit_code if exit_code is not None else 0)
        poll_s = min(poll_s * 1.3, 3.0)
    die(f"timed out waiting for run {run_id}")


# ── live output (SSE) + watch/credits/artifact commands ──────────────────
def _sse_read(path: str, on_event, timeout_s: float | None = 300.0,
              extra_headers: dict | None = None) -> bool:
    """Stream-parse an SSE endpoint. Calls on_event(type, payload_dict).
    Returns True if a terminal event (complete) was received, else False.
    timeout_s=None blocks forever (a live stream can idle between events)."""
    url = HUB.rstrip("/") + path
    hdrs = {"user-agent": f"{APP}/{VERSION}", "accept": "text/event-stream"}
    if extra_headers:
        hdrs.update(extra_headers)
    req = urllib.request.Request(url, headers=hdrs)
    etype = ""
    # socket.settimeout cannot represent infinity: `blnq watch` passed
    # float("inf") for "follow forever" and died with OverflowError before
    # reading a single byte (audit 2026-11-18). None = block forever.
    if timeout_s is not None and (timeout_s != timeout_s
                                  or timeout_s in (float("inf"), float("-inf"))):
        timeout_s = None
    try:
        with opener().open(req, timeout=timeout_s) as r:
            for raw in r:
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if line.startswith("event:"):
                    etype = line[6:].strip()
                elif line.startswith("data:"):
                    data = line[5:].strip()
                    try: payload = json.loads(data)
                    except json.JSONDecodeError: payload = {"text": data}
                    payload["_event"] = etype
                    terminal = on_event(etype, payload)
                    if terminal: return True
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError):
        return False
    return False


def _sse_stream_run(run_id: str, read_token: str | None = None,
                    file_path=None) -> bool:
    """Live-stream a run over SSE. If the hub lacks /stream (older hub), returns
    False so the caller falls back to polling."""
    state = {"done": False, "code": None}
    def on_event(etype, d):
        if etype == "status":
            warn(f"status: {d.get('status')}")
            return False
        if etype == "output":
            sys.stdout.write(d.get("text", "") or "")
            sys.stdout.flush()
            return False
        if etype == "complete":
            sys.stdout.write(d.get("stdout", "") or "")
            sys.stderr.write(d.get("stderr", "") or "")
            if not (d.get("stdout", "") or "").endswith("\n") and d.get("stdout"):
                sys.stdout.write("\n")
            state["done"] = True
            ec = d.get("exit_code")
            status = d.get("status")
            if status != "completed":
                _advise_on_failure(status, d.get("stderr", "") or d.get("stdout", ""),
                                   file_path)
                die(f"run {run_id} ended with status={status}", code=2 if ec is None else 0)
            state["code"] = ec
            return True
        return False
    hdrs = {"X-Run-Token": read_token} if read_token else None
    got_terminal = _sse_read(f"/api/run/{run_id}/stream", on_event, extra_headers=hdrs)
    if not got_terminal and not state["done"]:
        # no /stream route → let caller poll
        return False
    if state["done"]:
        sys.exit(state["code"] if state["code"] is not None else 0)
    return True


def cmd_watch(args) -> None:
    ident = args.id
    if ident.startswith("job_"):
        path = f"/api/jobs/{ident}/stream"
    else:
        path = f"/api/run/{ident}/stream"
    ok(f"watching {ident} (Ctrl-C to detach)")
    def on_event(etype, d):
        if etype == "output":
            sys.stdout.write(d.get("text", "") or ""); sys.stdout.flush(); return False
        if etype == "status":
            warn(f"status: {d.get('status')}"); return False
        if etype == "complete":
            if d.get("stdout"): sys.stdout.write(d["stdout"])
            if d.get("stderr"): sys.stderr.write(d["stderr"])
            warn(f"complete: {d.get('status')} exit={d.get('exit_code')}")
            return True
        return False
    _sse_read(path, on_event, timeout_s=None)   # None = follow forever


def cmd_credits(args) -> None:
    code, p = do_http("GET", "/api/user/credits")
    if code == 401:
        die(f"not logged in — run `{APP} login` first (then {APP} credits)")
    if isinstance(p, dict) and "credits" in p:
        print(f"  credits:  {p['credits']}")
        print(f"  (hub containers cost 1, collective jobs cost "
              f"{os.environ.get('BLNQ_JOB_CREDITS_COST','2')}; ask an operator for top-ups)")
    else:
        _print(p, code)


def _download_to(url: str, out: str) -> int:
    req = urllib.request.Request(url, headers={"user-agent": f"{APP}/{VERSION}"})
    try:
        with opener().open(req, timeout=120) as r, open(out, "wb") as f:
            total = 0
            while True:
                chunk = r.read(65536)
                if not chunk: break
                f.write(chunk); total += len(chunk)
        return total
    except urllib.error.HTTPError as e:
        die(f"download failed: http {e.code} (only the job owner can download artifacts)")
    except OSError as e:
        die(f"write failed: {e}")

def cmd_artifact(args) -> None:
    job_id = args.id
    member = getattr(args, "member", None)
    code, p = do_http("GET", f"/api/jobs/{job_id}/artifacts")
    if code != 200 or not isinstance(p, dict):
        die(f"could not list artifacts (http {code})")
    arts = p.get("artifacts") or []
    if args.list or not arts:
        if arts and args.list:
            print(f"  {len(arts)} artifact(s), {p.get('artifact_bytes', 0)} bytes archived:")
            for a in arts:
                tag = " [archive]" if a.get("archive") else ""
                print(f"    {a['size']:>10,} B  {a['name']}{tag}")
        else:
            _print(p, code)
        return
    if member:
        match = next((a for a in arts if a["name"] == member and not a.get("archive")), None)
        if not match:
            die(f"'{member}' not in this job's artifacts — try: {APP} artifact {job_id} --list")
        out = args.output or Path(member).name
        url = HUB.rstrip("/") + f"/api/jobs/{job_id}/artifact/" + \
              "/".join(urllib.parse.quote(seg) for seg in member.split("/"))
        n = _download_to(url, out)
        ok(f"saved {n} bytes -> {out}")
        return
    out = args.output or f"{job_id}-artifacts.tar.gz"
    n = _download_to(HUB.rstrip("/") + f"/api/jobs/{job_id}/artifact", out)
    ok(f"saved {n} bytes -> {out}")
    print(f"  extract with:  tar -xzf {out}")
    print(f"  or one file:   {APP} artifact {job_id} <name>")

def cmd_jobs_cancel(args) -> None:
    code, p = do_http("POST", f"/api/jobs/{args.id}/cancel", body={}, sign=False, timeout=15)
    if code == 200:
        ok(f"cancelled {args.id}")
    else:
        _print(p, code)


# ── local security scanner ─────────────────────────────────────────────
# Runs locally before `blnq FILE` uploads your code to blnq.org. Catches
# hardcoded secrets + dangerous stdlib calls + PII. Stdlib only — no AI, no pip.


def _luhn_ok(s: str) -> bool:
    """True if the digit characters in s form a Luhn-valid number (13-19 digits)."""
    digits = [int(c) for c in s if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0



def _security_scan_file(path):
    """Scan a local file. Returns a list of finding dicts."""
    findings = []
    try:
        text = path.read_text(errors="replace")
    except (OSError, UnicodeDecodeError) as e:
        return [{"severity": "WARN", "line": 0, "col": 0,
                 "message": f"could not read as text ({e}); skipped AST scan",
                 "snippet": "", "suggestion": "",
                 "rule_id": "read_error"}]

    lines = text.splitlines()

    def _finding(sev, line, col, msg, snippet, sugg, rid):
        return {"severity": sev, "line": line or 0, "col": col or 0,
                "message": msg, "snippet": (snippet or "")[:120],
                "suggestion": sugg, "rule_id": rid}

    def _line(n):
        return lines[n - 1].strip() if 1 <= n <= len(lines) else ""

    # ── AST pass: structural — eval / exec / os.system / pickle / yaml / shell=True
    try:
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = None; attr = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                name = func.value.id; attr = func.attr

            if name in ("eval", "exec") and attr is None:
                findings.append(_finding(
                    "CRITICAL", node.lineno, node.col_offset,
                    f"{name}() executes arbitrary Python code",
                    _line(node.lineno),
                    "use ast.literal_eval() for data, or refactor to explicit logic",
                    f"ast_{name}"))

            if name == "os" and attr == "system":
                findings.append(_finding(
                    "CRITICAL", node.lineno, node.col_offset,
                    "os.system() runs a shell command from a string",
                    _line(node.lineno),
                    "use subprocess.run([...], shell=False) with an argv list",
                    "ast_os_system"))

            if name == "subprocess" and attr in ("call", "run", "Popen", "check_call", "check_output"):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append(_finding(
                            "CRITICAL", node.lineno, node.col_offset,
                            f"subprocess.{attr}(..., shell=True) is shell-injection prone",
                            _line(node.lineno),
                            "drop shell=True and pass the command as a list",
                            "ast_shell_true"))
                        break

            if name == "pickle" and attr in ("load", "loads"):
                findings.append(_finding(
                    "CRITICAL", node.lineno, node.col_offset,
                    "pickle deserialisation can execute arbitrary code",
                    _line(node.lineno),
                    "use json or msgpack unless you fully control the input",
                    f"ast_pickle_{attr}"))

            if name == "marshal" and attr in ("load", "loads"):
                findings.append(_finding(
                    "CRITICAL", node.lineno, node.col_offset,
                    "marshal deserialisation can execute arbitrary code",
                    _line(node.lineno),
                    "almost never safe on untrusted input",
                    f"ast_marshal_{attr}"))

            if name == "yaml" and attr == "load":
                findings.append(_finding(
                    "CRITICAL", node.lineno, node.col_offset,
                    "yaml.load() executes arbitrary Python tags by default",
                    _line(node.lineno),
                    "use yaml.safe_load() instead",
                    "ast_yaml_load"))
    except SyntaxError:
        # not valid Python — fall back to regex only (e.g. JS/bash files)
        pass

    # ── Regex pass: secrets + reverse shells (string-literal-shaped patterns)
    secret_rules = [
        ("aws_access_key",     r"\bAKIA[0-9A-Z]{16}\b",
         "hardcoded AWS access key ID",
         "load from os.environ['AWS_ACCESS_KEY_ID']"),
        ("github_pat",         r"\bghp_[A-Za-z0-9]{36}\b",
         "hardcoded GitHub personal access token",
         "revoke at github.com/settings/tokens and load from env"),
        ("slack_token",        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
         "hardcoded Slack token",
         "revoke at api.slack.com and load from env"),
        ("private_key_block",  r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
         "embedded private-key block",
         "load from a file with 0600 permissions, never commit"),
        ("jwt_token",          r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
         "JWT-style token literal",
         "don't hardcode session tokens — load from a secure store"),
        ("generic_password",   r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"\\s]{6,}['\"]",
         "hardcoded password literal",
         "load from os.environ or a secret manager"),
        ("generic_api_key",    r"(?i)(api[_-]?key|api[_-]?token|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
         "hardcoded API key / token literal",
         "load from os.environ or a secret manager"),
        ("reverse_shell_devtcp", r"/dev/tcp/",
         "bash /dev/tcp redirect — classic reverse-shell pattern",
         "remove unless this is a deliberate networking demo"),
        ("reverse_shell_nc",   r"\bnc\s+-[a-zA-Z]*e\b",
         "netcat -e (reverse shell)",
         "remove — this is what a backdoor looks like"),
    ]
    for i, line_text in enumerate(lines, start=1):
        for rid, pat, msg, sugg in secret_rules:
            m = re.search(pat, line_text)
            if m:
                findings.append(_finding(
                    "CRITICAL", i, m.start(), msg, line_text.strip(), sugg, rid))

    # ── Regex pass: dynamic execution / shell spawn — ported from the hub's
    # safetyCheck.js so the OFFLINE first pass sees what the AI gate sees.
    # JavaScript previously scanned as "OK no issues found" (audit 2026-11-18);
    # skipped on Python files, where the AST pass already flags these.
    if path.suffix.lower() not in (".py", ".pyw"):
        code_rules = [
            ("js_dynamic_eval", r"(?<![.\w])(?:eval|Function)\s*\(",
             "dynamic code execution (eval / new Function)",
             "avoid eval — parse with JSON.parse, use explicit logic", "CRITICAL"),
            ("js_child_process",
             r"require\s*\(\s*['\"]child_process['\"]\s*\)|from\s*['\"]node:child_process['\"]"
             r"|\b(?:child_process\.)?(?:execSync|spawnSync|exec|spawn|fork)\s*\(",
             "spawns a shell / child process",
             "never build shell strings from input; pass argv arrays", "CRITICAL"),
            ("js_net", r"(?<![.\w])fetch\s*\(|https?\.(?:get|post|request)\s*\(|\baxios\b",
             "network call — data leaves this machine",
             "check exactly what is sent and where", "WARN"),
        ]
        for i, line_text in enumerate(lines, start=1):
            for rid, pat, msg, sugg, sev in code_rules:
                m = re.search(pat, line_text)
                if m:
                    findings.append(_finding(
                        sev, i, m.start(), msg, line_text.strip(), sugg, rid))

    # ── Regex pass: network evidence, ALL languages (audit 2026-11-19:
    # B04 subprocess-curl, B07 importlib urllib, URL literals and base64-fed
    # exec all returned 0 findings). Runs for python too — it complements the
    # AST pass and is what catches non-python files.
    net_rules = [
        ("net_dynamic_import",
         r"importlib\.(?:import_module|__import__)\s*\(|(?<![.\w])__import__\s*\(",
         "dynamic import — import scans cannot see what gets loaded",
         "import modules at the top level so every gate can see them", "WARN"),
        ("net_via_shell",
         r"(?<![\w./-])(?:curl|wget|ncat|netcat|socat|aria2c|axel|nmap)(?![\w-])",
         "network binary in code — leaves the machine via a shell, not an import",
         "route fetches through reviewed code paths, not ad-hoc shell", "WARN"),
        ("net_write_method",
         r"\.post\s*\(|\.put\s*\(|method\s*=\s*[\"'](?:POST|PUT|PATCH|DELETE)[\"']"
         r"|-X\s*(?:POST|PUT|PATCH|DELETE)\b|--data(?:-binary|-raw)?[=\s]"
         r"|CURLOPT_(?:POST|PUT|UPLOAD)\b",
         "write method (POST/PUT/…) — the egress proxy allows GET/HEAD only, "
         "so this would be refused at the socket",
         "reads may pass through egress; sends never do", "WARN"),
        ("net_url_literal",
         _URL_RE.pattern,
         "URL literal — the code points at an external host",
         "confirm the destination is intended and only that", "INFO"),
        ("b64_compile",
         r"\bcompile\s*\([^)]*(?:b64|base64|decode)",
         "compile() of decoded data — decoded-code obfuscation pattern",
         "ship source plainly; never compile payloads at runtime", "WARN"),
    ]
    for i, line_text in enumerate(lines, start=1):
        for rid, pat, msg, sugg, sev in net_rules:
            m = re.search(pat, line_text, re.I if rid == "net_url_literal" else 0)
            if m:
                findings.append(_finding(
                    sev, i, m.start(), msg, line_text.strip(), sugg, rid))

    # ── Regex pass: PII — credit cards (Luhn-validated), SSN, IBAN, BTC, etc.
    # CRITICAL = money/identity risk; WARN = likely personal but might be intentional.
    pii_rules = [
        # 13–19 digit strings with optional spaces/dashes — pass through Luhn check below.
        ("credit_card",   r"\b(?:\d[ -]?){12,18}\d\b",
         "possible credit card number (Luhn-validated)",
         "remove or redact — never commit card numbers to code", "luhn"),

        # US SSN: 123-45-6789 or 123 45 6789 (only when it matches the dashed form,
        # to avoid colliding with every 9-digit number)
        ("ssn_us",        r"\b\d{3}-\d{2}-\d{4}\b",
         "US Social Security Number",
         "remove or redact before sharing"),

        # IBAN: 2 letters + 2 digits + 10-30 alphanumerics
        ("iban",          r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b",
         "international bank account number (IBAN)",
         "remove or redact — never commit bank details to code"),

        # Bitcoin: legacy P2PKH (1...) / P2SH (3...) / Bech32 (bc1...)
        ("bitcoin_legacy", r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
         "Bitcoin address (legacy)",
         "if this is your wallet, redact before sharing"),
        ("bitcoin_bech32", r"\bbc1[ac-hj-np-z02-9]{6,87}\b",
         "Bitcoin address (bech32 / segwit)",
         "if this is your wallet, redact before sharing"),

        # Ethereum: 0x + 40 hex
        ("eth_address",   r"\b0x[0-9a-fA-F]{40}\b",
         "Ethereum address",
         "if this is your wallet, redact before sharing"),

        # US-style phone: (555) 123-4567 / 555-123-4567 / 555.123.4567
        # No leading \b — `(` and `+` are non-word chars so \b fails when the
        # number sits right after a quote like `"(415) 555-2671"`.
        ("phone_us",      r"(?:\(\d{3}\)\s?|\d{3}[-. ])\d{3}[-. ]\d{4}\b",
         "US-style phone number",
         "if personal, redact before sharing"),

        # International phone: +CC followed by 7-15 digits with optional separators
        ("phone_intl",    r"\+\d{1,3}[ .-]?\(?\d{2,4}\)?[ .-]?\d{2,4}[ .-]?\d{2,4}[ .-]?\d{0,4}\b",
         "international phone number",
         "if personal, redact before sharing"),

        # IPv4 — might be private/internal config; flag as WARN
        ("ipv4",          r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
         "IPv4 address",
         "if internal/private, redact before sharing"),

        # IPv6
        ("ipv6",          r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
         "IPv6 address",
         "if internal/private, redact before sharing"),

        # Email — most code intentionally references emails, so WARN unless it
        # looks like a labelled personal address (handled below)
        ("email",         r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
         "email address",
         "if this is personal, redact before sharing"),

        # Labelled DOB: "dob = 1990-04-15", "birthday: 04/15/1990"
        ("dob_labeled",   r"(?i)(?:date[_\s]?of[_\s]?birth|\bdob\b|birthday|birth[_\s]?date)\s*[:=]\s*['\"]?(\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4})",
         "labelled date of birth",
         "remove or redact — never commit personal DOB"),
    ]
    pii_severity = {
        "credit_card":     "CRITICAL",
        "ssn_us":          "CRITICAL",
        "iban":            "CRITICAL",
        "bitcoin_legacy":  "CRITICAL",
        "bitcoin_bech32":  "CRITICAL",
        "eth_address":     "CRITICAL",
        "phone_us":        "WARN",
        "phone_intl":      "WARN",
        "ipv4":            "WARN",
        "ipv6":            "WARN",
        "email":           "WARN",
        "dob_labeled":     "WARN",
    }
    for i, line_text in enumerate(lines, start=1):
        for rid, pat, msg, sugg, *extra in pii_rules:
            sev = pii_severity[rid]
            for m in re.finditer(pat, line_text):
                # Credit-card heuristic: confirm with Luhn check
                if extra and extra[0] == "luhn":
                    candidate = m.group(0)
                    if not _luhn_ok(candidate):
                        continue
                findings.append(_finding(
                    sev, i, m.start(), msg, line_text.strip(), sugg, rid))

    # ── Taint pass: a secret SOURCE and a network SINK in the SAME file is
    # the exfiltration shape no single-line rule can see — env var read plus
    # a network call scanned as "OK" (audit 2026-11-18). WARN, not CRITICAL:
    # reading an API key from env to call its API is the legitimate pattern;
    # the finding exists so it can never be silently "OK" again.
    _src_py = r"(?:os\.environ|os\.getenv|environ\[|getenv\()"
    _snk_py = r"(?:urlopen|urllib\.request|requests\.(?:get|post|put|request|head)|http\.client|socket\.socket)"
    _src_js = r"(?:process\.env|import\.meta\.env)"
    _snk_js = r"(?:fetch\s*\(|https?\.(?:get|post|request)\s*\(|\baxios\b|XMLHttpRequest)"
    for _src, _snk, _rid in ((_src_py, _snk_py, "taint_py_env_net"),
                             (_src_js, _snk_js, "taint_js_env_net")):
        if re.search(_src, text) and re.search(_snk, text):
            _ln = next((n for n, l in enumerate(lines, 1) if re.search(_src, l)), 1)
            findings.append(_finding(
                "WARN", _ln, 0,
                "secret source (environment) AND network call in one file — "
                "possible exfiltration",
                _line(_ln),
                "confirm only intended values leave; never send credentials",
                _rid))

    # Sort: critical first, then by line
    sev_order = {"CRITICAL": 0, "WARN": 1, "INFO": 2}
    findings.sort(key=lambda f: (sev_order.get(f["severity"], 99), f["line"], f["col"]))
    return findings


def _print_security_findings(path, findings):
    """Render findings as a coloured table. Always prints (even if empty)."""
    n = len(findings)
    crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
    warn = sum(1 for f in findings if f["severity"] == "WARN")
    info = sum(1 for f in findings if f["severity"] == "INFO")

    try:
        size = path.stat().st_size
    except OSError:
        size = 0

    print(f"\033[1m{APP} scan\033[0m — {path} ({size} bytes)", file=sys.stderr)
    if not findings:
        # "OK" is a claim that the rules RAN. For file types we have no
        # language rules for, say so instead — a green OK on an unscanned
        # file is how people end up trusting something that was never checked.
        if path.suffix.lower() in (".py", ".pyw", ".js", ".mjs", ".cjs",
                                   ".sh", ".bash", ".zsh"):
            print(f"  \033[32mOK\033[0m  no issues found", file=sys.stderr)
        else:
            print(f"  \033[33m⚠ NOT SCANNED\033[0m — local rules cover "
                  f"Python/JavaScript/shell; generic secret+PII rules did run.\n"
                  f"     the hub's AI gate still reviews this file before "
                  f"anything executes", file=sys.stderr)
        return

    # one line per finding
    color = {"CRITICAL": "\033[1;31m", "WARN": "\033[1;33m", "INFO": "\033[36m"}
    nc = "\033[0m"
    for f in findings:
        c = color.get(f["severity"], "")
        loc = f"line {f['line']}" if f["line"] else "file"
        print(f"  {c}{f['severity']:<8}{nc} {loc}: {f['message']}", file=sys.stderr)
        if f["snippet"]:
            print(f"           {f['snippet']}", file=sys.stderr)
        if f["suggestion"]:
            print(f"           → {f['suggestion']}", file=sys.stderr)
    print(file=sys.stderr)
    summary = f"  {crit} critical, {warn} warning, {info} info"
    print(summary, file=sys.stderr)


def cmd_security_scan(args, file_path=None):
    """Standalone `blnq scan FILE` subcommand."""
    if file_path is None:
        file_path = getattr(args, "file", None)
    if file_path is None:
        die(f"usage: {APP} scan <file>")
    path = Path(file_path)
    if not path.exists():
        die(f"file not found: {path}")
    if not path.is_file():
        die(f"not a regular file: {path}")

    findings = _security_scan_file(path)
    # for the explicit `scan` command we also enforce a minimum-severity filter
    min_sev = (getattr(args, "min_severity", "info") or "info").upper()
    sev_rank = {"INFO": 0, "WARN": 1, "CRITICAL": 2}
    threshold = sev_rank.get(min_sev, 0)
    findings = [f for f in findings if sev_rank.get(f["severity"], 0) >= threshold]

    json_out = getattr(args, "json", False)
    if json_out:
        import json as _json
        print(_json.dumps({"file": str(path), "findings": findings}, indent=2))
    else:
        _print_security_findings(path, findings)

    if any(f["severity"] == "CRITICAL" for f in findings):
        sys.exit(2)
    if any(f["severity"] == "WARN" for f in findings):
        sys.exit(1)
    sys.exit(0)


# ── local LLM helper ───────────────────────────────────────────────────
def _llm_which(cmd: str):
    """Find a binary on PATH or in common hand-built LLM-runtime dirs."""
    found = shutil.which(cmd)
    if found:
        return found
    home = os.path.expanduser("~")
    for extra in (
        os.path.join(home, "llama.cpp", "build", "bin"),
        "/usr/local/llama.cpp/build/bin",
        "/opt/llama.cpp/build/bin",
        "/opt/homebrew/bin",
        os.path.join(home, ".local", "bin"),
    ):
        cand = os.path.join(extra, cmd)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _llm_probe(url: str, timeout: float = 1.0):
    """GET a local URL. Returns (status_code, body). 0 means network error."""
    try:
        req = urllib.request.Request(url, method="GET",
            headers={"user-agent": f"{APP}/{VERSION}", "accept": "application/json"})
        with opener().open(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)


def _llm_detect():
    """Probe for ollama, llama.cpp, lm-studio, vllm on this box."""
    found = []

    # ollama
    ollama_bin = _llm_which("ollama")
    if ollama_bin:
        version = ""
        try:
            v = subprocess.run([ollama_bin, "--version"], capture_output=True, text=True, timeout=5)
            text = ((v.stdout or "") + (v.stderr or "")).strip()
            import re as _re
            m = _re.search(r"\d+\.\d+\.\d+", text)
            if m:
                version = m.group(0)
        except Exception:
            pass
        code, _ = _llm_probe("http://localhost:11434/api/version")
        listening = "running (port 11434)" if code == 200 else "installed, not running"
        found.append({"name": "ollama", "path": ollama_bin,
                      "version": version or "(unknown)",
                      "service": listening, "url": "http://localhost:11434"})
    else:
        code, _ = _llm_probe("http://localhost:11434/api/version")
        if code == 200:
            found.append({"name": "ollama", "path": "(server only, no CLI on PATH)",
                          "version": "?", "service": "running on :11434",
                          "url": "http://localhost:11434"})

    # llama.cpp
    for bin_name in ("llama-server", "llama-cli", "llama-quantize"):
        p = _llm_which(bin_name)
        if p:
            found.append({"name": "llama.cpp", "path": p, "version": "(git build)",
                          "service": "n/a (run llama-server manually)", "url": "n/a"})
            break

    # LM Studio
    if _llm_which("lms"):
        found.append({"name": "lm-studio", "path": _llm_which("lms"),
                      "version": "?", "service": "check `lms status`",
                      "url": "http://localhost:1234/v1"})

    # vLLM
    if _llm_which("vllm"):
        found.append({"name": "vllm", "path": _llm_which("vllm"),
                      "version": "?", "service": "n/a (run `vllm serve ...`)",
                      "url": "http://localhost:8000/v1"})

    return found


def _llm_sys_specs():
    """Inspect host: OS, CPU, RAM, GPU."""
    import platform as _p
    specs = {
        "system": _p.system(),
        "machine": _p.machine(),
        "release": _p.release(),
        "python":  _p.python_version(),
        "cpu_count": os.cpu_count() or 1,
        "ram_gb": None,
        "gpu": None,
        "apple_silicon": False,
    }
    # RAM
    try:
        if specs["system"] == "Linux":
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        specs["ram_gb"] = round(int(line.split()[1]) / 1024 / 1024, 1)
                        break
        elif specs["system"] == "Darwin":
            v = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=5)
            if v.returncode == 0:
                specs["ram_gb"] = round(int(v.stdout.strip()) / 1024**3, 1)
        elif specs["system"] == "Windows":
            v = subprocess.run(["wmic", "OS", "get", "TotalVisibleMemorySize", "/value"],
                               capture_output=True, text=True, timeout=5)
            if v.returncode == 0:
                for line in v.stdout.splitlines():
                    if "=" in line:
                        specs["ram_gb"] = round(int(line.split("=", 1)[1].strip()) / 1024 / 1024, 1)
                        break
    except Exception:
        pass

    # GPU (NVIDIA)
    if shutil.which("nvidia-smi"):
        try:
            v = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=5)
            if v.returncode == 0 and v.stdout.strip():
                parts = v.stdout.strip().split("\n")[0].split(",")
                specs["gpu"] = {"vendor": "nvidia", "name": parts[0].strip(),
                                "vram_gb": round(int(parts[1].strip()) / 1024, 1)}
        except Exception:
            pass

    if specs["system"] == "Darwin" and specs["machine"] in ("arm64", "arm64e"):
        specs["apple_silicon"] = True

    return specs


_LLM_TIERS = [
    {"tier": "apple-silicon", "min_ram_gb": 8,
     "require": {"gpu": False, "apple_silicon": True},
     "models": [
         ("qwen3:4b",         "~3 GB, Metal accelerated"),
         ("llama-3.2:3b",     "~2 GB, ANE friendly"),
         ("gemma4:e2b",       "~2 GB, lean"),
     ]},
    {"tier": "nvidia-big",   "vram_lo": 12, "require": {"gpu": True},
     "models": [
         ("qwen3:14b",        "~9 GB VRAM"),
         ("qwen3:32b",        "~20 GB VRAM"),
         ("llama-3.1:70b-q4", "~40 GB VRAM"),
         ("mixtral:8x7b",     "~25 GB VRAM"),
     ]},
    {"tier": "nvidia-8gb",   "vram_lo": 4, "vram_hi": 12, "require": {"gpu": True},
     "models": [
         ("qwen3:8b-q4",      "~5 GB VRAM"),
         ("llama-3.1:8b-q4",  "~5 GB VRAM"),
         ("mistral:7b",       "~5 GB VRAM"),
     ]},
    {"tier": "no-gpu-8core", "min_ram_gb": 8, "max_ram_gb": 96, "min_cpu": 8,
     "require": {"gpu": False, "apple_silicon": False},
     "models": [
         ("gemma4:e2b",       "~2 GB RAM, fastest on 8c CPU — Google efficient"),
         ("qwen3:4b",         "~3 GB RAM, very capable"),
         ("llama-3.2:3b",     "~2 GB RAM, Meta's mid"),
     ]},
    {"tier": "no-gpu-low",   "min_ram_gb": 8, "max_ram_gb": 96, "min_cpu": 4, "max_cpu": 7,
     "require": {"gpu": False, "apple_silicon": False},
     "models": [
         ("qwen3:1.7b",       "~1.5 GB RAM, snappy on 4-7 core CPU"),
         ("llama-3.2:3b",     "~2 GB RAM, Meta's mid"),
         ("phi-3.5-mini",     "~2.4 GB RAM, Microsoft small"),
     ]},
    {"tier": "no-gpu-tiny",  "min_ram_gb": 0, "max_ram_gb": 8,  "max_cpu": 3,
     "require": {"gpu": False, "apple_silicon": False},
     "models": [
         ("qwen3:0.6b",       "~0.6 GB RAM, ultra-tiny — for 2-core boxes"),
         ("qwen3:1.7b",       "~1.5 GB RAM, fast on any CPU"),
         ("llama-3.2:1b",     "~1 GB RAM, Meta's tiniest"),
     ]},
]

# Fallback target — when nothing matches, use the safest tiny-CPU model.
_FALLBACK_TIER = next(t for t in _LLM_TIERS if t["tier"] == "no-gpu-tiny")


def _llm_pick_model(specs):
    has_gpu   = specs.get("gpu") is not None
    vram      = specs.get("gpu", {}).get("vram_gb", 0) if has_gpu else 0
    ram       = specs.get("ram_gb") or 0
    cpu_count = specs.get("cpu_count") or 1
    apple     = bool(specs.get("apple_silicon"))

    for t in _LLM_TIERS:
        req = t["require"]
        # Apple Silicon short-circuits everything (Metal acceleration is decisive).
        if req.get("apple_silicon"):
            if not apple:
                continue
            return (t["tier"], t["models"],
                    "Apple Silicon detected — Metal acceleration available")
        # NVIDIA tiers — require a GPU.
        if req.get("gpu"):
            if not has_gpu:
                continue
            lo = t.get("vram_lo", 0); hi = t.get("vram_hi", 9999)
            if lo <= vram < hi:
                return (t["tier"], t["models"],
                        f"NVIDIA GPU with {vram} GB VRAM detected")
            continue
        # CPU-only tiers — explicitly skip when the box has a GPU
        # (so NVIDIA boxes can't accidentally fall into a CPU tier).
        if has_gpu:
            continue
        # Match on RAM + CPU core count.
        min_r = t.get("min_ram_gb", 0); max_r = t.get("max_ram_gb", 9999)
        min_c = t.get("min_cpu", 0);    max_c = t.get("max_cpu", 9999)
        if min_r <= ram <= max_r and min_c <= cpu_count <= max_c:
            if t["tier"] == "no-gpu-8core":
                why = f"{cpu_count}-core CPU, no GPU — gemma4:e2b is the sweet spot"
            else:
                why = f"{cpu_count}-core CPU, {ram} GB RAM, no GPU — CPU-friendly models"
            return (t["tier"], t["models"], why)
    # Fallback — couldn't classify (very rare; e.g. ram is huge, no GPU, <8 cores).
    return ("fallback", _FALLBACK_TIER["models"],
            "could not classify hardware — defaulting to smallest tier")


def cmd_llm_help(args):
    print(f"""\033[1m{APP} llm\033[0m — local AI runtime helper

find local LLM runtimes, recommend a model for your hardware, and benchmark
your box. works with ollama (recommended) or hand-built llama.cpp.

\033[1msubcommands:\033[0m
  llm detect                  find ollama, llama.cpp, lm-studio, vllm on this box
  llm suggest                 recommend a model given CPU / RAM / GPU
  llm bench                   quick CPU / RAM / disk benchmark
  llm status                  detect + bench + suggest in one shot
  llm install [--docker|--auto|--model NAME]   install ollama (print, run, or container)
  llm pull <model>            run `ollama pull <model>`
  llm serve [model] [--port]  run `ollama serve` in the foreground

\033[1mexamples:\033[0m
  {APP} llm detect
  {APP} llm suggest
  {APP} llm suggest --json    # machine-readable, used by installers
  {APP} llm bench
  {APP} llm install --docker
  {APP} llm install --auto --model qwen3:1.7b   # install + pull
  {APP} llm pull qwen3:1.7b
""")


def cmd_llm_detect(args):
    print(f"\033[1m{APP} llm detect\033[0m — scanning this box for AI runtimes")
    found = _llm_detect()
    if not found:
        print(f"  \033[33m(no local LLM runtimes detected)\033[0m")
        print()
        print(f"  \033[1mto install:\033[0m")
        print(f"    {APP} llm install            # native install for {os.uname().sysname}")
        print(f"    {APP} llm install --docker   # ollama in a container")
        print()
        print(f"  \033[1mthen:\033[0m")
        print(f"    {APP} llm suggest            # see recommended models")
        print(f"    {APP} llm pull <model>       # download one")
        return
    for r in found:
        v = f"  v={r['version']}" if r["version"] not in ("", "?", "(unknown)") else ""
        print(f"  \033[32m●\033[0m {r['name']:<14} {r['path']}{v}")
        print(f"      service: {r['service']}")
        print(f"      endpoint: {r['url']}")


def cmd_llm_suggest(args):
    specs = _llm_sys_specs()
    tier, models, reason = _llm_pick_model(specs)

    # Machine-readable output for installer scripts.
    if getattr(args, "json", False):
        import json as _json
        out = {
            "tier":    tier,
            "reason":  reason,
            "primary": models[0][0] if models else None,
            "models":  [{"name": n, "desc": d} for n, d in models],
            "host": {
                "system":  specs["system"],
                "machine": specs["machine"],
                "cpu":     specs["cpu_count"],
                "ram_gb":  specs.get("ram_gb"),
                "gpu":     specs.get("gpu"),
                "apple_silicon": bool(specs.get("apple_silicon")),
            },
        }
        print(_json.dumps(out, indent=2))
        return

    print(f"\033[1m{APP} llm suggest\033[0m — {reason}")
    print(f"  OS={specs['system']}  arch={specs['machine']}  cpu={specs['cpu_count']}c  ram={specs.get('ram_gb','?')}GB")
    if specs.get("gpu"):
        print(f"  gpu={specs['gpu']['name']}  vram={specs['gpu']['vram_gb']}GB")
    elif specs["apple_silicon"]:
        print(f"  gpu=Apple Silicon  (Metal)")
    else:
        print(f"  gpu=(none detected)")
    print()
    print(f"  \033[1mrecommendation (tier: {tier}):\033[0m")
    for name, desc in models:
        print(f"    • {name:<20} {desc}")
    print()
    has_ollama = any(r["name"] == "ollama" for r in _llm_detect())
    if has_ollama:
        print(f"  to install (ollama is already on this box):")
        for name, _ in models[:2]:
            print(f"    ollama pull {name}")
    else:
        print(f"  to get ollama first:")
        print(f"    {APP} llm install --docker    # or: {APP} llm install")
        print(f"  then:")
        print(f"    ollama pull {models[0][0]}")


def cmd_llm_bench(args):
    import hashlib, tempfile
    specs = _llm_sys_specs()
    print(f"\033[1m{APP} llm bench\033[0m — quick local benchmark")
    print(f"  OS={specs['system']} {specs['release']}  arch={specs['machine']}  python={specs['python']}  cpus={specs['cpu_count']}")

    data = os.urandom(1024 * 1024)
    n = 30
    t0 = time.perf_counter()
    for _ in range(n):
        hashlib.sha256(data).digest()
    dt = max(time.perf_counter() - t0, 1e-9)
    mb_s = round(n / dt, 1)
    print(f"  CPU sha256  : {mb_s} MB/s  ({n}× 1 MB blocks)")

    t0 = time.perf_counter()
    buf = bytearray(100 * 1024 * 1024)
    s = 0
    step = 4096
    for i in range(0, len(buf), step):
        s += buf[i]
    dt = max(time.perf_counter() - t0, 1e-9)
    gb_s = round(0.1 / dt, 2)
    print(f"  MEM touch   : {gb_s} GB/s  (100 MB alloc + page-touch)")

    mb_s_w = mb_s_r = None
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            tmp_path = f.name
        t0 = time.perf_counter()
        with open(tmp_path, "wb") as f:
            f.write(b"\x00" * 50 * 1024 * 1024)
            f.flush(); os.fsync(f.fileno())
        dt_w = max(time.perf_counter() - t0, 1e-9)
        mb_s_w = round(50.0 / dt_w, 0)
        t0 = time.perf_counter()
        with open(tmp_path, "rb") as f:
            _ = f.read()
        dt_r = max(time.perf_counter() - t0, 1e-9)
        mb_s_r = round(50.0 / dt_r, 0)
        print(f"  DISK write  : {int(mb_s_w)} MB/s  (50 MB file + fsync)")
        print(f"  DISK read   : {int(mb_s_r)} MB/s  (50 MB readback)")
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    if specs.get("gpu"):
        print(f"  GPU         : {specs['gpu']['name']}  ({specs['gpu']['vram_gb']} GB VRAM, CUDA)")
    elif specs["apple_silicon"]:
        print(f"  GPU         : Apple Silicon  (Metal)")
    else:
        print(f"  GPU         : (none — CPU-only inference)")
    if specs.get("ram_gb"):
        print(f"  RAM         : {specs['ram_gb']} GB")

    # Return the numbers, not only the pretty lines: `blnq speed` signs and
    # reports them, and a measurement that can only be printed can never be
    # verified or aggregated by anyone else.
    return {
        "system": f"{specs.get('system')} {specs.get('release')}",
        "arch": specs.get("machine"), "python": specs.get("python"),
        "cpus": specs.get("cpu_count"), "ram_gb": specs.get("ram_gb"),
        "gpu": specs.get("gpu"),
        "cpu_mbs": mb_s, "mem_gbs": gb_s,
        "disk_write_mbs": mb_s_w, "disk_read_mbs": mb_s_r,
    }


def cmd_llm_status(args):
    cmd_llm_detect(args)
    print()
    cmd_llm_bench(args)
    print()
    cmd_llm_suggest(args)


def cmd_llm_install(args):
    import subprocess as _sp
    sysname = os.uname().sysname
    do_auto  = bool(getattr(args, "auto", False))
    pull_arg = getattr(args, "model", None)

    if getattr(args, "docker", False):
        if not do_auto:
            print(f"\033[1m{APP} llm install --docker\033[0m — ollama in a container")
            print()
            print(f"    docker run -d --name {APP}-ollama \\")
            print(f"      -p 11434:11434 \\")
            print(f"      -v {APP}-ollama:/root/.ollama \\")
            print(f"      --restart unless-stopped \\")
            print(f"      ollama/ollama")
            print()
            print(f"  Wait ~10s for it to start, then:")
            print(f"    {APP} llm pull <model>")
            return
        cmd = ["docker", "run", "-d", "--name", f"{APP}-ollama",
               "-p", "11434:11434", "-v", f"{APP}-ollama:/root/.ollama",
               "--restart", "unless-stopped", "ollama/ollama"]
        print(f"\033[1m{APP} llm install --docker --auto\033[0m")
        print(f"  $ {' '.join(cmd)}")
        rc = _sp.call(cmd)
        if rc != 0:
            die(f"docker run failed (rc={rc})")
        print(f"  ✓ ollama container started — wait ~10s then run `{APP} llm pull <model>`")
        return

    # Pick the native install command for the host OS.
    if sysname == "Linux":
        cmd = ["sh", "-c", "curl -fsSL https://ollama.com/install.sh | sh"]
    elif sysname == "Darwin":
        cmd = ["brew", "install", "ollama"]
    elif sysname.startswith("MINGW") or sysname.startswith("MSYS") or sysname == "Windows":
        if _llm_which("winget"):
            cmd = ["winget", "install", "--id", "Ollama.Ollama",
                   "--accept-source-agreements", "--accept-package-agreements"]
        elif _llm_which("choco"):
            cmd = ["choco", "install", "ollama", "-y"]
        else:
            cmd = None
    else:
        cmd = None

    if not do_auto:
        print(f"\033[1m{APP} llm install\033[0m — install ollama natively ({sysname})")
        print()
        if sysname == "Linux":
            print(f"    curl -fsSL https://ollama.com/install.sh | sh")
        elif sysname == "Darwin":
            print(f"    brew install ollama")
            print(f"  or download from https://ollama.com/download")
        elif sysname.startswith("MINGW") or sysname.startswith("MSYS") or sysname == "Windows":
            print(f"    winget install Ollama.Ollama")
            print(f"  or download from https://ollama.com/download")
        else:
            print(f"    see https://ollama.com/download")
        print()
        print(f"  Or use docker (works everywhere):")
        print(f"    {APP} llm install --docker")
        print()
        print(f"  Or build llama.cpp from source:")
        print(f"    git clone https://github.com/ggerganov/llama.cpp")
        print(f"    cd llama.cpp && cmake -B build && cmake --build build --config Release")
        return

    # --auto path: actually run the install.
    print(f"\033[1m{APP} llm install --auto\033[0m — installing ollama on {sysname}")
    if cmd is None:
        die(f"no native installer known for {sysname}; try `{APP} llm install --docker --auto`")
    print(f"  $ {' '.join(cmd)}")
    rc = _sp.call(cmd)
    if rc != 0:
        die(f"install failed (rc={rc}); try `{APP} llm install --docker --auto`")

    # If ollama is on PATH and --model was passed, pull it.
    if _llm_which("ollama"):
        if pull_arg:
            print(f"\n\033[1m{APP} llm pull\033[0m — pulling model")
            rc = _sp.call(["ollama", "pull", pull_arg])
            if rc != 0:
                print(f"  ✗ pull failed (rc={rc}); retry with `ollama pull {pull_arg}`")
            else:
                print(f"  ✓ pulled {pull_arg}")
        else:
            specs   = _llm_sys_specs()
            tier, models, reason = _llm_pick_model(specs)
            primary = models[0][0] if models else "gemma4:e2b"
            print(f"\n  ✓ ollama installed. recommended model for this box ({tier}): \033[1m{primary}\033[0m")
            print(f"    ollama pull {primary}")
            print(f"  or pick another: `blnq llm suggest`")
    else:
        print(f"  ✗ ollama not on PATH after install. open a new shell or restart.")


def cmd_llm_pull(args):
    model = getattr(args, "model", None)
    if not model:
        die(f"missing model name. e.g. `{APP} llm pull qwen3:1.7b`")
    ollama = _llm_which("ollama")
    if not ollama:
        die(f"ollama not installed. run `{APP} llm install` or `{APP} llm install --docker`")
    print(f"[{APP}] ollama pull {model}")
    try:
        rc = subprocess.call([ollama, "pull", model])
        sys.exit(rc)
    except KeyboardInterrupt:
        sys.exit(130)


def cmd_llm_serve(args):
    port  = getattr(args, "port", 11434) or 11434
    model = getattr(args, "model", None)
    ollama = _llm_which("ollama")
    if not ollama:
        die(f"ollama not installed. run `{APP} llm install` or `{APP} llm install --docker`")
    cmd = [ollama, "serve"]
    env = os.environ.copy()
    env["OLLAMA_HOST"] = f"127.0.0.1:{port}"
    if model:
        print(f"[{APP}] starting ollama on :{port}  (will preload {model})")
    else:
        print(f"[{APP}] starting ollama on :{port}  (Ctrl-C to stop)")
    try:
        rc = subprocess.call(cmd, env=env)
        sys.exit(rc)
    except KeyboardInterrupt:
        print()
        sys.exit(0)


# ── arg parser ─────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=APP, description=__doc__.splitlines()[1],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")

    # operator / local
    sub.add_parser("start")
    sub.add_parser("stop")
    sub.add_parser("emergency", help="big red button: volunteer off + disable respawn + stop the agent")
    sub.add_parser("emergancy", help="alias for emergency")
    sub.add_parser("security", help="security posture: jail + permissions + network view (exit 1 = FAIL)")
    sp_i = sub.add_parser("install", help="install a jail: `blnq install sandbox` (best for this OS) or `blnq install docker`")
    sp_i.add_argument("what", nargs="?", choices=["sandbox", "docker"], default="sandbox")
    sub.add_parser("docker", help="install/check the docker runtime (same as: blnq install docker)")
    sub.add_parser("restart")
    sub.add_parser("status")
    sub.add_parser("info")
    sp_u = sub.add_parser("uninstall",
        help="stop the agent, disarm respawn, remove the code "
             "(keeps config+keys+logs; --purge removes those too)")
    sp_u.add_argument("--purge", action="store_true",
                      help="ALSO remove config, KEYS, state, logs, history — "
                           "private keys are unrecoverable (asks to confirm)")
    sp_u.add_argument("--yes", action="store_true",
                      help="skip the --purge confirmation (scripts only)")
    sp = sub.add_parser("logs");    sp.add_argument("n", nargs="?", type=int, default=50); sp.add_argument("-f", "--follow", action="store_true")
    sub.add_parser("free")
    sp = sub.add_parser("pct");     sp.add_argument("--watch", type=float, default=1.0)
    sp = sub.add_parser("update",  help="pull latest blnq-cli.py from blnq.org")
    sp_clg = sub.add_parser("changelog",
                            help="what changed and why (also printed by `update`)")
    sp_clg.add_argument("--since", help="only entries newer than this version")
    sp_clg.add_argument("--limit", type=int, default=3,
                        help="how many recent entries (default 3)")
    sp_clg.add_argument("--json", action="store_true", help="machine-readable")
    sp.add_argument("--from-url", dest="from_url", default=None,
                    help="download from this URL instead of <hub>/blnq-cli.py")
    sp.add_argument("--sha256", default=None,
                    help="verify downloaded bytes against this hex SHA256")

    # one-shot
    sub.add_parser("health")
    sub.add_parser("whoami")
    sp_m = sub.add_parser("metrics", help="GET /api/stats (hub stats) or --local (this bee's metrics)")
    sp_m.add_argument("--local", action="store_true", help="print this bee's local CPU/GPU/MEM/DISK snapshot")
    sub.add_parser("doctor",    help="one-glance health report (install + hub + agent + bee + version)")
    sub.add_parser("speed",     help="latency benchmark (DNS, TCP, hub ping, CPU/RAM/disk)")
    sub.add_parser("test",      help="doctor + speed + tiny run end-to-end smoke test")
    sp_tk = sub.add_parser("tasks", help="in-flight local jobs (kill <job_id> = operator stop)")
    sp_tk.add_argument("verb", nargs="?", choices=["kill"],
                       help="kill: stop one job this node is running")
    sp_tk.add_argument("job_id", nargs="?", help="job_id to kill")
    sp_tk.add_argument("--json", action="store_true", help="machine-readable rows")
    sp_au = sub.add_parser("auth",
        help="local authorization — who may run what HERE (tokens in any order)")
    sp_au.add_argument("tokens", nargs="*",
        help="identities + verbs (who|show|logs|default) + modes "
             "(allow|maybe|deny/revoke) + caps (all|run|network|secrets) — any order")
    sp_au.add_argument("--json", action="store_true", help="machine-readable")
    sp_az = sub.add_parser("authorize", help="alias of `auth`")
    sp_az.add_argument("tokens", nargs="*")
    sp_az.add_argument("--json", action="store_true")
    sp_nw = sub.add_parser("network",
        help="may this node run jobs that ask for egress? (on|off|status)")
    sp_nw.add_argument("action", nargs="?", choices=["on", "off", "status"],
                       default="status")
    sp_nw.add_argument("--json", action="store_true", help="machine-readable")
    sp_v = sub.add_parser("volunteer", help="opt in/out of running other people's jobs (on/off/status)")
    sp_v.add_argument("action", nargs="?", choices=["on", "off", "status"], default="status")
    sp_v.add_argument("--unsafe", action="store_true",
                      help="volunteer WITHOUT a docker/bwrap jail (not recommended)")
    sp_k = sub.add_parser("keepalive", help="reboot/crash-proofing: install a systemd respawn timer")
    sp_as = sub.add_parser("autostart",
        help="start the agent on boot/login (systemd, or no-root fallbacks)")
    sp_as.add_argument("action", nargs="?", choices=["on", "off", "status"],
                       default="status")
    sp_as.add_argument("--tier", choices=["systemd-system", "systemd-user",
                                          "xdg", "profile"],
                       help="force a mechanism instead of auto-picking")
    sp_k.add_argument("action", nargs="?", choices=["on", "off", "status", "run"], default="status")
    sub.add_parser("panic",     help="emergency help — diagnostics + how to report a bug")
    sub.add_parser("help-bang", help="alias for `panic` (the name `help!` is reserved by bash history expansion)")
    sub.add_parser("hi",        help="friendly greeter + first-run examples")
    sub.add_parser("support",   help="gather context for human support (doctor + log + metrics + FAQ)")
    sub.add_parser("workers", help="alias for `blnq workers list`")
    sp_n = sub.add_parser("nodes", help="who's out there — the network's nodes at a glance")
    sp_n.add_argument("--json", action="store_true",
                      help="raw JSON for scripts/AIs (same data, no table)")
    sp_sug = sub.add_parser("suggest", help="send a suggestion/report to the hub (humans + AIs)")
    sp_sug.add_argument("message", nargs="*", help="your idea, bug or report")
    sp_sug.add_argument("--kind", choices=["idea", "bug", "security", "question", "other"],
                        default="idea")
    sp_sug.add_argument("--contact", default="", help="email/handle if you want a reply")
    sp_sug.add_argument("--json", action="store_true", help="machine-readable result")

    sp = sub.add_parser("graph", help="`blnq graph stats|search|timeline|...`")
    sp_g = sp.add_subparsers(dest="graph_cmd", required=True)
    sp_g.add_parser("stats")
    sp_g.add_parser("timeline")
    sp_s = sp_g.add_parser("search"); sp_s.add_argument("query", nargs=argparse.REMAINDER)
    # default: `blnq graph` with no sub → full graph
    sp.set_defaults(func=None)

    sp = sub.add_parser("scripts", help="`blnq scripts list|get ID|love ID|leaderboard`")
    sp_sc = sp.add_subparsers(dest="scripts_cmd", required=True)
    sp_sc.add_parser("list")
    sp_g = sp_sc.add_parser("get"); sp_g.add_argument("id")
    sp_l = sp_sc.add_parser("love", help="love a script; author earns credits")
    sp_l.add_argument("id")
    sp_l.add_argument("--undo", action="store_true", help="remove your love")
    sp_sc.add_parser("leaderboard", help="most-loved scripts + authors")

    # ── catalog: what the network runs (code only, never the data) ─────────
    sp_cat = sub.add_parser(
        "catalog",
        help="`blnq catalog [search Q|categories|show SUBJECT]` — what the network runs")
    sp_c = sp_cat.add_subparsers(dest="catalog_cmd")
    sp_cat.add_argument("--limit", type=int, default=15, help="rows to show (default 15)")
    sp_cat.add_argument("--category", help="filter by category")
    sp_cat.add_argument("--sort", help="runs|recent|name|category|relevance")
    sp_cat.add_argument("--json", action="store_true", help="machine-readable")
    sp_cl = sp_c.add_parser("list", help="most-run first (default)")
    # Each sub-parser carries its OWN catalog_cmd via set_defaults. main()
    # resolves dotted commands by calling the sub-sub-parser directly, which
    # never runs sp_cat's add_subparsers(dest=...) — so relying on that dest
    # alone silently fell every action through to `list`.
    sp_cl.set_defaults(catalog_cmd="list")
    sp_cl.add_argument("--limit", type=int, default=15)
    sp_cl.add_argument("--category")
    sp_cl.add_argument("--sort")
    sp_cl.add_argument("--json", action="store_true")
    sp_cs = sp_c.add_parser("search", help="search by word — typo-tolerant")
    sp_cs.set_defaults(catalog_cmd="search")
    sp_cs.add_argument("query", help="words to search for")
    sp_cs.add_argument("--category", help="filter by category")
    sp_cs.add_argument("--sort", default="relevance",
                       help="relevance (default here)|runs|recent|name|category")
    sp_cs.add_argument("--limit", type=int, default=15)
    sp_cs.add_argument("--json", action="store_true")
    sp_c.add_parser("categories", help="counts per category (browse)") \
         .set_defaults(catalog_cmd="categories")
    sp_sh = sp_c.add_parser("show", help="one entry + its source, hash-verified")
    sp_sh.set_defaults(catalog_cmd="show")
    sp_sh.add_argument("subject", help="64-hex sha256 from `blnq catalog`")
    sp_sh.add_argument("--json", action="store_true")

    # ── trust layer ────────────────────────────────────────────────────────
    sp_ky = sub.add_parser("keys", help="list/inspect this machine's principal keys (public material only)")
    sp_ky.add_argument("role", nargs="?", default=None,
                       help="key to show (requester|runner|validator|any name on disk); omit to list all")
    sp_ky.add_argument("--register", action="store_true",
                       help="publish the public key to the hub so others can verify your signatures")
    sp_vf = sub.add_parser("verify", help="verify signed attestations + quorum (signatures checked locally)")
    sp_vf.add_argument("path", nargs="?", default=None, help="local file whose source hash to look up")
    sp_vf.add_argument("--subject", default=None, help="64-hex source hash")
    sp_vf.add_argument("--script", default=None, help="script id (scr_…)")
    sp_vf.add_argument("--attestation", default=None, help="attestation id (att_…)")
    for _name, _help in (
        ("approve", "file a signed HUMAN 'safe' verdict on a file"),
        ("vouch",   "alias for approve"),
        ("endorse", "alias for approve"),
        ("reject",  "file a signed human objection — a veto on that source"),
        ("object",  "alias for reject"),
    ):
        _sp = sub.add_parser(_name, help=_help)
        _sp.add_argument("path", help="file to judge")
        _sp.add_argument("--note", help="why you think this (shown to others)")
        _sp.add_argument("--json", action="store_true", help="machine-readable")

    sp_rv = sub.add_parser("review", help="multi-validator signed safety scan of a local file")
    sp_rv.add_argument("path")
    sp_rv.add_argument("--description", default=None)
    sp_rd = sub.add_parser("redo",
        help="re-submit with a FRESH AI review — skips the cached verdict "
             "(alias: recheck)")
    sp_rd.add_argument("file")
    sp_rd.add_argument("--endpoint", default=None,
        help="pin a configured AI endpoint (must be in BLNQ_AI_ENDPOINTS)")
    sp_rc = sub.add_parser("recheck", help="alias of `redo`")
    sp_rc.add_argument("file")
    sp_rc.add_argument("--endpoint", default=None)

    # ── P2P transport ──────────────────────────────────────────────────────
    sp_dm = sub.add_parser("dm", help="send an end-to-end encrypted message to a principal")
    sp_dm.add_argument("principal", help="recipient principal id (hivv_…)")
    sp_dm.add_argument("message", nargs="*", help="the message (or use --file / pipe stdin)")
    sp_dm.add_argument("--file", default=None, help="send the contents of this file instead")
    sp_dm.add_argument("--role", choices=["requester", "runner"], default="requester")
    sp_dm.add_argument("--relay-only", action="store_true",
                       help="skip the direct UDP attempt and always use the relay")
    sp_in = sub.add_parser("inbox", help="receive + decrypt P2P messages (long-poll)")
    sp_in.add_argument("--wait", type=int, default=0,
                       help="long-poll up to N seconds (max 50) instead of returning at once")
    sp_in.add_argument("--json", action="store_true", help="one JSON object per message")
    sp_in.add_argument("--role", choices=["requester", "runner"], default="requester")
    sp_in.add_argument("--relay-only", action="store_true",
                       help="do not open the direct UDP listener")
    sp_p2p = sub.add_parser("p2p", help="diagnose the direct transport / show P2P identity")
    sp_p2p.add_argument("action", nargs="?", choices=["status", "doctor"], default="status")
    sp_p2p.add_argument("--role", choices=["requester", "runner"], default="requester")

    sp = sub.add_parser("jobs", help="`blnq jobs list|submit SCR|status ID` — the collective queue")
    sp_j = sp.add_subparsers(dest="jobs_cmd", required=True)
    sp_jl = sp_j.add_parser("list"); sp_jl.add_argument("--status", default="all")
    sp_js = sp_j.add_parser("submit")
    sp_js.add_argument("script", nargs="?", default=None,
                       help="approved script id (scr_…) — omit when using --file")
    sp_js.add_argument("--file", default=None,
                       help="send a LOCAL file's code directly (inline path: "
                            "safety scan, no library round-trip)")
    sp_js.add_argument("--node", default=None,
                       help="run ONLY on this node's hostname (e.g. yalla) — "
                            "targeted claim; use `blnq nodes` for names")
    sp_js.add_argument("--stdin", default=None)
    sp_js.add_argument("--timeout", type=int, default=None)
    sp_js.add_argument("--secret", action="append", default=[], metavar="KEY=VALUE",
                       help="inject env var into the job (repeatable); encrypted at rest, redacted from output")
    sp_js.add_argument("--interactive", action="store_true",
                       help="keep stdin open so you can type into the running job (blnq send)")
    sp_jst = sp_j.add_parser("status"); sp_jst.add_argument("id")
    sp_jc = sp_j.add_parser("cancel"); sp_jc.add_argument("id")

    sp = sub.add_parser("watch", help="live-follow a job or run's output (SSE stream)")
    sp.add_argument("id", help="job_xxx or run uuid")

    sp = sub.add_parser("credits", help="your compute-credit balance")

    sp = sub.add_parser("love", help="show love for a script; author earns credits")
    sp.add_argument("id", help="script id (scr_…)")
    sp.add_argument("--undo", action="store_true", help="remove your love")

    sp = sub.add_parser("send", help="type input into a running interactive job")
    sp.add_argument("id", help="job id (job_…)")
    sp.add_argument("text", nargs="?", default=None, help="text to send (newline appended); or pipe via stdin")
    sp.add_argument("--eof", action="store_true", help="close the job's stdin (signal end of input)")

    sp = sub.add_parser("loveboard", help="the most-loved scripts + authors")
    sp = sub.add_parser("leaderboard", help="alias for loveboard")

    sp = sub.add_parser("artifact", help="download a finished job's output files (owner only)")
    sp.add_argument("id", help="job id")
    sp.add_argument("member", nargs="?", default=None,
                    help="single artifact file to fetch (omit for the whole tar.gz; see --list)")
    sp.add_argument("--list", action="store_true", help="just list the artifact manifest")
    sp.add_argument("-o", "--output", default=None, help="destination .tar.gz path")

    sp = sub.add_parser("login")
    sp.add_argument("--username"); sp.add_argument("--password")

    # local security scanner (runs before any smart-default file upload)
    for _name, _help in (
        ("check", "analyse a file BEFORE submitting it (local + remote)"),
        ("list",  "table of what has run: who, what, where, when"),
        ("who",   "machines and validators available right now"),
        ("peers", "who else is on this LAN (UDP broadcast, no internet)"),
        ("debug", "explain an error, or diagnose this machine"),
        ("why",   "alias for debug"),
        ("bugs",  "known issues from the hub + what failed here"),
        ("issues","alias for bugs"),
        ("details", "everything about the last run (or one run-id)"),
        ("last",  "alias for details"),
        ("runs",  "alias for list"),
        ("history", "alias for list"),
    ):
        _sp = sub.add_parser(_name, help=_help)
        if _name == "check":
            _sp.add_argument("file", help="file to analyse")
            _sp.add_argument("--argv", nargs="*", default=[],
                             help="args you would pass, for the cost estimate")
            _sp.add_argument("--json", action="store_true", help="machine-readable")
        elif _name in ("list", "runs", "history"):
            _sp.add_argument("limit", nargs="?", type=int, default=15)
            _sp.add_argument("--json", action="store_true", help="machine-readable")
        elif _name == "who":
            _sp.add_argument("--json", action="store_true", help="machine-readable")
        elif _name in ("peers", "bugs", "issues"):
            _sp.add_argument("--json", action="store_true", help="machine-readable")
        elif _name in ("debug", "why"):
            _sp.add_argument("error", nargs="?",
                             help="the error text (default: diagnose this machine)")
            _sp.add_argument("--json", action="store_true", help="machine-readable")
        else:  # details / last
            _sp.add_argument("run_id", nargs="?", help="run id (default: the last one)")
            _sp.add_argument("--json", action="store_true", help="machine-readable")

    for _name, _help in (
        ("about",   "who runs this, the mission, and how to reach a human"),
        ("contact", "alias for about"),
    ):
        _sp = sub.add_parser(_name, help=_help)
        _sp.add_argument("--json", action="store_true", help="machine-readable")

    sp_duh = sub.add_parser(
        "duh",
        help="is it dumb to run this remotely? (static pre-upload check)")
    sp_duh.add_argument("file", nargs="?", help="file to judge (default: stdin)")
    sp_duh.add_argument("--json", action="store_true", help="machine-readable")
    sp_duh.add_argument("--argv", nargs="*", default=[],
                         help="args you would pass, for the cost estimate")
    sp = sub.add_parser("scan", help="local security scan: secrets + dangerous stdlib calls")
    sp_ev = sub.add_parser("evaluate", help="study a codebase: where can blnq run it?")
    sp_ev.add_argument("path", nargs="?", default=".", help="project root (default: .)")
    sp_ev.add_argument("--json", action="store_true", help="machine-readable report")
    sp_ev.add_argument("--limit", type=int, default=0, help="max files to scan")
    sp.add_argument("file", help="path to a local file")
    sp.add_argument("--min-severity", choices=["info", "warn", "critical"], default="info",
                    help="only show findings at this severity or above (default info)")
    sp.add_argument("--json", action="store_true", help="emit findings as JSON")

    # local LLM helper
    sp = sub.add_parser("llm", help="local AI runtime helper (ollama, llama.cpp, ...)")
    sp_llm = sp.add_subparsers(dest="llm_cmd")
    sp_llm.add_parser("detect",  help="find ollama, llama.cpp, lm-studio, vllm on this box")
    sp_sg = sp_llm.add_parser("suggest", help="recommend a model for this hardware")
    sp_sg.add_argument("--json", action="store_true",
                       help="emit machine-readable JSON (used by installers)")
    sp_llm.add_parser("bench",   help="quick CPU / RAM / disk benchmark")
    sp_llm.add_parser("status",  help="detect + bench + suggest in one shot")
    sp_i = sp_llm.add_parser("install", help="print install commands (or --docker)")
    sp_i.add_argument("--docker", action="store_true", help="print docker run command")
    sp_i.add_argument("--auto",  action="store_true", help="actually run the install (instead of just printing)")
    sp_i.add_argument("--model", default=None, metavar="NAME",
                      help="after install, run `ollama pull <NAME>`")
    sp_p = sp_llm.add_parser("pull", help="ollama pull <model>")
    sp_p.add_argument("model", help="model name, e.g. qwen3:1.7b")
    sp_sv = sp_llm.add_parser("serve", help="ollama serve [model]")
    sp_sv.add_argument("model", nargs="?", default=None)
    sp_sv.add_argument("--port", type=int, default=11434)

    return p


# ── dispatcher ─────────────────────────────────────────────────────────
COMMANDS = {
    "_agent":           None,
    "start":            cmd_start,
    "stop":             cmd_stop,
    "emergency":        cmd_emergency,
    "emergancy":        cmd_emergency,
    "security":         cmd_security,
    "install":          cmd_install,
    "docker":           cmd_docker,
    "nodes":            cmd_nodes,
    "suggest":          cmd_suggest,
    "restart":          cmd_restart,
    "status":           cmd_status,
    "logs":             cmd_logs,
    "free":             cmd_free,
    "pct":              cmd_pct,
    "info":             cmd_info,
    "update":           cmd_update,
    "changelog":        cmd_changelog,
    "uninstall":        cmd_uninstall,
    "health":           cmd_health,
    "whoami":           cmd_whoami,
    "metrics":          cmd_metrics,
    "doctor":           cmd_doctor,
    "speed":            cmd_speed,
    "test":             cmd_test,
    "tasks":            cmd_tasks,
    "auth":             cmd_auth,
    "authorize":        cmd_auth,
    "network":          cmd_network,
    "redo":             cmd_redo,
    "recheck":          cmd_redo,
    "volunteer":        cmd_volunteer,
    "keepalive":        cmd_keepalive,
    "autostart":        cmd_autostart,
    "panic":            cmd_help_bang,
    "help-bang":        cmd_help_bang,
    "hi":               cmd_hi,
    "support":          cmd_support,
    "workers list":     cmd_workers_list,
    "graph":            cmd_graph,
    "graph stats":      cmd_graph_stats,
    "graph search":     cmd_graph_search,
    "graph timeline":   cmd_graph_timeline,
    "scripts list":     cmd_scripts_list,
    "catalog":          cmd_catalog,
    "catalog list":     cmd_catalog,
    "catalog search":   cmd_catalog,
    "catalog categories": cmd_catalog,
    "catalog show":     cmd_catalog,
    "scripts get":      cmd_scripts_get,
    "keys":             cmd_keys,
    "verify":           cmd_verify,
    "review":           cmd_review,
    "approve":          cmd_approve,
    "vouch":            cmd_approve,     # alias — humans say different things
    "endorse":          cmd_approve,     # alias
    "reject":           cmd_reject,
    "object":           cmd_reject,      # alias
    "dm":               cmd_dm,
    "inbox":            cmd_inbox,
    "p2p":              cmd_p2p,
    "scripts love":     cmd_love,
    "scripts leaderboard": cmd_leaderboard,
    "love":             cmd_love,
    "send":             cmd_send,
    "loveboard":        cmd_leaderboard,
    "leaderboard":      cmd_leaderboard,
    "jobs list":        cmd_jobs_list,
    "jobs submit":      cmd_jobs_submit,
    "jobs status":      cmd_jobs_status,
    "jobs cancel":      cmd_jobs_cancel,
    "watch":            cmd_watch,
    "credits":          cmd_credits,
    "artifact":         cmd_artifact,
    "login":            cmd_login,
    # local security scanner
    "scan":             cmd_security_scan,
    "duh":              cmd_duh,
    "about":            cmd_about,
    "contact":          cmd_about,     # alias
    "check":            cmd_check,
    "list":             cmd_list,
    "runs":             cmd_list,        # alias — humans say different things
    "history":          cmd_list,        # alias
    "who":              cmd_who,
    "peers":            cmd_peers,
    "debug":            cmd_debug,
    "why":              cmd_debug,       # alias — "why did it fail?"
    "bugs":             cmd_bugs,
    "issues":           cmd_bugs,        # alias
    "details":          cmd_details,
    "last":             cmd_details,     # alias
    "evaluate":         cmd_evaluate,
    # local LLM helper (dotted names resolved in main())
    "llm":              cmd_llm_help,
    "llm detect":       cmd_llm_detect,
    "llm suggest":      cmd_llm_suggest,
    "llm bench":        cmd_llm_bench,
    "llm status":       cmd_llm_status,
    "llm install":      cmd_llm_install,
    "llm pull":         cmd_llm_pull,
    "llm serve":        cmd_llm_serve,
}

def main(argv: list[str]) -> None:
    global HUB
    # A CLI that pipes into head/tail must die by SIGPIPE like every other
    # Unix tool, not print a BrokenPipeError traceback (`blnq keys | head`
    # did exactly that before this line). Windows has no SIGPIPE.
    if hasattr(signal, "SIGPIPE"):
        try:
            signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        except (OSError, ValueError):
            pass
    if argv and argv[0] == "_agent":
        from threading import Event
        cmd_agent(Event()); return

    # Healthcheck: must run BEFORE the smart-default chat fallback (otherwise
    # "healthcheck" would be sent to the LLM as a chat message).
    if argv and argv[0] == "--healthcheck":
        payload = {"ok": True, "version": VERSION, "hub": HUB, "ts": int(time.time())}
        try:
            st = read_state() or {}
            if isinstance(st, dict) and st.get("node_id"):
                payload["node_id"] = st["node_id"]
        except Exception: pass
        print(json.dumps(payload))
        sys.exit(0)

    if argv and argv[0] == "--version":
        print(VERSION); sys.exit(0)

    if not argv or argv[0] in ("-h", "--help"):
        _print_root_help(); return

    # `blnq help <cmd>` — the same request as `blnq <cmd> help` and
    # `blnq <cmd> --help`. "help" used to be lumped in with -h/--help, so
    # `blnq help catalog` printed the ROOT list and silently dropped the
    # command the user had actually asked about.
    if argv[0] == "help":
        if len(argv) > 1:
            _print_sub_help(" ".join(argv[1:]))
            return
        _print_root_help(); return

    # Opt-in self-update, before dispatch (never for _agent/healthcheck/help).
    _maybe_auto_update(argv)

    # resolve dotted subcommands: "graph stats", "scripts list", etc.
    cmd_parts = [argv[0]]
    rest = argv[1:]
    if argv[0] in ("graph", "scripts", "workers", "jobs", "llm", "catalog") and rest and not rest[0].startswith("-") and rest[0] != "help":
        cmd_parts.append(rest[0]); rest = rest[1:]
    # `workers` alone → alias for `workers list`
    if cmd_parts == ["workers"]:
        cmd_parts = ["workers", "list"]
    # `blnq <cmd> help` — the third spelling of the same request. Accept it for
    # every command, including nested ones (`blnq graph stats help`). Without
    # this, argparse saw a positional named "help" and died with
    # "invalid choice: 'help'".
    if rest and rest[0] == "help":
        _print_sub_help(" ".join(cmd_parts))
        return
    # `upgrade` is a friendlier alias for `update`. Without this, `blnq upgrade`
    # would fall through to the smart-default file detector and die with
    # "unknown subcommand or file not found".
    if cmd_parts == ["upgrade"]:
        cmd_parts = ["update"]
        argv[0] = "update"
    # `report` → `suggest`: same request, different word (house rule — an
    # unknown command is a worse failure than a redundant one).
    if cmd_parts == ["report"]:
        cmd_parts = ["suggest"]
        argv[0] = "suggest"
    cmd_name = " ".join(cmd_parts)

    # Smart default: if argv[0] doesn't match a known subcommand AND it's a path
    # to an existing file, upload + run it remotely. So:
    #   blnq runme.py
    #   blnq ./scripts/hello.js arg1 arg2
    # become remote code executions.
    if cmd_name not in COMMANDS or COMMANDS[cmd_name] is None:
        # strip known flags from anywhere in argv (lets the user put them
        # before or after the file)
        global VERBOSE, _ALLOW_SECRETS
        no_scan = False
        clean_argv = []
        i = 0
        while i < len(argv):
            a = argv[i]; i += 1
            if a == "--no-scan":
                no_scan = True
            elif a in ("--verbose", "--detailed", "-v"):
                VERBOSE = True
            elif a == "--allow-secrets":
                # The gate's documented escape hatch. It existed as an env var
                # (BLNQ_ALLOW_SECRETS=1) and in its own error text — but never
                # as a flag, so the advice was unrunnable (audit 2026-11-18).
                _ALLOW_SECRETS = True
            elif a == "--secret" or a.startswith("--secret="):
                if a.startswith("--secret="):
                    kv = a.split("=", 1)[1]
                else:
                    kv = argv[i] if i < len(argv) else None
                    i += 1
                if not kv or "=" not in kv:
                    die("--secret needs KEY=VALUE")
                # Loud beats silent: `blnq FILE.py` runs on the hub executor,
                # which has no secrets channel — the old behaviour dropped the
                # value without a word.
                die("--secret only reaches jobs that run on volunteer nodes "
                    "(blnq FILE.py runs on the hub executor, which does not\n"
                    f"    accept secrets yet). Use: {APP} jobs submit "
                    f"--secret {kv} … (needs {APP} login)",
                    code=2)
            else:
                clean_argv.append(a)
        if not clean_argv:
            die(f"unknown flag: {argv[0]} — try `{APP} --help`")
        if clean_argv[0].startswith("-"):
            die(f"unknown flag: {clean_argv[0]} — try `{APP} --help`")
        path = Path(clean_argv[0])
        if path.exists() and path.is_file():
            file_args = clean_argv[1:]
            if not no_scan:
                findings = _security_scan_file(path)
                # Quiet by default, but NEVER hide a finding: if the scan
                # found something, that is the script's problem to know about.
                if VERBOSE or any(f["severity"] in ("CRITICAL", "WARN")
                                  for f in findings):
                    _print_security_findings(path, findings)
                if any(f["severity"] == "CRITICAL" for f in findings):
                    die(f"refusing to upload {path.name}: critical security finding(s). "
                        f"fix the issues or pass --no-scan to override.", code=3)
            cmd_run_file(None, path, file_args)
            return
        die(f"unknown subcommand or file not found: {argv[0]} — try `{APP} --help`")

    # per-cmd --help
    if rest and rest[0] in ("-h", "--help"):
        _print_sub_help(cmd_name); return

    # `llm help` (and `llm` with no subcommand) should show the parent group's
    # own help — not be parsed as a subcommand choice.
    if cmd_name == "llm" and (len(argv) == 1 or argv[1] == "help"):
        cmd_llm_help(None)
        return

    # build_args: parse just the trailing flags through the right subparser
    parser = build_parser()
    sub_actions = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    parsed = None
    for sa in sub_actions:
        if cmd_parts[0] in sa.choices:
            sub = sa.choices[cmd_parts[0]]
            # has a nested subparsers? descend
            inner_actions = [a for a in sub._actions if isinstance(a, argparse._SubParsersAction)]
            if len(cmd_parts) > 1 and inner_actions:
                for ia in inner_actions:
                    if cmd_parts[1] in ia.choices:
                        parsed = ia.choices[cmd_parts[1]].parse_args(rest)
                        break
                if parsed is None:
                    parsed = sub.parse_args(rest)
            else:
                parsed = sub.parse_args(rest)
            break
    if parsed is None:
        parsed = argparse.Namespace(hub=None)
    if getattr(parsed, "hub", None): HUB = parsed.hub
    COMMANDS[cmd_name](parsed)


def _print_root_help() -> None:
    print(f"""\033[1m{APP}\033[0m — bLNQ.org client CLI / local agent
hub = {HUB}   version = {VERSION}

\033[1mOperator / local subcommands:\033[0m
  start              start the local blnq agent (background, heartbeats to hub)
  stop               stop the local blnq agent
  restart            stop + start
  status             pid, uptime, last heartbeat, last error
  logs [N] [-f]      tail ~/.local/share/blnq/agent.log (last N lines; -f to follow)
  free               host memory + swap + disk + per-process RSS
  tasks [kill ID]    in-flight local jobs — id, tier, elapsed (+ operator kill)
  auth …             local authorization: who may run what HERE (order-free:
                       `auth yalla all` · `auth x maybe` · `auth default deny`
                       · `auth who` · `auth logs` · `auth show yalla`)
  network on|off     may this node run jobs that ask for egress
  pct [--watch=N]    live CPU%/MEM% line (refreshes every N seconds)
  info               hub URL, version, install paths, hub_stats
  update             pull the latest blnq-cli.py from {HUB_NAME}
  changelog          what changed and why (also printed by `update`)
  upgrade            alias for `update`
  uninstall [--purge]
              stop the agent, disarm keepalive/autostart, remove the code —
              keeps config, keys, logs + auth history (reinstall finds your
              identity); --purge removes those too (keys unrecoverable)
  volunteer [on|off] opt in/out of running other people's jobs on your box
  keepalive [on|off] systemd timer: respawn the agent after reboot/crash (+auto-update)
  autostart [on|off] start the agent on boot/login — systemd, or no-root fallbacks
  --help, help       list every subcommand

\033[1mOne-shot subcommands (talk to {HUB_NAME}):\033[0m
  health             GET /api/stats (cheap liveness check)
  whoami             logged-in account + credits (falls back to hub liveness)
  workers list       GET /api/workers/list
  graph              GET /api/graph
  graph stats        GET /api/graph/stats
  graph search Q     GET /api/graph/search?q=Q
  graph timeline     GET /api/graph/timeline
  scripts list       GET /api/scripts
  catalog            GET /api/catalog — what the network runs (most-run first)
  catalog search Q   GET /api/catalog?q=Q   typo-tolerant, sort=relevance
  catalog categories GET /api/catalog/categories
  catalog show SUBJ  GET /api/catalog/:subject — source, sha256-verified
                      --json                machine-readable
  scripts get ID     GET /api/scripts/:id
  jobs list          GET /api/jobs/list — the collective queue
  jobs submit SCR    queue an approved script on volunteer machines
                      [--stdin=X] [--timeout=SEC] [--secret KEY=VALUE ...]
  jobs status ID     job metadata + status
   watch ID           live output stream (SSE) — job_xxx or a run id
   credits            your compute-credit balance (needs login)
   love SCR_ID        ❤ a script (author earns credits) — [--undo] to remove
   loveboard          most-loved scripts + authors (also: leaderboard)
   artifact ID [-o]   download a finished job's produced files (owner only)
  login              prompt for /api/auth/login, save session cookie
  duh [FILE]         is it dumb to run this remotely? (offline pre-upload check)
  about              who runs this, the mission, and how to reach us
  check FILE         analyse a file BEFORE submitting (local scan + remote trust)
  list [N]            table of what has run: who, what, where, when  (alias: runs)
  who                 machines and validators available right now
  details [RUN_ID]   everything about the last run  (alias: last)
  scan FILE          local security scan: secrets + dangerous stdlib calls
                      --min-severity [info|warn|critical]
                      --json                emit findings as JSON
  evaluate [PATH]    study a codebase: where can blnq run it? (default: .)
                      --json                machine-readable report
                      --limit N             max files to scan (default 3000)

\033[1mLocal LLM helper (talks to your own box, not the hub):\033[0m
  llm                show llm subcommands
  llm detect         find ollama, llama.cpp, lm-studio, vllm on this box
  llm suggest        recommend a model for this hardware (CPU/RAM/GPU)
  llm bench          quick CPU / RAM / disk benchmark
  llm status         detect + bench + suggest in one shot
  llm install [--docker]   print install commands for the detected OS
  llm pull <model>         ollama pull <model>
  llm serve [model] [--port]   ollama serve in the foreground

\033[1mExamples:\033[0m
  blnq whoami
  blnq review hello.py                   # scan + collect validator signatures
  blnq graph search 'climate change'
  blnq scan hello.py                # just scan, don't upload
  blnq hello.py                     # smart default: scan + upload + run remote (refused if critical)
  blnq hello.py --no-scan           # smart default: skip the scan
  blnq verify hello.py                   # check signatures locally (exit 0 = valid + quorum)
  blnq llm detect
  blnq llm suggest
  blnq llm install --docker
  blnq start
  blnq status
  blnq pct
  blnq update

Tip: every subcommand accepts --help (e.g. `blnq graph search --help`).
Tip: a positional path to an existing file auto-uploads + runs remotely.
""")


def _print_sub_help(cmd: str) -> None:
    table = {
        "start":     "start the local blnq agent (background)",
        "autostart": "start the agent automatically at boot or login\n"
                     "  usage: blnq autostart [on|off|status] [--tier TIER]\n"
                     "  picks the best mechanism this box allows, in order:\n"
                     "    systemd-system  survives logout, needs sudo\n"
                     "    systemd-user    starts at your login, no root\n"
                     "    xdg             GNOME/KDE/XFCE/MATE at login, no root\n"
                     "    profile         guarded ~/.profile line, works on bare SSH\n"
                     "  every tier runs the same `keepalive run`: no-op if already up,\n"
                     "  self-update first, then spawn — four installers, one behaviour.\n"
                     "  `status` shows which tiers are in place; `off` removes them all.",
        "stop":      "stop EVERYTHING (agent + jobs + respawn) — resumes with blnq start",
        "restart":   "restart everything (agent + jobs)",
        "security":  "security posture: jail, permissions, network view (exit 1 = FAIL)",
        "install":   "install a jail (sandbox/docker) so volunteer mode can run",
        "docker":    "install/check the docker runtime (= blnq install docker)",
        "nodes":     "who's out there — the network's nodes at a glance",
        "suggest":   "send a suggestion/report to the hub (alias: report)",
        "emergency": "big red button: volunteer off + disable respawn + stop the agent",
        "emergancy": "alias for emergency",
        "restart":   "stop + start",
        "status":    "pid, uptime, last heartbeat, last error, hub_stats",
        "info":      "hub URL, version, install paths, hub_stats",
        "logs":      "tail ~/.local/share/blnq/agent.log\n  args: [N=50] [-f|--follow]",
        "free":      "host memory + swap + disk + per-process RSS",
        "pct":       "live CPU%/MEM% (refreshes every N seconds)\n  flag: --watch=N (default 1; 0 = print once)",
        "update":    "pull latest blnq-cli.py from blnq.org\n  alias: upgrade\n"
                     "  prints the changelog for every version you just crossed, with\n"
                     "  the reason for each change — so an update explains itself.",
        "changelog": "what changed and why — newest first\n"
                     "  usage: blnq changelog [--since VER] [--limit N] [--json]\n"
                     "  the same entries `blnq update` prints after a successful upgrade;\n"
                     "  source: /changelog.json on the hub.",
        "upgrade":   "alias for `update`",
        "uninstall": "stop the agent + disarm keepalive/autostart + remove the code\n"
        "  keeps config, keys, logs and auth history (a reinstall finds your identity)\n"
        "  `uninstall --purge` removes those too — private keys are UNRECOVERABLE",
        "health":    "GET /api/stats",
        "whoami":    "GET /api/stats (cheap liveness check)",
        "metrics":   "GET /api/stats (hub stats)\n  flag: --local   print this bee's local CPU/GPU/MEM/DISK snapshot",
        "doctor":    "one-glance health report (install + hub + agent + bee + version)\n  output is pasteable for support",
        "speed":     "latency benchmark (DNS, TCP, hub ping x3, CPU/RAM/disk)",
        "test":      "doctor + speed + tiny run end-to-end smoke test",
        "tasks":     "in-flight local jobs; `tasks kill <job_id>` = operator stop",
        "auth":      "local authorization — who may run what on THIS machine\n"
        "  order-free: blnq auth [who|show|logs|default] [identity…] "
        "[allow|maybe|deny] [all|run|network|secrets]\n"
        "  e.g. blnq auth yalla all · blnq auth smokster maybe · "
        "blnq auth default deny · blnq auth logs 50 · blnq auth show yalla",
        "authorize": "alias of `auth`",
        "network":   "egress permission for jobs on this node\n"
        "  blnq network on|off|status — jobs requesting the network are "
        "refused with a reason when off",
        "volunteer": "opt in/out of running other people's jobs on your bee\n  usage: blnq volunteer [on|off|status]   (default: status)",
        "panic":     "emergency help — diagnostics + how to report a bug",
        "help-bang": "alias for `panic` (the name `help!` is reserved by bash history expansion)",
        "hi":        "friendly greeter + first-run examples (no chat — blnq runs code, doesn't talk)",
        "support":   "gather full context (doctor + last 10 log lines + bee metrics)\n  usage: blnq support    (prints paste-ready bundle + blnq-specific FAQ)",
        "workers list": "GET /api/workers/list",
        "graph":     "GET /api/graph",
        "graph stats": "GET /api/graph/stats",
        "graph search": "GET /api/graph/search?q=Q\n  usage: blnq graph search 'climate change'",
        "graph timeline": "GET /api/graph/timeline",
        "scripts list": "GET /api/scripts",
        "scripts love": "POST /api/scripts/:id/love (toggle) — author earns credits\n  usage: blnq scripts love scr_xxxxx",
        "scripts leaderboard": "GET /api/scripts/leaderboard/love — most-loved scripts + authors",
        "love":        "POST /api/scripts/:id/love (toggle)\n  usage: blnq love scr_xxxxx",
        "loveboard":   "GET /api/scripts/leaderboard/love",
        "scripts get": "GET /api/scripts/:id\n  usage: blnq scripts get <id>",
        "login":     "prompt for /api/auth/login, save session cookie",
        "check":    "analyse a file BEFORE submitting it — local + remote\n"
                     "  usage: blnq check <file.py> [--argv ...] [--json]\n"
                     "  local (offline, instant): parses? size, I/O shape, deps, loop\n"
                     "    depth, sha256 of what WOULD be signed, security findings and\n"
                     "    privacy hits (credentials + personal data).\n"
                     "  remote (one call): is this exact hash already signed by a quorum?\n"
                     "    what did a run cost last time — and is it dumb to run remotely?\n"
                     "  exits 3 if the sandbox could not run it (no network, no db, third-\n"
                     "    party imports) or if a credential is present in the source.",
        "list":     "table of what has run: who, what, where, when\n"
                     "  usage: blnq list [N] [--json]      aliases: blnq runs, blnq history\n"
                     "  shows run id, timestamp, language, status, execution time, who\n"
                     "  submitted it and which script — the overview before drilling in\n"
                     "  with `blnq details <run-id>`.",
        "debug":    "explain an error — or diagnose this machine\n"
                     "  usage: blnq debug \"paste the error\"   (no arg = local diagnosis)\n"
                     "  matches against a local knowledge base (523 origin down, 401 not\n"
                     "  logged in, 403 safety gate, 409 key conflict, sha256 mismatch,\n"
                     "  bwrap fallback, no volunteering machine, timeouts, EADDRINUSE…)\n"
                     "  and prints what it means plus the exact command to fix it.\n"
                     "  offline — no hub needed. alias: blnq why",
        "bugs":     "what is broken — known issues + this machine's failures\n"
                     "  usage: blnq bugs [--json]      alias: blnq issues\n"
                     "  two sources: /known-issues.json published by the hub (so the\n"
                     "  site and the CLI agree), and a tally of failures in your own last\n"
                     "  300 agent-log lines, ranked by how often they recur.",
        "peers":    "who else is on this LAN, without asking the internet\n"
                     "  usage: blnq peers [--json]\n"
                     "  UDP broadcast on port {dport} — announces hostname + p2p port only,\n"
                     "  never a key or a job. Shows the local view beside what the hub\n"
                     "  knows, so a node the hub cannot see is obvious.\n".format(dport=DISCOVERY_PORT),
        "who":      "machines and validators available right now\n"
                     "  usage: blnq who [--json]\n"
                     "  two halves: machines that can RUN your code (online / volunteering /\n"
                     "  load / capabilities) and validators that SIGN what code does\n"
                     "  (principal, role, fingerprint, active). Pairs with `blnq list`.",
        "details":  "everything about the last run, or one run-id\n"
                     "  usage: blnq details [RUN_ID] [--json]     alias: blnq last\n"
                     "  what ran, the timing breakdown (safety review / queue / execution /\n"
                     "  total), WHERE it executed (hub container, sandbox limits) and the\n"
                     "  quorum that authorised it — with each signer named.",
        "about":    "who runs this, the mission, and how to reach a human\n"
                     "  usage: blnq about [--json]\n"
                     "  the mission, the contact details, and where the docs live.\n"
                     "  text is the fast path — email works, it is just old school.\n"
                     "  alias: blnq contact",
        "duh":      "is it dumb to run this remotely? — the pre-upload check\n"
                     "  usage: blnq duh [FILE] [--argv ...] [--json]\n"
                     "  static analysis, fully offline: size, I/O shape, imports and\n"
                     "  loop depth go to /api/run/duh, which compares the remote cost\n"
                     "  (safety review + queue + exec + ping) against a local estimate.\n"
                     "  exits 3 if the sandbox cannot run it at all (no network, no db,\n"
                     "  third-party imports) — those fail remotely exactly as they fail\n"
                     "  here, so the round trip buys nothing.",
        "scan":     "local security scan: secrets + dangerous stdlib calls\n  usage: blnq scan <file> [--min-severity info|warn|critical] [--json]\n  the smart default `blnq FILE` runs this scan automatically and refuses to\n  upload if it finds anything CRITICAL; pass --no-scan to bypass.",
        "keys":     "list/inspect this machine's Ed25519 principal keys (trust layer)\n"
        "  usage: blnq keys            (inventory: every key on this box)\n"
        "         blnq keys <role>     (public key, principal id, fingerprint,\n"
        "                                REAL file perms, backup digest, hub state)\n"
        "         blnq keys <role> --register   publish so others can verify you\n"
        "  the private key's bytes are NEVER printed by any mode — only its path,\n"
        "  permissions and a file digest for matching backups",
        "verify":   "verify signed attestations + validator quorum\n  usage: blnq verify <file> | --subject <64hex> | --script <scr_id> | --attestation <att_id>\n  signatures are checked LOCALLY with the issuer's public key — the hub's own\n  \"verified\" claim is never taken on trust. exit 0 only if all valid AND quorum met.",
        "dm":       "send an end-to-end encrypted message to another principal\n"
                     "  usage: blnq dm <hivv_…> <message…> [--file F] [--role requester|runner]\n"
                     "  the hub stores CIPHERTEXT only — it cannot read the body, re-address it\n"
                     "  (AAD), forge one (Ed25519) or replay one (nonce).",
        "p2p":      "diagnose the direct (UDP) transport and show this machine's P2P identity\n"
                     "  usage: blnq p2p [status|doctor] [--role requester|runner]\n"
                     "  doctor round-trips a datagram to the hub's rendezvous to prove the UDP\n"
                     "  path works; if it fails, traffic falls back to the E2E relay.",
        "inbox":    "receive + decrypt P2P messages\n"
                     "  usage: blnq inbox [--wait N] [--json] [--role requester|runner]\n"
                     "  long-polls the relay, decrypts locally, then ACKs so the hub can drop it.\n"
                     "  a message that will not decrypt is reported and NOT acked.",
        "approve":  "file a signed HUMAN 'safe' verdict on a file\n"
                     "  usage: blnq approve <file> [--note \"why\"]   aliases: vouch, endorse\n"
                     "  needs `blnq login` — a validator vote gates execution for everyone,\n"
                     "  so it is bound to an account rather than to a fresh keypair.\n"
                     "  your Ed25519 key signs the verdict, so it cannot be forged or\n"
                     "  attributed to anyone else afterwards. counts toward quorum.\n"
                     "  cannot override an objection — the hub fails closed on those.",
        "reject":   "file a signed human objection — a veto on that source\n"
                     "  usage: blnq reject <file> [--note \"why\"]     alias: object\n"
                     "  ONE objection blocks that exact sha256 permanently: run.js fails\n"
                     "  closed on any objection, so an approve cannot unblock it. use it\n"
                     "  when you have actually read the code and it should not run.",
        "review":   "multi-validator signed safety scan of a local file\n  usage: blnq review <file> [--description text]\n  submits the file as a script (needs `blnq login`) and asks every configured\n  validator (local llama, hivv chat, hivv scan) to sign a verdict + plain-English\n  description. quorum = DISTINCT validators that said safe.",
        "evaluate": "study a codebase — which files can blnq run today, and what blocks the rest\n"
                     "  usage: blnq evaluate [PATH] [--json] [--limit N]     (PATH defaults to .)\n"
                     "  static analysis only, nothing is executed: each file is classified ready or\n"
                     "  blocked with a reason (deps / network / database / package / ui), plus the\n"
                     "  exact `blnq <file>` command for the ones that are ready to run.",
        "catalog":  "what the network actually runs — categorised, searchable, code-only\n"
                     "  usage: blnq catalog [list] [--limit N] [--category C] [--sort S] [--json]\n"
                     "  sorts: runs (default) | recent | name | category | relevance\n"
                     "  the catalog holds SOURCE and counters and never stdin/stdout — the data a\n"
                     "  script ran on stays private. every row is keyed by sha256 of its own code.",
        "catalog list": "most-run first — the default view of `blnq catalog`\n"
                     "  flag: --sort runs|recent|name|category   --category <name>   --json",
        "catalog search": "search by word — typo-tolerant (trigram + full-text)\n"
                     "  usage: blnq catalog search <words> [--category C] [--sort relevance] [--json]\n"
                     "  try a deliberate typo: `blnq catalog search wordfrq` still finds wordfreq.py",
        "catalog categories": "counts per category — browse what kinds of script run here\n"
                     "  usage: blnq catalog categories [--json]",
        "catalog show": "one entry WITH its source, verified in your terminal\n"
                     "  usage: blnq catalog show <64-hex-subject> [--json]\n"
                     "  re-hashes the code locally so sha256(code) must equal the subject — altered\n"
                     "  source is visible without trusting the hub. exits 3 on mismatch.",
        "help":      "help for a command. all three spellings do the same thing:\n"
                     "  blnq help <cmd>   blnq <cmd> help   blnq <cmd> --help\n"
                     "  blnq help         (or blnq --help) lists every command",
        "llm":       "local AI runtime helper (ollama, llama.cpp, ...)\n  subcommands: detect, suggest, bench, status, install, pull, serve\n  usage: blnq llm <sub> [--flag]",
        "llm detect":  "scan this box for ollama / llama.cpp / lm-studio / vllm",
        "llm suggest": "recommend a model for this hardware (CPU/RAM/GPU)\n  flag: --json   emit machine-readable JSON",
        "llm bench":   "quick CPU sha256 + memory + disk benchmark",
        "llm status":  "detect + bench + suggest in one shot",
        "llm install": "print install commands for the detected OS\n  flag: --docker   print the `docker run` for ollama\n  flag: --auto     actually run the install (instead of just printing)\n  flag: --model=X  after install, run `ollama pull X`",
        "llm pull":    "ollama pull <model>\n  usage: blnq llm pull qwen3:1.7b",
        "llm serve":   "ollama serve in the foreground\n  args: [model]   preload a model on startup\n  flag: --port=N  listen on port N (default 11434)",
    }
    desc = table.get(cmd, "(no help yet)")
    print(f"{APP} {cmd} — {desc}")


if __name__ == "__main__":
    main(sys.argv[1:])
