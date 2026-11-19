#!/usr/bin/env python3
"""tests/test_job_runner.py — end-to-end checks for the CLI job runner
(claim → sandboxed run → stream output → complete) against a fake hub.

Run:  python3 tests/test_job_runner.py
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

_TMP = tempfile.mkdtemp(prefix="blnq-test-runner-")
os.environ["BLNQ_STATE_DIR"]  = os.path.join(_TMP, "state")
os.environ["BLNQ_CONFIG_DIR"] = os.path.join(_TMP, "config")
os.environ["BLNQ_INSTALL_DIR"] = os.path.join(_TMP, "install")

# ── fake hub (must exist before CLI import so BLNQ_HUB can point at it) ──
APP = {"complete": [], "output": [], "start": [], "heartbeat": []}

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_a): pass

    def _reply(self, obj):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try: body = json.loads(raw or b"{}")
        except json.JSONDecodeError: body = {}
        p = self.path
        if p.endswith("/start"):      APP["start"].append(body);      return self._reply({"ok": True})
        if p.endswith("/heartbeat"):  APP["heartbeat"].append(body);  return self._reply({"ok": True})
        if p.endswith("/output"):     APP["output"].append(body);     return self._reply({"ok": True})
        if p.endswith("/complete"):   APP["complete"].append(body);   return self._reply({"ok": True})
        return self._reply({"ok": True})

_SRV = HTTPServer(("127.0.0.1", 0), _Handler)
_PORT = _SRV.server_address[1]
threading.Thread(target=_SRV.serve_forever, daemon=True).start()
os.environ["BLNQ_HUB"] = f"http://127.0.0.1:{_PORT}"

# ── import the CLI as a module ───────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("blnq_cli", os.path.join(_HERE, "..", "blnq-cli.py"))
blnq = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(blnq)

FAILS = 0
def check(name, cond, extra=""):
    global FAILS
    if cond:
        print(f"  ✓ {name}")
    else:
        FAILS += 1
        print(f"  ✗ {name}  {extra}")

def _run(job, timeout_wall=25):
    APP["complete"].clear(); APP["output"].clear(); APP["start"].clear()
    logf = open(os.devnull, "a")
    t0 = time.time()
    th = threading.Thread(target=blnq.run_job, args=("worker_test", job, logf))
    th.start(); th.join(timeout=timeout_wall)
    assert not th.is_alive(), "run_job hung past wall-clock limit"
    return time.time() - t0

# ── cases ─────────────────────────────────────────────────────────────────
def test_languages():
    langs = blnq._available_languages()
    check("_available_languages always includes python", "python" in langs, str(langs))

def test_job_command_unknown_lang():
    d = tempfile.mkdtemp()
    argv, comp = blnq._job_command("cobol", "x", "print(1)", __import__("pathlib").Path(d))
    check("unknown language → no argv", argv is None and comp is None)

def test_success():
    dt = _run({"job_id": "job_ok", "language": "python", "script_name": "hello.py",
               "script_content": "print('hi from job')", "timeout_seconds": 15})
    c = APP["complete"][-1] if APP["complete"] else {}
    out = "".join(o.get("line", "") for o in APP["output"])
    check("success status reported", c.get("status") == "success", json.dumps(c)[:150])
    check("stdout streamed back", "hi from job" in out, out[:150])
    check("exit code 0", c.get("exit_code") == 0)
    check("/start was called", len(APP["start"]) == 1)
    check("wall time sane", dt < 12, f"{dt:.1f}s")

def test_stdin():
    _run({"job_id": "job_in", "language": "python", "script_name": "cat.py",
          "script_content": "import sys\nprint(sys.stdin.read().strip().upper())",
          "stdin_data": "hello stdin", "timeout_seconds": 15})
    out = "".join(o.get("line", "") for o in APP["output"])
    check("stdin reaches the job", "HELLO STDIN" in out, out[:150])

def test_timeout():
    t0 = time.time()
    _run({"job_id": "job_to", "language": "python", "script_name": "slow.py",
          "script_content": "import time\nprint('before')\ntime.sleep(60)\nprint('never')",
          "timeout_seconds": 2}, timeout_wall=20)
    dt = time.time() - t0
    c = APP["complete"][-1] if APP["complete"] else {}
    out = "".join(o.get("line", "") for o in APP["output"])
    check("timeout status reported", c.get("status") == "timeout", json.dumps(c)[:150])
    check("output before timeout preserved", "before" in out, out[:150])
    check("killed promptly (not 60s)", dt < 15, f"{dt:.1f}s")

def test_failure_exit_code():
    _run({"job_id": "job_rc", "language": "python", "script_name": "rc.py",
          "script_content": "import sys\nsys.exit(3)", "timeout_seconds": 15})
    c = APP["complete"][-1] if APP["complete"] else {}
    check("failed status + rc=3", c.get("status") == "failed" and c.get("exit_code") == 3,
          json.dumps(c)[:150])

def test_missing_toolchain():
    _run({"job_id": "job_c89", "language": "rust", "script_name": "x.rs",
          "script_content": "fn main(){}", "timeout_seconds": 5})
    c = APP["complete"][-1] if APP["complete"] else {}
    check("unsupported lang → failed w/ toolchain note",
          c.get("status") == "failed" and "toolchain" in (c.get("error") or ""),
          json.dumps(c)[:160])

def test_clean_env():
    env = blnq._clean_env()
    check("PATH kept", "PATH" in env)
    check("secrets stripped", not any(k.upper().startswith(("AWS_", "API_", "TOKEN", "SECRET"))
                                      for k in env), str(list(env)))

def test_signed_headers_shape():
    h = blnq._signed_headers("POST", "/api/jobs/claim", b"{}", "t" * 64)
    check("signature headers present",
          all(k in h for k in ("X-Auth-Timestamp", "X-Auth-Nonce", "X-Auth-Signature")))
    check("sig is 64 hex chars", len(h["X-Auth-Signature"]) == 64)

def test_redaction():
    vals = ["super-secret-1", "ab"]
    out = blnq._redact_secrets("key=super-secret-1 short ab end", vals)
    check("long secret redacted", "super-secret-1" not in out and "***REDACTED***" in out)
    check("tiny values (<4 chars) untouched (avoid over-redaction)", " ab " in out, out)

def test_tier_selection():
    tiers = ("bwrap", "docker", "subprocess")
    check("explicit subprocess honored", blnq._pick_sandbox("subprocess", "python", False) == "subprocess")
    check("auto returns a known tier", blnq._pick_sandbox("auto", "python", False) in tiers)
    check("compile jobs never pick docker tier",
          blnq._pick_sandbox("docker", "cpp", True) in ("bwrap", "subprocess"))

def test_collect_artifacts():
    import pathlib
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "main.py").write_text("x")
    (d / "a.out").write_text("bin")
    (d / "out.txt").write_text("artifact-data")
    (d / "sub").mkdir()
    (d / "sub" / "deep.json").write_text("{}")
    blob = blnq._collect_artifacts(d, {"main.py", "a.out"}, 1024 * 1024)
    check("artifacts produce a gzip tar", blob is not None and blob[:2] == b"\x1f\x8b")
    import io, tarfile
    names = tarfile.open(fileobj=io.BytesIO(blob)).getnames()
    check("job outputs included, sources excluded",
          "out.txt" in names and "sub/deep.json" in names
          and "main.py" not in names and "a.out" not in names, str(names))
    only_excluded = pathlib.Path(tempfile.mkdtemp())
    (only_excluded / "main.py").write_text("x")
    check("nothing new → no upload", blnq._collect_artifacts(only_excluded, {"main.py"}, 1024) is None)
    big = pathlib.Path(tempfile.mkdtemp())
    (big / "huge.bin").write_bytes(b"0" * 5000)
    check("over-cap → None", blnq._collect_artifacts(big, set(), 1024) is None)

def test_sandbox_bootstrap_fallback():
    """A jail that dies instantly (userns EAGAIN, daemon down) must NOT stream
    its bootstrap error — the job must transparently re-run on the subprocess
    tier and succeed."""
    orig_works, orig_wrap = blnq._bwrap_works, blnq._bwrap_wrap
    blnq._bwrap_works = lambda: True
    # *a: _bwrap_wrap now takes (argv, jobdir, lang) — the monkeypatch must
    # accept the real call signature while still producing the bootstrap error.
    blnq._bwrap_wrap = lambda argv, jobdir, *a, **k: [
        sys.executable, "-c",
        "import sys; sys.stderr.write('bwrap: Creating new namespace failed: "
        "Resource temporarily unavailable\\n'); sys.exit(1)"]
    os.makedirs(blnq.CONFIG_DIR, exist_ok=True)
    blnq._VOLUNTEER_FILE.write_text('{"share_cpu": true, "sandbox": "bwrap", "max_mem_mb": 256}')
    try:
        _run({"job_id": "job_fb", "language": "python", "script_name": "f.py",
              "script_content": "print('fell-back-ok')", "timeout_seconds": 15})
        c = APP["complete"][-1] if APP["complete"] else {}
        out = "".join(o.get("line", "") for o in APP["output"])
        check("broken jail fell back → success",
              c.get("status") == "success" and "fell-back-ok" in out,
              json.dumps(c)[:120] + " OUT=" + out[:120])
        check("bootstrap error never streamed to hub", "bwrap:" not in out and "namespace" not in out,
              out[:150])
    finally:
        blnq._bwrap_works, blnq._bwrap_wrap = orig_works, orig_wrap
        if blnq._VOLUNTEER_FILE.exists():
            blnq._VOLUNTEER_FILE.write_text('{"share_cpu": true}')

if __name__ == "__main__":
    print("blnq job-runner tests")
    test_languages()
    test_job_command_unknown_lang()
    test_success()
    test_stdin()
    test_timeout()
    test_failure_exit_code()
    test_missing_toolchain()
    test_clean_env()
    test_signed_headers_shape()
    test_redaction()
    test_tier_selection()
    test_collect_artifacts()
    test_sandbox_bootstrap_fallback()
    print("ALL PASS" if FAILS == 0 else f"{FAILS} FAILED")
    raise SystemExit(1 if FAILS else 0)
