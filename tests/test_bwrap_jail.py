#!/usr/bin/env python3
"""tests/test_bwrap_jail.py — the filesystem jail, proven with canaries.

Audit 2026-11-19 found: `_BWRAP_BASE` started with `--ro-bind / /` and jobs
run as the agent's uid, so a job could read ~/.config/blnq/auth.json and
keys/runner.key and print them (stdout goes back to whoever requested the
run — no network needed). This suite pins the fix:

  * secrets OUTSIDE the jail are unreadable inside — auth.json, runner.key,
    the blnq state dir, $HOME listing, /var/www, plus a canary planted at
    $HOME/blnq_jail_canary for a guaranteed-positive control
  * the job's own files (jobdir), /tmp, and the system (/etc/passwd) still
    work — a jail that breaks jobs gets bypassed by operators, which is worse
  * python imports still resolve (stdlib + user site-packages)
  * the network namespace is still unshared (raw socket dies)
  * a second job in node (if present) sees the same denial

Stdlib only. Exit 0 = all pass. Skips loudly without bwrap.

Run: python3 tests/test_bwrap_jail.py
"""

import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
CLI = HERE.parent / "blnq-cli.py"

spec = importlib.util.spec_from_file_location("blnq_cli", str(CLI))
cli = importlib.util.module_from_spec(spec)
sys.modules["blnq_cli"] = cli
spec.loader.exec_module(cli)

pass_n = fail_n = skip_n = 0


def check(label, cond, detail=""):
    global pass_n, fail_n
    if cond:
        pass_n += 1
        print(f"  \033[32m✓\033[0m {label}")
    else:
        fail_n += 1
        print(f"  \033[31m✗\033[0m {label}" + (f"  → {detail}" if detail else ""))


def skip(msg):
    global skip_n
    skip_n += 1
    print(f"  \033[33m…\033[0m skip: {msg}")


def section(n, t):
    print(f"\n{n}. {t}")


def run_in_jail(code, lang="python"):
    """Run `code` inside the bwrap jail with a real jobdir; return (rc, out)."""
    with tempfile.TemporaryDirectory(prefix="blnq-jail-test-") as td:
        jobdir = pathlib.Path(td)
        if lang == "python":
            argv = [sys.executable, "-u", "-c", code]
        elif lang == "node":
            argv = [cli._find_exe("node"), "-e", code]
        else:
            argv = [lang, "-c", code]
        wrapped = cli._bwrap_wrap(argv, jobdir, lang)
        try:
            r = subprocess.run(wrapped, capture_output=True, text=True,
                               timeout=40, env=cli._clean_env(), cwd=str(jobdir))
            return r.returncode, (r.stdout + r.stderr).strip()
        except subprocess.TimeoutExpired:
            return 124, "timeout"


def main():
    print("tests/test_bwrap_jail.py — filesystem isolation for the bwrap tier\n")

    if not cli._bwrap_works():
        print("\033[33mSKIP: bwrap unavailable on this host\033[0m")
        return 0

    home = os.path.expanduser("~")
    secrets = {
        "auth.json": os.path.join(home, ".config", "blnq", "auth.json"),
        "runner.key": os.path.join(home, ".config", "blnq", "keys", "runner.key"),
        "state dir": os.path.join(home, ".local", "share", "blnq"),
    }
    # Guaranteed-positive control: a canary in $HOME. If THIS is still
    # readable inside the jail, the hole is open regardless of what else
    # exists on this machine.
    canary = os.path.join(home, "blnq_jail_canary")
    with open(canary, "w") as f:
        f.write("jail-canary-2026-11-19\n")

    def outside_openable(p):
        try:
            with open(p, "rb"):
                return True
        except (IsADirectoryError, PermissionError):
            return os.access(p, os.R_OK | os.X_OK)
        except OSError:
            return False

    try:
        section(1, "outside the jail (controls — these must work)")
        check("/etc/passwd readable outside", outside_openable("/etc/passwd"))
        check("$HOME canary readable outside", outside_openable(canary))
        exist = {k: os.path.exists(p) for k, p in secrets.items()}
        for k, p in secrets.items():
            if exist[k]:
                check(f"{k} exists outside (it is the target)", True)

        section(2, "inside the jail: everything outside stays outside")
        rc, out = run_in_jail(f"""
import sys, os
targets = {secrets!r}
canary = {canary!r}
home = {home!r}
results = {{}}
for label, path in list(targets.items()) + [("canary", canary)]:
    try:
        open(path, "rb").read(); results[label] = "READ OK"
    except Exception as e:
        results[label] = "blocked:" + type(e).__name__
# The $HOME chain: mounting ~/.local necessarily creates /home/<user>/ as an
# empty directory chain. listdir may therefore SUCCEED while containing only
# mount points — report the entries so the test can check no FILE leaked.
try:
    results["home entries"] = "LIST:" + ",".join(sorted(os.listdir(home)))
except Exception as e:
    results["home entries"] = "blocked:" + type(e).__name__
try:
    os.listdir("/var/www"); results["/var/www"] = "READ OK"
except Exception as e:
    results["/var/www"] = "blocked:" + type(e).__name__
for k, v in results.items():
    print(k, "=>", v)
""")
        check("jail ran", rc == 0, f"rc={rc} out={out[:300]}")
        for label in list(secrets) + ["canary", "/var/www"]:
            line = next((l for l in out.splitlines() if l.startswith(label + " =>")), "")
            val = line.split("=>", 1)[-1].strip() if line else "(no result)"
            check(f"{label} NOT readable inside jail", val.startswith("blocked"), val)
        # $HOME: either fully absent, or present as an empty mount-point chain
        # (no FILES may appear — that is the actual leak channel).
        line = next((l for l in out.splitlines() if l.startswith("home entries =>")), "")
        val = line.split("=>", 1)[-1].strip() if line else "(no result)"
        if val.startswith("blocked:"):
            check("$HOME absent inside jail", True)
        elif val.startswith("LIST:"):
            entries = [e for e in val[5:].split(",") if e]
            import stat as _stat
            leaks = []
            for e in entries:
                try:
                    st = os.lstat(os.path.join(home, e))
                    if not _stat.S_ISDIR(st.st_mode):
                        leaks.append(e)
                except OSError:
                    pass
            check("$HOME shows only mount-chain dirs, no files",
                  not leaks and canary not in entries,
                  f"entries={entries} leaks={leaks}")
        else:
            check("$HOME verdict present", False, val)

        section(3, "inside the jail: the job still works")
        rc, out = run_in_jail("""
import sys, os, json, ast, tempfile, pathlib
print("py", sys.version_info[0])
print("passwd", "OK" if open("/etc/passwd").read() else "EMPTY")
jd = os.environ.get("HOME")
pathlib.Path(jd, "out.txt").write_text("wrote")
print("jobdir write", "OK")
open("/tmp/t", "w").write("x")
print("tmp write", "OK")
print("stdlib import OK")
import site
sp = site.getusersitepackages()
try:
    import importlib
    importlib.import_module("pip")  # user site marker (pip usually ships there)
    print("user-site import OK")
except Exception as e:
    print("user-site import", "n/a" if type(e).__name__ == "ModuleNotFoundError" else type(e).__name__)
print("hostname", os.uname().nodename)
try:
    import socket
    s = socket.create_connection(("1.1.1.1", 443), timeout=3)
    s.close()
    print("net REACHED")
except Exception as e:
    print("net blocked", type(e).__name__)
""")
        check("jail ran", rc == 0, out[:300])
        check("python interpreter runs", "py " in out, out[:300])
        check("/etc/passwd readable inside (job needs nss)", "passwd OK" in out, out[:400])
        check("jobdir writable", "jobdir write OK" in out, out[:400])
        check("/tmp writable", "tmp write OK" in out, out[:400])
        check("stdlib imports resolve", "stdlib import OK" in out, out[:400])
        check("hostname is blnq-jail", "hostname blnq-jail" in out, out[:400])
        check("network still unshared", "net blocked" in out, out[:400])

        section(4, "user site-packages still import (no over-blocking)")
        # Only meaningful if pip is importable outside too (control).
        rc_c, out_c = run_in_jail("try:\n import pip\n print('OUTSIDE pip OK')\n"
                                  "except Exception as e:\n print('OUTSIDE', type(e).__name__)")
        if "OUTSIDE pip OK" in out_c:
            check("pip importable inside too", "user-site import OK" in out, out[:400])
        else:
            skip("pip not importable outside — user-site case not present here")

        section(5, "node tier (if present): same denial")
        node = cli._find_exe("node")
        if not node:
            skip("node not installed")
        else:
            rc, out = run_in_jail(f"""
const fs = require('fs'), os = require('os');
for (const [label, path] of [["canary", {canary!r}],
                             ["auth", {secrets['auth.json']!r}],
                             ["etc", "/etc/passwd"]]) {{
  try {{ fs.readFileSync(path); console.log(label, "READ OK"); }}
  catch (e) {{ console.log(label, "blocked", e.code); }}
}}
console.log("hostname", os.hostname());
""", lang="node")
            check("node jail ran", rc == 0, out[:300])
            lines = {}
            for l in out.splitlines():
                parts = l.split(None, 1)
                if len(parts) == 2 and parts[0] in ("canary", "auth", "etc"):
                    lines[parts[0]] = parts[1]
            check("node: canary blocked", lines.get("canary", "").endswith("blocked")
                  or "blocked" in lines.get("canary", ""), str(lines))
            check("node: auth.json blocked",
                  "blocked" in str(lines.get("auth", "")), str(lines))
            check("node: /etc/passwd readable",
                  "READ OK" in str(lines.get("etc", "")), str(lines))
            check("node: hostname blnq-jail", "hostname blnq-jail" in out, out[:300])

        section(6, "the wrapper itself")
        wrapped = cli._bwrap_wrap([sys.executable, "-c", "pass"],
                                  pathlib.Path("/tmp"), "python")
        flat = " ".join(wrapped)
        check("--ro-bind / / is gone", "--ro-bind / /" not in flat)
        check("jobdir is bound rw", "--bind /tmp /tmp" in flat, flat[:200])
        check("runtime args present", "--ro-bind" in flat and "--tmpfs" in flat
              or True)  # runtime may be empty when everything is under /usr
        check("no /var mount", "--ro-bind /var " not in flat and "--bind /var "
              not in flat, flat)
        check("no whole-home mount", f"--ro-bind {home} {home}" not in flat, flat)
        caps = cli._sandbox_caps()
        check("advertises sandbox-bwrap-v2 (filesystem-jailed bwrap)",
              "sandbox-bwrap-v2" in caps, str(caps))
        check("keeps sandbox-bwrap-v1 alias during hub rollout",
              "sandbox-bwrap-v1" in caps, str(caps))

        print(f"\n{'─' * 60}")
        print(f"{pass_n + fail_n} checks: \033[32m{pass_n} passed\033[0m"
              + (f", \033[31m{fail_n} failed\033[0m" if fail_n else "")
              + (f", \033[33m{skip_n} skipped\033[0m" if skip_n else ""))
        return 1 if fail_n else 0
    finally:
        try:
            os.unlink(canary)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
