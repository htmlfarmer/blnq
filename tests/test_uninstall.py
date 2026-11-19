#!/usr/bin/env python3
"""tests/test_uninstall.py — `blnq uninstall [--purge]` removes the right
things and NOTHING else.

Pinned (each was a real bug found 2026-11-19):
  * default run removes ALL code artifacts: client, wrapper, .bak/.new/.bad
    update leftovers (a 111KB previous-version .bak survived the old
    uninstall), and __pycache__ — but KEEPS config/keys/state/history
  * respawn paths (keepalive/autostart) are asked to disarm — a timer
    respawning a missing script forever is a silent error loop
  * `--purge --yes` removes config+keys+state wholesale (non-interactive)
  * `--purge` WITHOUT --yes and without a TTY → refuses (die), no partial
    deletions
  * INSTALL_DIR is only rmdir'd when empty (never deletes strangers' files)

Stdlib only. Exit 0 = all pass.  Run: python3 tests/test_uninstall.py
"""

import argparse
import importlib.util
import os
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
CLI = HERE.parent / "blnq-cli.py"

_TMP = pathlib.Path(tempfile.mkdtemp(prefix="blnq-uninstall-test-"))
INSTALL = _TMP / "lib"
BINDIR = _TMP / "bin"
CONFIG = _TMP / "config"
STATE = _TMP / "state"
(os.environ.__setitem__("BLNQ_INSTALL_DIR", str(INSTALL)),
 os.environ.__setitem__("BLNQ_BIN_DIR", str(BINDIR)),
 os.environ.__setitem__("BLNQ_CONFIG_DIR", str(CONFIG)),
 os.environ.__setitem__("BLNQ_STATE_DIR", str(STATE)))

# seed a realistic install
INSTALL.mkdir(parents=True)
BINDIR.mkdir(parents=True)
(INSTALL / "blnq-cli.py").write_text("# current client\n")
(INSTALL / "blnq-cli.py.bak").write_text("# OLD111KB previous version\n")
(INSTALL / "blnq-cli.py.new").write_text("x")
(INSTALL / "__pycache__").mkdir()
(INSTALL / "__pycache__" / "x.pyc").write_text("x")
(BINDIR / "blnq").write_text("#!/bin/sh\n")
(CONFIG / "keys").mkdir(parents=True)
(CONFIG / "keys" / "runner.key").write_text("deadbeef" * 8)
(CONFIG / "authz.json").write_text('{"default": "allow", "entries": {}}')
(CONFIG / "auth.json").write_text("{}")
STATE.mkdir(parents=True)
(STATE / "agent.log").write_text("logline\n")
(STATE / "authz-history.jsonl").write_text('{"ts": 1, "identity": "y"}\n')
# a STRANGER's file in install dir → must survive the rmdir attempt
(INSTALL / "keepme.txt").write_text("not ours")

spec = importlib.util.spec_from_file_location("blnq_cli", str(CLI))
cli = importlib.util.module_from_spec(spec)
sys.modules["blnq_cli"] = cli
spec.loader.exec_module(cli)

# never touch real systemd/sudo in a test: replace the disablers with spies
disarm_calls = []
cli.cmd_keepalive = lambda ns: disarm_calls.append(("keepalive", ns.action))
cli.cmd_autostart = lambda ns: disarm_calls.append(("autostart", ns.action))

pass_n = fail_n = 0


def check(label, cond, detail=""):
    global pass_n, fail_n
    if cond:
        pass_n += 1
        print(f"  \033[32m✓\033[0m {label}")
    else:
        fail_n += 1
        print(f"  \033[31m✗\033[0m {label}" + (f"  → {detail}" if detail else ""))


def exists(p):
    return pathlib.Path(p).exists()


def main():
    print("tests/test_uninstall.py — what leaves, what stays\n")

    print("1. default uninstall (code out, credentials kept, disarmed)")
    cli.cmd_uninstall(argparse.Namespace(purge=False, yes=True))
    check("client removed", not exists(INSTALL / "blnq-cli.py"))
    check("update leftover .bak removed (was 111KB of old code)",
          not exists(INSTALL / "blnq-cli.py.bak"))
    check("update leftover .new removed", not exists(INSTALL / "blnq-cli.py.new"))
    check("__pycache__ removed", not exists(INSTALL / "__pycache__"))
    check("wrapper removed", not exists(BINDIR / "blnq"))
    check("keepalive disarmed with action=off",
          ("keepalive", "off") in disarm_calls, str(disarm_calls))
    check("autostart disarmed with action=off",
          ("autostart", "off") in disarm_calls, str(disarm_calls))
    check("config KEPT", exists(CONFIG / "auth.json"))
    check("KEYS KEPT", exists(CONFIG / "keys" / "runner.key"))
    check("authz store KEPT", exists(CONFIG / "authz.json"))
    check("logs + auth history KEPT",
          exists(STATE / "agent.log") and exists(STATE / "authz-history.jsonl"))
    check("INSTALL_DIR NOT rmdir'd (stranger file present)",
          exists(INSTALL / "keepme.txt"))

    print("\n2. purge without --yes and without a TTY → refuses, deletes nothing")
    real_stdin = sys.stdin
    sys.stdin = _NoTTY()          # isatty() False, and must never be read
    try:
        try:
            cli.cmd_uninstall(argparse.Namespace(purge=True, yes=False))
            check("non-tty purge without --yes dies", False, "did not raise SystemExit")
        except SystemExit as e:
            check("non-tty purge without --yes dies BEFORE deleting",
                  e.code not in (0, None) and exists(CONFIG / "auth.json")
                  and exists(CONFIG / "keys" / "runner.key"),
                  f"code={e.code}")
    finally:
        sys.stdin = real_stdin

    print("\n3. purge --yes removes the lot")
    cli.cmd_uninstall(argparse.Namespace(purge=True, yes=True))
    check("config gone", not exists(CONFIG))
    check("keys gone", not exists(CONFIG / "keys"))
    check("state (logs + history) gone", not exists(STATE))
    check("stranger file in install dir still untouched", exists(INSTALL / "keepme.txt"))

    print(f"\n{'─' * 60}")
    print(f"{pass_n + fail_n} checks: \033[32m{pass_n} passed\033[0m"
          + (f", \033[31m{fail_n} failed\033[0m" if fail_n else ""))
    return 1 if fail_n else 0


class _NoTTY:
    def isatty(self):
        return False

    def readline(self):
        raise AssertionError("purge tried to prompt on a non-TTY — must die first")


if __name__ == "__main__":
    sys.exit(main())
