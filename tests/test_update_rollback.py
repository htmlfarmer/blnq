#!/usr/bin/env python3
"""
Unit tests for blnq-cli's atomic-update-with-rollback helper.

Mirror of hivv's test_update_rollback.py. See that file for full rationale.
Run:  python3 tests/test_update_rollback.py
"""

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
CLI_PATH = os.path.normpath(os.path.join(THIS_DIR, "..", "blnq-cli.py"))

spec = importlib.util.spec_from_file_location("blnq_cli", CLI_PATH)
blnq_cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(blnq_cli)

_apply_update = blnq_cli._apply_update
_parse_ver     = blnq_cli._parse_ver


# sys.argv[0] is the script path; --healthcheck is sys.argv[1].
FAKE_CLI_SRC = '''#!/usr/bin/env python3
"""Fake CLI for _apply_update tests. Behavior controlled by env var."""
import os, sys
rc = int(os.environ.get("FAKE_HEALTHCHECK_RC", "0"))
if len(sys.argv) > 1 and sys.argv[1] == "--healthcheck":
    sys.exit(rc)
sys.exit(0)
'''


def _make_fake_cli(rc: int) -> str:
    return FAKE_CLI_SRC.replace('"FAKE_HEALTHCHECK_RC", "0"',
                                f'"FAKE_HEALTHCHECK_RC", "{rc}"').encode()


def _isolated_install_dir(monkeypatch_target: Path):
    """Patch blnq_cli.INSTALL_DIR so _apply_update operates on the fake CLI."""
    class _Ctx:
        def __enter__(self_inner):
            self_inner._saved = blnq_cli.INSTALL_DIR
            blnq_cli.INSTALL_DIR = monkeypatch_target
            return self_inner
        def __exit__(self_inner, *a):
            blnq_cli.INSTALL_DIR = self_inner._saved
            return False
    return _Ctx()


def _setup_workspace(tmpdir: Path) -> tuple:
    inst = tmpdir / "INSTALL_DIR"
    inst.mkdir()
    target = inst / "blnq-cli.py"
    original = b"#!/usr/bin/env python3\n# original (good) binary\nprint('original')\n"
    target.write_bytes(original)
    return target, original


def case_a_happy_path():
    with tempfile.TemporaryDirectory() as td:
        tmpdir = Path(td)
        target, original = _setup_workspace(tmpdir)
        with _isolated_install_dir(target.parent):
            new_data = _make_fake_cli(rc=0)
            new_sha = hashlib.sha256(new_data).hexdigest()
            ok, msg, returned_target = _apply_update(new_data, expected_sha256=new_sha, source="test")
        if not ok:
            return False, f"expected ok=True, got ok=False, msg={msg!r}"
        if returned_target != target:
            return False, f"target mismatch: got {returned_target}, want {target}"
        if target.read_bytes() != new_data:
            return False, "target file was not replaced with new_data"
        bak = target.with_suffix(target.suffix + ".bak")
        if not bak.exists():
            return False, ".bak should have been created"
        if bak.read_bytes() != original:
            return False, ".bak should contain the original bytes"
        new = target.with_suffix(target.suffix + ".new")
        if new.exists():
            return False, ".new should have been promoted/removed"
        bad = target.with_suffix(target.suffix + ".bad")
        if bad.exists():
            return False, ".bad should NOT exist on happy path"
    return True, ""


def case_b_sha_mismatch():
    with tempfile.TemporaryDirectory() as td:
        tmpdir = Path(td)
        target, original = _setup_workspace(tmpdir)
        with _isolated_install_dir(target.parent):
            new_data = _make_fake_cli(rc=0)
            wrong_sha = "0" * 64
            ok, msg, returned_target = _apply_update(new_data, expected_sha256=wrong_sha, source="test")
        if ok:
            return False, f"expected ok=False, got ok=True, msg={msg!r}"
        if "sha256" not in msg.lower():
            return False, f"expected sha256 mention in msg, got {msg!r}"
        if target.read_bytes() != original:
            return False, "target file should NOT have been touched"
        bak = target.with_suffix(target.suffix + ".bak")
        if bak.exists():
            return False, ".bak should NOT be created when sha mismatches"
        new = target.with_suffix(target.suffix + ".new")
        if new.exists():
            return False, ".new should NOT exist when sha mismatches"
    return True, ""


def case_c_healthcheck_fail():
    with tempfile.TemporaryDirectory() as td:
        tmpdir = Path(td)
        target, original = _setup_workspace(tmpdir)
        with _isolated_install_dir(target.parent):
            new_data = _make_fake_cli(rc=1)
            new_sha = hashlib.sha256(new_data).hexdigest()
            ok, msg, returned_target = _apply_update(new_data, expected_sha256=new_sha, source="test")
        if ok:
            return False, f"expected ok=False, got ok=True, msg={msg!r}"
        if "healthcheck" not in msg.lower():
            return False, f"expected healthcheck mention in msg, got {msg!r}"
        if target.read_bytes() != original:
            return False, "target should have been restored from .bak to original"
        bad = target.with_suffix(target.suffix + ".bad")
        if not bad.exists():
            return False, ".bad should be retained for inspection"
        if bad.read_bytes() != new_data:
            return False, ".bad should contain the failed new_data"
        new = target.with_suffix(target.suffix + ".new")
        if new.exists():
            return False, ".new should NOT exist after healthcheck failure"
    return True, ""


def case_d_parse_ver():
    cases = [
        (("0.1.0",   "0.1.0"),   False),
        (("0.2.0",   "0.1.0"),   True),
        (("0.1.0",   "0.2.0"),   False),
        (("1.0",     "0.9.9"),   True),
        (("0.10.0",  "0.9.0"),   True),
        (("0.1",     "0.1.0"),   False),
    ]
    for (a, b), want in cases:
        got = _parse_ver(a) > _parse_ver(b)
        if got != want:
            return False, f"_parse_ver({a!r}) > _parse_ver({b!r}) = {got}, want {want}"
    return True, ""


def case_e_healthcheck_flag():
    with tempfile.TemporaryDirectory() as td:
        tmpdir = Path(td)
        sandbox = tmpdir / "cli"
        sandbox.mkdir()
        run_cli = sandbox / "blnq-cli.py"
        shutil.copy(CLI_PATH, run_cli)
        env = os.environ.copy()
        env["HOME"] = str(tmpdir / "home")
        env["PATH"] = "/usr/bin:/bin"
        proc = subprocess.run(
            [sys.executable, str(run_cli), "--healthcheck"],
            capture_output=True, timeout=10, env=env,
        )
        if proc.returncode != 0:
            return False, f"expected exit 0, got {proc.returncode}. stderr={proc.stderr.decode()}"
        try:
            payload = json.loads(proc.stdout.decode().strip().splitlines()[-1])
        except Exception as e:
            return False, f"could not parse JSON from stdout: {e}. stdout={proc.stdout.decode()[:300]!r}"
        for key in ("ok", "version"):
            if key not in payload:
                return False, f"missing key {key!r} in payload: {payload}"
        if payload.get("ok") is not True:
            return False, f"payload.ok should be True: {payload}"
    return True, ""


CASES = [
    ("A. happy path (sha OK + healthcheck pass)", case_a_happy_path),
    ("B. sha256 mismatch",                       case_b_sha_mismatch),
    ("C. healthcheck fail → rollback",           case_c_healthcheck_fail),
    ("D. _parse_ver tuple compare",              case_d_parse_ver),
    ("E. --healthcheck flag emits JSON",         case_e_healthcheck_flag),
]


def run():
    passed = failed = 0
    print(f"blnq-cli.py update-rollback tests — {len(CASES)} cases\n")
    for label, fn in CASES:
        try:
            ok, why = fn()
        except Exception as e:
            ok, why = False, f"raised {type(e).__name__}: {e}"
        status = "✓" if ok else "✗"
        if ok:
            passed += 1
        else:
            failed += 1
        print(f"  {status} {label}")
        if not ok:
            print(f"      {why}")
    print()
    print(f"  {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
