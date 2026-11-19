#!/usr/bin/env python3
"""tests/test_authz.py — the node-local authorization layer.

The permission matrix for `blnq auth` / `blnq network`, exercised through the
PURE decision engine and the order-free parser — no hub, no job, no sockets.

Pinned behaviors (each is a way this could silently fail OPEN, which is the
only direction that matters):

  * order never matters: `auth yalla network` == `auth network yalla` ==
    `authorize network yalla` — the exact ask from the humans
  * default-allow keeps today's fleet behavior; default-deny = whitelist and
    its refusal message NAMES the command that grants access
  * caps gate secrets and network independently; `all` implies both
  * `maybe` = allow + strict (the caller applies the probation scan)
  * deny beats default-allow; unknown-mode entries from a CORRUPT file load
    as DENY (fail closed — a mangled authz file must refuse, not open)
  * caps MERGE across grants (`auth x network` after `auth x run` keeps run)
  * history records every outcome, newest last, identity-filterable

Stdlib only. Exit 0 = all pass.  Run: python3 tests/test_authz.py
"""

import importlib.util
import json
import os
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
CLI = HERE.parent / "blnq-cli.py"

# Config/state → throwaway dirs BEFORE the module loads (same trick as
# cli_smoke.sh): the tests must never touch the real ~/.config/blnq.
_TMP = tempfile.mkdtemp(prefix="blnq-authz-test-")
os.environ["BLNQ_CONFIG_DIR"] = os.path.join(_TMP, "config")
os.environ["BLNQ_STATE_DIR"] = os.path.join(_TMP, "state")

spec = importlib.util.spec_from_file_location("blnq_cli", str(CLI))
cli = importlib.util.module_from_spec(spec)
sys.modules["blnq_cli"] = cli
spec.loader.exec_module(cli)

pass_n = fail_n = 0


def check(label, cond, detail=""):
    global pass_n, fail_n
    if cond:
        pass_n += 1
        print(f"  \033[32m✓\033[0m {label}")
    else:
        fail_n += 1
        print(f"  \033[31m✗\033[0m {label}" + (f"  → {detail}" if detail else ""))


def section(n, t):
    print(f"\n{n}. {t}")


def main():
    P = cli._authz_parse
    D = cli._authz_decision

    section(1, "order-free parsing (the humans' actual request)")
    a = P(["yalla", "network"])
    b = P(["network", "yalla"])
    c = P(["authorize", "network", "yalla"])
    check("`auth yalla network` == `auth network yalla`",
          a["identities"] == b["identities"] == ["yalla"]
          and a["caps"] == b["caps"] == ["network"], f"{a} vs {b}")
    check("`authorize network yalla` aliases identically",
          c["identities"] == ["yalla"] and c["caps"] == ["network"], str(c))
    check("caps aliases: net→network, secret→secrets",
          P(["x", "net", "secret"])["caps"] == ["network", "secrets"],
          str(P(["x", "net", "secret"])["caps"]))
    check("`all` collapses to the umbrella cap",
          P(["x", "run", "all"])["caps"] == ["all"])
    check("mode aliases: block/off→deny, on→allow, revoke→delete",
          P(["x", "block"])["mode"] == "deny"
          and P(["x", "off"])["mode"] == "deny"
          and P(["x", "on"])["mode"] == "allow"
          and P(["x", "revoke"])["mode"] == "delete"
          and P(["x", "remove"])["mode"] == "delete",
          f"block={P(['x','block'])['mode']} revoke={P(['x','revoke'])['mode']}")
    check("`revoke` vs `deny` are DIFFERENT promises (delete erases → default "
          "applies; deny blocks under any default)", "delete" != "deny"
          and P(["x", "deny"])["mode"] == "deny")
    check("verbs recognized anywhere: show/logs/history/list/who",
          P(["show", "yalla"])["verbs"] == ["show"]
          and P(["history", "yalla"])["verbs"] == ["logs"]
          and P(["list"])["verbs"] == ["who"])
    check("bare digits become a log count",
          P(["logs", "50"])["count"] == 50 and P(["logs", "9999"])["count"] == 500)
    check("`default deny` parsed", P(["default", "deny"])["default"] == "deny")
    check("`default` without value → error, not silent default",
          bool(P(["default"])["errors"]))
    check("bad identity → error (no path tricks)", bool(P(["../etc"])["errors"]))
    check("conflicting modes → error",
          bool(P(["x", "allow", "deny"])["errors"]))
    check("multi-identity: `auth yalla ishq run`",
          P(["yalla", "ishq", "run"])["identities"] == ["yalla", "ishq"]
          and P(["yalla", "ishq", "run"])["caps"] == ["run"])

    section(2, "decision matrix (the gate itself)")
    allow_cfg = {"default": "allow", "entries": {}}
    deny_cfg = {"default": "deny", "entries": {}}
    d = D(allow_cfg, True, "stranger", False, False)
    check("default-allow: unknown identity runs (today's fleet behavior)", d["ok"])
    d = D(deny_cfg, True, "stranger", False, False)
    check("default-deny: unknown identity refused AND the message grants",
          not d["ok"] and "blnq auth stranger" in d["reason"], d["reason"])
    d = D(allow_cfg, True, "", False, False)
    check("empty identity becomes 'unknown' (and passes default-allow)",
          d["identity"] == "unknown" and d["ok"])
    d = D(deny_cfg, True, "unknown", False, False)
    check("default-deny refuses even 'unknown'",
          not d["ok"] and "no entry" in d["reason"], d["reason"])

    cfg = {"default": "deny", "entries": {
        "yalla": {"mode": "allow", "caps": ["all"], "granted_at": 1},
        "runner2": {"mode": "allow", "caps": ["run"], "granted_at": 1},
        "tester": {"mode": "maybe", "caps": ["run"], "granted_at": 1},
        "bad": {"mode": "deny", "caps": [], "granted_at": 1},
        "netty": {"mode": "allow", "caps": ["run", "network"], "granted_at": 1},
    }}
    check("whitelist: listed identity runs", D(cfg, True, "yalla", False, False)["ok"])
    check("caps: all → secrets allowed", D(cfg, True, "yalla", True, False)["ok"])
    check("caps: run-only + secrets → refused with the grant command",
          not D(cfg, True, "runner2", True, False)["ok"]
          and "blnq auth runner2 secrets" in D(cfg, True, "runner2", True, False)["reason"])
    check("caps: run-only + network → refused",
          not D(cfg, True, "runner2", False, True)["ok"])
    check("node network OFF → refused regardless of caps",
          not D(cfg, False, "netty", False, True)["ok"]
          and "blnq network on" in D(cfg, False, "netty", False, True)["reason"])
    check("network cap + node on → runs",
          D(cfg, True, "netty", False, True)["ok"])
    d = D(cfg, True, "bad", False, False)
    check("explicit deny beats default (and even a listed identity)", not d["ok"])
    # defense in depth: a mode the loader can't produce (hand-edited file
    # loaded by some future path) must never fall through to allow
    weird = {"default": "allow",
             "entries": {"ghost": {"mode": "delete", "caps": ["all"]}}}
    check("non-stored mode in an entry → treated as deny (never allow)",
          not D(weird, True, "ghost", False, False)["ok"],
          str(D(weird, True, "ghost", False, False)))
    d = D(cfg, True, "tester", False, False)
    check("maybe → allowed but STRICT (probation scan applies)",
          d["ok"] and d["strict"] is True and d["mode"] == "maybe")
    d = D(allow_cfg, True, "nobody", True, True)
    check("default-allow entry-less + secrets+network: allowed (caps only "
          "bind GRANTED identities)", d["ok"], str(d))

    section(3, "store roundtrip — and fail CLOSED on corruption")
    cli._authz_save({"version": 1, "default": "allow",
                     "entries": {"yalla": {"mode": "allow", "caps": ["all"],
                                           "granted_at": 123}}})
    loaded = cli._authz_load()
    check("save→load roundtrip", loaded["entries"].get("yalla", {}).get("caps") == ["all"]
          and loaded["default"] == "allow", str(loaded))
    mode_file = cli._AUTHZ_FILE
    mode_file.write_text('{"default": "allow", "entries": '
                         '{"ghost": {"mode": "WAT", "caps": ["godmode"]}}}')
    loaded = cli._authz_load()
    check("corrupt entry MODE loads as deny (fails closed)",
          loaded["entries"]["ghost"]["mode"] == "deny",
          str(loaded["entries"]["ghost"]))
    check("unknown caps are dropped and the corrupt (deny) entry holds none",
          loaded["entries"]["ghost"]["caps"] == [],
          str(loaded["entries"]["ghost"]))
    check("…and the ghost entry therefore refuses",
          not D(loaded, True, "ghost", False, False)["ok"])
    mode_file.write_text("{not json")
    check("unreadable store → safe defaults (no crash)",
          cli._authz_load()["entries"] == {})

    section(4, "grants merge — caps accumulate, deny is replaceable")
    cfg = {"default": "allow", "entries": {}}
    cli._authz_grant(cfg, "yalla", "allow", ["run"])
    cli._authz_grant(cfg, "yalla", "allow", ["network"])
    check("`auth yalla run` then `auth yalla network` → both caps",
          cfg["entries"]["yalla"]["caps"] == ["network", "run"],
          str(cfg["entries"]["yalla"]))
    cli._authz_grant(cfg, "yalla", "deny", [])
    check("grant deny replaces (caps cleared)",
          cfg["entries"]["yalla"]["mode"] == "deny" and not cfg["entries"]["yalla"]["caps"])
    cli._authz_grant(cfg, "yalla", "allow", ["all"])
    check("re-grant after deny starts clean from the new caps",
          cfg["entries"]["yalla"]["caps"] == ["all"]
          and cfg["entries"]["yalla"]["mode"] == "allow")

    section(5, "audit history — every outcome, newest last")
    cli._authz_history.__globals__["_AUTHZ_HISTORY"] = pathlib.Path(
        _TMP) / "state" / "authz-history.jsonl"
    for i in range(5):
        cli._authz_history_append({"ts": time_ts() + i, "job_id": f"job_{i}",
                                   "identity": "yalla" if i % 2 else "stranger",
                                   "mode": "allow", "script": f"s{i}.py",
                                   "status": "completed" if i else "failed",
                                   "exit": 0, "ms": 10 + i, "detail": "ok"})
    rows = cli._authz_history(3)
    check("limit returns the NEWEST rows, last entry is last write",
          len(rows) == 3 and rows[-1]["job_id"] == "job_4", str([r["job_id"] for r in rows]))
    only = cli._authz_history(50, "yalla")
    check("identity filter", len(only) == 2 and all(r["identity"] == "yalla" for r in only),
          str([r["identity"] for r in only]))
    check("refusals are IN the audit (status failed recorded)",
          any(r["status"] == "failed" for r in cli._authz_history(50)))
    # history file redirect must survive a missing parent dir
    cli._authz_history.__globals__["_AUTHZ_HISTORY"] = pathlib.Path(
        _TMP) / "no" / "such" / "dir" / "h.jsonl"
    cli._authz_history_append({"ts": 1, "identity": "x"})
    check("history write into missing dirs creates them (audit never crashes)",
          (pathlib.Path(_TMP) / "no" / "such" / "dir" / "h.jsonl").exists())

    print(f"\n{'─' * 60}")
    print(f"{pass_n + fail_n} checks: \033[32m{pass_n} passed\033[0m"
          + (f", \033[31m{fail_n} failed\033[0m" if fail_n else ""))
    return 1 if fail_n else 0


def time_ts():
    import time
    return time.time()


if __name__ == "__main__":
    sys.exit(main())
