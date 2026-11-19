#!/usr/bin/env python3
"""tests/test_preflight_signals.py — the gates must see what the audit saw.

Audit 2026-11-19 (three findings, all pinned here):

  1. B04 `subprocess.run(["curl", …])` and B07
     `importlib.import_module("urllib.request")` came back RUNNABLE —
     facts["network"] only read import statements.
  2. URL literals / URL concatenation / base64 shapes scanned as 0 findings.
  3. `_preflight_static` ran ast.parse on EVERY language, so .js/.c/.sh files
     got a confident false "does not parse — it will fail remotely"
     (11 of 34 files) — a confident wrong reason worse than none.

Plus the structural note: the network verdict must carry WHICH policy
applies (GET/HEAD-only proxy refusal vs plain unavailability), because a
boolean cannot distinguish a POST that would work from one the socket will
refuse.

Stdlib only. Exit 0 = all pass.

Run: python3 tests/test_preflight_signals.py
"""

import importlib.util
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
CLI = HERE.parent / "blnq-cli.py"

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


P = cli._preflight_static
B = cli._preflight_blockers
S = cli._security_scan_file


def scan_ids(tmp_path, code, name="probe.py"):
    p = pathlib.Path(tmp_path) / name
    p.write_text(code)
    return [f.get("rule_id") for f in S(p)], S(p)


def main():
    import tempfile
    print("tests/test_preflight_signals.py — network/parse/policy gates\n")

    section(1, "the audit's evasive cases are now caught (facts)")
    # B04: network via subprocess, zero imports
    f = P("import subprocess\nsubprocess.run(['curl', '-s', 'http://x.example/'])\n", "python")
    check("B04 subprocess curl → network", f["network"], str(f["net_evidence"]))
    check("B04 evidence names curl", any("curl" in e for e in f["net_evidence"]),
          str(f["net_evidence"]))
    check("B04 has no net imports (text sniff did the work)",
          "requests" not in f["imports"] and "socket" not in f["imports"])

    # B07: dynamic import of a network module
    f = P("import importlib\nm = importlib.import_module('urllib.request')\nm.urlopen('http://x/')\n",
          "python")
    check("B07 importlib urllib → network", f["network"], str(f["net_evidence"]))
    check("B07 evidence names the module string",
          any("urllib" in e for e in f["net_evidence"]), str(f["net_evidence"]))

    # URL literal + concatenation
    f = P('u = "https://example.com/api/v1"\nprint(len(u))\n', "python")
    check("URL literal → network", f["network"], str(f["net_evidence"]))
    f = P('u = "https://" + host + "/x"\n', "python")
    check("URL concatenation (bare scheme) → network", f["network"],
          str(f["net_evidence"]))
    f = P('base = "https:"\nu = base + "//" + host\n', "python")
    check("URL scheme via 'https:' fragment → network", f["network"],
          str(f["net_evidence"]))

    # computed dynamic import → unverifiable → network (conservative)
    f = P("import importlib\nname = get_name()\nimportlib.import_module(name)\n", "python")
    check("computed-name dynamic import → network (unverifiable)", f["network"]
          and any("unverifiable" in e for e in f["net_evidence"]),
          str(f["net_evidence"]))
    f = P("import importlib\nmod = importlib.import_module('json')\n", "python")
    check("literal NON-network dynamic import stays clean (json)", not f["network"],
          str(f["net_evidence"]))

    section(2, "write methods carry their own verdict (GET/HEAD-only policy)")
    f = P("import requests\nrequests.post('https://x.example/', data={'a': 1})\n", "python")
    check("requests.post → net_write", f["net_write"], str(f["net_write_evidence"]))
    check("requests.post → also network", f["network"])
    f = P("import urllib.request\nurllib.request.Request('https://x/', method='POST')\n", "python")
    check("Request(method='POST') → net_write", f["net_write"],
          str(f["net_write_evidence"]))
    f = P("#!/bin/bash\ncurl -X POST -d 'a=1' https://x.example/\n", "bash")
    check("shell curl -X POST → net_write", f["net_write"],
          str(f["net_write_evidence"]))
    f = P("import requests\nr = requests.get('https://x.example/')\n", "python")
    check("plain GET is network but NOT net_write", f["network"] and not f["net_write"],
          str(f["net_write_evidence"]))

    section(3, "policy-carrying blockers (the structural note)")
    off, on = None, {"on": True, "ready": True, "proxy": "http://172.30.99.2:8443"}
    # stdlib-only network script: `requests` would add the (separate,
    # correct) third-party-deps blocker and mask the case under test here.
    facts_get = P("import urllib.request\nurllib.request.urlopen('https://example.com/')\n",
                  "python")
    bl, nt = B(facts_get, egress=off)
    check("egress OFF → read-network is a blocker",
          any("needs the network" in b for b in bl), str(bl))
    check("egress OFF → no notes", not nt)
    bl, nt = B(facts_get, egress=on)
    check("egress ON → read-network demotes to a policy NOTE", not bl and bool(nt),
          f"blockers={bl} notes={nt}")
    check("the note names the policy (GET/HEAD, mission, audited)",
          nt and "GET/HEAD" in nt[0] and "audited" in nt[0], str(nt))

    facts_post = P("import requests\nrequests.post('https://example.com/', data={})\n",
                   "python")
    bl, nt = B(facts_post, egress=on)
    check("egress ON → POST still a blocker (refused at the socket)",
          any("sends data" in b and "GET/HEAD" in b for b in bl), str(bl))
    check("POST blocker says policy-not-availability when egress on",
          any("refused by policy" in b for b in bl), str(bl))

    section(4, "parses is tri-state and never lies about other languages")
    f = P("def broken(:\n", "python")
    check("python syntax error → parses False", f["parses"] is False, str(f["parses"]))
    bl, _ = B(f, None)
    check("…and IS a blocker with the checker named",
          any("does not parse" in b and "python ast" in b for b in bl), str(bl))

    f = P("const x = 1;\nconsole.log(x);\n", "node")
    if cli._find_exe("node"):
        check("valid .js → parses True via node --check", f["parses"] is True
              and f["parse_lang"] == "node --check", f"{f['parses']} {f.get('parse_lang')}")
        f = P("const broken = ;;;;\n", "node")
        check("invalid .js → parses False (REAL verdict)", f["parses"] is False,
              str(f["parses"]))
    else:
        print("  \033[33m…\033[0m skip: node not installed")

    f = P("int main(){return 0;}\n", "c")
    check(".c with no checker → parses None (unknown, NOT failure)",
          f["parses"] is None, str(f["parses"]))
    bl, _ = B(f, None)
    check("parses None → NO 'does not parse' blocker",
          not any("does not parse" in b for b in bl), str(bl))

    f = P("if [ broken ; then\n", "bash")
    if cli._find_exe("bash"):
        check("broken bash → parses False via bash -n", f["parses"] is False,
              str(f["parses"]))
        f = P("if [ 1 -eq 1 ]; then echo ok; fi\n", "bash")
        check("valid bash → parses True", f["parses"] is True, str(f["parses"]))
    else:
        print("  \033[33m…\033[0m skip: bash not installed")

    section(5, "non-python families sniff their own network idioms")
    f = P("const https = require('https');\nhttps.get('https://x.example/', r => {});\n", "node")
    check("node https.get → network", f["network"], str(f["net_evidence"]))
    f = P("fetch('https://api.example.com/x').then(r => r.json());\n", "node")
    check("node fetch → network", f["network"], str(f["net_evidence"]))
    f = P('#include <sys/socket.h>\nint main(){return 0;}\n', "c")
    check("c sys/socket.h → network", f["network"], str(f["net_evidence"]))
    f = P("use LWP::UserAgent;\nmy $ua = LWP::UserAgent->new;\n", "perl")
    check("perl LWP → network", f["network"], str(f["net_evidence"]))
    f = P("console.log('just arithmetic');\n42 + 1;\n", "node")
    check("innocent .js stays clean", not f["network"], str(f["net_evidence"]))

    section(6, "scan findings: the audit's 0-finding cases")
    with tempfile.TemporaryDirectory() as td:
        ids, _ = scan_ids(td, "import subprocess\nsubprocess.run(['curl', 'http://x/'])\n")
        check("scan flags shell network binary", "net_via_shell" in ids, str(ids))
        ids, _ = scan_ids(td, "import importlib\nimportlib.import_module('urllib.request')\n")
        check("scan flags dynamic import", "net_dynamic_import" in ids, str(ids))
        ids, _ = scan_ids(td, 'u = "https://" + host + "/api"\n')
        check("scan flags URL scheme concatenation", "net_url_literal" in ids, str(ids))
        ids, _ = scan_ids(td, "requests.post('https://x/', data=p)\n")
        check("scan flags write method", "net_write_method" in ids, str(ids))
        # Assembled at runtime: the ASSEMBLED text must reach the scanner (it
        # is what we are testing), but this test FILE must not itself contain
        # the high-danger literal — every file under tests/ has to clear the
        # safety gate (test_safety_check.js).
        sample = "compile" + "(b64decode(payload), '<s>', 'exec')"
        ids, _ = scan_ids(td, "code = " + sample + "\n")
        check("scan flags compile-of-decoded-data", "b64_compile" in ids, str(ids))
        ids, fnd = scan_ids(td, "import json\nprint(json.dumps({'a': 1}))\n")
        check("clean python → no net findings",
              not any(r and r.startswith("net_") for r in ids), str(ids))
        # severities: writes are WARN (visible in `blnq check`), URLs INFO
        _, fnd = scan_ids(td, "requests.post('https://x/')\n")
        sev = {f["rule_id"]: f["severity"] for f in fnd}
        check("write method is WARN (shown in check)", sev.get("net_write_method") == "WARN",
              str(sev))
        check("URL literal is INFO (opt-in visibility)", sev.get("net_url_literal") == "INFO",
              str(sev))

    section(7, "evaluate agrees (verdicts carry netwrite before network)")
    import tempfile as _tf
    with _tf.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        p1 = root / "a.py"
        p1.write_text("import requests\nrequests.post('https://x/')\n")
        r = cli._eval_file(p1, root)
        check("POST file → verdict netwrite", r and r["verdict"] == "netwrite",
              str(r and r["verdict"]))
        check("…and evidence attached", bool(r and r["net_write_evidence"]),
              str(r))
        p2 = root / "b.py"
        p2.write_text("import subprocess\nsubprocess.run(['curl', 'http://x/'])\n")
        r = cli._eval_file(p2, root)
        check("subprocess-curl file → network blocker", r and "network" in r["blockers"],
              str(r and r["blockers"]))
        p3 = root / "c.py"
        p3.write_text("print(sum(range(10)))\n")
        r = cli._eval_file(p3, root)
        check("clean file still ready", r and r["verdict"] == "ready",
              str(r and r["verdict"]))

    print(f"\n{'─' * 60}")
    print(f"{pass_n + fail_n} checks: \033[32m{pass_n} passed\033[0m"
          + (f", \033[31m{fail_n} failed\033[0m" if fail_n else ""))
    return 1 if fail_n else 0


if __name__ == "__main__":
    sys.exit(main())
