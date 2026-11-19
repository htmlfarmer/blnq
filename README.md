# blnq — the blnq.org client CLI

Run code from anywhere: submit scripts to the [blnq.org](https://blnq.org)
collective — safety-reviewed by a layered ladder, executed inside real jails
(bubblewrap / Docker) on volunteer machines — **or run everything locally**.
This repo is the whole client: stdlib-only Python, zero dependencies.

## Quick start from a clone

```bash
git clone https://github.com/htmlfarmer/blnq.git
cd blnq
./blnq --help        # the launcher runs the blnq-cli.py NEXT TO IT — no download
./blnq doctor        # install + sandbox + hub + AI/egress/ladder health, one screen
./blnq duh my.py     # offline pre-check: is it dumb to run this remotely?
python3 my.py        # …or just run your code locally. always works.
```

## Optional: install system-wide

```bash
./install-blnq.sh                 # user-local (~/.local), no sudo
# or the classic one-liner:
curl -sSL https://blnq.org/install-blnq.sh | bash
blnq update                        # self-updates from the hub afterwards
```

## Volunteer your machine (runs OTHER people's code — jailed)

```bash
blnq volunteer on      # refuses without a real jail (bubblewrap or docker)
blnq status            # shows the sandbox tier + limits
blnq tasks             # in-flight local jobs — tasks kill <job_id> stops one
blnq security          # posture verdict + auto-hardening (700/600 perms)
blnq test              # doctor + speed + a real remote run, end to end
```

## Your keys & local authorization

```bash
blnq keys                       # inventory: principals, modes, fingerprints
blnq keys runner --register     # publish the PUBLIC key (private never printed)
blnq auth                       # who may run what on THIS machine
blnq auth yalla all             # grant (order-free: auth network yalla works too)
blnq auth someone maybe         # probation: strict scan gate, full audit
blnq auth default deny          # whitelist mode for the whole node
blnq auth logs                  # every decision, refusals included
blnq network on|off             # gate jobs that ask for egress
```

## Tests (offline, stdlib only — exit 0 = pass)

```bash
python3 tests/test_preflight_signals.py   # network/parse gate signals   (46)
python3 tests/test_authz.py               # permission matrix            (39)
python3 tests/test_rejection_card.py      # failure-report contract      (30)
python3 tests/test_bwrap_jail.py          # filesystem-jail proof        (33, needs bwrap)
python3 tests/test_job_runner.py          # fake-hub e2e: claim → sandbox → run
python3 tests/test_uninstall.py           # uninstall keeps/purges the right things
python3 tests/test_update_rollback.py     # atomic update + rollback
python3 tests/test_scan_secrets.py        # the secret scanner, self-tested
python3 tests/test_llm_tiers.py           # local LLM capability tiers
```

## Security in one paragraph

Jobs run **jailed**: bubblewrap with an *empty-root* filesystem (your
`~/.config`, keys and web roots are not even mounted — the job sees system
paths, its own directory, and nothing else), or Docker with a read-only
rootfs, dropped capabilities and **no network by default**. A job that is
explicitly granted network lands on an internal Docker bridge whose only
peer is a policy proxy: GET/HEAD only, mission allowlist, robots.txt
honoured, private/metadata addresses never reachable, every request audited.
Submissions pass a safety ladder — validator objections → quorum →
cached sha256 verdicts → an AI reviewer chain with per-endpoint health →
graded static fallback — plus a per-subject review flood cap so nobody can
hammer the reviewers. Details: [blnq.org/network.html](https://blnq.org/network.html);
the threat model lives as `SANDBOX.md` on the hub.

## Secrets policy

This repository must never contain credentials. Check before every push:

```bash
python3 scripts/scan_secrets.py blnq-cli.py install-blnq.sh install-blnq.ps1 \
    blnq blnq.cmd changelog.json scripts/ tests/
```

Hub operators keep their tokens in `api/.env` **on the server** — never here.
The scanner blocks (exit ≠ 0) on real findings; `$VARIABLE` examples in docs
are references, not secrets.

## Uninstall

```bash
blnq uninstall            # code out; config, keys, logs and audit kept
blnq uninstall --purge    # …plus credentials and history (keys unrecoverable)
```

---

GPLv3 — see [LICENSE](LICENSE).
The hub/API source runs on the server and is not part of this repo.
Issues and discussion: https://github.com/htmlfarmer/blnq
