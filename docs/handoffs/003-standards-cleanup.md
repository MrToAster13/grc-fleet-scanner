# grc-fleet-scanner: standards cleanup handoff

Written 2026-09-05 19:44:26. Closed 2026-09-06. Status: **complete, committed as `d17f1a9`.**

## Where the work is

Repo: `C:\Users\Elijah\grc-fleet-scanner`
Branch: `docs/standards-cleanup`, branched from `main` at `e717275`
Committed as `d17f1a9` on `docs/standards-cleanup`: 23 files, 199 insertions, 189 deletions.
`main` is still at `e717275`. Not yet pushed, no PR open.

Review it with:

```powershell
cd C:\Users\Elijah\grc-fleet-scanner
git show d17f1a9
```

## What was asked

"Project reflect the standards I set forth in my files, reduce the m dashes, clean up the
documentation."

The governing standard is `C:\Users\Elijah\.claude\CLAUDE.md`, not the repo's `AGENTS.md`.
The global file bans the em-dash outright. `AGENTS.md` only said "go easy on em-dash asides",
which is why they accumulated.

## What is done

A 13 agent workflow (`grc-standards-cleanup`, run id `wf_86edd3c2-05e`) ran 10 edit agents,
one per file or file group so no two agents wrote the same file. All 10 returned.

Em-dashes went from **175 across 22 files** to **1**. The survivor is intentional:
`AGENTS.md` line 14 now states the ban and names the `—` character inside backticks.

Diffstat against `main`: 23 files, 197 insertions, 189 deletions.

Also applied, and each one verified against the source before editing:

- `docs/design.md` stale test count `123` corrected to `148`. Verified by running the suite.
- `docs/design.md` "Known deferred enhancements" row for `config: treat_unknown_linux_as_ubuntu`
  deleted. The claim was false: the feature is fully shipped in `config.py` (dataclass field,
  config hash, YAML parser), `config.example.yaml`, `docs/operating.md`, and `classify.py`.
- `docs/design.md` "Run host" precondition rewritten. The old text said OpenSCAP is Linux native,
  which is misleading. OpenSCAP never runs on the run host at all; it runs on the remote target
  over SSH. The real reason the run host must be Linux is that the whole launcher layer
  (`install.sh`, `bin/*`, `grc-target-setup`) is bash.
- `README.md` install section gained one line stating you must already be inside a Linux shell.
- `README.md` quick start gained the target prep step (`grc-provision` / `grc-target-setup`),
  which previously appeared only as a table row further down.
- `tests/README.md` Layout table completed. It listed 7 test files; the directory has 12.
  Added rows for `test_cli.py`, `test_deps.py`, `test_detect.py`, `test_remote.py`, `test_rmf.py`.
- `AGENTS.md` line 14 tightened from "go easy on em-dash asides" to the outright ban.

## Verification, completed 2026-09-06

**Style sweep: PASS.** Across tracked files only: one U+2014 (the intentional `AGENTS.md` rule
text), zero U+2013, zero U+2026, zero curly quotes, exactly one H1 per markdown file. All three
AI-tell hits are false positives: two are the rule list in `AGENTS.md` itself, one is
"Leading-underscore files" naming the `_` character at `install.sh` line 30.

**Factual drift review: PASS after two fixes.** Every hunk was checked for a parenthetical aside
folded into a main clause, which can silently strengthen a claim. Two issues were found and
corrected before the commit:

- `docs/design.md` "Run host" precondition dropped the old wrong claim but never stated the
  replacement fact. It now says plainly that `oscap` is always invoked on the remote target over
  SSH and never on the run host, and that the run host must be Linux because the launcher layer
  is bash.
- `docs/validation.md` line 3 had orphaned a closing parenthesis onto its own line. Rejoined.

All five deliberate corrections were re-verified against source, not taken on the diff's word:
the 148 test count by collection, `treat_unknown_linux_as_ubuntu` as genuinely shipped in
`config.py`, `classify.py`, `config.example.yaml` and `docs/operating.md`, remote-only `oscap`
invocation in `scan.py` and `remote.py`, and both `README.md` additions against `bin/`.

**Test suite: PASS.** `python -m pytest` returns **148 passed, 0 failed**, exit 0, matching the
baseline. The repo's own pre-commit hook re-ran it independently at commit time and also passed.

**Secrets scan: CLEAN.** No private keys, no SSH public-key blobs, no AWS, GitHub or Slack token
patterns, no inline password or API-key assignments. The only IP address in the diff is
`10.0.10.0/24` in `config.example.yaml`, an RFC1918 documentation range.

## What is still open

Not pushed, and no PR exists. No GitHub issues exist (0 issues, 0 PRs). The remaining repo
defects are tracked as ELI-136 through ELI-144 in the Linear GRC Tool project, each ticket
carrying its own file paths and line numbers.

## Deliberately out of scope

The global `CLAUDE.md` also says to avoid hyphenated compound words. The repo's `AGENTS.md` does
not carry that rule, and a purge would touch most of the repo (`run-host`, `end-to-end`,
`single-word`, and many more). It was not requested and was left alone on purpose. This is a
separate decision for the owner, not an oversight.

## Standing constraints

- Never commit without first scanning for secrets. The scan already ran clean on `main`
  (no keys, tokens, real IPs, or hostnames). Re-run it on any newly added content.
- Never write to Linear without showing the draft first. Status changes are the only exception.
- Present a design or mockup and wait for explicit approval before a full implementation.
- Run the full suite after code changes and report pass/fail counts explicitly.

## Related

Consolidated audit findings from the five adversarial audits that preceded this work:
[002-audit-findings.md](002-audit-findings.md)

Earlier MVP carve handoff: [001-mvp-carve.md](001-mvp-carve.md)
