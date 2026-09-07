# Handoff: grc-fleet-scanner MVP simplification, adversarial audit, and dual tracking

> **Historical.** Written mid-session on 2026-09-05 while five audits were still in
> flight. Superseded by [002-audit-findings.md](002-audit-findings.md) for the findings and by
> Linear ELI-136 through ELI-144 for the live work. Kept for the reasoning behind the MVP carve.

**Written:** 2026-09-05 19:09:11
**Status:** in-progress. Five background audits were in flight when this was written
**Repo:** `C:\Users\Elijah\grc-fleet-scanner` (public: https://github.com/MrToAster13/grc-fleet-scanner)
**Linear project:** GRC Tool, `3a8ccd4d-2f85-4f2b-84e6-6db2b87e386c`, team Elijah-zion (`ELI`)

## Goal

Elijah says the tool is "too clunky" and wants to know how to cut it to an MVP. Scope then
grew to: many adversarial audits, general cleanup of both Linear and the code, and tracking
the result as GitHub issues/PRs **and** Linear tickets.

## Important correction carried into this session

Elijah first asked about "the DFIR tool." There is no DFIR tool. Verified exhaustively:

- All 12 GitHub repos under `MrToAster13` (owner + collaborator + org affiliations).
- All 16 Linear projects under team Elijah-zion. Only "DFIR" hits are five **Job applications**
  tickets, e.g. ELI-107 "Rewrite DFIR Analyst into the Arial template."
- Local filesystem sweep of `C:\Users\Elijah`.

`C:\Users\Elijah\GhostTrace` is 907 MB of **evidence only** (`Logs-DC`, `Logs-Client02`,
`Logs-Client03`; each has Application/Powershell/Security/Sysmon `.evtx` plus a `$MFT`). No
code, no git repo, no README, no Linear project. Those log files are off limits per the
`evidence-files-off-limits` memory. Never open or quote them.

Elijah then confirmed the real target is **grc-fleet-scanner**. Do not re-litigate this.

## Verified facts about the repo (checked, not assumed)

- 62 tracked files, 38 commits, branch `main`, working tree clean,
  0 ahead / 0 behind `origin/main`. Last commit `e717275` "build: mark the launchers and
  install scripts executable."
- **The test suite passes: 148 passed** (run on Windows via `.venv/Scripts/python.exe -m pytest -q`).
  So the code is not broken. The clunk is environmental and operational, not a code defect.
- Note a doc/version smell: commit `4fc0f68` says "correct test count to 123" but README
  claims 148. One of those is stale somewhere. An audit was checking this.
- No `CONTEXT.md`, no `docs/adr/`. Nothing constrains a redesign.
- Runtime deps are small: PyYAML, paramiko, Jinja2, defusedxml (+ pytest for dev).

### Module sizes (largest first)

`report.py` 577, `remote.py` 503, `cli.py` 415, `config.py` 406, `scan.py` 363, `store.py` 332,
`discovery.py` 321, `models.py` 287, `rmf.py` 273, `crosswalk.py` 214, `deps.py` 211,
`detect.py` 195, `classify.py` 133, `profiles.py` 112, `logging_setup.py` 46, `scap_xml.py` 16.

Shell surface: `install.sh` 75, `grc-target-setup` 161, `bin/_grc-common.sh` 65, plus nine
thin `bin/grc-*` launchers (6 to 42 lines each), 443 lines total.

Docs: `docs/operating.md` 324, `docs/validation.md` 280, `CHANGELOG.md` 260, `README.md` 163,
`docs/design.md` 158, `AGENTS.md` 31. 1,216 lines of prose against 7,147 lines of code.

### The pipeline

`discover (nmap) → classify → reach (SSH) → detect (oscap/SSG) → scan (oscap) → persist
(SQLite) → report (HTML/JSON/CSV + drift)`

Eight coverage buckets in `grc_auditor/models.py:49-56`: `non_ubuntu`, `no_credentials`,
`unreachable`, `scanner_absent`, `unsupported_version`, `host_key_mismatch`, `scanned`,
`scan_error`.

### Where the clunk comes from (my read before the audits reported)

The tool cannot emit a single number until a long chain of external preconditions is met:

1. A **Linux** run host. Elijah's daily driver is Windows 11 / PowerShell, so WSL2 is required.
2. `install.sh` + `~/.local/bin` on PATH + `grc-setup` to build the venv and install nmap.
3. A `config.yaml` with an authorized CIDR scope. First `grc-run` scaffolds it and **exits by
   design**, easy to misread as a crash.
4. An SSH scan account on every target.
5. Passwordless sudo on every target.
6. `oscap` **and** the matching SCAP Security Guide datastream already installed on every
   target. The tool refuses to install it and reports `scanner_absent`.

With one test VM the likely first-run outcome is a report where every host is `scanner_absent`:
technically correct, zero value on screen. That is the shape of ELI-6.

The MVP thesis to test against the audit findings: the nmap discovery + classify leg
(`discovery.py`, `classify.py`, `profiles.py`, credential_groups/bastion in `config.py` +
`remote.py`) is the largest source of ceremony and the least GRC value, because a GRC analyst
usually already has an inventory list. Cutting to "give me a host list, scan it, show me a
score" is the candidate MVP.

## Linear state (read, nothing written)

The GRC Tool project contains exactly **one** issue.

- **ELI-6** "GRC scanner having issues running at all", In Progress since 2026-07-08,
  priority Low, label `Bug`, assignee Elijah.
  Description: "might just need to download the open____ scanner, idk. Gotta be easy to use it,
  make the commands be run my a single word?"
  One comment (2026-08-04): the single-word commands, nmap auto-install, config scaffold and
  executable launchers are done; "Needs a confirmation run before this closes."

So ELI-6 is blocked on a confirmation run, and the single-word-command half of it already
shipped. The Linear cleanup is that one vague ticket is carrying an entire project's worth of
work and should be split.

**Team metadata (cached, do not re-fetch):**
- Statuses: In Review `e55a1719`, In Progress `da5c2757`, Done `d1a89d98`, Duplicate `5477d511`,
  Backlog `4461cbd8`, Todo `2d869f1d`, Canceled `1f53da04`.
- Existing labels: `Bug`, `Improvement`, `Feature`, `Task`, `ready-for-agent`, and the
  `wayfinder:*` set. **No new labels are needed, do not create any.**

## Work in flight when this was written

**UPDATE 19:16. Audits 1, 2 and 3 have reported. Their findings are written up in full at
[002-audit-findings.md](002-audit-findings.md). Read that file
first; it supersedes the "where the clunk comes from" section above and corrects the LOC count
(`grc_auditor/` is 4,423 LOC, not 7,147, that figure counted `tests/`). Audits 4 and 5 were
still running.**

Five background audit agents (all Sonnet, per the global default) against the repo:

1. **Architecture / deepening + MVP carve**: shallow modules, deletion test, and a
   value-vs-cost ranking of every module and CLI feature, with LOC and test counts that would
   disappear per cut.
2. **Security and correctness review**: command/argument injection through nmap/oscap/ssh
   args, SSH host-key enforcement in `remote.py`, XXE in the ARF/XCCDF parsing, HTML injection
   in `report.html.j2`, path traversal in `store.py`/`report.py`, secret leakage into
   `audit.log`/`report.json`, scoring and drift math, and the shell launchers.
3. **Adversarial onboarding audit**: every precondition between `git clone` and a first score,
   what happens on PowerShell, line-by-line breakage in `install.sh` and `bin/_grc-common.sh`,
   and the smallest change that yields a real report on day one.
4. **Docs-vs-reality audit**: every README/docs claim verified against code, the 148-vs-123
   test count, documented-but-ignored config keys, dead coverage buckets, and AGENTS.md
   writing-rule violations. This one matters because the repo is public job-search evidence.
5. **Test-quality and repo hygiene**: what the 148 tests actually prove versus mock, untested
   failure paths, plus `gh` issue/PR/CI state, packaging consistency, and a **secrets scan**
   (the repo was validated against a real cloud Ubuntu host, so `docs/validation.md`,
   `tests/fixtures/*.xml` and `CHANGELOG.md` need checking for real IPs/hostnames/keys).

**All five finished.** Their transcripts were session-local and are gone. The consolidated
findings they produced are in [002-audit-findings.md](002-audit-findings.md), which is the
authoritative record.

## Next steps

1. Collect the five audit reports and reconcile them (they overlap deliberately; treat
   contradictions as findings to verify, not as truth).
2. Build the HTML report to `%TEMP%\grc-fleet-scanner-<topic>-<timestamp>.html` per the global
   CLAUDE.md rule: Tailwind + Mermaid from CDN, before/after visuals per claim, cards over
   paragraphs. Follow
   `C:\Users\Elijah\.claude\skills\improve-codebase-architecture\HTML-REPORT.md` for the
   scaffold and the required vocabulary (module, interface, depth, seam, adapter, leverage,
   locality, never "component", "service", "wrapper", "boundary"). Open it with `start` and
   give the absolute path.
3. Present the MVP carve as a **design/mockup first and wait for explicit approval**. Elijah
   frequently reverts unrequested changes. Do not start deleting modules.
4. Only after approval: file GitHub issues and open PRs, and mirror them as Linear tickets.

## Gotchas that will bite you

- **Never write to Linear without showing the draft first.** Status changes are the one
  exception; comments and new tickets are not.
- **Never create a Linear label, project, or team without asking.** Applying an existing label
  inside an approved draft is fine.
- ELI-6 has no GitHub integration wired up, so nobody else moves its status. Per the global
  rules, work on it moves it to In Progress, and to Done when its criteria are met.
- **Scan for secrets before any `git add`.** Audit 5 was checking whether real infrastructure
  details from the cloud validation run got committed. Resolve that before pushing anything.
- Windows/PowerShell only: no bash line-continuations, no heredocs, no here-strings in
  PowerShell blocks. Keep commit messages single-line. Bake absolute `cd` paths into every
  command block, Elijah does not track the working directory.
- Writing rules are enforced in this repo by `AGENTS.md`: no em-dashes, no AI-tell words
  (robust, seamless, crucial, leverage), no hyphenated compounds. The same rules apply to
  issue and ticket text.
- The pre-commit hook runs the full suite; enable with
  `git config core.hooksPath .githooks`. Report pass/fail counts explicitly before committing.
- A 907 MB evidence folder sits at `C:\Users\Elijah\GhostTrace` and is unrelated to this work.
  Do not touch it.

## Suggested skills

- `/improve-codebase-architecture`, installed at `C:\Users\Elijah\.claude\skills\` but **not**
  in the loaded skill list, so read its `SKILL.md` and `HTML-REPORT.md` from disk and follow
  them manually. It is the source of the required HTML report format.
- `/codebase-design`, for the module/interface/depth/seam vocabulary the report must use.
- `/code-review`, for the standards-and-spec review pass once changes exist to review.
- `/linear-update`, for the draft-review-approve write to ELI-6 and any new tickets.
- `/grilling`, to stress-test the MVP carve with Elijah before cutting anything.
- `/pre-push`, before any push: simplify, review, security, test, commit as gated stages.

## Relevant files

- `C:\Users\Elijah\grc-fleet-scanner\README.md`
- `C:\Users\Elijah\grc-fleet-scanner\AGENTS.md`
- `C:\Users\Elijah\grc-fleet-scanner\config.example.yaml`
- `C:\Users\Elijah\grc-fleet-scanner\docs\design.md`
- `C:\Users\Elijah\grc-fleet-scanner\docs\operating.md`
- `C:\Users\Elijah\grc-fleet-scanner\docs\validation.md`
- `C:\Users\Elijah\grc-fleet-scanner\grc_auditor\cli.py`
- `C:\Users\Elijah\grc-fleet-scanner\grc_auditor\config.py`
- `C:\Users\Elijah\grc-fleet-scanner\grc_auditor\models.py`
- `C:\Users\Elijah\grc-fleet-scanner\grc_auditor\discovery.py`
- `C:\Users\Elijah\grc-fleet-scanner\grc_auditor\remote.py`
- `C:\Users\Elijah\grc-fleet-scanner\grc_auditor\report.py`
- `C:\Users\Elijah\grc-fleet-scanner\grc_auditor\store.py`
- `C:\Users\Elijah\grc-fleet-scanner\bin\_grc-common.sh`
- `C:\Users\Elijah\grc-fleet-scanner\install.sh`
- `C:\Users\Elijah\.claude\skills\improve-codebase-architecture\HTML-REPORT.md`
