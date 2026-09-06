# grc-fleet-scanner: consolidated audit findings

**Written:** 2026-09-05 19:16:02
**Status:** 2 of 5 audits reported. Code review, docs-vs-reality, and test/hygiene still running.
**Repo:** `C:\Users\Elijah\grc-fleet-scanner`

## Corrected measurements (supersede the handoff)

The handoff said 7,147 Python LOC. That counted `tests/`. Actual split, measured by the
architecture agent:

- `grc_auditor/` = **4,423 LOC across 18 files**
- `tests/` = **2,611 LOC across 13 files, 148 tests**
- `bin/` = **207 lines across 10 launcher scripts**

## Audit 1: architecture and MVP carve

### Dead code, confirmed by repo-wide grep

`Store.recent_scores_for_host` (`grc_auditor/store.py:303-332`, 30 LOC) has zero callers
anywhere, including its own test file.

### Zero-test module, confirmed by repo-wide grep

`grc_auditor/crosswalk.py` is 214 LOC with **no test coverage of any kind**. Grep for
`crosswalk|map_rule` across `tests/` returns nothing.

### Two NIST 800-53 mappings that look alike and are not

- `crosswalk.py`: rule-id stem to family-level guess, hand curated, its own docstring calls it
  "non-exhaustive". Used only by `report.py:top_failing_controls` (import at `report.py:30`).
- `rmf.py`: ARF-embedded `<reference>` parsing to control level, authoritative. Used only by
  `cli.py:cmd_rmf` (lines 312-357).

Keep `rmf.py`. Cut `crosswalk.py`.

### Shallow modules

- `scap_xml.py` (16 LOC): one function, `localname()`, whose docstring is longer than its body.
  Consumers are `scan.py` and `rmf.py`.
- `profiles.py` (112 LOC): sole importer is `detect.py`. Profile resolution is already part of
  "detect what to scan with", so the merge does not concentrate unrelated complexity.

### Duplicated ARF traversal

`scan.py:parse_xccdf_results` (221-348) and `rmf.py:_parse_one` (165-210) each run their own
`for el in root.iter()` loop dispatching on `localname(el.tag)` over the same document shape.
A shared `iter_rule_results(root)` generator in `scap_xml.py` removes it.

### Caller-sequencing bug risk in config

`config.py:apply_overrides` (363-406) applies the `deep` preset **last** (comment at 395-405),
so it silently overrides any explicit `--cis-level` or `--os-detect` the operator also passed.
The word "deep" appears once in `test_cli.py`'s 7 tests. Essentially uncovered.

### Prioritized cut list

| # | Cut | Prod LOC | Test LOC | Tests | Risk |
|---|---|---|---|---|---|
| 1 | `Store.recent_scores_for_host` (dead) | 30 | 0 | 0 | none |
| 2 | `--deep` preset + `bin/grc-deep` | ~30 | ~5 | 1 | none, every knob survives standalone |
| 3 | `crosswalk.py` + `report.py` wiring | 214-245 | 0 | 0 | low, `rmf.py` supersedes it |
| 4 | bastion (keep credential_groups) | ~80 | ~15-20 | 8-11 | low, manual `ssh -L` workaround |
| 5 | `fleet_trend`/`_sparkline` (keep `compute_drift`) | ~127 | ~10-15 | 3-5 | low, cosmetic |
| 6 | nmap discovery+classify leg + `deps.py` | ~530-570 | ~360-400 | ~25-28 | **medium-high**, product decision |

Cuts 1 through 5 remove roughly 480-510 prod LOC and 30-40 tests with no loss of stated core
value. Cut 6 removes the tool's headline feature and needs explicit sign-off.

Do not cut any export format. If `report.py` (577 LOC, largest file) needs trimming, the better
target is `executive_summary` (354-461, ~108 LOC of generated narrative prose).

## Audit 2: adversarial onboarding

### 17 independent gates between clone and one number

Nine on the run host, eight per target host. Any single one produces zero score.

Run host: POSIX shell with bash, git, Python 3.8+, `./install.sh`, `~/.local/bin` on PATH
(requires a **new shell**, see below), `grc-setup` for venv plus live PyPI, nmap auto-install
via sudo, the scaffold-and-exit first run, then a real `scope.cidrs`.

Target host: actually Ubuntu 18.04-24.04, survives default nmap discovery, SSH host key
accepted, credentials authenticate, **passwordless sudo** (`detect.py:73-81`, enforced 134-141),
`oscap` already installed (`detect.py:144-150`), the SSG datastream already present
(`detect.py:154-162`), and the requested CIS profile present inside it (`detect.py:164-180`).

Target gates 6 through 8 require `grc-target-setup`, which appears only as a table row at
`README.md:122`, not in the four-command Quick Start at `README.md:99-104`.

### The PowerShell dead end

The README's second command (`README.md:70`) is `./install.sh`. In PowerShell that produces
`The term '.\install.sh' is not recognized as the name of a cmdlet, function, script file, or
operable program.` Nothing in the repo executes. That is the whole session.

WSL2 is never stated as a requirement, only implied:

- `README.md:54` and `:65` list WSL2 descriptively.
- `docs/validation.md:13-19` same.
- `docs/design.md:25-26` is actively misleading: "nmap + Python run on Windows, but the OpenSCAP
  toolchain is Linux-native." False for this tool. OpenSCAP always runs on the remote target over
  SSH, never locally, and the entire launcher layer is bash only.

Zero `.ps1`, `.bat`, `.cmd`, or `.exe` files in the repo. Zero occurrences of `wsl --install`.

### .gitattributes gap, verified

```
.gitattributes:3-4
*.sh text eol=lf
.githooks/** text eol=lf
```

The `*.sh` glob misses all ten extensionless launchers: `bin/grc-run`, `grc-dry`, `grc-deep`,
`grc-demo`, `grc-history`, `grc-provision`, `grc-report`, `grc-rmf`, `grc-setup`, and top-level
`grc-target-setup`. They are left to `autocrlf`.

**Verified fact:** the gap is real and unguarded. `core.autocrlf` is locally `true`, yet
`bin/grc-run` is currently LF only (checked with `od -c`).

**Unverified, plausible:** a fresh clone from the Windows side with Git for Windows' installer
default would rewrite those files with CRLF, producing a carriage return on the shebang line and
a `bad interpreter` failure inside WSL2 on a `/mnt/c/...` path. That trap fires after the WSL2
problem is solved.

### PATH offer does not take effect

`install.sh:42-69` offers to append `~/.local/bin` to the shell rc file. Even on "yes" it only
writes to disk and never sources the rc into the running terminal. Every following README command
then fails as "command not found" with no sign that install actually succeeded.

### Exit code 2 is overloaded

`_scaffold_config()` (`cli.py:140-168`) prints "No config found -- wrote a starter to {dest}"
and returns exit **2**, the same code a genuine `ConfigError` refusal returns. Nothing in that
message says it is not an error.

The empty-CIDR refusal at `config.py:204-208` is fine and reads as deliberate: "scope.cidrs is
empty. Active scanning requires an explicit, authorized target scope. Refusing to run."

### Three independent ways to get a report with zero scanned hosts

- `scanner_absent`, HIGH: no stock Ubuntu ships `oscap` or an SSG datastream, and
  `grc-target-setup` is not in the Quick Start.
- `non_ubuntu`, HIGH for cloud VMs: `classify.py:30-32` matches the literal substring "ubuntu"
  in the nmap banner. Cloud images often do not advertise it. The authors already knew, which is
  why `treat_unknown_linux_as_ubuntu` exists, but a first-timer has not read that doc.
- Silent discovery miss, MEDIUM-HIGH: `discovery.py:77-92` issues no `-Pn` and scans only nmap's
  default port set. A security group dropping ICMP means the host never appears as a row at all.

### Smallest change that produces a real report on day one

Ship one file, `install.ps1` at the repo root, that detects Windows and prints: this tool
requires Linux, run `wsl --install`, reopen an Ubuntu terminal, re-run the same commands there.
No changes to working bash logic. Runner-up: fold `grc-provision` into the Quick Start block as
a literal fifth line.

## Audit 3: security and correctness review

**Zero high-severity findings.** One medium, two low. Eight attack classes were checked
explicitly and came back clean with evidence.

### MEDIUM: SCAP content installed on targets with no integrity verification

`grc-target-setup:94-109`. The script resolves "latest" by scraping the GitHub API
(`grep -oP '"tag_name":\s*"\K[^"]+'`), downloads a release asset from
`ComplianceAsCode/content`, unzips it, and copies it into
`/usr/share/xml/scap/ssg/content/` as root. No checksum. No signature.

Why it matters: OVAL and XCCDF content is not inert data. Some check types shell out. A
tampered release means the target installs a datastream that every later `oscap` run trusts and
executes **as root**, on every future audit. TLS to github.com protects the transport, not the
artifact.

Fix: verify the zip against the published SHA-256SUMS or signature before unzipping, or pin a
vetted release tag instead of trusting whatever "latest" resolves to.

### LOW: two pass-rate denominators that a reader could conflate

`models.py:141-161` (`ScanResult.assessment_confidence`) uses
`passed+failed+not_applicable+error+not_checked`. `models.py:270-277`
(`RunRecord.fleet_pass_rate`) and `store.py:fleet_pass_rate_history` use
`passed+failed+error`.

Both are individually correct and applied consistently. The risk is purely for the reader: an
analyst can read "fleet pass rate" as a coverage number when it is a posture number. A one-line
docstring and report label closes it. No code change.

### LOW: `--pubkey` is appended without a format check

`grc-target-setup:135-145` appends `$PUBKEY` to `authorized_keys` with no `ssh-ed25519` or
`ssh-rsa` prefix check. Not exploitable, the value is never evaluated. A typo silently produces
a key that does not authenticate instead of failing early.

### Verified clean, with evidence

1. **Command and argument injection.** Every `nmap`, `oscap`, and `ssh` call uses argv-list
   `subprocess.run()`. No `shell=True` anywhere. `RemoteHost.run_argv()` in `remote.py`
   `shlex.quote()`s every argument. `nmap_extra_args`, timing, and CIDRs are allow-listed in
   `config.py` before reaching argv.
2. **SSH host keys.** paramiko `RejectPolicy` exclusively. No `AutoAddPolicy` or
   `WarningPolicy` in the codebase.
3. **XXE and billion laughs.** `defusedxml` for every untrusted source: nmap `-oX`
   (`discovery.py`), XCCDF results (`scan.py`), ARF (`rmf.py`). Raw `ElementTree` appears only
   for exception types, never for parsing.
4. **HTML injection.** `report.py` forces `Environment(autoescape=True)` unconditionally,
   overriding the `.j2`-extension footgun where `select_autoescape` would resolve to `False`.
   Zero `|safe` filters and no `{% autoescape false %}` in `report.html.j2`.
5. **Path traversal.** Evidence dirs are `os.path.join(artifacts_root, run_id, host.ip)`
   (`scan.py:137`). `run_id` is internally generated and `host.ip` is nmap's own network-layer
   result, not attacker-forgeable the way a DNS-sourced hostname would be. Grep confirms
   `hostname` is never used as a path component.
6. **Secrets in logs.** No password field exists in the credential model at all, key auth only.
   `key_path` is used only as paramiko's `key_filename`, never logged or shelled out.
7. **Scoring math.** `finalize_scan_status()` enforces the non-overridable
   `HARD_CONFIDENCE_FLOOR` chokepoint. `rmf.py:_result_rank()` stops a later pass from
   overwriting an earlier fail for a repeated rule idref.
8. **Shell launchers.** Every script uses `set -euo pipefail`, quotes every expansion, contains
   no `eval`, and confines root operations to `grc-target-setup`. Its sudoers drop-in is
   validated with `visudo -cf` before install, so a malformed `--scan-user` fails safe.

Bonus: `report.py:_csv_safe()` guards every target-derived CSV cell against formula injection
(`=`, `+`, `-`, `@`, leading tab or CR). `rmf.py:write_rollup_csv()` correctly omits the guard,
since every cell it writes is a normalized control id, a fixed-vocabulary status, or an integer.

## Audit 4: docs versus reality

28 claims checked. **No overclaiming.** Every architectural and security claim in the README is
backed directly by code, and in places the code does more than the README says (the
`manifest.json` chain of custody in `report.py` is not mentioned in the README at all).

The only liabilities are internal drift.

### The 148 vs 123 question is settled

**148 is correct.** `grep -c '^def test_'` across `tests/*.py` sums to exactly 148: classify 8,
cli 7, config 24, deps 20, detect 8, discovery 5, profiles 9, remote 3, report 15, rmf 15,
scan 24, store 10.

README (lines 16, 91, 155) and `CHANGELOG.md:170` are right. **`docs/design.md:153` is stale**
and still says "123-test pytest suite". `CHANGELOG.md:75`'s "97-test" is fine, it is framed as
build history.

### FALSE claim in design.md

`docs/design.md:146` lists `treat_unknown_linux_as_ubuntu` under "Known deferred enhancements"
and says `classify.py` "already reads it defensively (default off); add the field + YAML wiring
to enable."

The feature shipped. It is a real dataclass field (`config.py:90`), serialized into the config
hash (`config.py:148`), parsed from YAML (`config.py:355-356`), documented as a working key in
both `config.example.yaml:27` and `docs/operating.md:191`, and fully implemented in
`classify.py:85-133` via `_looks_linux()` and `_NON_LINUX_MARKERS`. design.md contradicts three
other files in its own repo. Delete the row.

### tests/README.md Layout table is incomplete

It lists 8 files. The directory has 12. Missing: `test_cli.py`, `test_deps.py`,
`test_detect.py`, `test_remote.py`, `test_rmf.py`.

### Unsubstantiated by nature, not a doc bug

README and design.md claim validation "end-to-end against a real cloud Ubuntu 22.04 host". No
code artifact can confirm a past manual run. `grc-target-setup`'s "fire-tested on Ubuntu 22.04"
comment repeats the claim but is not proof. Either re-run `docs/validation.md` and date-stamp
it, or soften the wording.

### Verified with no fix needed

All 8 coverage buckets are reachable, each traced to its setting code. No dead bucket.
Every documented config key is read by `config.py` and every parsed key is documented, checked
field by field in both directions. No orphans. "Never modifies the system under audit" holds:
`detect.py` has explicit no-install comments at every `scanner_absent` branch and `scan.py`
removes its own temp dir in a `finally` block (191-198). Ubuntu 18.04 through 24.04 is exact,
`profiles.py:_DATASTREAM_BY_VERSION` maps those four and nothing else. All three CHANGELOG
security fixes are real: `_csv_safe()` at `report.py:90-102`, forced autoescape at
`report.py:498-508`, and the root-RCE `mktemp` guard at `scan.py:64`
(`^/tmp/grc_audit\.[A-Za-z0-9]{6,}$`).

Nmap timing validation is real but lives in `discovery.py:_safe_timing()`, not `config.py`. A
reader checking config alone would wrongly conclude it is unenforced.

### AGENTS.md compliance

Zero AI-tell-word violations across README, docs, CHANGELOG, and tests/README. The only hits
are inside AGENTS.md where the list is defined.

**Correction to my own brief:** I told the agent AGENTS.md bans hyphenated compounds. It does
not. That rule exists only in the personal global `~/.claude/CLAUDE.md`, not in this repo's
contributor guide. The repo's docs use `run-host`, `end-to-end`, and similar freely, and none of
that violates AGENTS.md as written.

**Open decision for Elijah:** em-dash counts in the docs are `operating.md` 41,
`validation.md` 38, `CHANGELOG.md` 36, `design.md` 20, `README.md` 11. AGENTS.md only says "go
easy on em-dash asides... a pattern is a tell", so by its own test the docs are in tension with
it. The personal global rule bans them outright. Either loosen AGENTS.md to match the house
style or run an editing pass. This is a preference call, not a defect.

## Still outstanding
- Test quality and repo hygiene agent `ac9a84c7a52956e0c` (owns the **secrets scan**)
