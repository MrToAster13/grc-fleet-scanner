# Changelog

All notable changes to GRC Fleet Auditor. This project is pre-1.0; until a tagged
release, everything lives under **Unreleased**.

## [Unreleased]

### Added
- **`--deep` high-assurance scan mode.** One flag turns every coverage dial to max: forces
  **CIS Level 2** fleet-wide (overriding the config level and any per-group `cis_level`), runs
  `oscap --fetch-remote-resources` so checks whose OVAL/CVE content lives off-box are evaluated
  instead of returning `notchecked`, and switches discovery to aggressive-but-accurate `-T4`
  timing plus OS detection. It's aggressive by design — the target reaches out to the network
  mid-scan — and it changes `config_hash` (the effective config records exactly what ran, so a
  deep run and a normal run don't share provenance). Also available as standing config:
  `fetch_remote_resources: true` (+ `cis_level: 2`).
- **`rmf` subcommand — NIST 800-53 control rollup for SSP evidence.** Reads a run's retained
  OpenSCAP ARF and aggregates each rule's pass/fail by the 800-53 control it maps to, using
  the datastream's OWN authoritative per-rule references (not the indicative family
  cross-walk). Emits `control-rollup.csv` — control, pass/fail counts, a suggested
  Implementation Status (`Implemented`/`Planned`/`Not Assessed`), and a draft justification —
  to fill an RMF SSP's control worksheet from real evidence. Reports honestly that the SSG
  references are 800-53 **Rev 4** (a DoD baseline is Rev 5), that the status is a suggestion
  from automated CIS checks (not an ATO decision), and that the results are the CIS profile,
  not a DISA STIG.
- **Structural never-false-pass chokepoint** — a single `finalize_scan_status` gate now
  decides `SCANNED`. A scan that evaluated nothing (empty/rule-result-less `results.xml`)
  or whose coverage falls below a **hard, non-overridable confidence floor (50%)** is
  recorded as `scan_error` ("evidence retained but not certifiable"), never a clean pass —
  independent of the operator-tunable low-confidence badge.
- **Assessment confidence** — `ScanResult.assessment_confidence` reports the % of the
  benchmark that produced a real verdict. A high score that reflects only the checks that
  actually ran (e.g. a low-privilege scan with many `notchecked`) is flagged **LOW
  CONFIDENCE** in the report (per-host badge + executive-summary callout) and exported in
  `hosts.csv`. The threshold is configurable (`low_confidence_threshold`, default 90;
  `--low-confidence-threshold` CLI override).
- **Parse reconciliation** — `scan.py` warns when OpenSCAP's own `<score>` diverges from
  the parsed pass/fail counts, so a mis-parse can't masquerade as truth.
- **Persistence** of `not_checked` / `other` counts (with a forward-safe column migration
  that upgrades an existing `history.db` in place).
- **`HostStatus.HOST_KEY_MISMATCH`** — a changed SSH host key is reported as a security
  finding (possible MITM / unverified re-provisioning), not plain "unreachable".
- Report sections: executive summary, fleet trend sparkline, severity breakdown, and a
  **non-exhaustive, orientation-only CIS→NIST 800-53 / ISO 27001 cross-walk**.
- **Opt-in unknown-Linux promotion** (`treat_unknown_linux_as_ubuntu`, default off):
  hosts that look like some non-specific Linux (no Ubuntu marker, but not clearly
  non-Linux) can be promoted to Ubuntu *candidates* so the authoritative SSH detect
  stage gets to confirm or reject them. The flag is part of the canonical config, so
  it changes `config_hash` — two runs that differ only by it don't share provenance.
- Project docs: README, operating guide, design doc, single-VM validation guide; MIT
  LICENSE; 97-test pytest suite with namespaced XCCDF fixtures.

### Fixed
- **`unknown` verdicts no longer read as trustworthy coverage (never-false-pass).** The prior
  confidence fix excluded the whole `other` bucket from the denominator, but the parser dumps
  XCCDF `unknown` (a check that ran but reached no verdict — OVAL probe error) into `other`
  alongside out-of-scope `notselected`. A scan returning mostly `unknown` could therefore read
  100% confidence and certify SCANNED. `unknown` is now counted with `error` (it owed a verdict
  and produced none); only genuinely out-of-scope results (`notselected`/`informational`/
  `fixed`) stay in `other` and out of the denominator. Verdict text is also lowercased so the
  scan parser and the `rmf` parser bucket identically.
- **Root-login groups (`sudo: false`) are no longer false-errored.** `scan_host` hardcoded
  `sudo -n` on the oscap run and the temp-dir cleanup, ignoring a credential group's
  `sudo: false` (which `detect` honors to mean "the login user is already root"). On a box
  without sudo that turned a fully scannable host into a `scan_error`. `ScanPlan` now carries
  `sudo` and `scan_host` respects it.
- **Drift baselines only against finished runs.** `previous_run_id` filtered on `run_id` alone,
  so a run that crashed mid-fleet (partial hosts persisted, `finished_at` NULL) could become the
  drift baseline and produce a spurious delta. It now requires `finished_at IS NOT NULL`.
- **`rmf` never downgrades a fail.** A merged / multi-`TestResult` ARF can repeat a rule's
  `idref`; last-write-wins could drop a real failure and report the control `Implemented` in SSP
  evidence. A failing result now sticks for that rule.
- **OS detection is provenance-tracked.** `--os-detect` (and `--deep`'s OS-detect) fed discovery
  without entering `config_hash`/`effective-config.json`, so two runs that behaved differently
  could hash identically. `os_detect` is now a canonical config field (settable in YAML or via
  the flags), honoring the "two runs hash the same iff they behave the same" invariant.
- **Out-of-profile rules no longer tank assessment confidence.** A complete CIS scan reports a
  `notselected` result for every datastream rule outside the chosen profile (241 of 639 on a
  real Ubuntu 22.04 run), which the parser buckets into `other`. `assessment_confidence` was
  dividing by *every* rule-result — so those out-of-scope rules read as "checks that did not
  run," dragging a clean, fully-privileged scan down to 62% and stamping it **LOW confidence /
  "insufficient privilege / scores NOT trustworthy."** Confidence is now measured only over the
  checks that *owed* a verdict (`pass + fail + notapplicable + error + notchecked`); a rule the
  profile never selected neither helps nor hurts it. The same run now reads 100% and certifies
  cleanly. The never-false-pass guard is unchanged: `error`/`notchecked` (the real
  insufficient-privilege signal) still lower confidence, and a scan where nothing owed a verdict
  is `scan_error`, never a clean pass. The LOW badge's "N unverified" count likewise drops
  `other`.
- **Actionable `scanner_absent` remediation.** The detail for missing SSG content pointed the
  operator at apt package `ssg-base`, but that package is not in the Ubuntu 22.04 archive (a
  live fire-test confirmed `apt install` can't find it). The detail now points at the real
  source — a SCAP Security Guide / ComplianceAsCode `ssg-ubuntu*-ds.xml` datastream, or
  setting `ssg_dir` — so the guidance is a next step, not a dead end. (The oscap-binary detail
  already named the correct package, `libopenscap8`.)
- **No false "first recorded run" in the report.** The executive-summary trend sentence
  claimed "(first recorded run)" whenever a fleet delta couldn't be computed — including when
  a *later* run simply scored nothing (e.g. every host `scanner_absent`), which misstated the
  audit history. It now distinguishes a genuine first run from "this run scored nothing" and
  "the prior run had no score"; the trend-chart caption likewise reads "Not enough scored runs
  yet to plot a trend." rather than "First recorded run with results".
- **Parse reconciliation no longer false-alarms.** The score-vs-counts check compared
  oscap's *weighted* `<score>` against a flat pass-ratio with too tight a tolerance, so a
  legitimate result warned "verify raw evidence" on every parse. It now flags only a gross
  contradiction, preserving the alarm's signal value.
- **Assessment confidence is now in the JSON export.** `to_dict()` surfaces the per-host
  `assessment_confidence` / `total_outcomes` that `dataclasses.asdict()` omitted, so the
  JSON matches the CSV and HTML.
- **Honest low-confidence badge.** The per-host badge said "N not run" using only
  `not_checked`; an error-driven low score then rendered "0 not run". It now reports the
  count of all undetermined checks (error + notchecked + other) as "N unverified".
- **`config_hash` is computed from the effective configuration.** It now hashes the
  resolved, override-applied config (canonicalized, order-independent) instead of the raw
  YAML with selective mirroring, so **every** run-affecting override — `--cis-level` (which
  changes the rule set), `--cidr`, `--concurrency`, threshold — changes the hash. Two runs
  hash identically iff they would behave identically. The effective config is also written
  per run as `effective-config.json`.
- **Runs persist incrementally and can't hang forever.** The run row is written before any
  SSH and each host is persisted as it completes, so a crash mid-fleet leaves a
  visibly-incomplete run with partial results instead of orphaned evidence and no record.
  SFTP transfers now carry a channel timeout, so a stalled/hostile host can no longer wedge
  a worker (and thus the whole run) indefinitely.
- **Graceful error on a non-numeric `low_confidence_threshold`** in YAML — a `ConfigError`
  instead of an unhandled `ValueError` traceback.
- **Faithful reload of coverage counts.** A run persisted before the `not_checked`/`other`
  columns existed reloads with those counts as `None` ("unknown"), so its confidence reads
  honestly as unknown instead of a fabricated 0 that would inflate an old low-privilege
  scan toward a false-clean reading.
- **Bastion host-key mismatch keeps its security signal.** A key mismatch on the *jump
  host* (possible MITM) is now reported as `host_key_mismatch`, not flattened into a
  generic bastion error and demoted to plain `unreachable`.
- **Collision-resistant run ids.** A run id is now a sortable UTC timestamp plus a short
  random suffix, so two runs started in the same second can no longer share an id and
  overwrite or be confused with each other's on-disk evidence. `begin_run` is also
  idempotent (it clears any rows already recorded for the id), so a resumed/retried run
  can't double-insert hosts or findings.
- **Inconclusive os-release is retry-able, not terminal.** A host whose `/etc/os-release`
  is readable but carries no `ID=` field (empty / garbled / truncated) is now recorded as
  `scan_error` ("inconclusive — re-run to confirm") instead of `non_ubuntu`. A transient
  truncation can no longer permanently bucket a possibly-Ubuntu host out of scope.

### Changed
- **Testable remote-exec seam.** Introduced `RemoteHostProtocol` and a `FakeRemoteHost`
  double so the detect/scan decision layer — the load-bearing middle of the never-false-pass
  guarantee, previously with zero coverage — is now exercised by offline decision-table tests
  (non-ubuntu, sudo-absent, scanner-absent, unsupported-version, happy path; oscap error /
  no-results / clean scan). This locks the injection and status-mapping fixes against
  regression.
- Documentation consolidated into `docs/` with a single canonical home per topic.
- **Live-validation guide fire-tested + corrected.** `docs/validation.md` was run
  end-to-end against a real cloud Ubuntu 22.04 target and rewritten to match reality: the
  mandatory venv (PEP 668), the correct `oscap` package (`libopenscap8` on 22.04 — the old
  `openscap-scanner`/`ssg-debderived` names aren't in Ubuntu's archive), pulling SSG content
  from the ComplianceAsCode release, an `echo`-based `authorized_keys` install (the
  interactive-`tee` paste silently corrupts the key), a pre-flight `AUTH_OK` SSH check, and
  the cloud-target classification fix (`nmap_extra_args: ["-Pn","-p22"]` +
  `treat_unknown_linux_as_ubuntu`). The run also live-validated the honest-coverage chain
  (`non_ubuntu` → `scanner_absent` → `scanned`).
- **Operating guide + status synced to the fire-tested reality.** `docs/operating.md` still
  showed a bare `pip install` (fails under PEP 668) and vague "provision oscap + SSG (config
  mgmt)" with no commands — the exact snags the live run hit. It now mandates the venv and
  cross-references `validation.md` §0/§1.1 for the real install (`libopenscap8`, SSG datastream
  from a ComplianceAsCode release), keeping `validation.md` the single source of truth. The
  README and `design.md` "live scan leg not yet validated" status is corrected — it has now
  been validated end-to-end — and the stale "96-test suite" count is updated to 97 everywhere.
- Refactor: single source of truth for the low-confidence default and rule
  (`models.DEFAULT_LOW_CONFIDENCE_THRESHOLD`, `ScanResult.is_low_confidence`); shared
  threshold validation; the report template renders low-confidence by IP membership rather
  than re-deriving the comparison.

### Security (hardening from an adversarial review)
- **Fixed a root-RCE on the audited host.** The remote temp dir came from the target's own
  `mktemp` stdout and was interpolated unquoted into a `sudo` cleanup command, so a hostile
  host could run arbitrary commands as root via the scan account. The path is now validated
  against a strict allowlist, and all remote commands go through a new shell-quoting argv
  seam (`RemoteHost.run_argv`).
- **Fixed stored XSS in the HTML report.** Jinja2 autoescape was effectively off (the
  `select_autoescape` filename check never matched `report.html.j2`), so a malicious host's
  hostname/banner/os-release or oscap rule titles rendered as live markup in the analyst's
  browser. Autoescaping is now forced on.
- **Fixed CSV formula injection.** Target-derived cells in `hosts.csv`/`findings.csv` that
  begin with `= + - @` are now quote-prefixed so a spreadsheet cannot execute them.
- **Closed scope / blast-radius gaps.** All scope inputs now run through one set of
  validators on both the file and CLI-override paths: `--cidr` is validated (it previously
  bypassed validation), an over-broad scope (wider than `/16`, e.g. `/8` or `0.0.0.0/0`) is
  refused, `ssh_concurrency` is bounded to 1–100, `nmap_extra_args` may not smuggle in
  targets or scope/output-altering flags, and `scope.exclude` is re-enforced after discovery
  before any SSH (defense in depth).
- **Hardened untrusted-XML parsing.** `results.xml` (written by a possibly-hostile target)
  and nmap output are now parsed with `defusedxml`, blocking entity-expansion ("billion
  laughs") DoS, DTD retrieval, and external-entity references regardless of the interpreter's
  expat version. Target-supplied rule ids/titles/severities are also control-char-stripped
  and length-bounded before entering the report model.
- **Evidence sealed at rest + owner-only outputs.** Each run writes a `manifest.json` of
  SHA-256 digests (and sizes) over the report and every retained per-host artifact, so a
  post-hoc edit to evidence on disk is detectable. All run output is now created owner-only
  (umask `0o077`) so the fleet's posture/scope isn't world-readable on a shared run host. The
  residual-trust boundary (a host rooted by the tool can forge its own scorecard) is
  documented in `docs/design.md`.

### Security / integrity posture
- The tool never installs software on or modifies the hosts it audits.
- Host-key verification is strict (`RejectPolicy`); unknown keys are rejected, not
  auto-accepted.
- The failure mode is visible under-reporting, never an invisible false pass.

---

## Build history

**Walking skeleton.** The approved design ([docs/design.md](docs/design.md)) was built one
host end-to-end across the full pipeline (discover → classify → reach → detect → scan →
persist → report), with three frozen contracts (config schema, per-host result model,
SQLite schema) as stable seams.

**Hardening (parallel team).** Five agents then hardened distinct modules with exclusive
file ownership:
- **oscap correctness** — version normalization, pre-flight `oscap info` profile check,
  evidence capture, namespace-tolerant XCCDF parsing, guaranteed remote temp cleanup.
- **reporting** — executive summary, fleet trend, severity breakdown, NIST/ISO cross-walk.
- **discovery/classify** — nmap XML parsing that tolerates missing elements, large-scope
  chunking, timing validation, broader Ubuntu heuristics.
- **SSH/bastion** — a `RemoteError` exception taxonomy (incl. host-key mismatch), bastion
  teardown, hardened command execution, host-key bootstrap docs.
- **tests** — the pytest suite + XCCDF fixtures.

All changes were re-verified on the merged tree, then the assessment-confidence guard and
configurable threshold were added on top.
