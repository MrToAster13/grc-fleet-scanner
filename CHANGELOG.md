# Changelog

All notable changes to GRC Fleet Auditor. This project is pre-1.0; until a tagged
release, everything lives under **Unreleased**.

## [Unreleased]

### Added
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
- Project docs: README, operating guide, design doc, single-VM validation guide; MIT
  LICENSE; 77-test pytest suite with namespaced XCCDF fixtures.

### Fixed
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
- **`--low-confidence-threshold` is captured in `config_hash`.** A CLI override is now
  mirrored into the hashed config, so two runs that differ only by threshold no longer
  share provenance.
- **Graceful error on a non-numeric `low_confidence_threshold`** in YAML — a `ConfigError`
  instead of an unhandled `ValueError` traceback.
- **Faithful reload of coverage counts.** A run persisted before the `not_checked`/`other`
  columns existed reloads with those counts as `None` ("unknown"), so its confidence reads
  honestly as unknown instead of a fabricated 0 that would inflate an old low-privilege
  scan toward a false-clean reading.
- **Bastion host-key mismatch keeps its security signal.** A key mismatch on the *jump
  host* (possible MITM) is now reported as `host_key_mismatch`, not flattened into a
  generic bastion error and demoted to plain `unreachable`.

### Changed
- Documentation consolidated into `docs/` with a single canonical home per topic.
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
  evidence capture, resilient XCCDF parsing, guaranteed remote temp cleanup.
- **reporting** — executive summary, fleet trend, severity breakdown, NIST/ISO cross-walk.
- **discovery/classify** — robust nmap XML parsing, large-scope chunking, timing
  validation, broader Ubuntu heuristics.
- **SSH/bastion** — a `RemoteError` exception taxonomy (incl. host-key mismatch), bastion
  teardown, hardened command execution, host-key bootstrap docs.
- **tests** — the pytest suite + XCCDF fixtures.

All changes were re-verified on the merged tree, then the assessment-confidence guard and
configurable threshold were added on top.
