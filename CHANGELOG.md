# Changelog

All notable changes to GRC Fleet Auditor. This project is pre-1.0; until a tagged
release, everything lives under **Unreleased**.

## [Unreleased]

### Added
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
  LICENSE; 58-test pytest suite with namespaced XCCDF fixtures.

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

### Changed
- Documentation consolidated into `docs/` with a single canonical home per topic.
- Refactor: single source of truth for the low-confidence default and rule
  (`models.DEFAULT_LOW_CONFIDENCE_THRESHOLD`, `ScanResult.is_low_confidence`); shared
  threshold validation; the report template renders low-confidence by IP membership rather
  than re-deriving the comparison.

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
