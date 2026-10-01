# Design

The rationale behind GRC Fleet Auditor: what it is, the decisions that shaped it, and
what is deliberately out of scope. For day-to-day use see [operating.md](operating.md);
for build history see [../CHANGELOG.md](../CHANGELOG.md).

---

## 1. Purpose

A Python CLI, run from a Linux workstation or jump host, that **discovers hosts on an
authorized network, audits the reachable Ubuntu hosts against the CIS Benchmark via
OpenSCAP, and produces a fleet compliance report with drift history** intended as audit
evidence for a GRC (Governance, Risk & Compliance) analyst.

The tool's value is **discovery + fleet orchestration + reporting**. It does **not**
reimplement compliance checks; it wraps a trusted scanner (OpenSCAP) so the verdicts stay
authoritative and audit-defensible.

## 2. Hard preconditions

- **Authorization.** The operator must have written sign-off to actively scan the target
  IP ranges. The tool refuses to run without an explicit scope and logs every action it
  takes. It cannot manufacture authority to scan.
- **Run host.** Must run from Linux (WSL2 is fine). OpenSCAP itself never runs here:
  `oscap` is always invoked on the remote target over SSH (see `scan.py` and `remote.py`).
  The run host must be Linux because the entire launcher layer (`install.sh`, `bin/*`,
  `grc-target-setup`) is bash, not just the Python core.
- **Network line-of-sight.** The run host must reach the target CIDRs and SSH to the
  in-scope hosts.

## 3. Pipeline

```
discover (nmap) → classify → reach (SSH) → detect (oscap/SSG) → scan (oscap) → persist (SQLite) → report
```

1. **Scope**: load YAML config; CLI flags override.
2. **Discover**: cautious `nmap` sweep over in-scope CIDRs → live hosts, OS fingerprint,
   open ports, banners. Exclusions honored. Every action logged.
3. **Classify**: Ubuntu vs non-Ubuntu (conservative hint); match each to a credential group.
4. **Reach**: SSH (agent keys, host keys verified against `known_hosts`),
   `sudo` for root-only checks.
5. **Detect**: confirm exact Ubuntu version; verify `oscap` + matching SSG content; a
   pre-flight `oscap info` confirms the resolved profile exists before scanning.
6. **Scan**: run OpenSCAP with the matching CIS profile; pull back raw ARF/HTML + scanner
   stdout/stderr.
7. **Persist**: timestamped, immutable result set in SQLite + raw artifacts on disk.
8. **Report**: HTML dashboard (coverage map, executive summary, severity breakdown, fleet
   trend, top failing controls, **assessment confidence**) + JSON/CSV exports + retained
   raw OpenSCAP evidence.

## 4. Coverage model

Every host lands in exactly one honest bucket. The report surfaces all of them so partial
coverage is never mistaken for a clean result:

| Status | Meaning |
|---|---|
| `scanned` | Audited against CIS |
| `non_ubuntu` | Alive, not Ubuntu (inventory only) |
| `no_credentials` | Ubuntu, no credential group matched its IP |
| `unreachable` | Expected reachable but SSH failed |
| `scanner_absent` | `oscap`/SSG content not present (never installed) |
| `unsupported_version` | No SSG CIS profile for that Ubuntu release |
| `host_key_mismatch` | SSH host key ≠ pinned key: a **security finding** |
| `scan_error` | Scan attempted but errored, or completed with too little coverage to certify (below the hard confidence floor) |

**Fleet pass rate, one definition.** "Fleet pass rate" is always `100 * passed /
(passed + failed + error)` summed across `SCANNED` hosts only (`ScanResult.total_evaluated`
is that denominator). `not_applicable`, `not_checked`, and `other` never enter either side of
the ratio. `models.RunRecord.fleet_pass_rate()` and `store.Store.fleet_pass_rate_history()`
both implement this same formula and every report surface (executive summary, fleet trend,
JSON/CSV exports) reads one of the two; do not add a third computation elsewhere.

### Fleet coverage and the executive posture

The executive summary's posture (`strong`, `moderate`, `weak`) is driven by the fleet pass
rate, and that rate only covers hosts that reached `scanned`. On its own it would call a
50-host fleet "strong" when 2 hosts were scanned and passed, even though 40 Ubuntu hosts
were never assessed. So posture also reads the **assessed share**: scanned hosts divided by
scan candidates, where a candidate is every host except `non_ubuntu`. The rules, in order:

| Condition | Posture |
|---|---|
| Nothing scanned, or no evaluable results | `no-data` (unchanged) |
| Pass rate below 75% | `weak`, at any coverage |
| Assessed share below **50%** | `incomplete` |
| Pass rate 90% or more and assessed share **90%** or more | `strong` |
| Anything else that would have been `strong` or `moderate` | `moderate` |

Why these numbers:

- **50% floor.** Below it, most of the in-scope fleet is unknown and the pass rate describes
  the minority that happened to be reachable. That sample is biased: the hosts we could not
  reach (missing credentials, broken SSH, no scanner) are usually the least maintained. This
  mirrors the per-host hard confidence floor of 50%: a fleet assessed less than halfway
  cannot be rated, just as a host whose benchmark ran less than halfway cannot be certified.
  `incomplete` renders with the red badge, so it never reads as clean.
- **90% for strong.** It matches the default `low_confidence_threshold` (90%), which already
  sets the bar for trusting a single host's score. A fleet earns "strong" on the same terms:
  at most one host in ten unassessed.
- **Weak stays weak.** Missing hosts can only hide more failures, so low coverage never
  softens a weak verdict into `incomplete`.

Edges:

- **All `non_ubuntu`.** No scan candidates, nothing scanned: `no-data`. The coverage gate
  never fires on an empty candidate set, so there is no division by zero and no invented
  share.
- **`non_ubuntu` hosts never lower the share.** They are out-of-scope inventory, the same
  reason `coverage_gaps()` excludes them. The coverage sentence under the headline still
  divides by every discovered host, as before.
- **Small fleets.** The rule is a plain percentage, so one gap weighs more in a small fleet:
  with 2 candidates and 1 scanned the share is 50% (rated, capped at `moderate`); with 3 of
  4 scanned it is 75% (`moderate`). A small fleet reaches `strong` only when every
  candidate is scanned (any fleet under 10 candidates needs all of them). This is
  deliberate: a single unassessed host in a 4-host fleet is a quarter of the estate.

These are proposed values (ELI-166), pending Elijah's confirmation. They live as
`MIN_COVERAGE_FOR_POSTURE` and `STRONG_COVERAGE_THRESHOLD` in `grc_auditor/report.py` and
are not operator-tunable, for the same reason the per-host floor is not: a config knob
would let a run be dressed up as clean.

## 5. Design principles

- **Audit integrity over coverage.** Never modify the system under assessment. Partial
  coverage is acceptable; silent or fabricated coverage is not.
- **Fail toward under-reporting, never toward a false pass.** A check that did not run is
  never counted as a pass; an unassessable host gets an explicit gap status, not an
  invented score. This is enforced *structurally*, not by convention: a single chokepoint
  (`finalize_scan_status`) gates the `scanned` verdict, and a scan that evaluated nothing,
  or whose coverage falls below a **hard, non-overridable floor (50%)**, is recorded as
  `scan_error`, never a clean pass. Above that floor, **assessment confidence** (the % of
  the benchmark that produced a verdict) still flags a high score that only reflects the few
  checks that actually ran (typically a low-privilege scan) via the operator-tunable badge.
  The same rule applies one level up: the fleet posture can't read `strong` unless 90% of
  scan candidates were assessed, and is `incomplete` below 50% (see section 4).
- **Authoritative check logic.** Compliance verdicts come from OpenSCAP, not hand-rolled
  checks, to keep evidence defensible.
- **Evidence is sealed at rest; the scanner on the target is trusted.** Each run writes a
  `manifest.json` of SHA-256 digests over the report and every retained per-host artifact, so
  post-hoc tampering with evidence on disk is detectable. This does **not** defend against a
  *host that forges its own results before they are pulled*: the tool reaches the target as
  root and trusts the `oscap` binary and the `results.xml` it produces, so a host already
  rooted can fabricate a clean scorecard. That is an inherent residual-trust property of any
  local/agent scanner (a host compromised enough to forge evidence is, by definition, not in
  a true-clean state): treat a target the tool reaches as root as able to lie about itself.
  Output is written owner-only (umask `0o077`) since it encodes the fleet's full internal
  posture and scope.
- **Profile-version match is mandatory.** A host is scanned only with the SSG profile
  matching its exact Ubuntu version; mismatches are flagged, never scanned.
- **Everything the tool does is logged**: the run log is itself an audit artifact.
- **Safe, configurable defaults.** Conservative scan timing, bounded concurrency, and a
  low-confidence threshold out of the box; all tunable.

## 6. Locked design decisions

| Dimension | Decision |
|---|---|
| Meaning of "systems" | Hosts on a network |
| Discovery | Active network scan (nmap) |
| Depth | Scan, then SSH deep-dive on hosts with credentials |
| Framework | CIS Ubuntu Benchmark |
| Build vs wrap | **Wrap OpenSCAP** (SCAP Security Guide CIS profile); do not reimplement checks |
| Missing scanner | Detect, flag, **do not install** on the audited host |
| Auth + privilege | SSH keys via ssh-agent + `sudo`; verify host keys |
| Output | HTML dashboard + JSON/CSV exports + retained raw evidence |
| Cadence | On-demand CLI, persist immutable history, report drift; schedule externally |
| Language | Python |
| Scale | Tens to low hundreds of hosts; cautious (`-T3`, ~10 parallel SSH, per-host timeouts) |
| CIS profile level | **Level 1** default; configurable globally and per credential-group |

## 7. Components

| Module | Responsibility |
|---|---|
| `models.py` | **Contract:** `HostStatus`, `HostRecord`, `ScanResult` (incl. `assessment_confidence`), `RunRecord` |
| `config.py` / `profiles.py` | **Contract:** YAML schema + validation; SSG datastream/profile registry |
| `discovery.py` | nmap orchestration + XML parse |
| `classify.py` | Ubuntu hint + credential-group matching |
| `remote.py` | SSH, host-key verification, sudo, SFTP; a clear failure taxonomy |
| `detect.py` | Ubuntu version + oscap/SSG presence + profile resolution |
| `scan.py` | remote `oscap` eval + evidence retrieval + XCCDF result parse + reconciliation |
| `store.py` | **Contract:** SQLite schema + immutable run persistence (forward-safe migration) |
| `report.py` | HTML dashboard + JSON/CSV + drift |
| `cli.py` | orchestration, argparse, bounded concurrency |

The three frozen contracts (the config schema, the per-host result model, and the SQLite
schema) are stable seams that let the modules evolve independently.

## 8. Deliberately out of scope (v1)

- Long-running daemon / live web service.
- Auto-remediation (OpenSCAP can generate fixes; assessment-only for v1).
- Non-Ubuntu deep-dive (other OSes appear in inventory as discovered-only).
- Pulling inventory from CMDB / Ansible / cloud APIs (active scan is the v1 source).
- Vault / short-lived credential issuance (agent-based keys for v1).

## 9. Drift baselines and scope

`compute_drift` and the fleet trend line only ever compare a run against a
prior run that audited the **same scope and configuration**, matched via the
persisted `config_hash` (it already encodes CIDRs/exclude, credential groups,
CIS level, and every other behavior-affecting setting via `Config.canonical`).
A narrowed CIDR, a different credential group, or any other config change
produces a different hash and is never silently diffed against as if it were
a compliance-posture change. When no comparable prior run exists, the report
says so plainly (distinguishing "first recorded run" from "an earlier run
exists but audited a different scope") instead of falling back to the nearest
run regardless of scope. Absence of a trend is a legitimate result.

**A `grc-dry` pass is never a valid drift or trend baseline, full stop.**
`dry_run` is deliberately excluded from `Config.canonical`/`config_hash` (a
dry run and a full run of the identical config hash identically), so
`config_hash` matching alone cannot tell them apart. A dry run performs no
scan and carries no compliance evidence; comparing against it, or charting it
on the trend line, would either silently skip a real comparable baseline or
report on a run that never assessed anything. Rather than adding a
`dry_run` column to the frozen `runs` schema, dry runs are detected
structurally: a dry run persists its candidate hosts while they are still in
`HostStatus.DISCOVERED` ("alive, not yet processed"), because it never runs
the classify -> reach -> detect -> scan pipeline on them. A real run always
advances every candidate to a terminal status before persisting it. So among
finished runs, any run holding a host row still `discovered` is provably a
dry run, with no schema change and no risk of drifting out of sync with the
pipeline that produces the signature. Both `Store.previous_run_id` and
`Store.fleet_pass_rate_history` exclude this signature unconditionally.

`fleet_pass_rate_history` (and the `fleet_trend`/sparkline it feeds) had the
identical scope blindness as drift: it charted the last N finished runs with
no config_hash filter, so a scope change read as a compliance swing on the
trend line too. It is fixed the same way, in the same pass: an optional
`config_hash` parameter filters the history to runs sharing this run's
config_hash (plus the same dry-run exclusion above). It is scope-comparable
now; there is no remaining reason to consider removing `fleet_trend`
outright.

## 10. Known deferred enhancements

Surfaced during development, intentionally not built yet:

| Enhancement | Rationale |
|---|---|
| `ScanResult.oscap_version` field | Scanner version is captured into `host.detail`; a dedicated field + column would make it queryable audit metadata. |
| `ScanResult.stdout_path` / `stderr_path` fields | `oscap.stdout.txt` / `oscap.stderr.txt` are written as evidence but their paths aren't recorded on the contract. |
| `findings` table denormalization (`ip` / `run_id`) | Would enable rule-level cross-run trend; not needed by current features. |

## 11. Status & validation

Offline behavior is covered by a 200-test pytest suite. The live SSH→`oscap` scan leg has
now been validated end-to-end against a real cloud Ubuntu 22.04 host: both the happy path
(a full CIS scan producing a real score) and the negative-path honest-gap checks
(`scanner_absent`, `host_key_mismatch`, and the rest of §6). Still re-run
[validation.md](validation.md) against a single VM in any new environment (including its
negative-path checks) before trusting a fleet run.
