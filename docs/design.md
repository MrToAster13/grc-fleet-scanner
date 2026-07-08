# Design

The rationale behind GRC Fleet Auditor — what it is, the decisions that shaped it, and
what is deliberately out of scope. For day-to-day use see [operating.md](operating.md);
for build history see [../CHANGELOG.md](../CHANGELOG.md).

---

## 1. Purpose

A Python CLI, run from a Linux workstation or jump host, that **discovers hosts on an
authorized network, audits the reachable Ubuntu hosts against the CIS Benchmark via
OpenSCAP, and produces a fleet compliance report with drift history** — intended as audit
evidence for a GRC (Governance, Risk & Compliance) analyst.

The tool's value is **discovery + fleet orchestration + reporting**. It does **not**
reimplement compliance checks; it wraps a trusted scanner (OpenSCAP) so the verdicts stay
authoritative and audit-defensible.

## 2. Hard preconditions

- **Authorization.** The operator must have written sign-off to actively scan the target
  IP ranges. The tool refuses to run without an explicit scope and logs every action it
  takes. It cannot manufacture authority to scan.
- **Run host.** Must run from Linux (WSL2 is fine). `nmap` + Python run on Windows, but
  the OpenSCAP toolchain is Linux-native.
- **Network line-of-sight.** The run host must reach the target CIDRs and SSH to the
  in-scope hosts (directly or via a configured bastion).

## 3. Pipeline

```
discover (nmap) → classify → reach (SSH) → detect (oscap/SSG) → scan (oscap) → persist (SQLite) → report
```

1. **Scope** — load YAML config; CLI flags override.
2. **Discover** — cautious `nmap` sweep over in-scope CIDRs → live hosts, OS fingerprint,
   open ports, banners. Exclusions honored. Every action logged.
3. **Classify** — Ubuntu vs non-Ubuntu (conservative hint); match each to a credential group.
4. **Reach** — SSH (agent keys, host keys verified against `known_hosts`, bastion-aware),
   `sudo` for root-only checks.
5. **Detect** — confirm exact Ubuntu version; verify `oscap` + matching SSG content; a
   pre-flight `oscap info` confirms the resolved profile exists before scanning.
6. **Scan** — run OpenSCAP with the matching CIS profile; pull back raw ARF/HTML + scanner
   stdout/stderr.
7. **Persist** — timestamped, immutable result set in SQLite + raw artifacts on disk.
8. **Report** — HTML dashboard (coverage map, executive summary, severity breakdown, fleet
   trend, top failing controls with a NIST/ISO cross-walk, **assessment confidence**) +
   JSON/CSV exports + retained raw OpenSCAP evidence.

## 4. Coverage model

Every host lands in exactly one honest bucket. The report surfaces all of them so partial
coverage is never mistaken for a clean result:

| Status | Meaning |
|---|---|
| `scanned` | Audited against CIS |
| `non_ubuntu` | Alive, not Ubuntu — inventory only |
| `no_credentials` | Ubuntu, no credential group matched its IP |
| `unreachable` | Expected reachable but SSH failed |
| `scanner_absent` | `oscap`/SSG content not present (never installed) |
| `unsupported_version` | No SSG CIS profile for that Ubuntu release |
| `host_key_mismatch` | SSH host key ≠ pinned key — a **security finding** |
| `scan_error` | Scan attempted but errored, or completed with too little coverage to certify (below the hard confidence floor) |

## 5. Design principles

- **Audit integrity over coverage.** Never modify the system under assessment. Partial
  coverage is acceptable; silent or fabricated coverage is not.
- **Fail toward under-reporting, never toward a false pass.** A check that did not run is
  never counted as a pass; an unassessable host gets an explicit gap status, not an
  invented score. This is enforced *structurally*, not by convention: a single chokepoint
  (`finalize_scan_status`) gates the `scanned` verdict, and a scan that evaluated nothing —
  or whose coverage falls below a **hard, non-overridable floor (50%)** — is recorded as
  `scan_error`, never a clean pass. Above that floor, **assessment confidence** (the % of
  the benchmark that produced a verdict) still flags a high score that only reflects the few
  checks that actually ran (typically a low-privilege scan) via the operator-tunable badge.
- **Authoritative check logic.** Compliance verdicts come from OpenSCAP, not hand-rolled
  checks, to keep evidence defensible.
- **Evidence is sealed at rest; the scanner on the target is trusted.** Each run writes a
  `manifest.json` of SHA-256 digests over the report and every retained per-host artifact, so
  post-hoc tampering with evidence on disk is detectable. This does **not** defend against a
  *host that forges its own results before they are pulled*: the tool reaches the target as
  root and trusts the `oscap` binary and the `results.xml` it produces, so a host already
  rooted can fabricate a clean scorecard. That is an inherent residual-trust property of any
  local/agent scanner (a host compromised enough to forge evidence is, by definition, not in
  a true-clean state) — treat a target the tool reaches as root as able to lie about itself.
  Output is written owner-only (umask `0o077`) since it encodes the fleet's full internal
  posture and scope.
- **Profile-version match is mandatory.** A host is scanned only with the SSG profile
  matching its exact Ubuntu version; mismatches are flagged, never scanned.
- **Everything the tool does is logged** — the run log is itself an audit artifact.
- **Safe, configurable defaults.** Conservative scan timing, bounded concurrency, and a
  low-confidence threshold out of the box; all tunable.

## 6. Locked design decisions

| Dimension | Decision |
|---|---|
| Meaning of "systems" | Hosts on a network |
| Discovery | Active network scan (nmap) |
| Depth | Scan, then SSH deep-dive on hosts with credentials |
| Framework | CIS Ubuntu Benchmark |
| Build vs wrap | **Wrap OpenSCAP** (SCAP Security Guide CIS profile) — do not reimplement checks |
| Missing scanner | Detect, flag, **do not install** on the audited host |
| Auth + privilege | SSH keys via ssh-agent + `sudo`; verify host keys; bastion supported |
| Output | HTML dashboard + JSON/CSV exports + retained raw evidence |
| Cadence | On-demand CLI, persist immutable history, report drift; schedule externally |
| Language | Python |
| Scale | Tens–low hundreds of hosts; cautious (`-T3`, ~10 parallel SSH, per-host timeouts) |
| CIS profile level | **Level 1** default; configurable globally and per credential-group |

## 7. Components

| Module | Responsibility |
|---|---|
| `models.py` | **Contract:** `HostStatus`, `HostRecord`, `ScanResult` (incl. `assessment_confidence`), `RunRecord` |
| `config.py` / `profiles.py` | **Contract:** YAML schema + validation; SSG datastream/profile registry |
| `discovery.py` | nmap orchestration + XML parse |
| `classify.py` | Ubuntu hint + credential-group matching |
| `remote.py` | SSH/bastion, host-key verification, sudo, SFTP; a clear failure taxonomy |
| `detect.py` | Ubuntu version + oscap/SSG presence + profile resolution |
| `scan.py` | remote `oscap` eval + evidence retrieval + XCCDF result parse + reconciliation |
| `store.py` | **Contract:** SQLite schema + immutable run persistence (forward-safe migration) |
| `report.py` / `crosswalk.py` | HTML dashboard + JSON/CSV + drift + indicative NIST/ISO cross-walk |
| `cli.py` | orchestration, argparse, bounded concurrency |

The three frozen contracts — the config schema, the per-host result model, and the SQLite
schema — are stable seams that let the modules evolve independently.

## 8. Deliberately out of scope (v1)

- Long-running daemon / live web service.
- Auto-remediation (OpenSCAP can generate fixes; assessment-only for v1).
- Non-Ubuntu deep-dive (other OSes appear in inventory as discovered-only).
- Pulling inventory from CMDB / Ansible / cloud APIs (active scan is the v1 source).
- Vault / short-lived credential issuance (agent-based keys for v1).

## 9. Known deferred enhancements

Surfaced during development, intentionally not built yet:

| Enhancement | Rationale |
|---|---|
| `config: treat_unknown_linux_as_ubuntu` | `classify.py` already reads it defensively (default off); add the field + YAML wiring to enable promoting unknown-Linux hosts to SSH-detect candidates. |
| `ScanResult.oscap_version` field | Scanner version is captured into `host.detail`; a dedicated field + column would make it queryable audit metadata. |
| `ScanResult.stdout_path` / `stderr_path` fields | `oscap.stdout.txt` / `oscap.stderr.txt` are written as evidence but their paths aren't recorded on the contract. |
| `findings` table denormalization (`ip` / `run_id`) | Would enable rule-level cross-run trend; not needed by current features. |

## 10. Status & validation

Offline behavior is covered by a 123-test pytest suite. The live SSH→`oscap` scan leg has
now been validated end-to-end against a real cloud Ubuntu 22.04 host — both the happy path
(a full CIS scan producing a real score) and the negative-path honest-gap checks
(`scanner_absent`, `host_key_mismatch`, and the rest of §6). Still re-run
[validation.md](validation.md) against a single VM in any new environment (including its
negative-path checks) before trusting a fleet run.
