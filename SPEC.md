# GRC Fleet Auditor — Specification

**Status:** Approved design (pre-implementation)
**Date:** 2026-06-27
**Owner:** elijahjzion@gmail.com

---

## 1. Purpose

A Python CLI, run from a Linux workstation or jump host, that **discovers hosts on an
authorized network, audits the reachable Ubuntu hosts against the CIS Benchmark via
OpenSCAP, and produces a fleet compliance report with drift history** — intended as
audit evidence for a GRC (Governance, Risk & Compliance) analyst.

The tool's value is **discovery + fleet orchestration + unified reporting**. It does
**not** reimplement compliance checks; it wraps a trusted scanner (OpenSCAP) so the
check logic stays authoritative and audit-defensible.

---

## 2. Hard preconditions

- **Authorization.** The operator must have written sign-off to actively scan the
  target IP ranges. The tool refuses to run without an explicitly populated scan scope
  and logs every action it takes. It cannot manufacture authority to scan.
- **Run host.** Must run from Linux (WSL2 is fine for development). `nmap` and Python
  run on Windows, but the OpenSCAP toolchain (`oscap`, `oscap-ssh`) is Linux-native.
- **Network line-of-sight.** The run host must be able to reach the target CIDRs and
  SSH to the in-scope hosts (directly or via a configured bastion).

---

## 3. Pipeline

1. **Scope** — load a YAML config: scan CIDRs + exclusions, credential groups
   (ssh user, key/agent, sudo method, bastion), output dir, concurrency/timing,
   optional SSG/profile overrides. CLI flags override config values.
2. **Discover** — `nmap` sweep (cautious `-T3`) over in-scope CIDRs → live hosts, OS
   fingerprint, open ports, service banners. Exclusions honored. Every action logged.
3. **Classify** — separate Ubuntu hosts from non-Ubuntu; match each Ubuntu host to a
   credential group.
4. **Reach** — SSH in (agent-based keys, host keys verified against `known_hosts`,
   bastion-aware). Use `sudo` for root-only checks.
5. **Detect** — confirm exact Ubuntu version; verify `oscap` + matching SSG content are
   present.
   - Scanner absent → mark host **reachable, scanner absent**; **do not install**
     anything (audit integrity).
   - No SSG profile for that version (odd/EOL release) → **flag, do not mis-scan**.
6. **Scan** — run OpenSCAP with the **CIS Level 1** profile matching that exact Ubuntu
   version. Pull back raw ARF + HTML.
7. **Persist** — write a timestamped, immutable result set to SQLite + raw artifacts on
   disk.
8. **Report** — produce:
   - **HTML fleet dashboard**: coverage map (scanned / reachable-unscanned /
     unreachable / non-Ubuntu), pass-fail rates, top fleet-wide failing controls,
     per-host drill-down, **drift vs. prior runs**.
   - **JSON/CSV exports** for ticketing / GRC-platform ingestion.
   - **Retained raw OpenSCAP ARF/HTML** per host as immutable audit evidence.

---

## 4. Locked design decisions

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
| Scale / aggressiveness | Tens–low hundreds of hosts; cautious (`-T3`, ~10 parallel SSH, per-host timeouts) |
| Config | YAML config file + CLI overrides; runs from workstation/jump host |
| CIS profile level | **Level 1** default; configurable per credential-group |

---

## 5. Design principles

- **Audit integrity over coverage.** Never modify the system under assessment. Partial
  coverage is acceptable; silent or fabricated coverage is not.
- **Honest coverage is a feature.** The report loudly surfaces what it could *not*
  assess (no creds, no scanner, EOL version) so partial coverage is never mistaken for
  a clean result.
- **Authoritative check logic.** Compliance verdicts come from OpenSCAP, not from
  hand-rolled checks, to keep evidence defensible.
- **Profile-version match is mandatory.** A host is scanned only with the SSG profile
  matching its exact Ubuntu version; mismatches are flagged, never scanned.
- **Everything the tool does is logged** — the run log is itself an audit artifact.
- **Safe, configurable defaults.** Conservative scan timing and bounded concurrency out
  of the box; tunable for the environment.

---

## 6. Component breakdown (Python)

- `config` — YAML schema + validation + CLI override merge. **Defines contracts the
  rest of the system depends on.**
- `discovery` — nmap orchestration + parse → host records.
- `classify` — Ubuntu detection, credential-group matching.
- `remote` — SSH/bastion connection mgmt (Paramiko/Fabric), host-key verification,
  sudo handling.
- `detect` — Ubuntu version + oscap/SSG presence + profile resolution.
- `scan` — OpenSCAP invocation (`oscap-ssh` or remote `oscap`), artifact retrieval.
- `store` — SQLite schema + immutable run persistence + raw artifact layout.
- `report` — Jinja2 HTML dashboard, JSON/CSV exporters, drift computation.
- `cli` — entrypoint, run orchestration, logging.

**Shared contracts (define first, before any parallel work):**
1. YAML config schema.
2. The per-host result object (status enum: scanned / reachable-unscanned /
   unreachable / non-Ubuntu / unsupported-version; plus scan results).
3. SQLite schema (runs, hosts, findings).

---

## 7. Suggested build order

Walking skeleton first — **one host end-to-end** — then fan out to the fleet:

1. `config` + scope loading
2. `discovery`
3. `remote` reach + `detect`
4. single-host `scan` (oscap)
5. `store` (persistence)
6. `report`
7. drift (multi-run)

---

## 8. Deliberately deferred / out of scope (v1)

- Long-running daemon / live web service.
- Auto-remediation (OpenSCAP can generate fixes; assessment-only for v1).
- Non-Ubuntu deep-dive (other OSes appear in inventory as discovered-only).
- Pulling inventory from CMDB/Ansible/cloud APIs (active scan is the v1 source).
- Vault/short-lived credential issuance (agent-based keys for v1).
