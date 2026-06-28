# GRC Fleet Auditor

Discovers hosts on an **authorized** network, audits the reachable Ubuntu hosts
against the **CIS Benchmark via OpenSCAP**, and produces a fleet compliance
report with drift history — built as audit evidence for a GRC analyst.

The tool's job is **discovery + fleet orchestration + reporting**. It does *not*
reimplement compliance checks; it wraps OpenSCAP so the verdicts stay
authoritative and audit-defensible. See [SPEC.md](SPEC.md) for the full approved
design and the decisions behind it.

> **Status: walking skeleton.** Every pipeline stage is present and wired
> end-to-end for a single host. The shared contracts (config, host model,
> SQLite schema) are frozen so the remaining hardening can be parallelized.

---

## Pipeline

```
discover (nmap) → classify → reach (SSH) → detect (oscap/SSG) → scan (oscap) → persist (SQLite) → report (HTML/JSON/CSV + drift)
```

Every host lands in an honest coverage bucket: `scanned`, `non_ubuntu`,
`no_credentials`, `unreachable`, `scanner_absent`, `unsupported_version`, or
`scan_error`. Partial coverage is never presented as a clean result.

## Hard preconditions

- **Authorization.** You must have written sign-off to actively scan the target
  ranges. The tool refuses to run without an explicit scope and logs everything
  it touches; it cannot manufacture authority to scan.
- **Run from Linux.** `nmap` + Python run on Windows, but the OpenSCAP toolchain
  is Linux-native. Run the tool from a Linux workstation or jump host (WSL2 is
  fine for development). It needs network line-of-sight + SSH to the fleet.
- **No install on targets.** If a host lacks `oscap`/SSG content, it is flagged
  `scanner_absent` — the tool never modifies the system under audit.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# On the RUN host you also need: nmap. Targets need: oscap + ssg content.
```

## Configure

```bash
cp config.example.yaml config.yaml
$EDITOR config.yaml          # set scope.cidrs and credential_groups
```

## Run

> **Operators:** see **[OPERATING.md](OPERATING.md)** for the full runbook — setup,
> config reference, reading the report, scheduling, troubleshooting, and audit hygiene.

```bash
# Discover + classify only — safe, no SSH, no scanning:
python -m grc_auditor run -c config.yaml --dry-run

# Full fleet audit:
python -m grc_auditor run -c config.yaml

# Overrides:
python -m grc_auditor run -c config.yaml --cidr 10.0.30.0/24 --cis-level 2 -o ./out

# History:
python -m grc_auditor history -o ./grc-output
```

Output lands under `output_dir/runs/<run_id>/`:
`report.html` (dashboard) · `report.json` · `hosts.csv` · `findings.csv` ·
`audit.log` · per-host raw `results.xml` / `arf.xml` / `report.html` evidence.
Run-over-run history lives in `output_dir/history.db` and drives drift.

## Verify the plumbing offline

No fleet handy? This renders a full report from canned data (needs only PyYAML +
Jinja2, runs on any OS):

```bash
python smoketest.py        # prints a path to a generated report.html
```

## Module map (seams for parallel work)

| Module | Responsibility |
|---|---|
| `models.py` | **Contract:** HostRecord, HostStatus, ScanResult, RunRecord |
| `config.py` / `profiles.py` | **Contract:** YAML schema; SSG datastream/profile registry |
| `discovery.py` | nmap orchestration + XML parse |
| `classify.py` | Ubuntu hint + credential-group matching |
| `remote.py` | SSH/bastion, host-key verification, sudo, SFTP |
| `detect.py` | Ubuntu version + oscap/SSG presence + profile resolution |
| `scan.py` | remote `oscap` eval + evidence retrieval + result parse |
| `store.py` | **Contract:** SQLite schema + immutable run persistence |
| `report.py` | HTML dashboard + JSON/CSV export + drift |
| `cli.py` | orchestration, argparse, bounded concurrency |

## Deliberately out of scope (v1)

Long-running daemon · auto-remediation · non-Ubuntu deep-dive · CMDB/Ansible
inventory import · Vault-issued credentials. See SPEC.md §8.
