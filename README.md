# GRC Fleet Auditor

Discover hosts on an **authorized** network, audit the reachable Ubuntu hosts against the
**CIS Benchmark** (via OpenSCAP), and produce a fleet compliance report with drift history
— built as audit evidence for a GRC (Governance, Risk & Compliance) analyst.

The tool's job is **discovery + fleet orchestration + reporting**. It does *not*
reimplement compliance checks — it wraps OpenSCAP so the verdicts stay authoritative and
audit-defensible.

> ⚠️ **Authorized use only.** This tool actively scans networks and logs into hosts. Run it
> only against systems you have **written authorization** to assess. It refuses to run
> without an explicit scope and logs every action — but it cannot grant you authority you
> don't have.

> ℹ️ **Status:** functional, tested offline (107-test suite), and validated end-to-end
> against a real cloud Ubuntu 22.04 host — the happy path (a full CIS scan producing a real
> score) plus the negative-path honest-gap checks (`scanner_absent`, `host_key_mismatch`, …).
> Re-run [docs/validation.md](docs/validation.md) in any new environment before relying on a
> production fleet run.

---

## Pipeline

```
discover (nmap) → classify → reach (SSH) → detect (oscap/SSG) → scan (oscap) → persist (SQLite) → report (HTML/JSON/CSV + drift)
```

Every host ends in an honest coverage bucket — `scanned`, `non_ubuntu`, `no_credentials`,
`unreachable`, `scanner_absent`, `unsupported_version`, `host_key_mismatch`, or
`scan_error`. Partial coverage is never presented as a clean result, and a high score that
only reflects the checks that actually ran is flagged **low confidence**.

## Features

- Active network discovery (nmap) with cautious defaults and large-scope chunking
- Authenticated CIS scanning via OpenSCAP + the SCAP Security Guide (Ubuntu 18.04–24.04)
- Strict SSH host-key verification, bastion support, agent-based keys + sudo
- HTML dashboard: executive summary, coverage map, severity breakdown, fleet trend,
  assessment-confidence flags, and a NIST 800-53 / ISO 27001 cross-walk
- Machine-readable exports (JSON/CSV) + retained raw OpenSCAP evidence (ARF/HTML) per host
- `rmf` export: a NIST 800-53 control rollup (RMF SSP evidence) built from the retained ARF's
  authoritative per-rule references
- Run-over-run **drift** history in SQLite
- Never modifies the system under audit (missing scanner → flagged, never installed)

## Requirements

**Run host** (where you run the tool): **Linux** (Debian/Ubuntu/Kali/WSL2), **Python 3.8+**
(3.10+ recommended), `nmap`, `git`, and SSH access to the targets.

**Target hosts** (to be deep-scanned): **Ubuntu** (18.04/20.04/22.04/24.04) with `oscap` +
the matching SCAP Security Guide datastream, and an SSH account with **passwordless sudo**
(CIS reads root-only files). Hosts without `oscap` are reported `scanner_absent` — the tool
never installs anything on a host under audit.

## Install (run host)

Works on Debian, Ubuntu, and Kali:

```bash
# 1. System dependencies
sudo apt update && sudo apt install -y git python3 python3-venv python3-pip nmap

# 2. Get the code
git clone https://github.com/MrToAster13/grc-fleet-scanner.git
cd grc-fleet-scanner

# 3. Python environment + dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 4. Verify (no network needed)
python -m pytest        # expect: 107 passed
python smoketest.py     # renders a sample report you can open in a browser
```

## Quick start

```bash
cp config.example.yaml config.yaml
nano config.yaml          # set scope.cidrs to your AUTHORIZED range + credential_groups

# Dry run — discover + classify only; NO SSH, NO scanning (always do this first)
python -m grc_auditor run -c config.yaml --dry-run -v

# Full audit
python -m grc_auditor run -c config.yaml

# History
python -m grc_auditor history -o ./grc-output
```

Reports and evidence land under `grc-output/runs/<run_id>/` (`report.html`, `report.json`,
`hosts.csv`, `findings.csv`, `audit.log`, and per-host raw OpenSCAP evidence). Full field
reference, scheduling, troubleshooting, and report interpretation are in the
[operating guide](docs/operating.md).

## Documentation

| Doc | Purpose |
|---|---|
| [docs/operating.md](docs/operating.md) | Operator runbook — setup, config reference, reading the report, scheduling, troubleshooting |
| [docs/validation.md](docs/validation.md) | Validate the live scan leg against one Ubuntu VM (incl. negative-path checks) |
| [docs/design.md](docs/design.md) | Design, decisions, coverage model, and what's out of scope |
| [AGENTS.md](AGENTS.md) | Writing + organization rules for AI agents editing this repo's docs |
| [CHANGELOG.md](CHANGELOG.md) | What's changed and the build history |

## Security & authorization

- Only scan ranges you are **authorized** to assess; keep the written approval with the output.
- Prefer `ssh-agent`; use a dedicated least-purpose scan account; protect any sudo-capable key.
- Host identity is verified against `known_hosts`; a changed key surfaces as
  `host_key_mismatch` (a security finding), never auto-accepted.
- Raw evidence and `audit.log` are your audit trail — retain per policy; never edit them.

## License

Released under the [MIT License](LICENSE).

## Contributing

Issues and PRs welcome. Run `python -m pytest` (107 tests) before submitting; keep the
offline `python smoketest.py` working.
