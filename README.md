# GRC Fleet Auditor

Discover hosts on an **authorized** network, audit the reachable Ubuntu hosts against the
**CIS Benchmark** (via OpenSCAP), and produce a fleet compliance report with drift history:
built as audit evidence for a GRC (Governance, Risk & Compliance) analyst.

The tool's job is **discovery + fleet orchestration + reporting**. It does *not*
reimplement compliance checks: it wraps OpenSCAP so the verdicts stay authoritative and
audit-defensible.

> ⚠️ **Authorized use only.** This tool actively scans networks and logs into hosts. Run it
> only against systems you have **written authorization** to assess. It refuses to run
> without an explicit scope and logs every action, but it cannot grant you authority you
> don't have.

> ℹ️ **Status:** functional, tested offline (148-test suite), and validated end-to-end
> against a real cloud Ubuntu 22.04 host: the happy path (a full CIS scan producing a real
> score) plus the negative-path honest-gap checks (`scanner_absent`, `host_key_mismatch`, ...).
> Re-run [docs/validation.md](docs/validation.md) in any new environment before relying on a
> production fleet run.

---

## Pipeline

```
discover (nmap) → classify → reach (SSH) → detect (oscap/SSG) → scan (oscap) → persist (SQLite) → report (HTML/JSON/CSV + drift)
```

Every host ends in an honest coverage bucket: `scanned`, `non_ubuntu`, `no_credentials`,
`unreachable`, `scanner_absent`, `unsupported_version`, `host_key_mismatch`, or
`scan_error`. Partial coverage is never presented as a clean result, and a high score that
only reflects the checks that actually ran is flagged **low confidence**.

## Features

- Active network discovery (nmap) with cautious defaults and large-scope chunking
- Authenticated CIS scanning via OpenSCAP + the SCAP Security Guide (Ubuntu 18.04 to 24.04)
- `--deep` high-assurance mode: forces CIS Level 2, `oscap --fetch-remote-resources`, and
  aggressive discovery for maximum coverage/confidence (recorded in `config_hash`)
- Strict SSH host-key verification, bastion support, agent-based keys + sudo
- HTML dashboard: executive summary, coverage map, severity breakdown, fleet trend,
  assessment-confidence flags, and a NIST 800-53 / ISO 27001 cross-walk
- Machine-readable exports (JSON/CSV) + retained raw OpenSCAP evidence (ARF/HTML) per host
- `rmf` export: a NIST 800-53 control rollup (RMF SSP evidence) built from the retained ARF's
  authoritative per-rule references
- Run-over-run **drift** history in SQLite
- Never modifies the system under audit (missing scanner → flagged, never installed)
- Single-word commands (`grc-run`, `grc-dry`, `grc-deep`, ...) with a self-bootstrapping
  virtualenv and run-host `nmap` auto-install; targets are prepped explicitly and separately

## Requirements

**Run host** (where you run the tool): **Linux** (Debian/Ubuntu/Kali/WSL2), **Python 3.8+**
(3.10+ recommended), `git`, and SSH access to the targets. `nmap` is installed for you by
`grc-setup` (or on demand at the start of the first run).

**Target hosts** (to be deep-scanned): **Ubuntu** (18.04/20.04/22.04/24.04) with `oscap` +
the matching SCAP Security Guide datastream, and an SSH account with **passwordless sudo**
(CIS reads root-only files). Hosts without `oscap` are reported `scanner_absent`: the tool
never installs anything on a host under audit.

## Install (run host)

Works on Debian, Ubuntu, Kali, and WSL2. Two commands, no root:

Run this from inside a Linux shell (WSL2, a VM, or a Linux box), not from Windows PowerShell.

```bash
git clone https://github.com/MrToAster13/grc-fleet-scanner.git
cd grc-fleet-scanner
./install.sh        # puts the grc-* commands on your PATH (~/.local/bin)
grc-setup           # builds the virtualenv + deps, and installs nmap on this host
```

`install.sh` copies the single-word launchers into `~/.local/bin` and records where the repo
lives (it offers to add `~/.local/bin` to your PATH if it isn't already). `grc-setup` then
builds the `.venv`, installs the Python dependencies, and makes sure `nmap` is present:
auto-installing it through your package manager (apt/dnf/pacman/zypper/brew) and asking for
`sudo` only when it has to. Sanity-check it offline:

```bash
grc-demo            # renders a sample report you can open in a browser
```

### Manual install (from source, no launchers)

```bash
sudo apt update && sudo apt install -y git python3 python3-venv python3-pip nmap
git clone https://github.com/MrToAster13/grc-fleet-scanner.git && cd grc-fleet-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest        # expect: 148 passed
python smoketest.py     # renders a sample report you can open in a browser
```

## Quick start

From any working directory:

```bash
grc-run             # first run scaffolds ./config.yaml, then stops so you can edit it
$EDITOR config.yaml # set scope.cidrs to your AUTHORIZED range + credential_groups
grc-dry             # discover + classify only; NO SSH, NO scanning (always do this first)
# on each TARGET (not this run host): grc-provision --print | ssh <user>@<target> 'sudo bash -s -- --scan-user grc-scan'
grc-run             # full audit against ./config.yaml
```

The first `grc-run` writes a starter `config.yaml` (from `config.example.yaml`, with an
**empty** scope) and exits: it refuses to run until you set an authorized range, and an
empty scope stays refused. That's the authorization guard, on purpose.

The commands (`grc-run`, `grc-dry`, and `grc-deep` read `./config.yaml`; extra flags pass straight through to the tool):

| Command | Does |
|---|---|
| `grc-run` | full fleet audit |
| `grc-dry` | discover + classify only: no SSH, no scan |
| `grc-deep` | high-assurance audit (CIS L2 + remote-resource fetch + aggressive discovery) |
| `grc-history` | list prior runs |
| `grc-report` | open the latest run's HTML report (or print its path when headless) |
| `grc-rmf` | export a NIST 800-53 control rollup (SSP evidence) from a run's ARF |
| `grc-demo` | render a sample report offline |
| `grc-setup` | build the venv/deps + install nmap on this run host |
| `grc-provision` | how to prepare an Ubuntu **target** (`grc-target-setup`) |

Reports and evidence land under `grc-output/runs/<run_id>/` (`report.html`, `report.json`,
`hosts.csv`, `findings.csv`, `audit.log`, and per-host raw OpenSCAP evidence); `grc-report`
opens the latest for you. The launchers just wrap `python -m grc_auditor ...`, which still
works directly (`python -m grc_auditor run -c config.yaml`) if you prefer. Full field
reference, scheduling, troubleshooting, and report interpretation are in the
[operating guide](docs/operating.md).

## Documentation

| Doc | Purpose |
|---|---|
| [docs/operating.md](docs/operating.md) | Operator runbook: setup, config reference, reading the report, scheduling, troubleshooting |
| [docs/validation.md](docs/validation.md) | Validate the live scan leg against one Ubuntu VM (incl. negative-path checks) |
| [docs/design.md](docs/design.md) | Design, decisions, coverage model, and what's out of scope |
| [docs/handoffs/](docs/handoffs/) | Session handoff docs: audit findings, the MVP carve reasoning, and what each pass verified |
| [AGENTS.md](AGENTS.md) | Writing + organization rules for AI agents editing this repo's docs |
| [CHANGELOG.md](CHANGELOG.md) | What's changed and the build history |

## Security & authorization

- Only scan ranges you are **authorized** to assess; keep the written approval with the output.
- Prefer `ssh-agent`; use a dedicated least-purpose scan account; protect any sudo-capable key.
- Host identity is verified against `known_hosts`; a changed key surfaces as
  `host_key_mismatch` (a security finding), never auto-accepted.
- Raw evidence and `audit.log` are your audit trail: retain per policy; never edit them.

## License

Released under the [MIT License](LICENSE).

## Contributing

Issues and PRs welcome. Run `python -m pytest` (148 tests) before submitting; keep the
offline `python smoketest.py` working.

A pre-commit hook runs the suite for you and blocks a commit if it fails. Enable it once
per clone:

```bash
git config core.hooksPath .githooks
```
