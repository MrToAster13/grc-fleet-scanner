# GRC Fleet Auditor

Discover hosts on an **authorized** network, audit the reachable Ubuntu hosts against the
**CIS Benchmark** (via OpenSCAP), and produce a fleet compliance report with drift history
— built as audit evidence for a GRC (Governance, Risk & Compliance) analyst.

The tool's job is **discovery + fleet orchestration + reporting**. It does *not*
reimplement compliance checks — it wraps OpenSCAP so the verdicts stay authoritative and
audit-defensible.

> ⚠️ **Authorized use only.** This tool actively scans networks and logs into hosts. Run
> it only against systems you have **written authorization** to assess. It refuses to run
> without an explicit scope and logs every action it takes — but it cannot grant you
> authority you don't have.

> ℹ️ **Status:** functional and tested offline (45-test suite). The live
> SSH → OpenSCAP scan path has not yet been validated against a real Ubuntu host — see
> [VALIDATION.md](VALIDATION.md) before relying on a production run.

---

## Pipeline

```
discover (nmap) → classify → reach (SSH) → detect (oscap/SSG) → scan (oscap) → persist (SQLite) → report (HTML/JSON/CSV + drift)
```

Every host ends in an honest coverage bucket — `scanned`, `non_ubuntu`, `no_credentials`,
`unreachable`, `scanner_absent`, `unsupported_version`, `host_key_mismatch`, or
`scan_error`. Partial coverage is never presented as a clean result.

## Features

- Active network discovery (nmap) with cautious defaults and large-scope chunking
- Authenticated CIS scanning via OpenSCAP + the SCAP Security Guide (Ubuntu 18.04–24.04)
- Strict SSH host-key verification, bastion/jump-host support, agent-based keys + sudo
- Consolidated HTML dashboard: executive summary, coverage map, severity breakdown,
  fleet trend, top failing controls with an indicative NIST 800-53 / ISO 27001 cross-walk
- Machine-readable exports (JSON/CSV) + retained raw OpenSCAP evidence (ARF/HTML) per host
- Run-over-run **drift** history in SQLite
- Never modifies the system under audit (missing scanner → flagged, never installed)

---

## Requirements

**Run host** (where you run the tool):
- **Linux** — Debian/Ubuntu/Kali/WSL2 (the OpenSCAP toolchain is Linux-native)
- **Python 3.8+** (3.10+ recommended)
- `nmap` and `git`
- SSH access to the targets (key in `ssh-agent`), directly or via a bastion

**Target hosts** (to be deep-scanned):
- **Ubuntu** (18.04 / 20.04 / 22.04 / 24.04 LTS)
- `oscap` + the matching SCAP Security Guide datastream installed
- An SSH account you hold a key for, with **passwordless sudo** (CIS reads root-only files)

> Hosts without `oscap`/content are reported `scanner_absent`; the tool does **not** install
> anything on a host under audit.

---

## Installation (run host)

Works on Debian, Ubuntu, and Kali.

```bash
# 1. System dependencies
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip nmap

# 2. Get the code
git clone https://github.com/MrToAster13/grc-fleet-scanner.git
cd grc-fleet-scanner

# 3. Python environment + dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Verify the install (no network needed)

```bash
# Unit suite — should report "45 passed"
python -m pytest

# Offline end-to-end demo — renders a sample report you can open in a browser
python smoketest.py
```

---

## Quick start

```bash
# 1. Create your config from the example
cp config.example.yaml config.yaml
nano config.yaml          # set scope.cidrs to your AUTHORIZED range + credential_groups

# 2. Dry run — discover + classify only; NO SSH, NO scanning (always do this first)
python -m grc_auditor run -c config.yaml --dry-run -v

# 3. Full audit
python -m grc_auditor run -c config.yaml

# 4. List prior runs
python -m grc_auditor history -o ./grc-output
```

Reports and evidence land under `grc-output/runs/<run_id>/` (see [Output](#output)).

### Common flags

| Flag | Effect |
|---|---|
| `-c, --config PATH` | config file (required) |
| `--dry-run` | discover + classify only; no SSH, no scan |
| `--cidr CIDR` | override scope CIDR (repeatable) |
| `--cis-level {1,2}` | override CIS level (default 1) |
| `--concurrency N` | parallel SSH/scan workers |
| `--os-detect` | enable nmap OS detection (`-O`; needs root on the run host) |
| `-v, --verbose` | debug logging |

---

## Preparing a target host

Full provisioning + a step-by-step first-run validation is in [VALIDATION.md](VALIDATION.md).
The essentials, on the **Ubuntu target**:

```bash
# OpenSCAP + CIS content (package names vary by release)
sudo apt update
sudo apt install -y openscap-scanner ssg-debderived
ls /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml   # match your release

# A scan account with passwordless sudo (CIS reads root-only files)
sudo adduser --disabled-password grc-scan
echo 'grc-scan ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/grc-scan
# ...then add the run host's SSH public key to /home/grc-scan/.ssh/authorized_keys
```

On the **run host**, pre-trust the target's SSH host key (verification is strict — unknown
keys are rejected, not auto-accepted):

```bash
ssh-keyscan -t ed25519 <target_ip> >> ~/.ssh/known_hosts
# verify the fingerprint out-of-band before trusting it
```

---

## Configuration

Minimal `config.yaml`:

```yaml
scope:
  cidrs: [10.0.10.0/24]      # REQUIRED — your authorized range(s)
output_dir: "./grc-output"
cis_level: 1                 # 1 = baseline, 2 = stricter
credential_groups:
  - name: servers
    targets: [10.0.10.0/24]
    ssh_user: grc-scan
    key_path: "~/.ssh/grc_scan_ed25519"   # omit to rely on ssh-agent
    sudo: true
```

Full field reference (exclusions, nmap timing, concurrency, bastion, per-group CIS level,
`ssg_dir`, `known_hosts`) is documented in [OPERATING.md](OPERATING.md) and
[config.example.yaml](config.example.yaml).

---

## Output

Under `output_dir/runs/<run_id>/`:

| File | What it is |
|---|---|
| `report.html` | Consolidated fleet dashboard |
| `report.json` | Full run data for GRC-platform ingestion |
| `hosts.csv`, `findings.csv` | Spreadsheet/ticketing exports (findings include NIST/ISO tags) |
| `audit.log` | Every action the tool took (an audit artifact itself) |
| `<host_ip>/results.xml`, `arf.xml`, `report.html` | Raw OpenSCAP evidence (immutable) |
| `<host_ip>/oscap.stdout.txt`, `oscap.stderr.txt` | Captured scanner output |

`output_dir/history.db` holds run history and powers drift.

---

## Documentation

| Doc | Purpose |
|---|---|
| [OPERATING.md](OPERATING.md) | Operator runbook — setup, config reference, reading the report, scheduling, troubleshooting |
| [VALIDATION.md](VALIDATION.md) | Validate the live scan leg against one Ubuntu VM (incl. negative-path checks) |
| [SPEC.md](SPEC.md) | Design and the decisions behind it |
| [INTEGRATION.md](INTEGRATION.md) | What was built/hardened and the deferred decisions |

---

## Security & authorization

- Only scan ranges you are **authorized** to assess; keep the written approval with the output.
- Prefer `ssh-agent`; use a dedicated least-purpose scan account; protect any sudo-capable key.
- Host identity is verified against `known_hosts`; a changed key surfaces as
  `host_key_mismatch` (a security finding), never auto-accepted.
- Raw evidence and `audit.log` are your audit trail — retain per policy; never edit them.

## License

Released under the [MIT License](LICENSE).

## Contributing

Issues and pull requests welcome. Run `python -m pytest` (45 tests) before submitting;
keep the offline `python smoketest.py` working.
