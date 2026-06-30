# Operating Guide — GRC Fleet Auditor

A hands-on runbook for the analyst who runs this tool. For the design rationale see
[design.md](design.md); for first-time live validation see [validation.md](validation.md).
For installation, see the [README](../README.md#install-run-host).

---

## The golden rule

**Only scan what you are authorized to scan.** This tool performs *active* network
discovery and logs into hosts. Run it only against IP ranges your organization has given
you written sign-off to assess. The tool will refuse to run without an explicit scope and
records every action in an audit log — but it cannot grant you authority you don't have.

---

## 1. What it does (in one breath)

`discover (nmap)` → `classify` → `SSH in` → `detect oscap/CIS content` →
`run OpenSCAP CIS scan` → `persist` → `report (HTML + JSON/CSV + drift)`.

Every host ends in an **honest coverage bucket**. Partial coverage is never dressed up as
a clean result — see the status table in §6.

---

## 2. Before you operate

**Run host** (where you run the tool) — must be **Linux** (WSL2 is fine):
- `nmap` installed (`sudo apt install nmap`)
- Python 3.10+ and this project's deps (`pip install -r requirements.txt`)
- Network line-of-sight to the targets, and SSH reachability (directly or via a bastion)
- Your SSH key loaded in `ssh-agent`

**Target hosts** (to be deep-scanned) — must be **Ubuntu** with:
- `oscap` installed + the matching SCAP Security Guide datastream
  (`/usr/share/xml/scap/ssg/content/ssg-ubuntu<NNNN>-ds.xml`)
- An SSH account you hold a key for, with **passwordless sudo** (CIS reads root-only files)

> Hosts missing `oscap`/content are reported `scanner_absent` — the tool **never installs
> anything** on a host under audit.

---

## 3. One-time setup

### 3.1 Install (run host)
```bash
cd grc-fleet-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 3.2 Bootstrap host keys (host identity is verified — strictly)
The tool refuses unknown host keys (no auto-accept). Pre-populate `known_hosts` and
**verify each fingerprint out-of-band** before trusting it:
```bash
ssh-keyscan -t ed25519 <host_or_cidr_members> >> ~/.ssh/known_hosts
# compare against the host's own:  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```
Treat `known_hosts` as audit-controlled inventory. A *changed* key later surfaces as
`host_key_mismatch` (a security finding), and must be re-verified, not blindly re-added.

### 3.3 Write `config.yaml`
Copy and edit the example:
```bash
cp config.example.yaml config.yaml
$EDITOR config.yaml
```
See the full field reference in §5.

---

## 4. Running

Always **dry-run first** — it discovers and classifies but does **no SSH and no scanning**:
```bash
python -m grc_auditor run -c config.yaml --dry-run -v
```
Confirm the host list and scope look right, then run for real:
```bash
python -m grc_auditor run -c config.yaml
```

**Reading the console summary:**
```
Run 20260627T161000Z-3f9a1c complete.   # sortable UTC stamp + short random suffix
  Hosts discovered : 42      # alive hosts found by nmap
  Scanned          : 31      # successfully audited against CIS
  Coverage gaps    : 7       # Ubuntu hosts we could NOT fully assess (investigate these)
  Fleet pass rate  : 88.4%   # aggregate CIS pass % across scanned hosts
  Report           : .../runs/<run_id>/report.html
```

**List prior runs:**
```bash
python -m grc_auditor history -o ./grc-output
```

### CLI flags (override config per-run)
| Flag | Effect |
|---|---|
| `-c, --config PATH` | config file (required) |
| `--dry-run` | discover + classify only; no SSH, no scan |
| `--cidr CIDR` | override scope CIDR (repeatable) |
| `--exclude CIDR` | override exclusions (repeatable) |
| `-o, --output DIR` | override output directory |
| `--cis-level {1,2}` | override global CIS level |
| `--concurrency N` | override parallel SSH/scan workers |
| `--low-confidence-threshold PCT` | flag a score LOW CONFIDENCE below this % of the benchmark producing a verdict (default 90) |
| `--os-detect` | enable nmap OS detection (`-O`; needs root on the run host) |
| `-v, --verbose` | debug-level console logging |

---

## 5. Configuration reference

```yaml
scope:
  cidrs: [10.0.10.0/24]      # REQUIRED — authorized ranges. Empty => refuses to run.
                             #   Refused if wider than /16 (blast-radius guard).
  exclude: [10.0.10.1]       # IPs/ranges to skip; re-enforced before SSH, not just nmap
  nmap_timing: "-T3"         # cautious default; only -T0..-T5 accepted
  nmap_extra_args: []        # flags only — no bare targets, no scope/output-altering flags
  ssh_concurrency: 10        # bounded parallel SSH/scan workers (1..100)
  host_timeout_seconds: 600  # per-host scan timeout

output_dir: "./grc-output"   # history.db + per-run reports/evidence
cis_level: 1                 # global default: 1 = baseline, 2 = stricter
ssg_dir: "/usr/share/xml/scap/ssg/content"   # where SSG content lives on targets
low_confidence_threshold: 90 # flag a host LOW CONFIDENCE below this % of checks running
treat_unknown_linux_as_ubuntu: false  # default false; if true, probe unknown-Linux hosts
                             #   as Ubuntu candidates (SSH detect stays authoritative)
# known_hosts: "~/.ssh/known_hosts"          # omit => system + user known_hosts

credential_groups:           # first matching group (top-down) wins
  - name: prod
    targets: [10.0.10.0/24]  # CIDRs / exact IPs / ["default"] catch-all
    ssh_user: grc-scan
    key_path: "~/.ssh/grc_scan_ed25519"   # omit => rely on ssh-agent
    use_agent: true
    ssh_port: 22
    sudo: true               # uses passwordless `sudo -n` for root-only checks
    cis_level: 2             # optional per-group override of global cis_level
    bastion:                 # optional jump host
      host: bastion.example.com
      user: jump
      key_path: "~/.ssh/bastion_ed25519"
```

---

## 6. Interpreting the report

Open `runs/<run_id>/report.html`. The **coverage map** tells you, for every host, why it
is where it is. Act on the gaps:

| Status | Meaning | What to do |
|---|---|---|
| `scanned` | Audited against CIS | Review failing controls / score |
| `non_ubuntu` | Alive, not Ubuntu | Out of scope for this tool; inventory only |
| `no_credentials` | Ubuntu, no credential group matched its IP | Add/adjust a `credential_groups` entry |
| `unreachable` | Expected reachable but SSH failed | Check network/sshd/firewall/key |
| `scanner_absent` | `oscap`/SSG content missing on host | Provision oscap + SSG (config mgmt) |
| `unsupported_version` | No SSG CIS profile for that Ubuntu release | EOL/odd release — upgrade or accept gap |
| `host_key_mismatch` | **SSH host key ≠ pinned key** | **SECURITY: investigate** (MITM? re-provision?) before re-trusting |
| `scan_error` | Scan errored, **or** completed with too little coverage to certify (below the hard floor) | Read the host's `oscap.stderr.txt` + `audit.log`; if "assessment incomplete", fix the scan account's sudo/privilege |

**Other report sections:** executive summary (posture + biggest risks), fleet trend
(pass-rate sparkline over recent runs), severity breakdown, and top failing controls with
an indicative **NIST 800-53 / ISO 27001 cross-walk** (orientation only — authoritative
references live in the raw ARF evidence).

**Assessment confidence (read this before trusting a score).** Each scanned host shows a
confidence % = how much of the benchmark actually produced a verdict. A low-privilege scan
leaves many checks `notchecked`, so a high *score* can cover only a few checks that ran.
Any host below `low_confidence_threshold` (default 90%) is flagged **LOW · N unverified**
next to its score, with a callout in the executive summary. Treat low-confidence scores as
untrustworthy until the scan account's `sudo` access is fixed. Tune the threshold via
`low_confidence_threshold` in config or `--low-confidence-threshold` on the CLI.

> The configurable threshold only controls the **badge**. Below a separate **hard,
> non-overridable floor (50%)** a scan is too incomplete to certify at all: the host is
> recorded as `scan_error` ("assessment incomplete"), never `scanned`, regardless of the
> threshold you set. A near-empty scan can never read as a clean host.
**Always read the coverage-gaps count alongside the pass rate** — never the pass rate alone.

**Where everything lands** under `output_dir/runs/<run_id>/`:
- `report.html` — the fleet dashboard
- `report.json` — full data for GRC-platform ingestion
- `hosts.csv`, `findings.csv` — spreadsheet/ticketing exports
- `audit.log` — every action the tool took (an audit artifact in its own right)
- `<host_ip>/results.xml`, `arf.xml`, `report.html` — **raw OpenSCAP evidence** (immutable)
- `<host_ip>/oscap.stdout.txt`, `oscap.stderr.txt` — captured scanner output
- `manifest.json` — SHA-256 + size of every report/evidence file (chain-of-custody seal)
- `effective-config.json` — the resolved config (after CLI overrides) this run used
- `output_dir/history.db` — run history that powers drift

Outputs are written **owner-only** (umask `0o077`): the evidence encodes the fleet's full
internal posture and scope, so it must not be world-readable on a shared run/jump host.

---

## 7. Recurring runs (scheduling)

The tool is on-demand and persists history; schedule it **externally**.

**cron (run host):**
```cron
# 02:30 every Monday
30 2 * * 1  cd /opt/grc-fleet-scanner && . .venv/bin/activate && python -m grc_auditor run -c config.yaml >> /var/log/grc-audit.cron.log 2>&1
```

**systemd timer:** a `grc-audit.service` (`Type=oneshot`, `ExecStart=...python -m grc_auditor run -c config.yaml`) plus a `grc-audit.timer` (`OnCalendar=weekly`).

Each run appends an immutable, timestamped result set, so trend/drift accrues automatically.

---

## 8. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `config error: scope.cidrs is empty` | Populate `scope.cidrs` (the authorization guard) |
| `nmap not found on the run host` | `sudo apt install nmap`; run from Linux/WSL2 |
| Host shows `host_key_mismatch` | **Stop.** Verify the host's real key (§3.2); only re-trust after confirming a legitimate re-provision |
| Host shows `unreachable` | sshd down / firewall / wrong key / agent not loaded — test `ssh -i <key> <user>@<ip>` |
| Host shows `scanner_absent` | oscap/SSG not installed on target, or `ssg_dir` wrong |
| Host shows `scan_error` | Read `<ip>/oscap.stderr.txt` and the run `audit.log` |
| Scans hang / slow | Lower `ssh_concurrency`, raise `host_timeout_seconds`, or use `-T2` |
| Permission/sudo failures | The scan account needs **passwordless** sudo on targets |

Run with `-v` for debug logging; the per-run `audit.log` has the full trace.

---

## 9. Security & audit hygiene

- **Authorization first.** Keep the written scope approval with the run output.
- **Credentials:** prefer `ssh-agent`; use a dedicated least-purpose scan account; protect
  any key authorized for sudo across the fleet. The tool never uses password auth.
- **Host identity:** keep `known_hosts` under change control; treat `host_key_mismatch`
  as a security event.
- **Evidence:** the raw ARF/HTML per host and the `audit.log` are your audit trail — retain
  them per your evidence-retention policy; never edit them.
- **The tool never:** installs software on audited hosts, modifies their configuration,
  auto-accepts unknown host keys, or scans outside the configured scope.

---

## 10. First time? 

Don't point it at the fleet on day one. Run one Ubuntu VM through
[validation.md](validation.md) end-to-end — including the six negative-path checks — then
widen `scope.cidrs` to the authorized range.
