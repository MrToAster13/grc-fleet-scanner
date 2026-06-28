# Live-Scan Validation — Single Ubuntu VM

Goal: exercise the one path the offline tests can't — **discover → SSH → `oscap` → report**
— against a real Ubuntu host, and confirm each coverage-gap status fires correctly.
Do this before trusting a fleet run.

All of this must run from a **Linux run host** (WSL2 is fine). The run host needs `nmap`
and the Python deps; the target VM needs `oscap` + SSG content.

---

## 0. Prerequisites

**Run host (Linux / WSL2):**
```bash
sudo apt install -y nmap
cd grc-fleet-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

**Target VM:** a fresh Ubuntu 22.04 LTS (or 20.04/24.04) on a network the run host can
reach. Note its IP (referred to as `<VM_IP>`).

---

## 1. Provision the target VM

```bash
# On the VM — install the scanner + CIS content:
sudo apt update
sudo apt install -y openscap-scanner ssg-debderived
# Verify the binary and the datastream the tool expects exist:
command -v oscap
ls -l /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml   # match your release
```
> Package names vary by release. The tool needs the `oscap` binary and a datastream at
> `/usr/share/xml/scap/ssg/content/ssg-ubuntu<NNNN>-ds.xml`. If the content lands
> elsewhere, set `ssg_dir` in the config.

**Scan account with passwordless sudo** (CIS reads root-only files):
```bash
# On the VM:
sudo adduser --disabled-password grc-scan
echo 'grc-scan ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/grc-scan
sudo mkdir -p /home/grc-scan/.ssh
# paste the run host's public key:
sudo tee /home/grc-scan/.ssh/authorized_keys < ~/.ssh/grc_scan_ed25519.pub
sudo chown -R grc-scan:grc-scan /home/grc-scan/.ssh && sudo chmod 600 /home/grc-scan/.ssh/authorized_keys
```

---

## 2. Bootstrap the host key (host-key verification is strict)

The tool uses `RejectPolicy` — an unknown host key is refused, not auto-accepted.
```bash
# On the run host:
ssh-keyscan -t ed25519 <VM_IP> >> ~/.ssh/known_hosts
# VERIFY the fingerprint out-of-band against the VM:
#   on the VM:  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
ssh-keygen -lf <(ssh-keyscan -t ed25519 <VM_IP> 2>/dev/null)   # compare the two
```

---

## 3. Write a scoped config

`vm-validate.yaml`:
```yaml
scope:
  cidrs:
    - <VM_IP>/32          # exactly one host
  nmap_timing: "-T3"
output_dir: "./vm-output"
cis_level: 1
credential_groups:
  - name: vm
    targets: ["<VM_IP>/32"]
    ssh_user: grc-scan
    key_path: "~/.ssh/grc_scan_ed25519"
    use_agent: true
    sudo: true
```

---

## 4. Happy path

```bash
# Discovery + classify only (no SSH, no scan) — should find the VM and mark it ready:
python -m grc_auditor run -c vm-validate.yaml --dry-run -v

# Full audit:
python -m grc_auditor run -c vm-validate.yaml -v
```

**Expect:** console summary shows `Scanned: 1`, a fleet pass rate, and a report path.

**Confirm artifacts under `vm-output/runs/<run_id>/`:**
- [ ] `report.html` — host shows `scanned`, a CIS score, pass/fail counts, failing controls
- [ ] `report.json`, `hosts.csv`, `findings.csv` (findings.csv has NIST/ISO columns)
- [ ] `audit.log` — records the AUTHORIZATION line + every action
- [ ] `<VM_IP>/results.xml`, `arf.xml`, `report.html` (raw OpenSCAP evidence)
- [ ] `<VM_IP>/oscap.stdout.txt`, `oscap.stderr.txt` (captured scanner output)
- [ ] `vm-output/history.db` exists

**Cross-check the numbers** (the integrity test — our parse vs. OpenSCAP's own report):
- [ ] Open the per-host `<VM_IP>/report.html` (OpenSCAP's own) and confirm its
      pass/fail totals match the fleet `report.html` and `results.xml`.

---

## 5. Negative paths (each should produce the right honest-gap status)

Run a fresh audit after each change and check the host's status in `report.html`:

- [ ] **`scanner_absent`** — `sudo apt remove -y openscap-scanner` on the VM, re-run.
      Host should be `scanner_absent` (and the tool must **not** install anything).
- [ ] **`unsupported_version`** — temporarily point `ssg_dir` at an empty dir, or test on
      a non-LTS release. Host should be `unsupported_version`, not a mis-scan.
- [ ] **`no_credentials`** — remove the `credential_groups` entry (or change its
      `targets` so it doesn't match). Host should be `no_credentials`.
- [ ] **`unreachable`** — stop sshd on the VM (`sudo systemctl stop ssh`), re-run.
      Host should be `unreachable` with a clear reason.
- [ ] **`host_key_mismatch`** — corrupt the pinned key:
      `ssh-keygen -R <VM_IP>` then add a *wrong* key line for `<VM_IP>` to
      `~/.ssh/known_hosts` (or re-provision the VM's host key). Re-run.
      Host should be **`host_key_mismatch`** (security finding), not `unreachable`.
      Then re-bootstrap (step 2) to restore.
- [ ] **sudo-not-passwordless** — remove the sudoers drop-in, re-run. Should report a
      scanner/sudo failure with an actionable detail, not a silent zero-score scan.

---

## 6. Drift (history)

```bash
# Run twice (optionally harden one control between runs to change the score):
python -m grc_auditor run -c vm-validate.yaml
python -m grc_auditor run -c vm-validate.yaml
python -m grc_auditor history -o ./vm-output
```
- [ ] Second `report.html` shows a **drift Δ vs prior** for the host and a fleet trend
      with two points.
- [ ] `history` lists both runs, newest first.

---

## Sign-off

The live-scan leg is validated when: the happy path produces matching numbers against
OpenSCAP's own report, **all six negative paths** produce the correct status, and drift
renders across two runs. After that, widen `scope.cidrs` to the authorized fleet range
and run for real.
