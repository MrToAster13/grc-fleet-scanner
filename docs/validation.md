# Live-Scan Validation — Single Ubuntu Host

Goal: exercise the one path the offline tests can't — **discover → SSH → `oscap` → report**
— against a real Ubuntu host, and confirm each coverage-gap status fires correctly. Do this
before trusting a fleet run.

This guide is **fire-tested against a cloud Ubuntu 22.04 target from a Kali run host**, so
it calls out the real-world snags (PEP 668, varying package names, cloud SSH banners, strict
host-key auth) that trip up the happy path.

---

## Topology — two machines

| Role | Machine | Needs |
|---|---|---|
| **Run host** | Any Linux (Kali / WSL2 / a VM) | `nmap` + the Python deps; runs the tool |
| **Target** | a **separate Ubuntu** host | `oscap` + the CIS datastream + an SSH scan account |

> ⚠️ **The run host can't be its own target unless the run host is Ubuntu.** The tool only
> deep-scans hosts whose `/etc/os-release` says `ID=ubuntu`. Point it at a Kali/Debian/other
> box and it will (correctly) report `non_ubuntu` and never scan. Kali makes a fine *run
> host*; it is not a valid *target*.

---

## 0. Run host setup

`nmap` ships on Kali; on plain Linux: `sudo apt install -y nmap`. Then:

```bash
cd grc-fleet-scanner
python3 -m venv .venv && source .venv/bin/activate   # REQUIRED
pip install -r requirements.txt
```

> **Why the venv is mandatory:** modern Debian/Kali/Ubuntu mark the system Python
> "externally managed" (PEP 668) and refuse `pip install` into it (`error:
> externally-managed-environment`). The virtualenv is the supported fix — do **not** use
> `--break-system-packages`. If `python3 -m venv` fails, `sudo apt install -y python3-full`.
> Re-activate (`source .venv/bin/activate`) in every new shell — without it you'll hit
> `ModuleNotFoundError`.

Sanity-check the tool offline before going live:
```bash
python -m pytest        # expect: all green
python smoketest.py     # renders a sample report
```

---

## 1. Provision the target (on the **Ubuntu** host)

### 1.1 Install `oscap` + the CIS datastream

```bash
# Ubuntu keeps the openscap packages in 'universe' — enable it if needed:
sudo add-apt-repository -y universe && sudo apt update   # ignore unrelated 3rd-party repo 404s

# oscap binary. The PACKAGE NAME VARIES BY RELEASE — let apt's "command-not-found" confirm:
#   Ubuntu 22.04 -> libopenscap8      |   newer Ubuntu / Debian -> openscap-scanner
sudo apt install -y openscap-scanner || sudo apt install -y libopenscap8
command -v oscap && oscap --version          # must print /usr/bin/oscap + a version
```

The CIS **content** is the part that bites you: the `ssg-*` apt packages are Debian's and
are **not reliably in Ubuntu's archive**. The dependable, version-independent way is the
official SCAP Security Guide release:

```bash
sudo apt install -y unzip curl
cd /tmp
LATEST=$(curl -fsSL https://api.github.com/repos/ComplianceAsCode/content/releases/latest \
         | grep -oP '"tag_name":\s*"\K[^"]+')
curl -fsSL -o ssg.zip \
  "https://github.com/ComplianceAsCode/content/releases/download/${LATEST}/scap-security-guide-${LATEST#v}.zip"
unzip -oq ssg.zip
sudo mkdir -p /usr/share/xml/scap/ssg/content
sudo cp "$(find /tmp -name ssg-ubuntu2204-ds.xml | head -1)" /usr/share/xml/scap/ssg/content/

# Confirm — this is the gate; all three must succeed:
command -v oscap
oscap --version
ls /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml   # match your release: 2004/2204/2404
```
> The tool needs the `oscap` binary plus a datastream at
> `/usr/share/xml/scap/ssg/content/ssg-ubuntu<NNNN>-ds.xml`. If you place content elsewhere,
> set `ssg_dir` in the config. (An older `oscap` — e.g. 1.2.x from `libopenscap8` — can still
> evaluate a current datastream; if it can't, the tool reports `scan_error`, not a false pass.)

### 1.2 Create the scan account (passwordless sudo — CIS reads root-only files)

```bash
sudo adduser --disabled-password --gecos "" grc-scan    # --gecos "" skips the Full Name prompts
echo 'grc-scan ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/grc-scan
sudo chmod 440 /etc/sudoers.d/grc-scan
```

### 1.3 Authorize the run host's key

On the **run host**, generate a key and print its public half:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/grc_scan_ed25519 -N ''   # no passphrase
cat ~/.ssh/grc_scan_ed25519.pub                          # copy this whole line
```

On the **Ubuntu target**, write that line into `grc-scan`'s `authorized_keys`:
```bash
sudo mkdir -p /home/grc-scan/.ssh
echo 'ssh-ed25519 AAAA...your-key... root@runhost' | sudo tee /home/grc-scan/.ssh/authorized_keys
sudo chown -R grc-scan:grc-scan /home/grc-scan/.ssh
sudo chmod 700 /home/grc-scan/.ssh
sudo chmod 600 /home/grc-scan/.ssh/authorized_keys
```
> **Use `echo '<key>' | tee`, not an interactive `tee` you paste into.** When pasted as part
> of a block, an interactive `tee … authorized_keys` silently swallows the *following* pasted
> lines as its input, leaving a garbage key file. The `chmod 700`/`600` matter too — sshd
> ignores keys in a group/world-writable `.ssh` (StrictModes).

---

## 2. Bootstrap the host key (verification is strict)

The tool uses `RejectPolicy` — an unknown host key is refused, not auto-accepted. Pin it on
the **run host** and verify the fingerprint out-of-band:
```bash
ssh-keyscan -t ed25519 <VM_IP> >> ~/.ssh/known_hosts
# compare against the target's own:  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```
A *changed* key later surfaces as `host_key_mismatch` (a security finding), to be re-verified,
not blindly re-added.

---

## 3. Pre-flight: prove the credential chain

**Do this before running the tool** — it verifies key-auth *and* passwordless sudo in one
shot (and the first `yes` also pins the host key). On the **run host**:
```bash
ssh -i ~/.ssh/grc_scan_ed25519 grc-scan@<VM_IP> "sudo -n true && echo AUTH_OK"
```
You must see **`AUTH_OK`** with **no password prompt**. If it asks for a password, the key
isn't accepted — the usual causes:
- the public key on the target doesn't match the private key
  (check on the run host: `ssh-keygen -y -f ~/.ssh/grc_scan_ed25519` vs the installed line);
- wrong ownership/permissions on `/home/grc-scan/.ssh` (re-run the `chown`/`chmod` in §1.3);
- watch the target's `sudo tail -f /var/log/auth.log` while retrying — it states the reason.

Don't proceed until you get `AUTH_OK`.

---

## 4. Write a scoped config

`vm-validate.yaml` (replace `<VM_IP>`; `~` is fine, or use an explicit path like
`/root/.ssh/...`):
```yaml
scope:
  cidrs:
    - <VM_IP>/32                       # exactly one host
  nmap_timing: "-T3"
  nmap_extra_args: ["-Pn", "-p22"]     # see the cloud-target note below
output_dir: "./vm-output"
cis_level: 1
treat_unknown_linux_as_ubuntu: true    # see the cloud-target note below
credential_groups:
  - name: vm
    targets: ["<VM_IP>/32"]
    ssh_user: grc-scan
    key_path: "~/.ssh/grc_scan_ed25519"
    use_agent: true
    sudo: true
```

> **Cloud / firewalled targets** (the two settings above):
> - `-Pn` — cloud hosts usually drop ICMP ping, so nmap would mark them "down" and skip
>   them. `-Pn` treats the host as up.
> - `-p22` — scanning the default 1000 ports over the internet often fails to grab the SSH
>   version banner, so the host classifies as `non_ubuntu` and never gets SSH'd. Scoping to
>   the SSH port gives `-sV` a clean banner read (and is much faster).
> - `treat_unknown_linux_as_ubuntu: true` — if the banner is still stripped, this promotes
>   the host to a *candidate* so the authoritative SSH `detect` (which reads `/etc/os-release`)
>   makes the real call. Safe for a known target; a genuinely non-Ubuntu host is reclassified.
>
> On a plain LAN VM with a normal SSH banner you can omit all three.

---

## 5. Happy path

```bash
source .venv/bin/activate
# Discovery + classify only (no SSH, no scan):
python -m grc_auditor run -c vm-validate.yaml --dry-run -v
# Full audit:
python -m grc_auditor run -c vm-validate.yaml -v
```

The dry-run is your **green light**: it must log `classify: discovered=1` and
`1 host(s) would be deep-scanned`. If it logs `non_ubuntu=1` / `0 would be deep-scanned`,
fix classification first (the cloud-target note in §4).

**Expect** from the real run: `Scanned : 1`, a fleet pass rate, and a report path.

**Confirm artifacts under `vm-output/runs/<run_id>/`:**
- [ ] `report.html` — host shows `scanned`, a CIS score, pass/fail counts, failing controls
- [ ] `report.json`, `hosts.csv`, `findings.csv` (findings.csv has NIST/ISO columns)
- [ ] `manifest.json` — SHA-256 of every artifact; `effective-config.json` — the resolved config
- [ ] `audit.log` — the AUTHORIZATION line + every action
- [ ] `<VM_IP>/results.xml`, `arf.xml`, `report.html`, `oscap.stdout.txt`, `oscap.stderr.txt`
- [ ] `vm-output/history.db` exists

**Cross-check the numbers** (the integrity test — our parse vs. OpenSCAP's own report):
- [ ] Open the per-host `<VM_IP>/report.html` (OpenSCAP's own) and confirm its pass/fail
      totals match the fleet `report.html` and `results.xml`.
- [ ] The host shows a **Confidence** value (≈100% with full sudo) and is **not** flagged
      `LOW` — confirming the scan ran the whole benchmark.

---

## 6. Negative paths (each must produce the right honest-gap status)

Run a fresh audit after each change and check the host's status in `report.html`:

- [ ] **`non_ubuntu`** — point the scope at a non-Ubuntu host (e.g. the Kali run host's own
      IP). Must be `non_ubuntu`, never scanned against the Ubuntu benchmark.
- [ ] **`scanner_absent`** — break the scanner either way and re-run after each: remove the
      oscap binary (`sudo apt remove -y libopenscap8`), **or** hide the SSG content
      (`sudo mv /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml /tmp/`). Host should be
      `scanner_absent` both times (and the tool must **not** install anything). Restore with
      `sudo apt install -y libopenscap8` or by moving the datastream back.
- [ ] **`unsupported_version`** — test on a release the tool has no datastream mapping for
      (anything other than Ubuntu 18.04 / 20.04 / 22.04 / 24.04). Host should be
      `unsupported_version`, not a mis-scan. *(Pointing `ssg_dir` at an empty dir does **not**
      test this: the version is still supported, so missing content reports as `scanner_absent`
      above — `unsupported_version` fires only when no datastream is mapped for the version, or
      the datastream lacks the requested CIS profile.)*
- [ ] **`no_credentials`** — remove the `credential_groups` entry (or change its `targets`
      so it doesn't match). Host should be `no_credentials`.
- [ ] **`unreachable`** — stop sshd on the target (`sudo systemctl stop ssh`), re-run.
      Host should be `unreachable` with a clear reason.
- [ ] **`host_key_mismatch`** — corrupt the pinned key: `ssh-keygen -R <VM_IP>` then add a
      *wrong* key line for `<VM_IP>` to `~/.ssh/known_hosts`. Re-run. Host should be
      **`host_key_mismatch`** (security finding), not `unreachable`. Re-bootstrap (§2) to restore.
- [ ] **sudo-not-passwordless** — remove the sudoers drop-in, re-run. Should report a
      scanner/sudo failure with an actionable detail, not a silent zero-score scan. If a
      partial scan runs, the host must be flagged **LOW confidence** — never a clean high score.

---

## 7. Drift (history)

```bash
python -m grc_auditor run -c vm-validate.yaml      # run twice (optionally harden a control between)
python -m grc_auditor run -c vm-validate.yaml
python -m grc_auditor history -o ./vm-output
```
- [ ] Second `report.html` shows a **drift Δ vs prior** for the host and a two-point trend.
- [ ] `history` lists both runs, newest first.

---

## Sign-off

The live-scan leg is validated when: the happy path produces matching numbers against
OpenSCAP's own report, **all negative paths** produce the correct status, and drift renders
across two runs. Then widen `scope.cidrs` to the authorized fleet range and run for real.

> **Authorization, always.** Only ever scan hosts you are authorized to assess — keep the
> scope at `/32` for this single-host test. A public-IP target is fine if it's your own box.
