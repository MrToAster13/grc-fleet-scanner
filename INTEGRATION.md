# Integration Report — Walking Skeleton → Hardened Tool

**Date:** 2026-06-27
**Process:** The approved walking skeleton (see [SPEC.md](SPEC.md)) was hardened by a
5-agent team working in parallel, each with **exclusive file ownership** so there were
no write collisions. The three shared contracts (`models.py`, `config.py` schema,
`store.py` schema) were frozen for the duration; agents reported needed contract changes
instead of editing them. All changes were then re-verified on the merged tree.

---

## Verification (final merged state)

| Check | Result |
|---|---|
| `python -m py_compile` (24 files) | clean |
| `pytest` | **45 passed** (~0.6s) |
| `python smoketest.py` (offline end-to-end) | renders all report sections |
| CLI surface (`--version`, `history`) | works |
| Safety refusal (empty scope) | exits 2 with clear message |
| Cross-module wiring (cli→remote taxonomy, report→crosswalk→store) | works |

> **Unproven path:** the live SSH → `oscap` scan leg cannot be exercised on the Windows
> dev box (no nmap/oscap/live SSH). See [VALIDATION.md](VALIDATION.md) for the single-VM
> checklist that closes this gap.

---

## What each agent changed

### Agent 1 — `detect.py`, `scan.py`, `profiles.py` (oscap correctness)
- `profiles.py`: `normalize_version()` (`22.04.3` → `22.04`); verified SSG datastream
  filenames; `profile_present_in_info()` to confirm a profile exists in a datastream
  (whole-token match so `level1` ≠ `level2`); documented server-vs-workstation choice.
- `detect.py`: distinguishes three failure modes with actionable detail — passwordless
  `sudo -n` fails, `oscap` missing (names `libopenscap8`), SSG content missing (names
  `ssg-base`); **pre-flight `oscap info` check** that the resolved profile exists before
  scanning (no mid-scan failures); captures oscap version into `host.detail`.
- `scan.py`: verifies `results.xml` was produced before parsing; persists
  `oscap.stdout.txt`/`oscap.stderr.txt` as evidence; precise exit-code handling (0 & 2
  = success, 1 = error); guaranteed remote temp cleanup on every path;
  `parse_xccdf_results` tolerant of missing `<score>`, namespace variance, empty files;
  raises `ValueError` on malformed/oversized input.

### Agent 2 — `report.py`, `templates/report.html.j2`, `store.py` (read-side), `crosswalk.py` (new)
- New report sections: **executive summary** (posture rating, biggest risks), **fleet
  trend** (unicode sparkline over last N runs, first-run fallback), **severity
  breakdown** (stacked bar), **CIS→NIST 800-53 / ISO 27001 cross-walk** column with
  per-control failing-host IPs.
- `top_failing_controls` now sorts by **severity then blast-radius** and lists failing
  host IPs.
- `crosswalk.py`: static, **non-exhaustive, orientation-only** rule→framework mapping
  (clearly labeled; authoritative refs remain in the ARF evidence).
- `store.py` (read-only additions; schema untouched): `fleet_pass_rate_history()`,
  `recent_scores_for_host()`.
- `findings.csv` gained `nist_800_53` + `iso_27001` columns; JSON export gained the new
  sections.

### Agent 3 — `discovery.py`, `classify.py`
- `parse_nmap_xml` robust to multi-address hosts (IPv4>IPv6, skips MAC), multiple
  hostnames (user>PTR), missing service fields, `open|filtered` ports, malformed XML
  (→ `DiscoveryError`).
- Three distinct discovery outcomes (not-installed / errored / ran-but-zero-hosts);
  large-scope **CIDR chunking** (`batch_size=64` default = no change for typical scopes);
  nmap timing validated (`-T0..-T5` only; rejects injection-shaped tokens).
- Broader Ubuntu heuristics + optional unknown-Linux→candidate promotion (default
  **off**, read via `getattr` so behavior is unchanged unless the config flag is added).

### Agent 4 — `remote.py` (SSH/bastion)
- Exception taxonomy, all subclassing `RemoteError`: `ConnectionFailed`,
  `AuthenticationFailed`, `HostKeyMismatch` (includes both fingerprints, flags possible
  MITM), `UnknownHostKey`, `BastionError`.
- Bastion teardown on failure (mock-tested); bastion-side vs target-side failures
  distinguishable.
- `run()` hardened against hung commands + verbose oscap output (channel timeout,
  chunked drain, stdin shutdown); `sudo_password_required()` helper.
- Documented the **host-key bootstrap workflow** (`ssh-keyscan` + out-of-band
  fingerprint verification) in the module docstring.

### Agent 5 — `tests/`, `requirements.txt`, `pyproject.toml`
- 45-test pytest suite over the stable public surface + pure functions, with realistic
  namespaced XCCDF fixtures (`tests/fixtures/`).
- `pyproject.toml` (`[tool.pytest.ini_options]`, `pythonpath = ["."]`); `pytest>=7.0`
  added under a `# --- test/dev ---` section in `requirements.txt`.

---

## Contract decisions

### Applied
- **`HostStatus.HOST_KEY_MISMATCH`** (from Agent 4). `cli.py` now catches
  `HostKeyMismatch` *before* the generic `RemoteError` and maps it to this status, so a
  changed host key is reported as a **security finding** (possible MITM / unverified
  re-provisioning), not plain "unreachable". Included in `is_coverage_gap`; labeled as a
  SECURITY gap in the report coverage map. Verified (45 tests still pass).

### Deferred (by decision — not gaps)
| Change | Source | Status / rationale |
|---|---|---|
| `config: treat_unknown_linux_as_ubuntu: bool = False` | Agent 3 | **Dormant-but-safe.** `classify.py` reads it via `getattr(..., False)`, so current behavior is unchanged. Add the field + YAML wiring to enable. |
| `ScanResult.oscap_version` | Agent 1 | Scanner version is captured but currently lands in `host.detail`. A dedicated field (+ `hosts` column + save/load) would make it queryable audit metadata. |
| `ScanResult.stdout_path` / `stderr_path` | Agent 1 | `oscap.stdout.txt`/`oscap.stderr.txt` are written as evidence but have no contract field to record their paths (parallel to `arf_path`/`html_path`). Needs a small schema bump. |
| `findings` denormalization (`ip`/`run_id`) + `hosts` `not_checked`/`other` columns | Agent 2 | Only needed for a future rule-level cross-run trend feature. Schema change. |

> Note: the three deferred schema-touching changes (`oscap_version`, `stdout/stderr_path`,
> findings denormalization) would each require recreating any existing dev `history.db`
> (the schema uses `CREATE TABLE IF NOT EXISTS`, which does not add columns to existing
> tables).

---

## Next step
Run the single-VM live-scan validation in [VALIDATION.md](VALIDATION.md) to exercise the
SSH→`oscap` leg against a real Ubuntu host before trusting a fleet run.
