# Test harness: GRC Fleet Auditor

Offline pytest suite over the **stable public surface** and pure functions of
`grc_auditor`. It needs **no nmap, no oscap, no live SSH, and no network**;
filesystem/DB work goes through pytest's `tmp_path`. It runs on the Windows /
Python 3.8 dev box even though the tool itself targets Linux / Python 3.10+
(the test code avoids 3.10-only syntax).

## Run it

Pytest config lives in the repo-root `pyproject.toml` (`[tool.pytest.ini_options]`
with `pythonpath = ["."]`), so from the **repo root** just run:

```bash
python -m pytest
```

Equivalently, with the import path wired explicitly (works from any directory):

```bash
# Windows PowerShell
$env:PYTHONPATH = "C:\Users\Elijah\grc-fleet-scanner"; python -m pytest C:\Users\Elijah\grc-fleet-scanner\tests

# bash / Linux
PYTHONPATH=/path/to/grc-fleet-scanner python -m pytest tests
```

Install the test dependency first (it is in `requirements.txt` under
`# --- test/dev ---`):

```bash
python -m pip install pytest
```

## Layout

| File | Covers |
|---|---|
| `conftest.py` | Shared fixtures: the smoketest nmap XML, `make_config`, `fabricate_scanned_host`, fixture-path helper |
| `test_cli.py` | `cli._run_id` timestamp-sortable with a unique suffix under rapid calls, `_scaffold_config`/`cmd_run` scaffold-or-refuse flow (starter config ships with an empty scope, `config.load_config` refuses a blind re-run on it) |
| `test_discovery.py` | `discovery.parse_nmap_xml`: ip/hostname/ports/banners, down host skipped, missing service fields, OS match, non-IP host skipped |
| `test_deps.py` | `deps.detect_package_manager` priority order, `wrapped_command` root/sudo/interactive matrix, `manual_command` text, `ensure_nmap` install flow (already present, install success, refresh-failure tolerated, no manager, install failure, no-tty `sudo -n`, binary still absent after install, sudo itself missing), `discovery.discover` wiring into `ensure_nmap` and its `DiscoveryError` surfacing |
| `test_classify.py` | `classify.classify`: Ubuntu+group -> DISCOVERED, non-Ubuntu -> NON_UBUNTU, Ubuntu no SSH -> UNREACHABLE, Ubuntu no group -> NO_CREDENTIALS |
| `test_config.py` | `config.load_config` validation, `credential_group_for` (CIDR + default fallthrough), `apply_overrides`, `hash()` stability |
| `test_remote.py` | `remote.RemoteHost.run_argv` shell-quotes every token, `_bastion_error` classification: a host-key mismatch on the bastion stays `HostKeyMismatch` rather than flattening to `BastionError`, other bastion failures stay `BastionError` |
| `test_detect.py` | `detect.detect` status-mapping decision table over a `FakeRemoteHost`: non-Ubuntu, unsupported version, os-release with no ID is SCAN_ERROR not NON_UBUNTU, sudo password required and missing oscap/profile map to SCANNER_ABSENT/UNSUPPORTED_VERSION, happy-path plan, a sudo:false group yields a no-sudo plan |
| `test_profiles.py` | `datastream_for_version`, `datastream_path`, `profile_id`, `supported_versions` |
| `test_scan.py` | `scan.parse_xccdf_results` against namespaced XCCDF fixtures (counts, score, failed-rule ids/severities/titles; missing score) |
| `test_rmf.py` | `rmf.rollup_from_arf`, `_base_control`, `write_rollup_csv` against a synthetic ARF: control rollup and status (Implemented/Planned/Not Assessed), enhancement refs of the same base counted once, a duplicate rule-result never downgrades a fail or buries an error/notselected verdict, revision parsed from the reference href, malformed XML raises `RmfError` |
| `test_store.py` | `store.Store`: save/load round-trip incl. findings, `previous_run_id`, `list_runs` ordering, output layout |
| `test_report.py` | `report.compute_drift`, `top_failing_controls`, `write_reports` (artifacts on disk, HTML/JSON/CSV content) |

## Fixtures

`fixtures/xccdf-results.xml` and `fixtures/xccdf-results-no-score.xml` are
namespaced XCCDF 1.2 documents shaped like real `oscap xccdf eval --results`
output (a `Benchmark` embedding `Rule` titles plus a `TestResult` of
`rule-result` elements and a `score`). The second omits `<score>` to prove the
parser returns `score=None` without erroring.
