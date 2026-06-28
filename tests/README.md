# Test harness — GRC Fleet Auditor

Offline pytest suite over the **stable public surface** and pure functions of
`grc_auditor`. It needs **no nmap, no oscap, no live SSH, and no network** —
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
| `test_discovery.py` | `discovery.parse_nmap_xml`: ip/hostname/ports/banners, down host skipped, missing service fields, OS match, non-IP host skipped |
| `test_classify.py` | `classify.classify`: Ubuntu+group -> DISCOVERED, non-Ubuntu -> NON_UBUNTU, Ubuntu no SSH -> UNREACHABLE, Ubuntu no group -> NO_CREDENTIALS |
| `test_config.py` | `config.load_config` validation, `credential_group_for` (CIDR + default fallthrough), `apply_overrides`, `hash()` stability |
| `test_profiles.py` | `datastream_for_version`, `datastream_path`, `profile_id`, `supported_versions` |
| `test_scan.py` | `scan.parse_xccdf_results` against namespaced XCCDF fixtures (counts, score, failed-rule ids/severities/titles; missing score) |
| `test_store.py` | `store.Store`: save/load round-trip incl. findings, `previous_run_id`, `list_runs` ordering, output layout |
| `test_report.py` | `report.compute_drift`, `top_failing_controls`, `write_reports` (artifacts on disk, HTML/JSON/CSV content) |

## Fixtures

`fixtures/xccdf-results.xml` and `fixtures/xccdf-results-no-score.xml` are
namespaced XCCDF 1.2 documents shaped like real `oscap xccdf eval --results`
output (a `Benchmark` embedding `Rule` titles plus a `TestResult` of
`rule-result` elements and a `score`). The second omits `<score>` to prove the
parser returns `score=None` without erroring.
