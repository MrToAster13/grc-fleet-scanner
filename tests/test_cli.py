"""Tests for grc_auditor.cli helpers: run-id collision resistance and the
config scaffold-or-refuse behavior of `run` when no config file exists."""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest
import yaml

import grc_auditor.cli as cli_mod
from grc_auditor import discovery
from grc_auditor.cli import (
    _example_config_path, _exit_code_for_run, _print_summary, _run_id,
    _scaffold_config, _starter_config_text, cmd_run,
)
from grc_auditor.config import ConfigError, load_config
from grc_auditor.models import HostRecord, HostStatus, RunRecord

from conftest import fabricate_scanned_host


def test_run_id_is_timestamp_sortable_with_random_suffix():
    # 20260629T161000Z-ab12cd : a sortable UTC stamp (history ordering relies on
    # `run_id < ?` string comparison) plus a short random hex suffix.
    rid = _run_id()
    assert re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{6}", rid), rid


def test_run_ids_are_unique_within_the_same_second():
    # Two runs started back-to-back in the same wall-clock second must still mint
    # distinct ids, so one can never overwrite another's evidence dir / DB row.
    # Uniqueness rests on the 24-bit random suffix (the timestamp prefix is
    # identical across microsecond-apart calls); asserting >= len-1 proves the
    # suffix genuinely varies (a constant/low-entropy suffix would collapse this
    # toward 1) without flaking on the ~1-in-13k birthday collision of two equal
    # suffixes -- losing two pairs at once is ~1e-8, effectively never.
    ids = {_run_id() for _ in range(50)}
    assert len(ids) >= 49


# --------------------------------------------------------------------------- #
# `run` config scaffold-or-refuse
# --------------------------------------------------------------------------- #
def test_example_config_is_locatable():
    # The scaffold source must exist regardless of cwd (package-relative lookup).
    assert _example_config_path() is not None


def test_starter_config_empties_scope_but_keeps_the_rest():
    example = _example_config_path()
    with open(example, "r", encoding="utf-8") as fh:
        starter = _starter_config_text(fh.read())
    doc = yaml.safe_load(starter)
    # Authorization guard: the scaffold ships an EMPTY scope so a blind re-run is
    # refused rather than scanning the example's sample range.
    assert doc["scope"]["cidrs"] == []
    # ...while the rest of the template survives (comments + other sections).
    assert "credential_groups" in doc
    assert "# " in starter  # comments preserved, not a stripped yaml round-trip


def test_starter_config_is_refused_by_the_authorization_guard(tmp_path):
    example = _example_config_path()
    with open(example, "r", encoding="utf-8") as fh:
        starter = _starter_config_text(fh.read())
    dest = tmp_path / "config.yaml"
    dest.write_text(starter, encoding="utf-8")
    # It parses fine but is refused on the empty scope -- proving the guard, not
    # a YAML error, is what stops it.
    with pytest.raises(ConfigError) as ei:
        load_config(str(dest))
    assert "empty" in str(ei.value).lower()


def test_scaffold_writes_starter_and_returns_two(tmp_path, capsys):
    dest = tmp_path / "config.yaml"
    rc = _scaffold_config(str(dest))
    assert rc == 2
    assert dest.exists()
    assert yaml.safe_load(dest.read_text(encoding="utf-8"))["scope"]["cidrs"] == []
    assert "starter" in capsys.readouterr().out.lower()


def test_cmd_run_scaffolds_when_config_missing(tmp_path, capsys):
    dest = tmp_path / "config.yaml"
    rc = cmd_run(SimpleNamespace(config=str(dest)))
    assert rc == 2                       # nothing scanned; operator must edit first
    assert dest.exists()
    # A blind re-run of the scaffolded config is still refused.
    with pytest.raises(ConfigError):
        load_config(str(dest))


# --------------------------------------------------------------------------- #
# zero-scanned signal: exit code + console summary (ELI-140)
# --------------------------------------------------------------------------- #
def _run(hosts):
    return RunRecord(run_id="20260627T000000Z", started_at="2026-06-27T00:00:00+00:00",
                     hosts=hosts)


def test_exit_code_is_zero_scanned_code_when_nothing_scanned():
    hosts = [
        HostRecord(ip="10.0.10.10", status=HostStatus.NO_CREDENTIALS),
        HostRecord(ip="10.0.10.11", status=HostStatus.UNREACHABLE),
    ]
    assert _exit_code_for_run(_run(hosts)) == 3


def test_exit_code_is_zero_when_at_least_one_host_scanned():
    hosts = [
        HostRecord(ip="10.0.10.10", status=HostStatus.NO_CREDENTIALS),
        fabricate_scanned_host(ip="10.0.10.11"),
    ]
    assert _exit_code_for_run(_run(hosts)) == 0


def test_exit_code_does_not_collide_with_config_scaffold_or_discovery_codes():
    # ELI-143 already flags 2 as overloaded between "scaffold written" and a
    # real ConfigError; discovery failure returns 1. The zero-scanned signal
    # must not reuse either.
    hosts = [HostRecord(ip="10.0.10.10", status=HostStatus.NO_CREDENTIALS)]
    rc = _exit_code_for_run(_run(hosts))
    assert rc not in (0, 1, 2)


def test_print_summary_warns_loudly_when_zero_scanned(capsys):
    hosts = [HostRecord(ip="10.0.10.10", status=HostStatus.NO_CREDENTIALS)]
    _print_summary(_run(hosts), {"html": "r.html", "json": "r.json"})
    out = capsys.readouterr().out
    assert "ZERO HOSTS SCANNED" in out


def test_print_summary_is_quiet_when_hosts_scanned(capsys):
    hosts = [fabricate_scanned_host(ip="10.0.10.11")]
    _print_summary(_run(hosts), {"html": "r.html", "json": "r.json"})
    out = capsys.readouterr().out
    assert "ZERO HOSTS SCANNED" not in out


def test_cmd_run_dry_run_never_alarms_even_when_the_only_host_would_gate(
    tmp_path, monkeypatch, capsys,
):
    """End-to-end through cmd_run with --dry-run. Adversary-review repro
    (ELI-140): --dry-run discovers + classifies only and never scans by
    design, so even a host that would have gated in a real run must not trip
    the zero-scanned alarm on any of the three surfaces."""
    cfg_path = tmp_path / "config.yaml"
    _scaffold_config(str(cfg_path))
    doc = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    doc["scope"]["cidrs"] = ["10.0.10.0/29"]
    doc["output_dir"] = str(tmp_path / "out")
    cfg_path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    def fake_discover(scope, want_os=False):
        return [HostRecord(ip="10.0.10.10", status=HostStatus.DISCOVERED)]

    monkeypatch.setattr(discovery, "discover", fake_discover)
    monkeypatch.setattr(cli_mod.classify_mod, "classify", lambda hosts, cfg: None)

    args = SimpleNamespace(
        config=str(cfg_path), cidr=None, exclude=None, output=None, cis_level=None,
        concurrency=None, low_confidence_threshold=None, os_detect=False,
        deep=False, dry_run=True, verbose=False,
    )
    rc = cmd_run(args)
    out = capsys.readouterr().out

    assert rc == 0
    assert "ZERO HOSTS SCANNED" not in out

    runs_dir = tmp_path / "out" / "runs"
    run_dirs = list(runs_dir.iterdir())
    assert len(run_dirs) == 1
    html = (run_dirs[0] / "report.html").read_text(encoding="utf-8")
    assert "ZERO HOSTS SCANNED" not in html
    assert 'class="zero-scanned-banner"' not in html
