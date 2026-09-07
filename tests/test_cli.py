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
    _example_config_path, _exit_code_for_run, _print_summary, _process_host,
    _run_id, _scaffold_config, _starter_config_text, cmd_run,
)
from grc_auditor.config import ConfigError, load_config
from grc_auditor.models import HostRecord, HostStatus, RunRecord
from grc_auditor.remote import ConnectionFailed, HostKeyMismatch, RemoteError

from conftest import fabricate_scanned_host, make_config


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


# --------------------------------------------------------------------------- #
# _process_host sequencing contract (ELI-141)
#
# _process_host is the per-host orchestrator: reach (RemoteHost.__enter__) ->
# detect -> scan_host -> bucket assignment. These tests pin the ORDER of that
# sequence, that a failure at any step stops the steps after it, and that each
# way a step can fail lands the host in the right coverage bucket. RemoteHost,
# detect and scan_host are monkeypatched at the cli_mod names _process_host
# actually calls, so nothing here touches the network or a real SSH stack.
# --------------------------------------------------------------------------- #
class _FakeConn:
    """Stand-in for the ``with RemoteHost(...) as conn:`` context manager."""

    def __init__(self, calls, enter_exc=None):
        self._calls = calls
        self._enter_exc = enter_exc

    def __enter__(self):
        if self._enter_exc is not None:
            raise self._enter_exc
        self._calls.append("reach")
        return self

    def __exit__(self, *exc):
        return False


def _patch_pipeline(monkeypatch, calls, *, enter_exc=None,
                    detect_result="PLAN", detect_exc=None,
                    scan_exc=None, scan_sets_status=None):
    """Wire cli_mod.RemoteHost / detect / scan_host to fakes that record call
    order in ``calls`` and can be made to fail at a chosen step."""
    monkeypatch.setattr(
        cli_mod, "RemoteHost",
        lambda ip, group, known_hosts: _FakeConn(calls, enter_exc=enter_exc),
    )

    def fake_detect(host, conn, cfg):
        calls.append("detect")
        if detect_exc is not None:
            raise detect_exc
        return detect_result

    def fake_scan_host(host, conn, plan, run_id, artifacts_root, timeout):
        calls.append("scan")
        if scan_sets_status is not None:
            host.status = scan_sets_status
        if scan_exc is not None:
            raise scan_exc
        host.status = HostStatus.SCANNED

    monkeypatch.setattr(cli_mod, "detect", fake_detect)
    monkeypatch.setattr(cli_mod, "scan_host", fake_scan_host)


def _host_and_cfg():
    host = HostRecord(ip="10.0.10.21")
    cfg = make_config()
    return host, cfg


def test_process_host_runs_reach_then_detect_then_scan_in_order(monkeypatch):
    calls = []
    _patch_pipeline(monkeypatch, calls)
    host, cfg = _host_and_cfg()

    result = _process_host(host, cfg, "run1", "/tmp/artifacts")

    assert calls == ["reach", "detect", "scan"]
    assert result.status == HostStatus.SCANNED


def test_process_host_breaking_the_order_is_caught_by_this_test(monkeypatch):
    # Sanity check on the test itself: if the pipeline ran scan before detect,
    # this assertion (not just the happy-path return value) must fail.
    calls = []
    _patch_pipeline(monkeypatch, calls)
    host, cfg = _host_and_cfg()
    _process_host(host, cfg, "run1", "/tmp/artifacts")

    assert calls != ["reach", "scan", "detect"]
    assert calls.index("reach") < calls.index("detect") < calls.index("scan")


def test_process_host_no_credential_group_short_circuits_before_reach(monkeypatch):
    calls = []
    _patch_pipeline(monkeypatch, calls)
    host, cfg = _host_and_cfg()
    monkeypatch.setattr(cfg, "credential_group_for", lambda ip: None)

    result = _process_host(host, cfg, "run1", "/tmp/artifacts")

    assert calls == []  # never even attempted to connect
    assert result.status == HostStatus.NO_CREDENTIALS
    assert result.detail


def test_process_host_reach_failure_stops_detect_and_scan(monkeypatch):
    calls = []
    _patch_pipeline(monkeypatch, calls, enter_exc=RemoteError("connection refused"))
    host, cfg = _host_and_cfg()

    result = _process_host(host, cfg, "run1", "/tmp/artifacts")

    assert calls == []
    assert result.status == HostStatus.UNREACHABLE
    assert "connection refused" in result.detail


def test_process_host_reach_timeout_lands_in_unreachable_bucket(monkeypatch):
    # ConnectionFailed (raised by remote.py for a connect-level socket.timeout)
    # is a RemoteError subclass; it must still land the host in UNREACHABLE,
    # not fall through to the generic/unexpected-error branch.
    calls = []
    _patch_pipeline(
        monkeypatch, calls,
        enter_exc=ConnectionFailed("connection to 10.0.10.21 timed out"),
    )
    host, cfg = _host_and_cfg()

    result = _process_host(host, cfg, "run1", "/tmp/artifacts")

    assert calls == []
    assert result.status == HostStatus.UNREACHABLE
    assert "timed out" in result.detail


def test_process_host_host_key_mismatch_stops_detect_and_scan(monkeypatch):
    calls = []
    _patch_pipeline(
        monkeypatch, calls,
        enter_exc=HostKeyMismatch("host-key MISMATCH for 10.0.10.21"),
    )
    host, cfg = _host_and_cfg()

    result = _process_host(host, cfg, "run1", "/tmp/artifacts")

    assert calls == []
    assert result.status == HostStatus.HOST_KEY_MISMATCH
    assert "MISMATCH" in result.detail


def test_process_host_detect_failure_stops_scan(monkeypatch):
    # detect() returning None means it already set an explanatory status; scan
    # must never run afterward.
    calls = []

    def failing_detect(host, conn, cfg):
        calls.append("detect")
        host.status = HostStatus.SCANNER_ABSENT
        host.detail = "oscap not found"
        return None

    _patch_pipeline(monkeypatch, calls)
    monkeypatch.setattr(cli_mod, "detect", failing_detect)
    host, cfg = _host_and_cfg()

    result = _process_host(host, cfg, "run1", "/tmp/artifacts")

    assert calls == ["reach", "detect"]
    assert "scan" not in calls
    assert result.status == HostStatus.SCANNER_ABSENT
    assert result.detail == "oscap not found"


def test_process_host_detect_unexpected_error_lands_in_scan_error(monkeypatch):
    calls = []
    _patch_pipeline(monkeypatch, calls, detect_exc=ValueError("bad os-release"))
    host, cfg = _host_and_cfg()

    result = _process_host(host, cfg, "run1", "/tmp/artifacts")

    assert calls == ["reach", "detect"]
    assert result.status == HostStatus.SCAN_ERROR
    assert "unexpected error" in result.detail


def test_process_host_scan_failure_without_status_is_defaulted_to_scan_error(
    monkeypatch,
):
    # scan_host raises but (defensively) never set host.status itself; the
    # caller's fallback must still land it in SCAN_ERROR with a useful detail.
    calls = []
    _patch_pipeline(monkeypatch, calls, scan_exc=RuntimeError("oscap crashed"))
    host, cfg = _host_and_cfg()

    result = _process_host(host, cfg, "run1", "/tmp/artifacts")

    assert calls == ["reach", "detect", "scan"]
    assert result.status == HostStatus.SCAN_ERROR
    assert "oscap crashed" in result.detail


def test_process_host_scan_failure_preserves_status_scan_host_already_set(
    monkeypatch,
):
    # When scan_host already set a specific SCAN_ERROR detail before raising,
    # _process_host's fallback must not clobber it with its own generic one.
    calls = []
    _patch_pipeline(
        monkeypatch, calls,
        scan_exc=RuntimeError("oscap crashed"),
        scan_sets_status=HostStatus.SCAN_ERROR,
    )
    host, cfg = _host_and_cfg()
    host.detail = None

    def scan_host_sets_detail(host, conn, plan, run_id, artifacts_root, timeout):
        calls.append("scan")
        host.status = HostStatus.SCAN_ERROR
        host.detail = "specific scan_host detail"
        raise RuntimeError("oscap crashed")

    monkeypatch.setattr(cli_mod, "scan_host", scan_host_sets_detail)

    result = _process_host(host, cfg, "run1", "/tmp/artifacts")

    assert result.status == HostStatus.SCAN_ERROR
    assert result.detail == "specific scan_host detail"


def test_process_host_unexpected_exception_outside_remote_lands_in_scan_error(
    monkeypatch,
):
    # An exception that is neither HostKeyMismatch nor RemoteError (e.g. a bug
    # surfaced while building the connection) must still be caught and turned
    # into an honest SCAN_ERROR rather than crashing the whole run.
    calls = []
    monkeypatch.setattr(
        cli_mod, "RemoteHost",
        lambda ip, group, known_hosts: (_ for _ in ()).throw(KeyError("boom")),
    )
    monkeypatch.setattr(cli_mod, "detect", lambda host, conn, cfg: calls.append("detect"))
    monkeypatch.setattr(cli_mod, "scan_host",
                        lambda *a, **kw: calls.append("scan"))
    host, cfg = _host_and_cfg()

    result = _process_host(host, cfg, "run1", "/tmp/artifacts")

    assert calls == []
    assert result.status == HostStatus.SCAN_ERROR
    assert "unexpected error" in result.detail
