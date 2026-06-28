"""Tests for grc_auditor.report: drift, top controls, and report rendering."""

from __future__ import annotations

import json
import os

from grc_auditor.models import HostRecord, HostStatus, RuleResult, RunRecord, ScanResult
from grc_auditor.report import (
    compute_drift, low_confidence_hosts, top_failing_controls, write_reports,
)
from grc_auditor.store import Store

from conftest import fabricate_scanned_host


def _scanned_host(ip, passed, failed, score, failed_rules=None):
    host = HostRecord(ip=ip, hostname=ip.replace(".", "-"), open_ports=[22])
    host.is_ubuntu = True
    host.ubuntu_version = "22.04"
    host.credential_group = "lab"
    host.status = HostStatus.SCANNED
    host.scan = ScanResult(
        profile_id="xccdf_org.ssgproject.content_profile_cis_level1_server",
        datastream="ssg-ubuntu2204-ds.xml",
        benchmark_version="0.1.70",
        passed=passed, failed=failed, error=0, score=score,
        failed_rules=failed_rules or [],
    )
    return host


def _run(run_id, started_at, hosts):
    return RunRecord(
        run_id=run_id, started_at=started_at, finished_at=started_at,
        scope=["10.0.10.0/24"], config_hash="hash", hosts=hosts,
    )


# --- compute_drift --------------------------------------------------------- #

def test_compute_drift_per_host_and_fleet_delta(tmp_path):
    store = Store(str(tmp_path))
    try:
        # prior run: host at 90% (180/200)
        prev = _run("20260601T000000Z", "2026-06-01T00:00:00+00:00",
                    [_scanned_host("10.0.10.21", 180, 20, 90.0)])
        store.save_run(prev)

        # current run: same host improved to 95% (190/200)
        curr = _run("20260627T000000Z", "2026-06-27T00:00:00+00:00",
                    [_scanned_host("10.0.10.21", 190, 10, 95.0)])
        store.save_run(curr)

        drift = compute_drift(curr, store)

        assert drift.prev_run_id == "20260601T000000Z"
        assert drift.prev_pass_rate == 90.0
        assert drift.curr_pass_rate == 95.0
        assert drift.fleet_delta == 5.0

        assert len(drift.per_host) == 1
        hd = drift.per_host[0]
        assert hd.ip == "10.0.10.21"
        assert hd.prev_score == 90.0
        assert hd.curr_score == 95.0
        assert hd.delta == 5.0
    finally:
        store.close()


def test_compute_drift_first_run_has_no_prior(tmp_path):
    store = Store(str(tmp_path))
    try:
        curr = _run("20260627T000000Z", "2026-06-27T00:00:00+00:00",
                    [_scanned_host("10.0.10.21", 180, 20, 90.0)])
        store.save_run(curr)

        drift = compute_drift(curr, store)
        assert drift.prev_run_id is None
        assert drift.prev_pass_rate is None
        assert drift.curr_pass_rate == 90.0
        assert drift.fleet_delta is None
        assert drift.per_host == []
    finally:
        store.close()


def test_compute_drift_new_host_has_no_prev_score(tmp_path):
    store = Store(str(tmp_path))
    try:
        store.save_run(_run("20260601T000000Z", "2026-06-01T00:00:00+00:00",
                            [_scanned_host("10.0.10.21", 180, 20, 90.0)]))
        # current run adds a brand-new host not present before
        curr = _run("20260627T000000Z", "2026-06-27T00:00:00+00:00",
                    [_scanned_host("10.0.10.21", 180, 20, 90.0),
                     _scanned_host("10.0.10.22", 100, 0, 100.0)])
        store.save_run(curr)

        drift = compute_drift(curr, store)
        by_ip = {hd.ip: hd for hd in drift.per_host}
        assert by_ip["10.0.10.22"].prev_score is None
        assert by_ip["10.0.10.22"].delta is None  # no prior -> no delta
    finally:
        store.close()


# --- top_failing_controls -------------------------------------------------- #

def test_top_failing_controls_aggregates_across_hosts():
    shared = RuleResult(
        "xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
        "fail", "high", "Disable SSH root login")
    only_one = RuleResult(
        "xccdf_org.ssgproject.content_rule_audit_rules_time_change",
        "fail", "medium", "Record events that modify date/time")

    h1 = _scanned_host("10.0.10.21", 180, 20, 90.0, failed_rules=[shared, only_one])
    h2 = _scanned_host("10.0.10.22", 170, 30, 85.0, failed_rules=[shared])
    run = _run("20260627T000000Z", "2026-06-27T00:00:00+00:00", [h1, h2])

    top = top_failing_controls(run)
    by_id = {c["rule_id"]: c for c in top}

    shared_row = by_id["xccdf_org.ssgproject.content_rule_sshd_disable_root_login"]
    assert shared_row["count"] == 2          # failing on both hosts
    assert shared_row["severity"] == "high"
    assert shared_row["title"] == "Disable SSH root login"

    single_row = by_id["xccdf_org.ssgproject.content_rule_audit_rules_time_change"]
    assert single_row["count"] == 1

    # most_common ordering: the 2-host control comes first
    assert top[0]["rule_id"] == (
        "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
    )


def test_top_failing_controls_empty_when_no_scans():
    run = _run("20260627T000000Z", "2026-06-27T00:00:00+00:00",
               [HostRecord(ip="10.0.10.30", status=HostStatus.NON_UBUNTU)])
    assert top_failing_controls(run) == []


# --- write_reports --------------------------------------------------------- #

def test_write_reports_produces_all_artifacts(tmp_path):
    store = Store(str(tmp_path))
    try:
        host = fabricate_scanned_host(ip="10.0.10.21")
        gap = HostRecord(ip="10.0.10.40", status=HostStatus.NO_CREDENTIALS,
                         is_ubuntu=True, detail="no credential group")
        run = _run("20260627T000000Z", "2026-06-27T00:00:00+00:00", [host, gap])
        store.save_run(run)

        run_dir = os.path.join(str(tmp_path), "runs", run.run_id)
        paths = write_reports(run, store, run_dir)

        # all four artifacts exist on disk
        for kind in ("html", "json", "hosts_csv", "findings_csv"):
            assert os.path.isfile(paths[kind]), kind
        assert os.path.isfile(os.path.join(run_dir, "report.html"))
        assert os.path.isfile(os.path.join(run_dir, "report.json"))
        assert os.path.isfile(os.path.join(run_dir, "hosts.csv"))
        assert os.path.isfile(os.path.join(run_dir, "findings.csv"))

        # HTML mentions a scanned host IP
        html = open(paths["html"], encoding="utf-8").read()
        assert "10.0.10.21" in html

        # JSON carries the run + computed summary
        payload = json.loads(open(paths["json"], encoding="utf-8").read())
        assert payload["run_id"] == "20260627T000000Z"
        assert payload["summary"]["scanned"] == 1
        assert payload["summary"]["fleet_pass_rate"] == 90.0
        assert "top_failing_controls" in payload

        # findings.csv has a row for each failed rule of the scanned host
        findings = open(paths["findings_csv"], encoding="utf-8").read()
        assert "sshd_disable_root_login" in findings
        assert "10.0.10.21" in findings

        # hosts.csv lists both hosts including the coverage gap
        hosts_csv = open(paths["hosts_csv"], encoding="utf-8").read()
        assert "10.0.10.21" in hosts_csv
        assert "10.0.10.40" in hosts_csv
        assert "no_credentials" in hosts_csv
    finally:
        store.close()


# --- low-confidence (anti-false-pass) -------------------------------------- #

def test_low_confidence_host_is_flagged(tmp_path):
    store = Store(str(tmp_path))
    try:
        # 100% score, but 190 of 200 checks never ran -> must be flagged.
        host = _scanned_host("10.0.10.21", 10, 0, 100.0)
        host.scan.not_checked = 190
        run = _run("20260627T000000Z", "2026-06-27T00:00:00+00:00", [host])
        store.save_run(run)

        low = low_confidence_hosts(run)
        assert len(low) == 1
        assert low[0]["ip"] == "10.0.10.21"
        assert low[0]["confidence"] == 5.0

        run_dir = os.path.join(str(tmp_path), "runs", run.run_id)
        paths = write_reports(run, store, run_dir)

        html = open(paths["html"], encoding="utf-8").read()
        assert "LOW" in html            # per-host badge
        assert "Low confidence" in html  # exec-summary callout

        payload = json.loads(open(paths["json"], encoding="utf-8").read())
        assert payload["executive_summary"]["low_confidence_count"] == 1

        # the not_checked count is exported for the analyst
        hosts_csv = open(paths["hosts_csv"], encoding="utf-8").read()
        assert "confidence" in hosts_csv  # header present
    finally:
        store.close()


def test_fully_assessed_host_not_flagged(tmp_path):
    store = Store(str(tmp_path))
    try:
        # 180/200 with nothing notchecked -> confidence high, no flag.
        host = _scanned_host("10.0.10.21", 180, 20, 90.0)
        run = _run("20260627T000000Z", "2026-06-27T00:00:00+00:00", [host])
        assert low_confidence_hosts(run) == []
    finally:
        store.close()
