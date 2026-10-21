"""Tests for grc_auditor.models: the RunRecord aggregates fleet posture reads.

The zero-scanned predicate moved to grc_auditor.posture; its tests live in
tests/test_posture.py. What stays here is the per-run arithmetic posture
builds on: which hosts count as scanned, which count as coverage gaps, and
the fleet pass rate.
"""

from __future__ import annotations

from grc_auditor.models import HostRecord, HostStatus, RunRecord

from conftest import fabricate_scanned_host


def _run(hosts):
    return RunRecord(run_id="20260627T000000Z", started_at="2026-06-27T00:00:00+00:00",
                     hosts=hosts)


def test_scanned_hosts_needs_both_the_status_and_a_scan_result():
    # A host marked SCANNED with no ScanResult attached is not counted.
    bare = HostRecord(ip="10.0.10.10", status=HostStatus.SCANNED)
    real = fabricate_scanned_host(ip="10.0.10.11")
    assert _run([bare, real]).scanned_hosts() == [real]


def test_coverage_gaps_exclude_scanned_and_non_ubuntu_hosts():
    hosts = [
        fabricate_scanned_host(ip="10.0.10.10"),
        HostRecord(ip="10.0.10.11", status=HostStatus.NON_UBUNTU),
        HostRecord(ip="10.0.10.12", status=HostStatus.NO_CREDENTIALS),
    ]
    assert [h.ip for h in _run(hosts).coverage_gaps()] == ["10.0.10.12"]


def test_fleet_pass_rate_is_none_when_nothing_was_scanned():
    hosts = [HostRecord(ip="10.0.10.10", status=HostStatus.UNREACHABLE)]
    assert _run(hosts).fleet_pass_rate() is None
    assert _run([]).fleet_pass_rate() is None
