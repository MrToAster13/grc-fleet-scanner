"""Tests for grc_auditor.models: the zero_scanned predicate.

zero_scanned is the single home for "did anything get scanned this run" --
shared by the console summary, the report banner, and the exit code, so the
three can't drift apart. It is a pure function over RunRecord.hosts, testable
with no SSH, nmap, or oscap.
"""

from __future__ import annotations

from grc_auditor.models import HostRecord, HostStatus, RunRecord

from conftest import fabricate_scanned_host


def _run(hosts):
    return RunRecord(run_id="20260627T000000Z", started_at="2026-06-27T00:00:00+00:00",
                     hosts=hosts)


def test_zero_scanned_true_when_no_host_reached_scanned():
    hosts = [
        HostRecord(ip="10.0.10.10", status=HostStatus.NO_CREDENTIALS),
        HostRecord(ip="10.0.10.11", status=HostStatus.UNREACHABLE),
        HostRecord(ip="10.0.10.12", status=HostStatus.SCANNER_ABSENT),
    ]
    assert _run(hosts).zero_scanned() is True


def test_zero_scanned_true_when_no_hosts_discovered_at_all():
    assert _run([]).zero_scanned() is True


def test_zero_scanned_false_when_at_least_one_host_scanned():
    hosts = [
        HostRecord(ip="10.0.10.10", status=HostStatus.NO_CREDENTIALS),
        fabricate_scanned_host(ip="10.0.10.11"),
    ]
    assert _run(hosts).zero_scanned() is False
