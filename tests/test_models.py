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


def test_zero_scanned_false_when_one_scanned_and_forty_are_gaps():
    # One good host out of forty-one must never alarm: the predicate is about
    # *nothing* being scanned, not about a low scan rate.
    gaps = [HostRecord(ip=f"10.0.10.{i}", status=HostStatus.UNREACHABLE)
            for i in range(40)]
    hosts = [fabricate_scanned_host(ip="10.0.10.99")] + gaps
    assert _run(hosts).zero_scanned() is False


def test_zero_scanned_false_for_a_dry_run_even_with_every_host_gated():
    # --dry-run never scans by design (discover + classify only). Every host
    # left DISCOVERED (the dry-run outcome) or already gated by classify must
    # not trip the alarm meant for a real run that scanned nothing.
    hosts = [
        HostRecord(ip="10.0.10.10", status=HostStatus.DISCOVERED),
        HostRecord(ip="10.0.10.11", status=HostStatus.NO_CREDENTIALS),
    ]
    assert _run(hosts).zero_scanned(dry_run=True) is False


def test_zero_scanned_false_when_fleet_is_entirely_non_ubuntu():
    # non_ubuntu hosts were never scan candidates -- scanning none of them is
    # the tool working as designed, not the same failure as every credential
    # or SSH path being wrong across the fleet.
    hosts = [
        HostRecord(ip="10.0.10.10", status=HostStatus.NON_UBUNTU),
        HostRecord(ip="10.0.10.11", status=HostStatus.NON_UBUNTU),
    ]
    assert _run(hosts).zero_scanned() is False
