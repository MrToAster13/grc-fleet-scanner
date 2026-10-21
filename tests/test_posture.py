"""Tests for grc_auditor.posture: scan candidates, assessed share, the
zero-scanned predicate, and the fleet posture ladder.

zero_scanned is the single home for "did anything get scanned this run",
shared by the console summary, the report banner, and the exit code, so the
three can't drift apart. Every function here is pure over a RunRecord, so the
tests need no SSH, nmap, oscap, or store.
"""

from __future__ import annotations

from grc_auditor import posture
from grc_auditor.models import HostRecord, HostStatus, RunRecord, ScanResult

from conftest import fabricate_scanned_host


def _run(hosts, dry_run=None):
    return RunRecord(run_id="20260627T000000Z", started_at="2026-06-27T00:00:00+00:00",
                     hosts=hosts, dry_run=dry_run)


def _scanned(ip, passed=200, failed=0):
    host = HostRecord(ip=ip, hostname=ip.replace(".", "-"), open_ports=[22])
    host.is_ubuntu = True
    host.ubuntu_version = "22.04"
    host.status = HostStatus.SCANNED
    host.scan = ScanResult(
        profile_id="xccdf_org.ssgproject.content_profile_cis_level1_server",
        datastream="ssg-ubuntu2204-ds.xml", benchmark_version="0.1.70",
        passed=passed, failed=failed, error=0, score=None, failed_rules=[],
    )
    return host


def _fleet(scanned, gaps=0, non_ubuntu=0, passed=200, failed=0, dry_run=None):
    hosts = [_scanned("10.0.1.%d" % i, passed, failed) for i in range(scanned)]
    hosts += [HostRecord(ip="10.0.2.%d" % i, status=HostStatus.NO_CREDENTIALS)
              for i in range(gaps)]
    hosts += [HostRecord(ip="10.0.3.%d" % i, status=HostStatus.NON_UBUNTU)
              for i in range(non_ubuntu)]
    return _run(hosts, dry_run=dry_run)


STRONG = "Fleet compliance is strong, with only isolated gaps to close."
MODERATE = "Fleet compliance is moderate; several controls need attention."
WEAK = "Fleet compliance is weak; broad remediation is required."
NOTHING_SCANNED = ("No hosts were successfully scanned this run; compliance posture "
                   "cannot be assessed. Resolve the coverage gaps below.")
NOTHING_EVALUABLE = "Hosts were scanned but produced no evaluable results."


# --- zero_scanned ------------------------------------------------------------ #

def test_zero_scanned_true_when_no_host_reached_scanned():
    hosts = [
        HostRecord(ip="10.0.10.10", status=HostStatus.NO_CREDENTIALS),
        HostRecord(ip="10.0.10.11", status=HostStatus.UNREACHABLE),
        HostRecord(ip="10.0.10.12", status=HostStatus.SCANNER_ABSENT),
    ]
    assert posture.zero_scanned(_run(hosts)) is True


def test_zero_scanned_true_when_no_hosts_discovered_at_all():
    assert posture.zero_scanned(_run([])) is True


def test_zero_scanned_false_when_at_least_one_host_scanned():
    hosts = [
        HostRecord(ip="10.0.10.10", status=HostStatus.NO_CREDENTIALS),
        fabricate_scanned_host(ip="10.0.10.11"),
    ]
    assert posture.zero_scanned(_run(hosts)) is False


def test_zero_scanned_false_when_one_scanned_and_forty_are_gaps():
    # One good host out of forty-one must never alarm: the predicate is about
    # *nothing* being scanned, not about a low scan rate.
    gaps = [HostRecord(ip=f"10.0.10.{i}", status=HostStatus.UNREACHABLE)
            for i in range(40)]
    hosts = [fabricate_scanned_host(ip="10.0.10.99")] + gaps
    assert posture.zero_scanned(_run(hosts)) is False


def test_zero_scanned_false_for_a_dry_run_even_with_every_host_gated():
    # --dry-run never scans by design (discover + classify only). Every host
    # left DISCOVERED (the dry-run outcome) or already gated by classify must
    # not trip the alarm meant for a real run that scanned nothing.
    hosts = [
        HostRecord(ip="10.0.10.10", status=HostStatus.DISCOVERED),
        HostRecord(ip="10.0.10.11", status=HostStatus.NO_CREDENTIALS),
    ]
    assert posture.zero_scanned(_run(hosts, dry_run=True)) is False


def test_zero_scanned_false_for_a_dry_run_that_discovered_nothing():
    assert posture.zero_scanned(_run([], dry_run=True)) is False


def test_zero_scanned_treats_a_missing_dry_run_marker_as_a_real_run():
    # A run loaded from before the marker existed has dry_run=None. It reads
    # the same as an explicit False, which was the old default.
    hosts = [HostRecord(ip="10.0.10.10", status=HostStatus.NO_CREDENTIALS)]
    assert posture.zero_scanned(_run(hosts, dry_run=None)) is True
    assert posture.zero_scanned(_run(hosts, dry_run=False)) is True


def test_zero_scanned_false_when_fleet_is_entirely_non_ubuntu():
    # non_ubuntu hosts were never scan candidates -- scanning none of them is
    # the tool working as designed, not the same failure as every credential
    # or SSH path being wrong across the fleet.
    hosts = [
        HostRecord(ip="10.0.10.10", status=HostStatus.NON_UBUNTU),
        HostRecord(ip="10.0.10.11", status=HostStatus.NON_UBUNTU),
    ]
    assert posture.zero_scanned(_run(hosts)) is False


# --- scan_candidates and assessed_share ------------------------------------- #

def test_scan_candidates_exclude_only_non_ubuntu():
    run = _fleet(scanned=1, gaps=2, non_ubuntu=3)
    candidates = posture.scan_candidates(run)
    assert len(candidates) == 3
    assert all(h.status is not HostStatus.NON_UBUNTU for h in candidates)


def test_assessed_share_is_none_with_zero_candidates():
    assert posture.scan_candidates(_run([])) == []
    assert posture.assessed_share(_run([])) is None
    assert posture.assessed_share(_fleet(scanned=0, non_ubuntu=4)) is None


def test_assessed_share_ignores_non_ubuntu_and_counts_discovered_as_unassessed():
    hosts = [_scanned("10.0.1.1"),
             HostRecord(ip="10.0.2.1", status=HostStatus.DISCOVERED),
             HostRecord(ip="10.0.3.1", status=HostStatus.NON_UBUNTU)]
    assert posture.assessed_share(_run(hosts)) == 50.0


# --- fleet_posture ladder --------------------------------------------------- #

def test_nothing_scanned_is_no_data():
    p = posture.fleet_posture(_fleet(scanned=0, gaps=3))
    assert p == posture.Posture("no-data", NOTHING_SCANNED)


def test_zero_candidates_is_no_data():
    assert posture.fleet_posture(_run([])) == posture.Posture("no-data", NOTHING_SCANNED)


def test_all_non_ubuntu_fleet_is_no_data_not_incomplete():
    p = posture.fleet_posture(_fleet(scanned=0, non_ubuntu=5))
    assert p.level == "no-data"


def test_scanned_with_nothing_evaluable_is_no_data():
    p = posture.fleet_posture(_fleet(scanned=2, passed=0, failed=0))
    assert p == posture.Posture("no-data", NOTHING_EVALUABLE)


def test_pass_rate_exactly_75_is_not_weak():
    # 75.0% is the weak cutoff: below it is weak, 75.0 itself is not.
    p = posture.fleet_posture(_fleet(scanned=1, passed=75, failed=25))
    assert p == posture.Posture("moderate", MODERATE)


def test_pass_rate_just_under_75_is_weak():
    p = posture.fleet_posture(_fleet(scanned=1, passed=749, failed=251))   # 74.9%
    assert p == posture.Posture("weak", WEAK)


def test_weak_stays_weak_at_low_coverage():
    p = posture.fleet_posture(_fleet(scanned=1, gaps=20, passed=100, failed=100))
    assert p.level == "weak"


def test_pass_rate_exactly_90_with_full_coverage_is_strong():
    p = posture.fleet_posture(_fleet(scanned=1, passed=90, failed=10))
    assert p == posture.Posture("strong", STRONG)


def test_pass_rate_just_under_90_is_moderate_even_with_full_coverage():
    p = posture.fleet_posture(_fleet(scanned=1, passed=899, failed=101))   # 89.9%
    assert p == posture.Posture("moderate", MODERATE)


def test_share_exactly_50_is_rated_and_capped_at_moderate():
    p = posture.fleet_posture(_fleet(scanned=1, gaps=1))
    assert p.level == "moderate"
    assert p.headline == (
        "Assessed hosts score well, but only 50.0% of scan candidates were "
        "assessed; posture is capped at moderate until coverage gaps are closed.")


def test_share_just_under_50_is_incomplete():
    p = posture.fleet_posture(_fleet(scanned=49, gaps=51))
    assert p.level == "incomplete"
    assert p.headline == (
        "Only 49.0% of scan candidates were assessed, too little of the fleet "
        "to rate its compliance. Close the coverage gaps below before relying "
        "on the pass rate.")


def test_share_exactly_90_with_high_pass_rate_is_strong():
    assert posture.fleet_posture(_fleet(scanned=9, gaps=1)) == posture.Posture(
        "strong", STRONG)


def test_share_just_under_90_with_high_pass_rate_is_capped_at_moderate():
    p = posture.fleet_posture(_fleet(scanned=89, gaps=11))
    assert p.level == "moderate"
    assert "89.0%" in p.headline


def test_headline_names_the_non_ubuntu_exclusion():
    # One excluded host takes the singular, several take the plural.
    one = posture.fleet_posture(_fleet(scanned=2, gaps=40, non_ubuntu=1))
    assert one.level == "incomplete"
    assert "(2 of 42; 1 non-Ubuntu host excluded)" in one.headline
    many = posture.fleet_posture(_fleet(scanned=8, gaps=2, non_ubuntu=5))
    assert many.level == "moderate"
    assert "(8 of 10; 5 non-Ubuntu hosts excluded)" in many.headline


def test_non_ubuntu_inventory_does_not_count_against_coverage():
    p = posture.fleet_posture(_fleet(scanned=9, gaps=1, non_ubuntu=40))
    assert p.level == "strong"


def test_dry_run_marker_does_not_change_the_posture():
    # A dry run scans nothing, so the ladder already reads no-data; the marker
    # only silences the zero-scanned alarm, not the posture.
    dry = _run([HostRecord(ip="10.0.2.1", status=HostStatus.DISCOVERED)], dry_run=True)
    assert posture.fleet_posture(dry) == posture.Posture("no-data", NOTHING_SCANNED)
