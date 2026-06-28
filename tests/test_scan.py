"""Tests for grc_auditor.scan.parse_xccdf_results against namespaced XCCDF.

The fixtures under tests/fixtures/ are namespaced XCCDF 1.2 documents shaped
like real `oscap xccdf eval --results` output; the parser strips namespaces by
local-name, so the namespace prefix is exercised on purpose.
"""

from __future__ import annotations

from grc_auditor.scan import parse_xccdf_results

from conftest import fixture_path


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


def test_is_low_confidence_predicate():
    # The single low-confidence rule, threshold-driven.
    from grc_auditor.models import ScanResult
    s = ScanResult(profile_id="", datastream="",
                   passed=10, failed=0, not_checked=190)  # 5% confidence
    assert s.is_low_confidence(90.0) is True
    assert s.is_low_confidence(2.0) is False
    # nothing evaluated -> confidence None -> not flagged
    assert ScanResult(profile_id="", datastream="").is_low_confidence(90.0) is False
