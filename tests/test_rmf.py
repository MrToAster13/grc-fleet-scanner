"""Tests for grc_auditor.rmf: ARF -> 800-53 control rollup.

Uses a small synthetic ARF (namespaced + nested like a real one) so the
localname-based parse and the rollup/status logic are exercised offline.
"""

from __future__ import annotations

import csv

from grc_auditor import rmf

# A miniature ARF: a Benchmark (rules + 800-53 references) and a TestResult
# (rule-results), namespaced and nested the way oscap emits them.
_ARF = """<?xml version="1.0"?>
<arf:asset-report-collection
    xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1"
    xmlns:cdf="http://checklists.nist.gov/xccdf/1.2">
  <arf:report-requests><arf:report-request><arf:content>
    <cdf:Benchmark>
      <cdf:Rule id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">
        <cdf:title>Disable SSH root login</cdf:title>
        <cdf:reference href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf">AC-6(2)</cdf:reference>
        <cdf:reference href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf">AC-17(a)</cdf:reference>
        <cdf:reference href="https://static.open-scap.org/">CCE-12345-6</cdf:reference>
      </cdf:Rule>
      <cdf:Rule id="xccdf_org.ssgproject.content_rule_audit_time_change">
        <cdf:reference href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf">AU-9(3)</cdf:reference>
        <cdf:reference href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf">nist</cdf:reference>
      </cdf:Rule>
      <cdf:Rule id="xccdf_org.ssgproject.content_rule_cm6_notchecked">
        <cdf:reference href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf">CM-6(a)</cdf:reference>
      </cdf:Rule>
      <cdf:Rule id="xccdf_org.ssgproject.content_rule_no_mapping">
        <cdf:title>No 800-53 reference</cdf:title>
      </cdf:Rule>
    </cdf:Benchmark>
  </arf:content></arf:report-request></arf:report-requests>
  <arf:reports><arf:report><arf:content>
    <cdf:TestResult>
      <cdf:rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login"><cdf:result>pass</cdf:result></cdf:rule-result>
      <cdf:rule-result idref="xccdf_org.ssgproject.content_rule_audit_time_change"><cdf:result>fail</cdf:result></cdf:rule-result>
      <cdf:rule-result idref="xccdf_org.ssgproject.content_rule_cm6_notchecked"><cdf:result>notchecked</cdf:result></cdf:rule-result>
      <cdf:rule-result idref="xccdf_org.ssgproject.content_rule_no_mapping"><cdf:result>pass</cdf:result></cdf:rule-result>
    </cdf:TestResult>
  </arf:content></arf:report></arf:reports>
</arf:asset-report-collection>
"""


def _write_arf(tmp_path, text=_ARF, name="arf.xml"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_base_control_normalization():
    assert rmf._base_control("AC-17(2)") == "AC-17"
    assert rmf._base_control("CM-6(a)") == "CM-6"
    assert rmf._base_control("AU-9(3).1") == "AU-9"
    assert rmf._base_control("nist") is None
    assert rmf._base_control("") is None


def test_rollup_maps_and_aggregates(tmp_path):
    rows = rmf.rollup_from_arf([_write_arf(tmp_path)])
    by = {r.control: r for r in rows}

    # Four controls -- one per distinct base control that has an evaluated rule.
    assert set(by) == {"AC-6", "AC-17", "AU-9", "CM-6"}

    # A passing rule maps its pass to every control it references.
    assert by["AC-6"].passed == 1 and by["AC-6"].failed == 0
    assert by["AC-6"].status == "Implemented"
    assert by["AC-17"].status == "Implemented"

    # A failing rule -> Planned (feeds a POA&M row).
    assert by["AU-9"].failed == 1 and by["AU-9"].status == "Planned"

    # notchecked -> unverified (a check that ran/was attempted with no verdict), not
    # a pass; a control with only unverified checks is Not Assessed, never Implemented.
    assert by["CM-6"].unverified == 1 and by["CM-6"].passed == 0
    assert by["CM-6"].status == "Not Assessed"

    # The revision is read from the reference href, not assumed.
    assert all(r.revision == "Rev 4" for r in rows)


def test_unmapped_rule_is_excluded(tmp_path):
    rows = rmf.rollup_from_arf([_write_arf(tmp_path)])
    # The rule with no 800-53 reference contributes to no control, and the CCE
    # reference (non-800-53 href) is ignored.
    for r in rows:
        assert "content_rule_no_mapping" not in r.rules


def test_rows_sorted_by_family_then_number(tmp_path):
    rows = rmf.rollup_from_arf([_write_arf(tmp_path)])
    assert [r.control for r in rows] == ["AC-6", "AC-17", "AU-9", "CM-6"]


def test_fleet_merge_one_failing_host_makes_control_planned(tmp_path):
    # Same control passes in one ARF, fails in another -> Planned fleet-wide.
    pass_arf = _write_arf(tmp_path, name="a.xml")
    fail_text = _ARF.replace(
        "content_rule_sshd_disable_root_login\"><cdf:result>pass",
        "content_rule_sshd_disable_root_login\"><cdf:result>fail")
    fail_arf = _write_arf(tmp_path, text=fail_text, name="b.xml")
    rows = {r.control: r for r in rmf.rollup_from_arf([pass_arf, fail_arf])}
    assert rows["AC-6"].passed == 1 and rows["AC-6"].failed == 1
    assert rows["AC-6"].status == "Planned"


def test_write_rollup_csv(tmp_path):
    rows = rmf.rollup_from_arf([_write_arf(tmp_path)])
    out = tmp_path / "control-rollup.csv"
    rmf.write_rollup_csv(rows, str(out))
    parsed = list(csv.DictReader(out.open(encoding="utf-8")))
    assert parsed[0]["control"] == "AC-6"
    assert parsed[0]["implementation_status_suggestion"] == "Implemented"
    assert parsed[0]["nist_800_53_rev"] == "Rev 4"
    au9 = next(r for r in parsed if r["control"] == "AU-9")
    assert au9["fail"] == "1" and au9["implementation_status_suggestion"] == "Planned"


def test_duplicate_rule_result_never_downgrades_a_fail(tmp_path):
    # A merged / multi-TestResult ARF can repeat an idref. A later pass must not
    # overwrite an earlier fail -- dropping the fail would report the control
    # Implemented (a false pass in SSP evidence).
    dup = _ARF.replace(
        '<cdf:rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">'
        '<cdf:result>pass</cdf:result></cdf:rule-result>',
        '<cdf:rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">'
        '<cdf:result>fail</cdf:result></cdf:rule-result>'
        '<cdf:rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">'
        '<cdf:result>pass</cdf:result></cdf:rule-result>')
    assert dup != _ARF  # the replace matched
    rows = {r.control: r for r in rmf.rollup_from_arf([_write_arf(tmp_path, text=dup)])}
    # That rule maps to AC-6 and AC-17; the fail must stick despite the later pass.
    assert rows["AC-6"].failed == 1 and rows["AC-6"].passed == 0
    assert rows["AC-6"].status == "Planned"


def test_duplicate_rule_result_error_then_pass_is_not_a_false_pass(tmp_path):
    # The mirror of the fail-sticky case: a later pass must not bury an earlier
    # error either. error + pass on one idref means coverage was incomplete, so the
    # control is 'unverified' -> Not Assessed, never Implemented (a false pass).
    dup = _ARF.replace(
        '<cdf:rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">'
        '<cdf:result>pass</cdf:result></cdf:rule-result>',
        '<cdf:rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">'
        '<cdf:result>error</cdf:result></cdf:rule-result>'
        '<cdf:rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">'
        '<cdf:result>pass</cdf:result></cdf:rule-result>')
    assert dup != _ARF
    rows = {r.control: r for r in rmf.rollup_from_arf([_write_arf(tmp_path, text=dup)])}
    assert rows["AC-6"].unverified == 1 and rows["AC-6"].passed == 0
    assert rows["AC-6"].status == "Not Assessed"


def test_duplicate_rule_result_out_of_scope_does_not_bury_a_real_verdict(tmp_path):
    # A later 'notselected' (out of scope under a second profile) must not overwrite
    # an earlier pass and drop the control from the rollup entirely.
    dup = _ARF.replace(
        '<cdf:rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">'
        '<cdf:result>pass</cdf:result></cdf:rule-result>',
        '<cdf:rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">'
        '<cdf:result>pass</cdf:result></cdf:rule-result>'
        '<cdf:rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">'
        '<cdf:result>notselected</cdf:result></cdf:rule-result>')
    assert dup != _ARF
    rows = {r.control: r for r in rmf.rollup_from_arf([_write_arf(tmp_path, text=dup)])}
    assert "AC-6" in rows and rows["AC-6"].passed == 1
    assert rows["AC-6"].status == "Implemented"


def test_bad_arf_raises_rmferror(tmp_path):
    bad = tmp_path / "arf.xml"
    bad.write_text("<not-xml", encoding="utf-8")
    try:
        rmf.rollup_from_arf([str(bad)])
        assert False, "expected RmfError"
    except rmf.RmfError:
        pass


# --- Regression coverage for the /code-review aggregation fixes ---------------

_HREF_R4 = "http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf"
_ARF_HEAD = (
    '<?xml version="1.0"?>\n'
    '<arf:asset-report-collection '
    'xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1" '
    'xmlns:cdf="http://checklists.nist.gov/xccdf/1.2">\n'
    '  <arf:report-requests><arf:report-request><arf:content><cdf:Benchmark>\n')
_ARF_MID = ('</cdf:Benchmark></arf:content></arf:report-request></arf:report-requests>\n'
            '  <arf:reports><arf:report><arf:content><cdf:TestResult>\n')
_ARF_TAIL = ('</cdf:TestResult></arf:content></arf:report></arf:reports>\n'
             '</arf:asset-report-collection>\n')


def _arf(rules_refs, results):
    """Build a minimal ARF. rules_refs: {rule_id: [ref,...]}; results: {rule_id: verdict}."""
    rules = "".join(
        f'<cdf:Rule id="{rid}">'
        + "".join(f'<cdf:reference href="{_HREF_R4}">{ref}</cdf:reference>' for ref in refs)
        + "</cdf:Rule>"
        for rid, refs in rules_refs.items())
    rrs = "".join(
        f'<cdf:rule-result idref="{rid}"><cdf:result>{res}</cdf:result></cdf:rule-result>'
        for rid, res in results.items())
    return _ARF_HEAD + rules + _ARF_MID + rrs + _ARF_TAIL


def _rows(tmp_path, text):
    p = tmp_path / "arf.xml"
    p.write_text(text, encoding="utf-8")
    return {r.control: r for r in rmf.rollup_from_arf([str(p)])}


def test_notselected_rules_are_excluded(tmp_path):
    # A rule the profile did not select is out of scope -- it must NOT create a
    # spurious 'Not Assessed' control row (mirrors the assessment-confidence model).
    rows = _rows(tmp_path, _arf({"r": ["CM-7(1)"]}, {"r": "notselected"}))
    assert rows == {}


def test_error_counts_as_unverified_not_not_applicable(tmp_path):
    # error is the insufficient-privilege danger signal: 'unverified', distinct from
    # a genuine not-applicable, and a control whose only check errored is Not Assessed.
    au9 = _rows(tmp_path, _arf({"r": ["AU-9(1)"]}, {"r": "error"}))["AU-9"]
    assert au9.unverified == 1 and au9.not_applicable == 0 and au9.passed == 0
    assert au9.status == "Not Assessed"


def test_partial_coverage_is_not_implemented_and_is_disclosed(tmp_path):
    # One pass + one notchecked on the same control: NOT Implemented, and the
    # justification discloses the unverified check instead of claiming 'All pass'.
    cm6 = _rows(tmp_path, _arf(
        {"a": ["CM-6(a)"], "b": ["CM-6(b)"]}, {"a": "pass", "b": "notchecked"}))["CM-6"]
    assert cm6.passed == 1 and cm6.unverified == 1
    assert cm6.status == "Planned"
    assert not cm6.justification.startswith("All ")
    assert "could not be verified" in cm6.justification


def test_enhancement_refs_of_same_base_count_once(tmp_path):
    # A single rule citing two enhancements of the same base counts ONCE for the
    # base control (was double-counted once per reference string).
    rows = _rows(tmp_path, _arf({"r": ["AC-17(1)", "AC-17(2)"]}, {"r": "pass"}))
    assert set(rows) == {"AC-17"}
    assert rows["AC-17"].passed == 1 and len(rows["AC-17"].rules) == 1


def test_revision_unspecified_when_href_lacks_marker(tmp_path):
    # No rN token in the href -> revision is honestly 'unspecified', not a false 'Rev 4'.
    text = _arf({"r": ["AC-3"]}, {"r": "pass"}).replace("800-53r4", "800-53")
    assert _rows(tmp_path, text)["AC-3"].revision == "unspecified"
