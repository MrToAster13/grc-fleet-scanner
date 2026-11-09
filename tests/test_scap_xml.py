"""Tests for grc_auditor.scap_xml.read_results, the one reader of SCAP evidence.

scan.parse_xccdf_results and rmf.rollup_from_arf both map its result onto their
own objects, so the parse, the size cap, field cleaning and the duplicate-rule
rule are tested here once and checked through both consumers where they differ.
"""

from __future__ import annotations

import inspect

import pytest

from grc_auditor import rmf, scan, scap_xml
from grc_auditor.scan import parse_xccdf_results

_NS = 'xmlns:cdf="http://checklists.nist.gov/xccdf/1.2"'
_R4 = "http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf"


def _doc(rules: str = "", results: str = "") -> str:
    return (f'<?xml version="1.0"?>\n<cdf:Benchmark {_NS}>{rules}'
            f"<cdf:TestResult>{results}</cdf:TestResult></cdf:Benchmark>\n")


def _rr(idref: str, verdict: str, severity: str = "") -> str:
    sev = f' severity="{severity}"' if severity else ""
    return (f'<cdf:rule-result idref="{idref}"{sev}>'
            f"<cdf:result>{verdict}</cdf:result></cdf:rule-result>")


def _write(tmp_path, text: str, name: str = "results.xml") -> str:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


# --- criterion 1: one reader -------------------------------------------------

def test_scan_and_rmf_hold_no_xml_walk_of_their_own():
    for module in (scan, rmf):
        src = inspect.getsource(module)
        assert "defusedxml" not in src, module.__name__
        assert ".iter(" not in src, module.__name__


def test_read_results_returns_outcomes_rules_score_and_version(tmp_path):
    rules = (f'<cdf:Rule id="r1"><cdf:title>One</cdf:title>'
             f'<cdf:reference href="{_R4}">AC-6(2)</cdf:reference></cdf:Rule>')
    text = _doc(rules, _rr("r1", "FAIL", "high")).replace(
        "</cdf:TestResult>", "<cdf:score>42.5</cdf:score></cdf:TestResult>"
    ).replace("<cdf:TestResult>", "<cdf:version>v0.1.74</cdf:version><cdf:TestResult>")
    res = scap_xml.read_results(_write(tmp_path, text))
    assert res.empty is False
    assert res.outcomes["r1"].verdict == "fail"
    assert res.outcomes["r1"].severity == "high"
    assert res.score == 42.5
    assert res.benchmark_version == "v0.1.74"
    assert res.rules["r1"].title == "One"
    assert res.rules["r1"].references == [("AC-6(2)", _R4)]


def test_read_results_flags_an_empty_file(tmp_path):
    res = scap_xml.read_results(_write(tmp_path, ""))
    assert res.empty is True
    assert res.outcomes == {}


# --- criterion 2: a repeated rule counts once, worst verdict ----------------

@pytest.mark.parametrize("first,second,kept", [
    ("pass", "fail", "fail"),
    ("fail", "pass", "fail"),
    ("pass", "error", "error"),
    ("notapplicable", "pass", "pass"),
    ("pass", "notselected", "pass"),
])
def test_read_results_keeps_the_most_decision_critical_verdict(tmp_path, first, second, kept):
    path = _write(tmp_path, _doc(results=_rr("r1", first) + _rr("r1", second)))
    assert scap_xml.read_results(path).outcomes["r1"].verdict == kept


def test_scan_counts_a_repeated_pass_once(tmp_path):
    path = _write(tmp_path, _doc(results=_rr("r1", "pass") * 5 + _rr("r2", "fail")))
    result = parse_xccdf_results(path)
    assert (result.passed, result.failed) == (1, 1)


def test_scan_lets_a_repeated_fail_beat_a_pass(tmp_path):
    path = _write(tmp_path, _doc(results=_rr("r1", "pass") + _rr("r1", "fail", "high")))
    result = parse_xccdf_results(path)
    assert (result.passed, result.failed) == (0, 1)
    assert [(fr.rule_id, fr.severity) for fr in result.failed_rules] == [("r1", "high")]


# --- adversarial review regressions -----------------------------------------

@pytest.mark.parametrize("first", ["<cdf:result/>", "<cdf:result>bogus</cdf:result>"])
def test_scan_keeps_an_error_that_follows_an_empty_or_unknown_verdict(tmp_path, first):
    repeated = (f'<cdf:rule-result idref="r1">{first}</cdf:rule-result>'
                + _rr("r1", "error"))
    result = parse_xccdf_results(_write(tmp_path, _doc(results=repeated)))
    assert result.error == 1


def test_scan_counts_each_rule_result_without_an_idref(tmp_path):
    nameless = "<cdf:rule-result><cdf:result>error</cdf:result></cdf:rule-result>"
    result = parse_xccdf_results(_write(tmp_path, _doc(results=nameless * 3)))
    assert result.error == 3


def test_scan_counts_ids_that_differ_only_past_the_field_cap(tmp_path):
    long_ids = "".join(_rr("a" * 1024 + str(i), "error") for i in range(3))
    result = parse_xccdf_results(_write(tmp_path, _doc(results=long_ids)))
    assert result.error == 3


# --- criterion 3: the size cap reaches the RMF rollup -----------------------

def test_rmf_refuses_an_oversized_arf(tmp_path, monkeypatch):
    path = _write(tmp_path, _doc(results=_rr("r1", "pass")), "arf.xml")
    monkeypatch.setattr(scap_xml, "MAX_RESULTS_BYTES", 10)
    with pytest.raises(rmf.RmfError):
        rmf.rollup_from_arf([path])


def test_scan_refuses_an_oversized_results_file(tmp_path, monkeypatch):
    path = _write(tmp_path, _doc(results=_rr("r1", "pass")))
    monkeypatch.setattr(scap_xml, "MAX_RESULTS_BYTES", 10)
    with pytest.raises(ValueError):
        parse_xccdf_results(path)


# --- criterion 4: hostile and malformed XML keep their error types ----------

_HOSTILE = ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "boom">]>'
            f'<cdf:Benchmark {_NS}>&e;</cdf:Benchmark>')


@pytest.mark.parametrize("text", [_HOSTILE, "<not-xml"])
def test_rmf_raises_rmferror_on_hostile_or_malformed_xml(tmp_path, text):
    with pytest.raises(rmf.RmfError):
        rmf.rollup_from_arf([_write(tmp_path, text, "arf.xml")])


@pytest.mark.parametrize("text", [_HOSTILE, "<not-xml"])
def test_scan_raises_valueerror_on_hostile_or_malformed_xml(tmp_path, text):
    with pytest.raises(ValueError):
        parse_xccdf_results(_write(tmp_path, text))


def test_rmf_raises_rmferror_on_an_empty_arf(tmp_path):
    with pytest.raises(rmf.RmfError):
        rmf.rollup_from_arf([_write(tmp_path, "", "arf.xml")])


# --- criterion 5: target-supplied ids are cleaned the same for both ----------

def test_rmf_cleans_rule_ids_like_scan(tmp_path):
    rules = f'<cdf:Rule id="r&#9;1"><cdf:reference href="{_R4}">AC-6</cdf:reference></cdf:Rule>'
    path = _write(tmp_path, _doc(rules, _rr("r&#9;1", "fail")), "arf.xml")
    rows = {r.control: r for r in rmf.rollup_from_arf([path])}
    assert rows["AC-6"].rules == {"r1"}
    assert [fr.rule_id for fr in parse_xccdf_results(path).failed_rules] == ["r1"]


@pytest.mark.parametrize("order", [("<cdf:result/>", "<cdf:result>foo</cdf:result>"),
                                   ("<cdf:result>foo</cdf:result>", "<cdf:result/>")])
def test_scan_resolves_an_empty_and_an_unknown_verdict_the_same_in_either_order(tmp_path, order):
    repeated = "".join(f'<cdf:rule-result idref="r1">{r}</cdf:rule-result>' for r in order)
    assert parse_xccdf_results(_write(tmp_path, _doc(results=repeated))).other == 1
