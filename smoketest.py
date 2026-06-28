#!/usr/bin/env python3
"""Offline smoke test — exercises the parts that don't need nmap/oscap/SSH.

Runs on any OS (needs only PyYAML + Jinja2). Feeds canned nmap XML through the
discovery parser and classify stage, fabricates a scanned host, then persists a
run and renders the full report so you can open the HTML and verify the
pipeline's plumbing end-to-end without a live fleet.

    python smoketest.py
"""

from __future__ import annotations

import os
import tempfile

from grc_auditor.classify import classify
from grc_auditor.config import Config, CredentialGroup, ScanScope
from grc_auditor.discovery import parse_nmap_xml
from grc_auditor.logging_setup import setup_logging
from grc_auditor.models import HostRecord, HostStatus, RuleResult, ScanResult, RunRecord
from grc_auditor.report import write_reports
from grc_auditor.store import Store

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.10.21" addrtype="ipv4"/>
    <hostnames><hostname name="web01.lab"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu-3ubuntu0.6" extrainfo="Ubuntu Linux"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.0.10.30" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.2p1 Debian"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def fabricate_scan(host: HostRecord):
    host.is_ubuntu = True
    host.ubuntu_version = "22.04"
    host.status = HostStatus.SCANNED
    host.scan = ScanResult(
        profile_id="xccdf_org.ssgproject.content_profile_cis_level1_server",
        datastream="ssg-ubuntu2204-ds.xml",
        benchmark_version="0.1.70",
        passed=180, failed=20, error=0, not_applicable=15, score=90.0,
        failed_rules=[
            RuleResult("xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
                       "fail", "high", "Disable SSH root login"),
            RuleResult("xccdf_org.ssgproject.content_rule_audit_rules_time_change",
                       "fail", "medium", "Record events that modify date/time"),
        ],
        html_path="(would be runs/<id>/10.0.10.21/report.html)",
    )


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="grc_smoke_")
    run_id = "20260627T000000Z"
    run_dir = os.path.join(tmp, "runs", run_id)
    setup_logging(run_dir, verbose=True)

    cfg = Config(
        scope=ScanScope(cidrs=["10.0.10.0/24"]),
        credential_groups=[CredentialGroup(name="lab", ssh_user="ubuntu",
                                           targets=["default"])],
        output_dir=tmp,
    )

    hosts = parse_nmap_xml(SAMPLE_NMAP_XML)
    classify(hosts, cfg)
    for h in hosts:
        if h.ip == "10.0.10.21":
            fabricate_scan(h)

    run = RunRecord(run_id=run_id, started_at="2026-06-27T00:00:00+00:00",
                    finished_at="2026-06-27T00:02:00+00:00",
                    scope=cfg.scope.cidrs, config_hash=cfg.hash(), hosts=hosts)

    store = Store(tmp)
    try:
        store.save_run(run)
        paths = write_reports(run, store, run_dir)
    finally:
        store.close()

    print("\nSmoke test OK.")
    print(f"  Output dir : {tmp}")
    print(f"  Report     : {paths['html']}")
    print(f"  History DB : {os.path.join(tmp, 'history.db')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
