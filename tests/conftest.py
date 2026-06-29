"""Shared fixtures for the GRC Fleet Auditor test suite.

These tests exercise only the documented public surface and pure functions of
``grc_auditor`` -- no nmap, no oscap, no live SSH. Filesystem/DB work goes
through pytest's ``tmp_path`` so nothing touches the developer's tree.
"""

from __future__ import annotations

import os
import posixpath

import pytest

from grc_auditor.config import Config, CredentialGroup, ScanScope
from grc_auditor.models import HostRecord, HostStatus, RuleResult, ScanResult
from grc_auditor.remote import CommandResult, RemoteError


class FakeRemoteHost:
    """Scripted stand-in for ``RemoteHost`` so detect/scan decision logic runs
    fully offline (satisfies ``RemoteHostProtocol`` structurally).

    ``responses`` is a list of ``(substring, CommandResult)`` tried in order
    against each command (both ``run`` and ``run_argv``); the first whose
    substring appears in the command wins, default is exit 0 / empty output.
    ``files`` maps a remote-path *basename* to the text ``get_file`` writes
    locally; a basename not present raises ``RemoteError`` (a missing remote
    file), exercising the real best-effort/abort paths.
    """

    def __init__(self, responses=None, files=None):
        self.responses = list(responses or [])
        self.files = dict(files or {})
        self.commands: list[str] = []

    def _match(self, command: str) -> CommandResult:
        self.commands.append(command)
        for sub, res in self.responses:
            if sub in command:
                return res
        return CommandResult(0, "", "")

    def run(self, command, *, sudo=False, timeout=None):
        return self._match(command)

    def run_argv(self, argv, *, sudo=False, timeout=None):
        return self._match(" ".join(str(a) for a in argv))

    def get_file(self, remote_path, local_path):
        key = posixpath.basename(remote_path)
        if key not in self.files:
            raise RemoteError(f"remote file not found: {remote_path}")
        parent = os.path.dirname(local_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(local_path, "w", encoding="utf-8") as fh:
            fh.write(self.files[key])


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


# nmap -oX sample reused verbatim from smoketest.py: one Ubuntu SSH+HTTP host
# (10.0.10.21) and one Debian SSH host (10.0.10.30).
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


@pytest.fixture
def sample_nmap_xml() -> str:
    return SAMPLE_NMAP_XML


@pytest.fixture
def fixtures_dir() -> str:
    return FIXTURES_DIR


def fixture_path(name: str) -> str:
    return os.path.join(FIXTURES_DIR, name)


def make_config(cidrs=None, groups=None, output_dir="./grc-output"):
    """Build a minimal valid Config in code (mirrors smoketest.py).

    Defaults to the lab catch-all credential group from the smoketest so an
    Ubuntu host in 10.0.10.0/24 matches a group.
    """
    if cidrs is None:
        cidrs = ["10.0.10.0/24"]
    if groups is None:
        groups = [CredentialGroup(name="lab", ssh_user="ubuntu", targets=["default"])]
    return Config(
        scope=ScanScope(cidrs=list(cidrs)),
        credential_groups=list(groups),
        output_dir=output_dir,
    )


@pytest.fixture
def config_factory():
    return make_config


def fabricate_scanned_host(ip="10.0.10.21", hostname="web01.lab", score=90.0):
    """A SCANNED HostRecord carrying a ScanResult + failed_rules.

    Mirrors smoketest.fabricate_scan so store/report round-trips exercise the
    same shape the real pipeline persists.
    """
    host = HostRecord(ip=ip, hostname=hostname, open_ports=[22, 80])
    host.is_ubuntu = True
    host.ubuntu_version = "22.04"
    host.credential_group = "lab"
    host.status = HostStatus.SCANNED
    host.scan = ScanResult(
        profile_id="xccdf_org.ssgproject.content_profile_cis_level1_server",
        datastream="ssg-ubuntu2204-ds.xml",
        benchmark_version="0.1.70",
        passed=180, failed=20, error=0, not_applicable=15, score=score,
        failed_rules=[
            RuleResult("xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
                       "fail", "high", "Disable SSH root login"),
            RuleResult("xccdf_org.ssgproject.content_rule_audit_rules_time_change",
                       "fail", "medium", "Record events that modify date/time"),
        ],
        arf_path="(runs/<id>/%s/arf.xml)" % ip,
        html_path="(runs/<id>/%s/report.html)" % ip,
        results_xml_path="(runs/<id>/%s/results.xml)" % ip,
    )
    return host
