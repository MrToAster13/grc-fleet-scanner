"""Decision-table tests for grc_auditor.detect over a FakeRemoteHost.

These exercise the detect-layer status mapping fully offline -- the load-bearing
middle of the never-false-pass guarantee that previously had no test double.
detect returns a Verdict instead of writing host.status, so each test asserts
on the returned Verdict and that the host's status is untouched.
"""

from __future__ import annotations

from grc_auditor.config import CredentialGroup
from grc_auditor.detect import ScanPlan, detect
from grc_auditor.models import HostRecord, HostStatus, Verdict
from grc_auditor.remote import CommandResult

from conftest import FakeRemoteHost, make_config

_PROFILE = "xccdf_org.ssgproject.content_profile_cis_level1_server"
_UBUNTU_OSR = 'ID=ubuntu\nVERSION_ID="22.04"\n'


def _cfg():
    return make_config(groups=[
        CredentialGroup(name="lab", ssh_user="u", targets=["default"], sudo=True),
    ])


def _host():
    return HostRecord(ip="10.0.10.5")


def _assert_verdict(result, host, status, detail_part):
    assert isinstance(result, Verdict)
    assert result.status is status
    assert detail_part in result.detail
    assert host.status is HostStatus.DISCOVERED  # detect never writes status
    assert host.detail is None


def test_detect_non_ubuntu():
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, 'ID=debian\nVERSION_ID="12"\n', "")),
    ])
    host = _host()
    _assert_verdict(detect(host, conn, _cfg()), host,
                    HostStatus.NON_UBUNTU, "os-release ID=debian (not Ubuntu)")


def test_detect_unsupported_version():
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, 'ID=ubuntu\nVERSION_ID="19.10"\n', "")),
    ])
    host = _host()
    _assert_verdict(detect(host, conn, _cfg()), host,
                    HostStatus.UNSUPPORTED_VERSION, "Ubuntu 19.10: no SSG CIS profile available")


def test_detect_os_release_without_id_is_scan_error_not_non_ubuntu():
    # os-release readable but carrying no ID= field (empty / garbled / truncated)
    # is an INCONCLUSIVE read, not positive evidence of a non-Ubuntu host. It must
    # map to a retry-able SCAN_ERROR, never a terminal NON_UBUNTU -- otherwise a
    # transient truncation could permanently bucket an Ubuntu host out of scope.
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, 'PRETTY_NAME="Linux"\n', "")),
    ])
    host = _host()
    _assert_verdict(detect(host, conn, _cfg()), host,
                    HostStatus.SCAN_ERROR, "os-release readable but has no ID= field")


def test_detect_sudo_password_required_is_scanner_absent():
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, _UBUNTU_OSR, "")),
        ("true", CommandResult(1, "", "sudo: a password is required")),
    ])
    host = _host()
    _assert_verdict(detect(host, conn, _cfg()), host,
                    HostStatus.SCANNER_ABSENT, "passwordless sudo unavailable")


def test_detect_oscap_missing_is_scanner_absent():
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, _UBUNTU_OSR, "")),
        ("true", CommandResult(0, "", "")),
        ("command -v oscap", CommandResult(1, "", "")),
    ])
    host = _host()
    _assert_verdict(detect(host, conn, _cfg()), host,
                    HostStatus.SCANNER_ABSENT, "oscap binary not found")


def test_detect_profile_absent_is_unsupported_version():
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, _UBUNTU_OSR, "")),
        ("true", CommandResult(0, "", "")),
        ("command -v oscap", CommandResult(0, "/usr/bin/oscap", "")),
        ("--version", CommandResult(0, "OpenSCAP 1.3.6", "")),
        ("test -f", CommandResult(0, "", "")),
        ("oscap info", CommandResult(0, "Profiles:\n  some_other_profile\n", "")),
    ])
    host = _host()
    _assert_verdict(detect(host, conn, _cfg()), host,
                    HostStatus.UNSUPPORTED_VERSION, "profile xccdf_org.ssgproject.content_profile_cis_level1_server not present")


def test_detect_happy_path_returns_plan():
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, _UBUNTU_OSR, "")),
        ("true", CommandResult(0, "", "")),
        ("command -v oscap", CommandResult(0, "/usr/bin/oscap", "")),
        ("--version", CommandResult(0, "OpenSCAP 1.3.6", "")),
        ("test -f", CommandResult(0, "", "")),
        ("oscap info", CommandResult(0, f"Profiles:\n  {_PROFILE}\n", "")),
    ])
    host = _host()
    plan = detect(host, conn, _cfg())
    assert isinstance(plan, ScanPlan)
    assert plan.profile_id == _PROFILE
    assert plan.ubuntu_version == "22.04"
    assert plan.ready_detail == "Ubuntu 22.04, OpenSCAP 1.3.6, CIS L1 ready"
    assert host.is_ubuntu is True
    assert host.status is HostStatus.DISCOVERED  # assess records the verdict
    assert plan.sudo is True          # a sudo:true group -> oscap runs under sudo


def test_detect_sudo_false_group_yields_no_sudo_plan():
    # A root-login group (sudo: false) is scannable without the sudo probe, and
    # the plan must carry sudo=False so scan.py does not wrap oscap in `sudo -n`
    # on a host that may not provide sudo at all.
    cfg = make_config(groups=[
        CredentialGroup(name="root", ssh_user="root", targets=["default"], sudo=False),
    ])
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, _UBUNTU_OSR, "")),
        ("command -v oscap", CommandResult(0, "/usr/bin/oscap", "")),
        ("--version", CommandResult(0, "OpenSCAP 1.3.6", "")),
        ("test -f", CommandResult(0, "", "")),
        ("oscap info", CommandResult(0, f"Profiles:\n  {_PROFILE}\n", "")),
    ])
    host = _host()
    plan = detect(host, conn, cfg)
    assert isinstance(plan, ScanPlan)
    assert plan.sudo is False
