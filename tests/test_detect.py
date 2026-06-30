"""Decision-table tests for grc_auditor.detect over a FakeRemoteHost.

These exercise the detect-layer status mapping fully offline -- the load-bearing
middle of the never-false-pass guarantee that previously had no test double.
"""

from __future__ import annotations

from grc_auditor.config import CredentialGroup
from grc_auditor.detect import detect
from grc_auditor.models import HostRecord, HostStatus
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


def test_detect_non_ubuntu():
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, 'ID=debian\nVERSION_ID="12"\n', "")),
    ])
    host = _host()
    assert detect(host, conn, _cfg()) is None
    assert host.status is HostStatus.NON_UBUNTU


def test_detect_unsupported_version():
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, 'ID=ubuntu\nVERSION_ID="19.10"\n', "")),
    ])
    host = _host()
    assert detect(host, conn, _cfg()) is None
    assert host.status is HostStatus.UNSUPPORTED_VERSION


def test_detect_os_release_without_id_is_scan_error_not_non_ubuntu():
    # os-release readable but carrying no ID= field (empty / garbled / truncated)
    # is an INCONCLUSIVE read, not positive evidence of a non-Ubuntu host. It must
    # map to a retry-able SCAN_ERROR, never a terminal NON_UBUNTU -- otherwise a
    # transient truncation could permanently bucket an Ubuntu host out of scope.
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, 'PRETTY_NAME="Linux"\n', "")),
    ])
    host = _host()
    assert detect(host, conn, _cfg()) is None
    assert host.status is HostStatus.SCAN_ERROR


def test_detect_sudo_password_required_is_scanner_absent():
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, _UBUNTU_OSR, "")),
        ("true", CommandResult(1, "", "sudo: a password is required")),
    ])
    host = _host()
    assert detect(host, conn, _cfg()) is None
    assert host.status is HostStatus.SCANNER_ABSENT


def test_detect_oscap_missing_is_scanner_absent():
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, _UBUNTU_OSR, "")),
        ("true", CommandResult(0, "", "")),
        ("command -v oscap", CommandResult(1, "", "")),
    ])
    host = _host()
    assert detect(host, conn, _cfg()) is None
    assert host.status is HostStatus.SCANNER_ABSENT


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
    assert detect(host, conn, _cfg()) is None
    assert host.status is HostStatus.UNSUPPORTED_VERSION


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
    assert plan is not None
    assert plan.profile_id == _PROFILE
    assert plan.ubuntu_version == "22.04"
    assert host.is_ubuntu is True
