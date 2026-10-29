"""The sudoers drop-in grc-target-setup writes allows exactly the commands the
scanner runs under sudo, and nothing broader (ELI-718).

The rule text comes from the real script: these tests source grc-target-setup
in test mode and call its ``scan_sudoers`` function. The commands come from the
real scanner: ``detect._sudo_available`` and ``scan.scan_host`` run against a
recording fake remote, so a new sudo call or a changed oscap argument in the
scanner fails here until the target setup rule covers it.

Matching follows sudoers(5): the command path must match, an argument list of
``""`` allows no arguments, and any other argument list is a shell-style
pattern that fnmatch(3) compares against the arguments joined by spaces.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess

import pytest

from grc_auditor import profiles
from grc_auditor.detect import ScanPlan, _sudo_available
from grc_auditor.models import HostRecord
from grc_auditor.remote import CommandResult
from grc_auditor.scan import scan_host

from conftest import FakeRemoteHost

SCRIPT = os.path.join(os.path.dirname(__file__), os.pardir, "grc-target-setup")
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="needs bash")

# Where sudo would find each bare command through secure_path on Ubuntu.
BINS = {"true": "/usr/bin/true", "oscap": "/usr/bin/oscap", "rm": "/usr/bin/rm"}
DATASTREAM = profiles.datastream_path("22.04")
REMOTE_DIR = "/tmp/grc_audit.Ab3xZ9"   # mktemp -d /tmp/grc_audit.XXXXXX shape

RESULTS_XML = (
    '<?xml version="1.0"?>\n'
    '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">\n'
    '  <rule-result idref="r1"><result>pass</result></rule-result>\n'
    '</TestResult>\n'
)


def _scan_sudoers(datastream: str = DATASTREAM) -> subprocess.CompletedProcess:
    return subprocess.run(
        [BASH, "-c", 'source "$1"; scan_sudoers grc-scan "$2" "$3" "$4" "$5"',
         "_", SCRIPT, BINS["true"], BINS["oscap"], BINS["rm"], datastream],
        env={**os.environ, "GRC_TARGET_SETUP_TEST": "1"},
        capture_output=True, text=True,
    )


def _rule_entries(text: str):
    """(user, runas, [(path, args or None)]) from the one rule in the drop-in."""
    body = re.sub(r"\\\n", " ", text)
    lines = [ln for ln in body.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    assert len(lines) == 1, lines
    m = re.fullmatch(r"(\S+)\s+ALL=\((\w+)\)\s+NOPASSWD:\s*(.+)", lines[0].strip())
    assert m, lines[0]
    entries = []
    for cmnd in re.split(r"(?<!\\),", m.group(3)):
        parts = cmnd.strip().split(None, 1)
        entries.append((parts[0], parts[1] if len(parts) > 1 else None))
    return m.group(1), m.group(2), entries


def _allowed(entries, command: str) -> bool:
    name, _, args = command.partition(" ")
    path = BINS.get(name, name)
    for e_path, e_args in entries:
        if e_path != path:
            continue
        if e_args is None:
            return True
        if e_args == '""':
            if args == "":
                return True
            continue
        if fnmatch.fnmatchcase(args, e_args):
            return True
    return False


class _SudoRecorder(FakeRemoteHost):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.sudo_commands: list[str] = []

    def run(self, command, *, sudo=False, timeout=None):
        if sudo:
            self.sudo_commands.append(command)
        return self._match(command)

    def run_argv(self, argv, *, sudo=False, timeout=None):
        cmd = " ".join(str(a) for a in argv)
        if sudo:
            self.sudo_commands.append(cmd)
        return self._match(cmd)


def _scanner_sudo_commands(tmp_path) -> list[str]:
    """Every command the scanner runs under sudo, for both CIS levels with and
    without fetch_remote_resources."""
    seen = []
    probe = _SudoRecorder()
    assert _sudo_available(probe, True)
    seen += probe.sudo_commands
    for level in (1, 2):
        for fetch in (False, True):
            conn = _SudoRecorder(
                responses=[("mktemp", CommandResult(0, REMOTE_DIR, ""))],
                files={"results.xml": RESULTS_XML, "arf.xml": "<x/>",
                       "report.html": "<html/>"},
            )
            plan = ScanPlan(datastream_path=DATASTREAM,
                            profile_id=profiles.profile_id(level),
                            cis_level=level, ubuntu_version="22.04",
                            fetch_remote_resources=fetch)
            scan_host(HostRecord(ip="10.0.0.7"), conn, plan,
                      f"run-{level}-{fetch}", str(tmp_path))
            seen += conn.sudo_commands
    return seen


def test_rule_runs_as_root_with_no_blanket_or_wildcard_entry():
    res = _scan_sudoers()
    assert res.returncode == 0, res.stderr
    user, runas, entries = _rule_entries(res.stdout)
    assert user == "grc-scan"
    assert runas == "root"
    assert entries
    for path, args in entries:
        assert path.startswith("/") and path != "ALL", path
        assert args is not None, f"{path} allows any arguments"
        assert "*" not in args and "?" not in args, args
    assert {p for p, _ in entries} == set(BINS.values())


def test_every_scanner_sudo_command_is_allowed(tmp_path):
    _, _, entries = _rule_entries(_scan_sudoers().stdout)
    commands = _scanner_sudo_commands(tmp_path)
    assert any(c.startswith("oscap ") for c in commands)
    assert any(c.startswith("rm ") for c in commands)
    assert "true" in commands
    denied = [c for c in commands if not _allowed(entries, c)]
    assert denied == []


@pytest.mark.parametrize("command", [
    "true --anything",
    "rm -rf /",
    "rm -rf /etc",
    f"rm -rf {REMOTE_DIR} /etc",
    "rm -rf /tmp/grc_audit.a b c",
    f"oscap xccdf eval --profile {profiles.profile_id(1)} --remediate "
    f"--results {REMOTE_DIR}/results.xml --results-arf {REMOTE_DIR}/arf.xml "
    f"--report {REMOTE_DIR}/report.html {DATASTREAM}",
    f"oscap xccdf eval --profile {profiles.profile_id(1)} "
    f"--results /etc/shadow --results-arf {REMOTE_DIR}/arf.xml "
    f"--report {REMOTE_DIR}/report.html {DATASTREAM}",
    f"oscap xccdf eval --profile {profiles.profile_id(1)} "
    f"--results {REMOTE_DIR}/results.xml --results-arf {REMOTE_DIR}/arf.xml "
    f"--report {REMOTE_DIR}/report.html /home/grc-scan/evil-ds.xml",
    "oscap info /etc/shadow",
    "/bin/bash",
    "cat /etc/shadow",
])
def test_commands_outside_the_scanner_are_denied(command):
    _, _, entries = _rule_entries(_scan_sudoers().stdout)
    assert not _allowed(entries, command)


@pytest.mark.parametrize("bad", [
    "/usr/share/x,y/ds.xml",
    "/usr/share/x y/ds.xml",
    "/usr/share/x=y/ds.xml",
    "relative/ds.xml",
])
def test_unsafe_datastream_path_is_refused(bad):
    res = _scan_sudoers(bad)
    assert res.returncode != 0
    assert res.stdout == ""
