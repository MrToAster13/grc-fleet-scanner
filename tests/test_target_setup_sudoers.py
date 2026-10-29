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
import posixpath
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
BINS = {"true": "/usr/bin/true", "mktemp": "/usr/bin/mktemp", "chgrp": "/usr/bin/chgrp",
        "chmod": "/usr/bin/chmod", "oscap": "/usr/bin/oscap", "rm": "/usr/bin/rm"}
SCAN_GROUP = "grc-scan"   # adduser gives the scan account a group of its own name
DATASTREAM = profiles.datastream_path("22.04")
REMOTE_DIR = "/var/lib/grc_audit.Ab3xZ9"   # mktemp -d /var/lib/grc_audit.XXXXXX shape
# Directories only root can create entries in. The scanner's oscap output dir
# has to be made by root inside one of these. In a dir the scan user can write,
# it could plant results.xml as a symlink and aim a root oscap write at any
# file (review finding grc-r2-1).
ROOT_ONLY_PARENTS = ("/var/lib",)
OSCAP_OUTPUT_FLAGS = ("--results", "--results-arf", "--report")

RESULTS_XML = (
    '<?xml version="1.0"?>\n'
    '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">\n'
    '  <rule-result idref="r1"><result>pass</result></rule-result>\n'
    '</TestResult>\n'
)


def _scan_sudoers(datastream: str = DATASTREAM,
                  group: str = SCAN_GROUP) -> subprocess.CompletedProcess:
    return subprocess.run(
        [BASH, "-c",
         'source "$1"; scan_sudoers grc-scan "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"',
         "_", SCRIPT, group, BINS["true"], BINS["mktemp"], BINS["chgrp"],
         BINS["chmod"], BINS["oscap"], BINS["rm"], datastream],
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


def _scanner_sudo_commands(tmp_path, datastream: str = DATASTREAM) -> list[str]:
    """Every command the scanner runs under sudo, for both CIS levels with and
    without fetch_remote_resources."""
    seen = []
    probe = _SudoRecorder()
    assert _sudo_available(probe, True)
    seen += probe.sudo_commands
    for level in (1, 2):
        for fetch in (False, True):
            conn = _SudoRecorder(
                responses=[("mktemp", CommandResult(0, REMOTE_DIR, "")),
                           ("id -gn", CommandResult(0, SCAN_GROUP, ""))],
                files={"results.xml": RESULTS_XML, "arf.xml": "<x/>",
                       "report.html": "<html/>"},
            )
            plan = ScanPlan(datastream_path=datastream,
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
    # grc-r2-1: a dir the scan user made itself, where it could plant symlinks.
    f"oscap xccdf eval --profile {profiles.profile_id(1)} "
    f"--results /tmp/grc_audit.Ab3xZ9/results.xml --results-arf /tmp/grc_audit.Ab3xZ9/arf.xml "
    f"--report /tmp/grc_audit.Ab3xZ9/report.html {DATASTREAM}",
    f"oscap xccdf eval --profile {profiles.profile_id(1)} "
    f"--results /home/grc-scan/x/results.xml --results-arf /home/grc-scan/x/arf.xml "
    f"--report /home/grc-scan/x/report.html {DATASTREAM}",
    "mktemp -d /tmp/grc_audit.XXXXXX",
    "mktemp -d /etc/grc_audit.XXXXXX",
    "mktemp -u /var/lib/grc_audit.XXXXXX",
    "mktemp /var/lib/grc_audit.XXXXXX",
    "chmod 0755 /etc",
    "chmod 0777 /var/lib/grc_audit.Ab3xZ9",
    "chmod 4755 /var/lib/grc_audit.Ab3xZ9",
    "chmod -R 0755 /var/lib/grc_audit.Ab3xZ9",
    f"chmod 0755 {REMOTE_DIR} /etc/shadow",
    "chmod 0755 /var/lib/grc_audit.a b c",
    # grc-r3-1: the dir is never opened to other local accounts, and only the
    # scan account's group gets it.
    f"chmod 0755 {REMOTE_DIR}",
    f"chmod 0751 {REMOTE_DIR}",
    f"chmod 0770 {REMOTE_DIR}",
    f"chgrp users {REMOTE_DIR}",
    f"chgrp root {REMOTE_DIR}",
    f"chgrp -R {SCAN_GROUP} {REMOTE_DIR}",
    f"chgrp {SCAN_GROUP} /etc",
    f"chgrp {SCAN_GROUP} {REMOTE_DIR} /etc/shadow",
    "rm -rf /tmp/grc_audit.Ab3xZ9",
])
def test_commands_outside_the_scanner_are_denied(command):
    _, _, entries = _rule_entries(_scan_sudoers().stdout)
    assert not _allowed(entries, command)


def _oscap_outputs(args: str) -> list[str]:
    words = args.split()
    return [words[words.index(flag) + 1] for flag in OSCAP_OUTPUT_FLAGS]


def test_scanner_has_root_create_the_oscap_output_dir(tmp_path):
    # grc-r2-1: the dir oscap writes into comes from a mktemp run under sudo,
    # in a parent only root can write, so the scan user cannot put entries in it.
    commands = _scanner_sudo_commands(tmp_path)
    mk = [c for c in commands if c.startswith("mktemp ")]
    assert mk, "the scanner must create its output dir under sudo"
    for c in mk:
        assert c.split()[:2] == ["mktemp", "-d"], c
        assert posixpath.dirname(c.split()[-1]) in ROOT_ONLY_PARENTS, c
    oscap = [c for c in commands if c.startswith("oscap ")]
    assert oscap
    for c in oscap:
        for out in _oscap_outputs(c):
            assert posixpath.dirname(out) == REMOTE_DIR, c


def test_rule_lets_oscap_write_only_under_a_root_only_parent():
    _, _, entries = _rule_entries(_scan_sudoers().stdout)
    oscap = [args for path, args in entries if path == BINS["oscap"]]
    assert oscap
    for args in oscap:
        for out in _oscap_outputs(args):
            parent = posixpath.dirname(posixpath.dirname(out))
            assert parent in ROOT_ONLY_PARENTS, out
    for path, args in entries:
        if path in (BINS["mktemp"], BINS["chgrp"], BINS["chmod"], BINS["rm"]):
            target = args.split()[-1]
            assert posixpath.dirname(target) in ROOT_ONLY_PARENTS, (path, args)


def test_rule_never_opens_the_output_dir_to_other_users():
    # grc-r3-1: oscap's files come out 0644, so the dir mode alone keeps other
    # local accounts away from the list of failed controls.
    _, _, entries = _rule_entries(_scan_sudoers().stdout)
    modes = [args.split()[0] for path, args in entries if path == BINS["chmod"]]
    assert modes
    for mode in modes:
        assert int(mode, 8) & 0o007 == 0, mode
    groups = [args.split()[0] for path, args in entries if path == BINS["chgrp"]]
    assert groups == [SCAN_GROUP]


@pytest.mark.parametrize("bad", ["", "-R", "a b", "a,b", "a=b", "root\\", "$(id)", "a:b"])
def test_unsafe_scan_group_is_refused(bad):
    res = _scan_sudoers(group=bad)
    assert res.returncode != 0
    assert res.stdout == ""


def _require_private_group(user, group_entry, passwd_db) -> subprocess.CompletedProcess:
    return subprocess.run(
        [BASH, "-c", 'source "$1"; require_private_group "$2" "$3" "$4"',
         "_", SCRIPT, user, group_entry, passwd_db],
        env={**os.environ, "GRC_TARGET_SETUP_TEST": "1"},
        capture_output=True, text=True,
    )


_PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
           "grc-scan:x:1001:1001::/home/grc-scan:/bin/bash\n"
           "alice:x:1000:1000::/home/alice:/bin/bash\n")


@pytest.mark.parametrize("group_entry,passwd_db", [
    ("grc-scan:x:1001:", _PASSWD),
    ("grc-scan:x:1001:grc-scan", _PASSWD),
])
def test_private_scan_group_is_accepted(group_entry, passwd_db):
    res = _require_private_group("grc-scan", group_entry, passwd_db)
    assert res.returncode == 0, res.stderr


@pytest.mark.parametrize("group_entry,passwd_db", [
    # review finding grc-r4-1: a group others belong to would let them read
    # the 0644 results through the 0750 dir.
    ("users:x:100:alice", _PASSWD.replace("1001:1001", "1001:100")),
    ("users:x:100:grc-scan,alice", _PASSWD.replace("1001:1001", "1001:100")),
    ("users:x:100:", _PASSWD.replace("1001:1001", "1001:100")
     + "bob:x:1002:100::/home/bob:/bin/bash\n"),
    ("", _PASSWD),
])
def test_shared_scan_group_is_refused(group_entry, passwd_db):
    res = _require_private_group("grc-scan", group_entry, passwd_db)
    assert res.returncode == 1
    assert ("needs a group of its own" in res.stderr
            or "could not read grc-scan's primary group" in res.stderr), res.stderr


def test_setup_checks_the_scan_group_before_writing_sudoers():
    with open(SCRIPT, encoding="utf-8") as fh:
        text = fh.read()
    check = text.find('require_private_group "$SCAN_USER"')
    write = text.find('scan_sudoers "$SCAN_USER"')
    assert 0 < check < write


def _normalize_ssg_dir(value: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [BASH, "-c", 'source "$1"; normalize_ssg_dir "$2"', "_", SCRIPT, value],
        env={**os.environ, "GRC_TARGET_SETUP_TEST": "1"},
        capture_output=True, text=True,
    )


@pytest.mark.parametrize("given,want", [
    ("/opt/ssg", "/opt/ssg"),
    ("/opt/ssg/", "/opt/ssg"),
    ("/opt/ssg///", "/opt/ssg"),
    ("/usr/share/xml/scap/ssg/content/", "/usr/share/xml/scap/ssg/content"),
])
def test_normalize_ssg_dir_strips_trailing_slashes(given, want):
    res = _normalize_ssg_dir(given)
    assert res.returncode == 0, res.stderr
    assert res.stdout == want


def test_normalize_ssg_dir_refuses_root():
    res = _normalize_ssg_dir("/")
    assert res.returncode != 0
    assert res.stdout == ""


def test_trailing_slash_ssg_dir_still_allows_the_scanner(tmp_path):
    # grc-r2-2: `--ssg-dir /opt/ssg/` must give the same datastream path the
    # scanner builds from `ssg_dir: /opt/ssg/`, or sudo refuses the oscap call.
    ssg_dir = "/opt/ssg/"
    scanner_ds = profiles.datastream_path("22.04", ssg_dir)
    norm = _normalize_ssg_dir(ssg_dir).stdout
    rule_ds = f"{norm}/{posixpath.basename(scanner_ds)}"
    _, _, entries = _rule_entries(_scan_sudoers(rule_ds).stdout)
    commands = _scanner_sudo_commands(tmp_path, scanner_ds)
    denied = [c for c in commands if not _allowed(entries, c)]
    assert denied == []


def test_ssg_dir_option_is_normalized_when_parsed():
    with open(SCRIPT, encoding="utf-8") as fh:
        text = fh.read()
    assert re.search(r'--ssg-dir\)\s+SSG_DIR="\$\(normalize_ssg_dir ', text)


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
