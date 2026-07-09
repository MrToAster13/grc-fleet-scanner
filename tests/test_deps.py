"""Tests for grc_auditor.deps (run-host nmap auto-installer) and its wiring into
discovery. All offline: the package manager, sudo, and nmap are faked through
the module's injectable seams, so nothing is installed and nothing can hang.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from grc_auditor import deps, discovery
from grc_auditor.deps import (
    DependencyError, detect_package_manager, manual_command, wrapped_command,
)
from grc_auditor.discovery import DiscoveryError, parse_nmap_xml


# --------------------------------------------------------------------------- #
# Test doubles
# --------------------------------------------------------------------------- #
def which_from(names):
    """A shutil.which stand-in: resolves a binary iff its name is in ``names``."""
    def _which(binary):
        return f"/usr/bin/{binary}" if binary in names else None
    return _which


class FakeRunner:
    """Records every command run and returns a scripted exit code.

    Backs its own ``which`` off a mutable ``present`` set. A successful install
    step (the only command that names ``nmap``; a refresh like ``apt-get update``
    never does) adds ``nmap`` to that set, so a subsequent ``which('nmap')``
    succeeds -- modelling a real install. ``install_provides=False`` models the
    pathological "installer exits 0 but nmap still isn't on PATH" case.
    """

    def __init__(self, present, fail_on=(), install_provides=True):
        self.present = set(present)
        self.fail_on = tuple(fail_on)
        self.install_provides = install_provides
        self.calls: list[str] = []

    def __call__(self, cmd, check=False):
        joined = " ".join(cmd)
        self.calls.append(joined)
        rc = 1 if any(sub in joined for sub in self.fail_on) else 0
        if rc == 0 and "nmap" in joined and self.install_provides:
            self.present.add("nmap")
        return SimpleNamespace(returncode=rc)

    def which(self, binary):
        return f"/usr/bin/{binary}" if binary in self.present else None


class CapturingLog:
    """Minimal logger double capturing (level, message) for audit-log asserts."""

    def __init__(self):
        self.records: list[tuple[str, str]] = []

    def _cap(self, level):
        def _log(msg, *args):
            self.records.append((level, msg % args if args else msg))
        return _log

    info = property(lambda self: self._cap("info"))
    warning = property(lambda self: self._cap("warning"))
    error = property(lambda self: self._cap("error"))

    def text(self):
        return "\n".join(m for _, m in self.records)


# --------------------------------------------------------------------------- #
# detect_package_manager
# --------------------------------------------------------------------------- #
def test_detect_prefers_apt_when_several_present():
    mgr = detect_package_manager(which_from({"apt-get", "dnf", "brew"}))
    assert mgr is not None and mgr.name == "apt-get"


def test_detect_falls_through_priority_order():
    # apt absent -> dnf wins over pacman.
    mgr = detect_package_manager(which_from({"pacman", "dnf"}))
    assert mgr.name == "dnf"


def test_detect_returns_none_when_no_manager():
    assert detect_package_manager(which_from(set())) is None


# --------------------------------------------------------------------------- #
# wrapped_command: the privilege-escalation matrix
# --------------------------------------------------------------------------- #
def test_wrapped_root_runs_bare():
    cmd = wrapped_command(("apt-get", "install", "-y", "nmap"),
                          is_root=True, interactive=False, privileged=True)
    assert cmd == ["apt-get", "install", "-y", "nmap"]


def test_wrapped_nonroot_tty_uses_interactive_sudo():
    cmd = wrapped_command(("apt-get", "install", "-y", "nmap"),
                          is_root=False, interactive=True, privileged=True)
    assert cmd == ["sudo", "apt-get", "install", "-y", "nmap"]


def test_wrapped_nonroot_no_tty_uses_sudo_dash_n():
    # No terminal: sudo -n so it fails fast instead of blocking on a prompt.
    cmd = wrapped_command(("apt-get", "install", "-y", "nmap"),
                          is_root=False, interactive=False, privileged=True)
    assert cmd == ["sudo", "-n", "apt-get", "install", "-y", "nmap"]


def test_wrapped_brew_never_uses_sudo():
    # brew refuses to run as root: a non-privileged manager is never wrapped.
    cmd = wrapped_command(("brew", "install", "nmap"),
                          is_root=False, interactive=False, privileged=False)
    assert cmd == ["brew", "install", "nmap"]


# --------------------------------------------------------------------------- #
# manual_command
# --------------------------------------------------------------------------- #
def test_manual_command_apt_chains_refresh_with_sudo():
    apt = detect_package_manager(which_from({"apt-get"}))
    assert manual_command(apt) == "sudo apt-get update && sudo apt-get install -y nmap"


def test_manual_command_brew_has_no_sudo():
    brew = detect_package_manager(which_from({"brew"}))
    assert manual_command(brew) == "brew install nmap"


# --------------------------------------------------------------------------- #
# ensure_nmap
# --------------------------------------------------------------------------- #
def test_ensure_nmap_noop_when_already_present():
    r = FakeRunner(present={"nmap", "apt-get"})
    assert deps.ensure_nmap(which=r.which, run=r) is True
    assert r.calls == []  # never shelled out


def test_ensure_nmap_installs_as_root_without_sudo():
    r = FakeRunner(present={"apt-get"})
    log = CapturingLog()
    assert deps.ensure_nmap(which=r.which, run=r, is_root=True,
                            interactive=False, log=log) is True
    assert r.calls == ["apt-get update", "apt-get install -y nmap"]
    # Audit log records the attempt and the success.
    assert "auto-installing via apt-get" in log.text()
    assert "installed successfully via apt-get" in log.text()


def test_ensure_nmap_no_manager_raises_with_guidance():
    r = FakeRunner(present=set())
    with pytest.raises(DependencyError) as ei:
        deps.ensure_nmap(which=r.which, run=r)
    assert "no supported package manager" in str(ei.value)
    assert r.calls == []


def test_ensure_nmap_install_failure_names_manual_command():
    r = FakeRunner(present={"apt-get"}, fail_on=("apt-get install",))
    with pytest.raises(DependencyError) as ei:
        deps.ensure_nmap(which=r.which, run=r, is_root=True, interactive=False)
    msg = str(ei.value)
    assert "installing nmap failed" in msg
    assert "sudo apt-get update && sudo apt-get install -y nmap" in msg


def test_ensure_nmap_no_tty_tries_sudo_n_then_fails_fast():
    # The cron/CI case: no terminal, sudoers refuses -> we still ATTEMPT sudo -n
    # (proving we don't just give up), and fail fast rather than hang.
    r = FakeRunner(present={"apt-get"}, fail_on=("sudo -n apt-get install",))
    log = CapturingLog()
    with pytest.raises(DependencyError) as ei:
        deps.ensure_nmap(which=r.which, run=r, is_root=False,
                         interactive=False, log=log)
    assert "sudo -n apt-get install -y nmap" in r.calls   # it tried sudo -n
    assert "passwordless sudo (sudo -n) was refused" in str(ei.value)


def test_ensure_nmap_refresh_failure_is_best_effort():
    # apt-get update failing (flaky mirror) must not abort the install.
    r = FakeRunner(present={"apt-get"}, fail_on=("apt-get update",))
    log = CapturingLog()
    assert deps.ensure_nmap(which=r.which, run=r, is_root=True,
                            interactive=False, log=log) is True
    assert "apt-get install -y nmap" in r.calls
    assert any(lvl == "warning" for lvl, _ in log.records)  # refresh warned


def test_ensure_nmap_success_but_binary_absent_raises():
    r = FakeRunner(present={"dnf"}, install_provides=False)
    with pytest.raises(DependencyError) as ei:
        deps.ensure_nmap(which=r.which, run=r, is_root=True, interactive=False)
    assert "still not on PATH" in str(ei.value)


def test_ensure_nmap_missing_sudo_binary_raises_cleanly():
    # sudo itself absent -> OSError from run() becomes a DependencyError, not a
    # traceback, and still points at the manual command.
    def boom(cmd, check=False):
        raise FileNotFoundError("sudo")
    r = FakeRunner(present={"pacman"})
    with pytest.raises(DependencyError) as ei:
        deps.ensure_nmap(which=r.which, run=boom, is_root=False, interactive=True)
    assert "Install nmap manually" in str(ei.value)


# --------------------------------------------------------------------------- #
# discovery wiring
# --------------------------------------------------------------------------- #
def test_discover_attempts_install_then_surfaces_failure(monkeypatch, config_factory):
    """When nmap is missing, discover() delegates to deps.ensure_nmap and, on a
    hard failure, re-raises it as a DiscoveryError with the same guidance."""
    monkeypatch.setattr(discovery, "_nmap_available", lambda: False)

    def fail(**kwargs):
        raise DependencyError("no supported package manager ... install manually")

    monkeypatch.setattr(discovery.deps, "ensure_nmap", fail)
    with pytest.raises(DiscoveryError) as ei:
        discovery.discover(config_factory().scope)
    assert "install manually" in str(ei.value)


def test_discover_proceeds_after_successful_install(monkeypatch, config_factory):
    """A successful auto-install lets discovery continue to the nmap run."""
    monkeypatch.setattr(discovery, "_nmap_available", lambda: False)
    monkeypatch.setattr(discovery.deps, "ensure_nmap", lambda **kw: True)
    sentinel = parse_nmap_xml(
        '<nmaprun><host><status state="up"/>'
        '<address addr="10.0.10.7" addrtype="ipv4"/></host></nmaprun>'
    )
    monkeypatch.setattr(discovery, "_run_nmap", lambda scope, want_os, cidrs: sentinel)
    hosts = discovery.discover(config_factory().scope)
    assert [h.ip for h in hosts] == ["10.0.10.7"]


def test_parse_never_triggers_install(monkeypatch, sample_nmap_xml):
    """The offline suite exercises parse_nmap_xml directly; parsing must never
    reach the auto-installer (the guarantee that keeps the tests hermetic)."""
    def tripwire(**kwargs):
        raise AssertionError("ensure_nmap must not be called during parsing")

    monkeypatch.setattr(discovery.deps, "ensure_nmap", tripwire)
    hosts = parse_nmap_xml(sample_nmap_xml)
    assert len(hosts) == 2
