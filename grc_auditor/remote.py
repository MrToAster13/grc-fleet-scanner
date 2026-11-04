"""Stage 4: SSH connection layer.

A thin context manager over Paramiko that:
  * verifies host keys against known_hosts (RejectPolicy - never auto-accept)
  * authenticates via ssh-agent and/or an explicit key (no passwords)
  * runs commands, optionally via passwordless ``sudo -n``
  * retrieves files via SFTP (used to pull raw scan evidence back)

Every SSH failure is funnelled into a :class:`RemoteError` (or a subclass) with a
precise, actionable message so callers can map the host to an honest coverage
status. The exception subclasses let a caller that *wants* to discriminate do so,
while ``except RemoteError`` continues to catch every connection failure.

Failure taxonomy (all subclass :class:`RemoteError`):
  * :class:`AuthenticationFailed`   - keys/agent rejected by the server.
  * :class:`ConnectionFailed`       - refused / no route / DNS / timeout (no TLS-
                                      layer trust decision was reached).
  * :class:`HostKeyMismatch`        - the host presented a key that DIFFERS from
                                      the one pinned in known_hosts. This is a
                                      hard security signal (possible MITM or a
                                      re-provisioned host) - never auto-healed.
  * :class:`UnknownHostKey`         - the host is not in any known_hosts file at
                                      all (RejectPolicy rejection). Resolve via
                                      the bootstrap workflow below, not by
                                      relaxing the policy.

------------------------------------------------------------------------------
HOST-KEY BOOTSTRAP WORKFLOW (operational prerequisite, read before first scan)
------------------------------------------------------------------------------
Host-key verification is strict by design: this layer uses ``RejectPolicy`` and
NEVER auto-accepts an unseen key. That keeps the audit defensible - we only talk
to hosts whose identity we have already vouched for - but it means an operator
must pre-populate ``known_hosts`` for the fleet *before* the first scan, or every
host comes back ``unreachable`` with an "unknown host key" detail.

Recommended one-time bootstrap, performed from the SAME run host over a
trusted/maintenance window:

  1. Collect keys for the in-scope hosts into the configured known_hosts file
     (``config.known_hosts``; when unset, ``~/.ssh/known_hosts`` is used, and
     when set, that file is the only one trusted)::

         ssh-keyscan -t ed25519,rsa -f authorized_targets.txt \\
             >> /path/to/fleet_known_hosts

  2. VERIFY each fingerprint out-of-band (provisioning record, console, config
     management) before trusting the file. ssh-keyscan is trust-on-first-use;
     pairing it with an authoritative source is what makes the pin defensible.

  3. Point the config at that file (``known_hosts: /path/to/fleet_known_hosts``)
     and commit/treat it as audit-controlled inventory.

When a host is later legitimately re-provisioned its key changes: the scan will
fail loudly with :class:`HostKeyMismatch` (NOT silently reconnect). Re-run the
bootstrap for that host and re-verify the new fingerprint out-of-band before
removing the stale entry. A mismatch is a finding, not a nuisance.
"""

from __future__ import annotations

import os
import shlex
import socket
import time
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

try:
    import paramiko
except ImportError as exc:  # pragma: no cover - dependency guard
    raise SystemExit(
        "paramiko is required. Install dependencies: pip install -r requirements.txt"
    ) from exc

from .config import CredentialGroup
from .logging_setup import get_logger

log = get_logger()

# The target controls what a command prints and what a file holds, so neither
# is trusted to be small. oscap's own stdout for a CIS scan is well under 1 MiB;
# the reports go over SFTP, not stdout.
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024  # stdout + stderr, per command
MAX_EVIDENCE_BYTES = 256 * 1024 * 1024       # per file pulled over SFTP
_READ_CHUNK = 65536
_POLL_SECONDS = 0.05


class RemoteError(Exception):
    """Any SSH connection or remote-operation failure.

    Callers map this to :class:`HostStatus.UNREACHABLE`. The subclasses below
    refine *why* it failed; all subclass this so existing ``except RemoteError``
    handlers keep catching every case.
    """


class ConnectionFailed(RemoteError):
    """Could not establish a transport: refused / no route / DNS / timeout.

    No host-key trust decision was reached - the failure is below that layer.
    """


class AuthenticationFailed(RemoteError):
    """The server rejected our credentials (agent keys and/or explicit key).

    We never fall back to passwords, so this almost always means the right key
    is not loaded in the agent / not at ``key_path``, or the user is wrong.
    """


class HostKeyMismatch(RemoteError):
    """The host presented a key that DIFFERS from the pinned known_hosts entry.

    A hard security signal (possible MITM, or a re-provisioned host). Never
    auto-healed: re-run the bootstrap workflow and re-verify out-of-band.
    """


class UnknownHostKey(RemoteError):
    """The host's key is not present in any known_hosts file (RejectPolicy).

    Resolve by pre-populating known_hosts (see the module docstring's bootstrap
    workflow), never by relaxing the verification policy.
    """


@dataclass
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@runtime_checkable
class RemoteHostProtocol(Protocol):
    """The remote-exec surface that ``detect.py`` and ``scan.py`` depend on.

    Declaring it as a Protocol turns "conn is a parameter" into a real, testable
    seam: any object exposing these methods -- the production :class:`RemoteHost`
    or a ``FakeRemoteHost`` in tests -- can drive the detect/scan decision logic
    fully offline. The decision layer is the load-bearing middle of the
    never-false-pass guarantee, so it must be exercisable without a live host.
    """

    def run(self, command: str, *, sudo: bool = ...,
            timeout: Optional[int] = ...) -> CommandResult: ...

    def run_argv(self, argv: list, *, sudo: bool = ...,
                 timeout: Optional[int] = ...) -> CommandResult: ...

    def get_file(self, remote_path: str, local_path: str) -> None: ...


# A stderr signature emitted by ``sudo -n`` when the user would be prompted for
# a password (i.e. passwordless sudo is not configured for this command/user).
_SUDO_PASSWORD_MARKERS = (
    "sudo: a password is required",
    "a terminal is required to read the password",
    "sudo: a terminal is required",
    "no tty present and no askpass program specified",
)


def sudo_password_required(result: "CommandResult") -> bool:
    """True if a ``sudo -n`` command failed because it wanted a password.

    Recognised purely from stderr - we never prompt. Lets callers surface a
    clear "passwordless sudo not configured" coverage gap instead of an opaque
    non-zero exit.
    """
    if result.ok:
        return False
    err = result.stderr.lower()
    return any(marker in err for marker in _SUDO_PASSWORD_MARKERS)


def _load_host_keys(client: "paramiko.SSHClient", known_hosts: Optional[str]):
    # A configured file is the audit-controlled pin, so it is the only source:
    # paramiko's "system" keys are ~/.ssh/known_hosts, which anyone with the
    # run account can append to.
    if known_hosts:
        client.load_host_keys(os.path.expanduser(known_hosts))
    else:
        client.load_system_host_keys()
    # Reject anything not already trusted - host identity must be verified.
    # See the module docstring for the bootstrap workflow that populates these.
    client.set_missing_host_key_policy(paramiko.RejectPolicy())


def _classify_connect_error(exc: Exception, target: str) -> RemoteError:
    """Translate a paramiko/OS connect exception into a precise RemoteError.

    ``target`` is a human label for the endpoint that failed (e.g. the target
    IP) so the resulting message is actionable. Ordering
    matters: BadHostKeyException is a subclass of SSHException, so it is checked
    first.
    """
    # Host presented a key that does not match the pinned one - hard signal.
    if isinstance(exc, paramiko.BadHostKeyException):
        got = _fingerprint(exc.key)
        want = _fingerprint(exc.expected_key)
        return HostKeyMismatch(
            f"host-key MISMATCH for {target}: server offered {got} but "
            f"known_hosts pins {want}. Possible MITM or re-provisioned host; "
            f"refusing to connect. Re-verify the fingerprint out-of-band and "
            f"re-run the host-key bootstrap before scanning."
        )
    # RejectPolicy raised SSHException for a host absent from known_hosts.
    if isinstance(exc, paramiko.SSHException) and _is_unknown_host_key(exc):
        return UnknownHostKey(
            f"unknown host key for {target}: not present in known_hosts. "
            f"Pre-populate known_hosts via the bootstrap workflow (see "
            f"remote.py module docstring); host keys are never auto-accepted."
        )
    if isinstance(exc, paramiko.AuthenticationException):
        return AuthenticationFailed(
            f"authentication to {target} failed: no accepted key. Ensure the "
            f"identity is loaded in ssh-agent or present at the configured "
            f"key_path, and that the SSH user is correct (passwords disabled)."
        )
    if isinstance(exc, socket.timeout):
        return ConnectionFailed(
            f"connection to {target} timed out (no SSH response within the "
            f"connect timeout)."
        )
    if isinstance(exc, paramiko.SSHException):
        # Negotiation/protocol-level failure that is not specifically a host-key
        # rejection (e.g. no matching kex/cipher, banner timeout).
        return ConnectionFailed(f"SSH connect to {target} failed: {exc}")
    if isinstance(exc, OSError):
        # ConnectionRefusedError, "No route to host", DNS failure, etc. all land
        # here; str(exc) carries the specific errno text.
        return ConnectionFailed(f"connection to {target} failed: {exc}")
    return RemoteError(f"SSH connect to {target} failed: {exc}")


def _is_unknown_host_key(exc: "paramiko.SSHException") -> bool:
    """Distinguish RejectPolicy's 'unknown server' SSHException from others."""
    msg = str(exc).lower()
    return "unknown server" in msg or "not found in known_hosts" in msg


def _fingerprint(key) -> str:
    """Render a host key as 'type SHA256:...' for actionable messages."""
    try:
        import base64
        import hashlib

        digest = hashlib.sha256(key.asbytes()).digest()
        b64 = base64.b64encode(digest).decode("ascii").rstrip("=")
        return f"{key.get_name()} SHA256:{b64}"
    except Exception:  # pragma: no cover - never let formatting mask the error
        return "<unrenderable key>"


class RemoteHost:
    """Connect to a single host for the duration of a scan."""

    def __init__(self, ip: str, group: CredentialGroup,
                 known_hosts: Optional[str], connect_timeout: int = 20):
        self.ip = ip
        self.group = group
        self.known_hosts = known_hosts
        self.connect_timeout = connect_timeout
        self._client: Optional[paramiko.SSHClient] = None

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> "RemoteHost":
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    def connect(self):
        g = self.group
        self._client = paramiko.SSHClient()
        _load_host_keys(self._client, self.known_hosts)
        try:
            self._client.connect(
                hostname=self.ip, port=g.ssh_port, username=g.ssh_user,
                key_filename=os.path.expanduser(g.key_path) if g.key_path else None,
                allow_agent=g.use_agent, look_for_keys=g.use_agent,
                timeout=self.connect_timeout,
            )
        except Exception as exc:
            self.close()
            raise _classify_connect_error(exc, self.ip) from exc
        log.debug("remote: connected to %s as %s", self.ip, g.ssh_user)

    def close(self):
        for c in (self._client,):
            if c is not None:
                try:
                    c.close()
                except Exception:  # pragma: no cover - best effort
                    pass
        self._client = None

    # -- operations --------------------------------------------------------
    def run(self, command: str, *, sudo: bool = False,
            timeout: Optional[int] = None) -> CommandResult:
        """Run a command and return its exit code + captured stdout/stderr.

        stdout and stderr are read together, up to MAX_COMMAND_OUTPUT_BYTES
        combined, and ``timeout`` is a total deadline for the whole command. A
        target that floods output, trickles it, or never exits raises
        :class:`RemoteError`. With ``sudo=True`` the command is wrapped in ``sudo -n``
        (passwordless); a password prompt is surfaced as recognisable stderr
        (see :func:`sudo_password_required`) rather than blocking on a prompt.
        """
        if self._client is None:
            raise RemoteError("not connected")
        full = f"sudo -n {command}" if sudo else command
        log.debug("remote[%s]: %s", self.ip, full)
        try:
            stdin, stdout, stderr = self._client.exec_command(
                full, timeout=timeout
            )
        except paramiko.SSHException as exc:
            raise RemoteError(
                f"command on {self.ip} failed to start: {exc}"
            ) from exc

        # Never feed the command from our end; closing stdin keeps a process that
        # expects input (or an unexpected sudo prompt) from blocking the reads.
        try:
            stdin.channel.shutdown_write()
        except Exception:  # pragma: no cover - best effort
            pass

        channel = stdout.channel
        try:
            out_bytes, err_bytes = self._collect(channel, command, timeout)
            code = channel.recv_exit_status()
        except (RemoteError, socket.timeout) as exc:
            try:
                channel.close()
            except Exception:  # pragma: no cover - best effort
                pass
            if isinstance(exc, RemoteError):
                raise
            raise RemoteError(
                f"command on {self.ip} timed out after {timeout}s: {command}"
            ) from exc

        out = out_bytes.decode("utf-8", errors="replace")
        err = err_bytes.decode("utf-8", errors="replace")
        return CommandResult(code, out, err)

    def _collect(self, channel, command: str, timeout: Optional[int]):
        """Read stdout and stderr until the command exits.

        Both streams are read in one loop, because they share the channel's
        flow-control window: a target that fills stderr would otherwise stall
        a stdout read. Only bytes paramiko already holds are read, so no call
        blocks, and the cap and the deadline are checked on every pass.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        out, err = bytearray(), bytearray()
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                raise RemoteError(
                    f"command on {self.ip} timed out after {timeout}s: {command}")
            got = False
            if channel.recv_ready():
                out += channel.recv(_READ_CHUNK)
                got = True
            if channel.recv_stderr_ready():
                err += channel.recv_stderr(_READ_CHUNK)
                got = True
            if len(out) + len(err) > MAX_COMMAND_OUTPUT_BYTES:
                raise RemoteError(
                    f"command on {self.ip} sent more than "
                    f"{MAX_COMMAND_OUTPUT_BYTES} bytes of output; refusing the "
                    f"rest: {command}")
            if not got:
                # paramiko queues data ahead of the exit status, so once the
                # status is in and both buffers are empty, all output is read.
                if channel.exit_status_ready():
                    return bytes(out), bytes(err)
                time.sleep(_POLL_SECONDS)

    def run_argv(self, argv: list, *, sudo: bool = False,
                 timeout: Optional[int] = None) -> CommandResult:
        """Run a command given as an ARGV LIST, shell-quoting every token.

        paramiko's ``exec_command`` always runs through the remote login shell
        (there is no argv exec), so any interpolated value that is not a trusted
        constant -- a path, a value derived from a target host's command output --
        MUST be quoted or a crafted token (``;``, ``$(...)``, ``|``, ``$IFS``)
        injects into that shell, and with ``sudo=True`` it runs as root. This is
        the safe seam: callers build a list and never hand-format a shell string.
        """
        command = " ".join(shlex.quote(str(a)) for a in argv)
        return self.run(command, sudo=sudo, timeout=timeout)

    def get_file(self, remote_path: str, local_path: str,
                 timeout: Optional[int] = 300):
        """Pull a remote file to ``local_path`` via SFTP.

        Creates the local parent directory, always closes the SFTP channel (even
        on error), and raises a clear :class:`RemoteError` if the remote file is
        missing, unreadable, or larger than MAX_EVIDENCE_BYTES. The size is
        counted on the bytes received, not taken from the target's stat(), and
        a failed pull leaves no partial file behind.

        A ``timeout`` is enforced on the SFTP channel: without it a stalled
        transfer from a slow/hostile host would block the worker thread (and thus
        the run) indefinitely, since a thread pool cannot interrupt a blocked
        C-level read. A timeout surfaces as a :class:`RemoteError` instead.
        """
        if self._client is None:
            raise RemoteError("not connected")
        parent = os.path.dirname(local_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        try:
            sftp = self._client.open_sftp()
            if timeout is not None:
                sftp.get_channel().settimeout(timeout)
        except paramiko.SSHException as exc:
            raise RemoteError(
                f"could not open SFTP channel to {self.ip}: {exc}"
            ) from exc
        try:
            self._copy_capped(sftp, remote_path, local_path)
        except BaseException:
            try:
                os.remove(local_path)
            except OSError:
                pass
            raise
        finally:
            try:
                sftp.close()
            except Exception:  # pragma: no cover - best effort
                pass

    def _copy_capped(self, sftp, remote_path: str, local_path: str) -> None:
        # Not sftp.get(): it prefetches as many bytes as the target's stat()
        # claims, so a lying size queues unbounded reads.
        try:
            received = 0
            with sftp.open(remote_path, "rb") as src, open(local_path, "wb") as dst:
                while True:
                    chunk = src.read(32768)
                    if not chunk:
                        return
                    received += len(chunk)
                    if received > MAX_EVIDENCE_BYTES:
                        raise RemoteError(
                            f"{remote_path} on {self.ip} is larger than "
                            f"{MAX_EVIDENCE_BYTES} bytes; refusing to pull it")
                    dst.write(chunk)
        except FileNotFoundError as exc:
            raise RemoteError(
                f"remote file not found on {self.ip}: {remote_path}"
            ) from exc
        except IOError as exc:
            # paramiko raises IOError/SFTPError for missing/unreadable remote
            # paths; ENOENT means the file is simply not there.
            errno = getattr(exc, "errno", None)
            if errno == 2:  # ENOENT
                raise RemoteError(
                    f"remote file not found on {self.ip}: {remote_path}"
                ) from exc
            raise RemoteError(
                f"could not retrieve {remote_path} from {self.ip}: {exc}"
            ) from exc
