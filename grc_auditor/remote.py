"""Stage 4: SSH/bastion connection layer.

A thin context manager over Paramiko that:
  * verifies host keys against known_hosts (RejectPolicy - never auto-accept)
  * optionally tunnels through a bastion (ProxyJump-style direct-tcpip channel)
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
  * :class:`BastionError`           - the failure was reaching/authenticating to
                                      the BASTION, not the target behind it.

------------------------------------------------------------------------------
HOST-KEY BOOTSTRAP WORKFLOW (operational prerequisite, read before first scan)
------------------------------------------------------------------------------
Host-key verification is strict by design: this layer uses ``RejectPolicy`` and
NEVER auto-accepts an unseen key. That keeps the audit defensible - we only talk
to hosts whose identity we have already vouched for - but it means an operator
must pre-populate ``known_hosts`` for the fleet *before* the first scan, or every
host comes back ``unreachable`` with an "unknown host key" detail.

Recommended one-time bootstrap, performed from the SAME run host (and, if a
bastion is used, from the bastion's vantage point so tunnelled fingerprints
match) over a trusted/maintenance window:

  1. Collect keys for the in-scope hosts into the configured known_hosts file
     (``config.known_hosts``; defaults to the system files + ``~/.ssh/known_hosts``)::

         ssh-keyscan -t ed25519,rsa -f authorized_targets.txt \\
             >> /path/to/fleet_known_hosts

     For hosts only reachable through the bastion, run ssh-keyscan FROM the
     bastion (or ``ssh -J bastion host true`` and accept once there) so the
     fingerprint paramiko sees through the tunnel matches what is pinned.

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


class RemoteError(Exception):
    """Any SSH/bastion connection or remote-operation failure.

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


class BastionError(RemoteError):
    """The failure was reaching/authenticating to the BASTION, not the target."""


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
    client.load_system_host_keys()
    default_user_kh = os.path.expanduser("~/.ssh/known_hosts")
    if known_hosts:
        client.load_host_keys(os.path.expanduser(known_hosts))
    elif os.path.exists(default_user_kh):
        client.load_host_keys(default_user_kh)
    # Reject anything not already trusted - host identity must be verified.
    # See the module docstring for the bootstrap workflow that populates these.
    client.set_missing_host_key_policy(paramiko.RejectPolicy())


def _classify_connect_error(exc: Exception, target: str) -> RemoteError:
    """Translate a paramiko/OS connect exception into a precise RemoteError.

    ``target`` is a human label for the endpoint that failed (e.g. the target
    IP, or ``bastion <host>``) so the resulting message is actionable. Ordering
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


def _bastion_error(exc: Exception, bastion_label: str) -> RemoteError:
    """Translate a bastion-side connect failure into a RemoteError.

    A host-key MISMATCH on the bastion is still a hard security signal (possible
    MITM on the jump host), so its :class:`HostKeyMismatch` type is PRESERVED --
    flattening it into a generic :class:`BastionError` would let the caller demote
    a MITM indicator to plain unreachability. Every other bastion-side failure is
    wrapped as :class:`BastionError` so callers can still tell bastion-side from
    target-side problems. The classified message already names the bastion.
    """
    base = _classify_connect_error(exc, bastion_label)
    if isinstance(base, HostKeyMismatch):
        return base
    return BastionError(str(base))


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
    """Connect to a single host (optionally via bastion) for the duration of a scan."""

    def __init__(self, ip: str, group: CredentialGroup,
                 known_hosts: Optional[str], connect_timeout: int = 20):
        self.ip = ip
        self.group = group
        self.known_hosts = known_hosts
        self.connect_timeout = connect_timeout
        self._client: Optional[paramiko.SSHClient] = None
        self._bastion: Optional[paramiko.SSHClient] = None

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> "RemoteHost":
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    def connect(self):
        sock = None
        g = self.group

        if g.bastion is not None:
            sock = self._open_bastion_channel()

        self._client = paramiko.SSHClient()
        _load_host_keys(self._client, self.known_hosts)
        try:
            self._client.connect(
                hostname=self.ip, port=g.ssh_port, username=g.ssh_user,
                key_filename=os.path.expanduser(g.key_path) if g.key_path else None,
                allow_agent=g.use_agent, look_for_keys=g.use_agent,
                sock=sock, timeout=self.connect_timeout,
            )
        except Exception as exc:
            # Tear everything down - in particular the bastion, which we own and
            # which would otherwise leak when the target connection fails.
            self.close()
            raise _classify_connect_error(exc, self.ip) from exc
        log.debug("remote: connected to %s as %s", self.ip, g.ssh_user)

    def _open_bastion_channel(self):
        """Connect the bastion and open a direct-tcpip channel to the target.

        On ANY bastion-side failure the bastion client is torn down and a
        :class:`BastionError` is raised, so a half-open bastion never leaks and
        the caller can tell bastion-side from target-side failures.
        """
        b = self.group.bastion
        log.debug("remote: opening bastion %s@%s for %s", b.user, b.host, self.ip)
        self._bastion = paramiko.SSHClient()
        _load_host_keys(self._bastion, self.known_hosts)
        bastion_label = f"bastion {b.user}@{b.host}:{b.port}"
        try:
            self._bastion.connect(
                hostname=b.host, port=b.port, username=b.user,
                key_filename=os.path.expanduser(b.key_path) if b.key_path else None,
                allow_agent=True, look_for_keys=True, timeout=self.connect_timeout,
            )
        except Exception as exc:
            self.close()
            raise _bastion_error(exc, bastion_label) from exc

        try:
            transport = self._bastion.get_transport()
            if transport is None:  # pragma: no cover - defensive
                raise paramiko.SSHException("bastion transport unavailable")
            return transport.open_channel(
                "direct-tcpip", (self.ip, self.group.ssh_port), ("127.0.0.1", 0)
            )
        except Exception as exc:
            # Could authenticate to the bastion but could not open the forwarding
            # channel to the target (e.g. bastion ACL blocks it, target down from
            # the bastion's vantage point). Still a bastion-side problem.
            self.close()
            raise BastionError(
                f"{bastion_label}: could not open forwarding channel to "
                f"{self.ip}:{self.group.ssh_port}: {exc}"
            ) from exc

    def close(self):
        for c in (self._client, self._bastion):
            if c is not None:
                try:
                    c.close()
                except Exception:  # pragma: no cover - best effort
                    pass
        self._client = None
        self._bastion = None

    # -- operations --------------------------------------------------------
    def run(self, command: str, *, sudo: bool = False,
            timeout: Optional[int] = None) -> CommandResult:
        """Run a command and return its exit code + captured stdout/stderr.

        Safe for large/verbose output (oscap can emit a lot): output is drained
        from both streams rather than assuming it fits a single read, and the
        channel carries a hard ``timeout`` so a hung command cannot block
        forever - a stalled read raises :class:`RemoteError` rather than wedging
        the run. With ``sudo=True`` the command is wrapped in ``sudo -n``
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
        # The channel timeout (set via exec_command above) guards the blocking
        # reads: a stalled command raises socket.timeout out of read() instead of
        # hanging indefinitely.
        try:
            out_bytes = self._drain(stdout)
            err_bytes = self._drain(stderr)
            code = channel.recv_exit_status()
        except socket.timeout as exc:
            try:
                channel.close()
            except Exception:  # pragma: no cover - best effort
                pass
            raise RemoteError(
                f"command on {self.ip} timed out after {timeout}s "
                f"(no output/exit within the limit): {command}"
            ) from exc

        out = out_bytes.decode("utf-8", errors="replace")
        err = err_bytes.decode("utf-8", errors="replace")
        return CommandResult(code, out, err)

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

    @staticmethod
    def _drain(stream) -> bytes:
        """Read a paramiko file stream to EOF in chunks.

        ``read()`` already loops to EOF, but doing it in bounded chunks keeps a
        very large oscap report (tens of MB) from forcing one giant allocation,
        and any per-read stall still surfaces as the channel's socket.timeout.
        """
        chunks = []
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def get_file(self, remote_path: str, local_path: str):
        """Pull a remote file to ``local_path`` via SFTP.

        Creates the local parent directory, always closes the SFTP channel (even
        on error), and raises a clear :class:`RemoteError` if the remote file is
        missing or otherwise unreadable.
        """
        if self._client is None:
            raise RemoteError("not connected")
        parent = os.path.dirname(local_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        try:
            sftp = self._client.open_sftp()
        except paramiko.SSHException as exc:
            raise RemoteError(
                f"could not open SFTP channel to {self.ip}: {exc}"
            ) from exc
        try:
            sftp.get(remote_path, local_path)
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
        finally:
            try:
                sftp.close()
            except Exception:  # pragma: no cover - best effort
                pass
