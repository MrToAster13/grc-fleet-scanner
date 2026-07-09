"""Run-host dependency bootstrap: install the one external binary the tool needs.

The auditor shells out to exactly one binary on the RUN host -- ``nmap`` (for
discovery). Everything else on the run host is pure Python; ``oscap`` runs on the
*target* over SSH and is never touched by this module. When ``nmap`` is missing,
``ensure_nmap`` installs it via the host's own package manager, escalating with
``sudo`` only as far as the environment allows and never blocking on a password
prompt that can't be answered.

Design rules that must not drift:
  * **Run host only.** This never connects to, or modifies, a target under audit.
    The audit pipeline's hands-off guarantee (missing scanner -> ``scanner_absent``)
    is untouched.
  * **Never hang.** With a terminal we let ``sudo`` prompt; without one (cron/CI) we
    try ``sudo -n`` once and, if the sudoers policy refuses it, fail fast with the
    exact manual command instead of waiting forever on a prompt nobody can answer.
  * **Cross-platform import.** ``os.geteuid`` is Unix-only; it is read through
    ``getattr`` so the Windows dev box (where the offline test suite runs) still
    imports this module. The installer never fires during the tests -- they drive
    ``parse_nmap_xml`` directly, and ``ensure_nmap`` short-circuits when nmap is
    already present regardless.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple

from .logging_setup import get_logger


class DependencyError(Exception):
    """A required run-host dependency is missing and could not be installed."""


@dataclass(frozen=True)
class PackageManager:
    """A supported package manager and how to install nmap with it.

    ``install`` is the argv that must succeed. ``refresh`` is a best-effort
    pre-step (e.g. ``apt-get update``) whose failure is logged but not fatal --
    an installer shouldn't abort just because a metadata refresh hit a flaky
    mirror when the package may already be cached. ``privileged`` is False only
    for Homebrew, which refuses to run as root and is never wrapped in ``sudo``.
    """

    name: str                       # binary that must be on PATH to select it
    install: Tuple[str, ...]        # required install argv (sans sudo)
    refresh: Tuple[str, ...] = ()   # optional best-effort pre-step (sans sudo)
    privileged: bool = True         # False -> never wrap in sudo (brew)


# Ordered by ubiquity on the run hosts this tool targets (Debian/Ubuntu/Kali
# first). The first manager whose binary is on PATH wins. pacman's ``-Sy`` and
# zypper/dnf's implicit metadata handling mean only apt needs an explicit refresh.
_MANAGERS: Tuple[PackageManager, ...] = (
    PackageManager("apt-get", ("apt-get", "install", "-y", "nmap"),
                   refresh=("apt-get", "update")),
    PackageManager("dnf", ("dnf", "install", "-y", "nmap")),
    PackageManager("pacman", ("pacman", "-Sy", "--noconfirm", "nmap")),
    PackageManager("zypper", ("zypper", "--non-interactive", "install", "nmap")),
    PackageManager("brew", ("brew", "install", "nmap"), privileged=False),
)

Which = Callable[[str], Optional[str]]
Runner = Callable[..., "subprocess.CompletedProcess"]


def detect_package_manager(which: Which = shutil.which) -> Optional[PackageManager]:
    """Return the first supported package manager present on PATH, or None."""
    for mgr in _MANAGERS:
        if which(mgr.name):
            return mgr
    return None


def _is_root() -> bool:
    """True if the process runs as root. ``os.geteuid`` is Unix-only; on a
    platform without it (Windows) we are, by definition, not a Unix root."""
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def _interactive() -> bool:
    """True if there is a terminal ``sudo`` could prompt on. Both stdin and
    stdout must be a TTY -- a cron job or piped invocation has neither, and must
    fall through to the non-interactive ``sudo -n`` path."""
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (ValueError, AttributeError):  # detached / replaced streams
        return False


def wrapped_command(argv: Sequence[str], *, is_root: bool, interactive: bool,
                    privileged: bool) -> List[str]:
    """Wrap ``argv`` with the right privilege escalation for the environment.

    Root or a non-privileged manager (brew) runs bare. Otherwise we prepend
    ``sudo`` when a terminal is available to answer a prompt, and ``sudo -n``
    when it is not -- the latter fails fast rather than hanging.
    """
    if is_root or not privileged:
        return list(argv)
    if interactive:
        return ["sudo", *argv]
    return ["sudo", "-n", *argv]


def manual_command(mgr: PackageManager) -> str:
    """The exact command to run by hand when auto-install can't proceed.

    Written for the common non-root case (so it carries ``sudo`` for a
    privileged manager) and chains the refresh step when there is one.
    """
    def one(argv: Sequence[str]) -> str:
        prefix = ["sudo"] if mgr.privileged else []
        return " ".join([*prefix, *argv])

    parts = [one(mgr.refresh)] if mgr.refresh else []
    parts.append(one(mgr.install))
    return " && ".join(parts)


def ensure_nmap(*, log=None, which: Optional[Which] = None,
                run: Optional[Runner] = None,
                is_root: Optional[bool] = None,
                interactive: Optional[bool] = None) -> bool:
    """Ensure ``nmap`` is on PATH on the RUN host, installing it if missing.

    Returns True if nmap is already present or was installed. Raises
    ``DependencyError`` when it is missing and cannot be installed: no supported
    package manager, a refused ``sudo -n`` with no terminal to prompt on, an
    installer that errored, or an install that "succeeded" yet left no nmap on
    PATH. Every step is logged to the run's audit log.

    The injectable ``which``/``run``/``is_root``/``interactive`` seams exist for
    the offline tests; production calls pass nothing and get real behavior.
    """
    log = log or get_logger()
    which = which or shutil.which
    run = run or subprocess.run

    if which("nmap"):
        return True

    mgr = detect_package_manager(which)
    if mgr is None:
        raise DependencyError(
            "nmap is not installed and no supported package manager "
            "(apt-get/dnf/pacman/zypper/brew) was found on the run host. "
            "Install nmap manually and re-run."
        )

    root = _is_root() if is_root is None else is_root
    tty = _interactive() if interactive is None else interactive
    log.info("deps: nmap missing on run host; auto-installing via %s "
             "(root=%s, interactive_tty=%s)", mgr.name, root, tty)

    # Best-effort refresh first (apt lists may be stale); a failure here is only
    # a warning -- the install below is the step that actually has to work.
    if mgr.refresh:
        cmd = wrapped_command(mgr.refresh, is_root=root, interactive=tty,
                              privileged=mgr.privileged)
        log.info("deps: running %s", " ".join(cmd))
        try:
            proc = run(cmd, check=False)
            if proc.returncode != 0:
                log.warning("deps: '%s' exited %d; continuing to install anyway",
                            " ".join(cmd), proc.returncode)
        except OSError as exc:
            log.warning("deps: could not run '%s' (%s); continuing to install",
                        " ".join(cmd), exc)

    cmd = wrapped_command(mgr.install, is_root=root, interactive=tty,
                          privileged=mgr.privileged)
    log.info("deps: running %s", " ".join(cmd))
    try:
        proc = run(cmd, check=False)
    except OSError as exc:
        # sudo itself absent, or the manager vanished between detect and run.
        log.error("deps: could not execute '%s' (%s)", " ".join(cmd), exc)
        raise DependencyError(
            f"could not run the nmap installer ('{cmd[0]}': {exc}). "
            f"Install nmap manually: {manual_command(mgr)}"
        ) from exc

    if proc.returncode != 0:
        hint = ""
        if mgr.privileged and not root and not tty:
            hint = (" -- passwordless sudo (sudo -n) was refused and there is no "
                    "terminal to prompt for a password on (cron/CI)")
        log.error("deps: nmap install failed (exit %d)%s", proc.returncode, hint)
        raise DependencyError(
            f"installing nmap failed (exit {proc.returncode}){hint}. "
            f"Install nmap manually: {manual_command(mgr)}"
        )

    if not which("nmap"):
        log.error("deps: installer via %s reported success but nmap is still "
                  "not on PATH", mgr.name)
        raise DependencyError(
            f"ran the nmap installer via {mgr.name} but nmap is still not on "
            f"PATH. Install nmap manually: {manual_command(mgr)}"
        )

    log.info("deps: nmap installed successfully via %s", mgr.name)
    return True
