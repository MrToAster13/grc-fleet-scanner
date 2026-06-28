"""Stage 3: classify discovered hosts.

Applies an Ubuntu *hint* (from service banners / OS guess) and matches each host
to a credential group. The hint is intentionally conservative; the authoritative
Ubuntu determination is made later over SSH in the detect stage (which reads
/etc/os-release and will override a wrong hint). Classification only sets the
initial coverage status:

  * Ubuntu hint + credential group  -> stays DISCOVERED (proceeds to reach)
  * Ubuntu hint + no group          -> NO_CREDENTIALS
  * Ubuntu hint + no SSH port       -> UNREACHABLE
  * no Ubuntu hint                  -> NON_UBUNTU (inventory only)

Optionally (gated on config, default off) unknown-Linux hosts can be promoted to
Ubuntu *candidates* so they proceed to the authoritative SSH detect stage.
"""

from __future__ import annotations

from .config import Config
from .logging_setup import get_logger
from .models import HostRecord, HostStatus

log = get_logger()

# Substrings that, when present in an OS guess or service banner, strongly
# indicate Ubuntu. nmap renders Ubuntu's OpenSSH version as e.g.
# "8.9p1 Ubuntu-3ubuntu0.6"; the embedded build token "ubuntu" (lowercased)
# matches plain "ubuntu" already, so these focus on the distinct shapes.
_UBUNTU_MARKERS = (
    "ubuntu",      # banner product/extrainfo/ostype, os fingerprint, build tags
)

# Generic Linux markers used only for the optional unknown-Linux promotion.
# Deliberately broad but still Linux-specific (avoids Windows/BSD/macOS).
_LINUX_MARKERS = (
    "linux",
    "debian",        # Ubuntu derives from Debian; close enough to warrant a probe
    "gnu/linux",
)

# Markers that clearly indicate a NON-Linux OS; if any of these dominate the
# fingerprint we never promote it as an Ubuntu candidate.
_NON_LINUX_MARKERS = (
    "windows",
    "microsoft",
    "freebsd",
    "openbsd",
    "netbsd",
    "darwin",
    "mac os",
    "macos",
    "cisco",
    "juniper",
    "vmware esxi",
)


def _host_blob(host: HostRecord) -> str:
    """Lowercased haystack of everything we know about the host's identity."""
    haystacks = [host.os_guess or ""] + list(host.banners.values())
    return " ".join(haystacks).lower()


def _looks_ubuntu(host: HostRecord) -> bool:
    """Conservative Ubuntu hint from banners / OS fingerprint."""
    blob = _host_blob(host)
    return any(marker in blob for marker in _UBUNTU_MARKERS)


def _looks_linux(host: HostRecord) -> bool:
    """Best-effort 'this is some Linux' hint, excluding clear non-Linux OSes."""
    blob = _host_blob(host)
    if any(marker in blob for marker in _NON_LINUX_MARKERS):
        return False
    return any(marker in blob for marker in _LINUX_MARKERS)


def _has_ssh(host: HostRecord) -> bool:
    return 22 in host.open_ports or any(
        key.startswith("22/") for key in host.banners
    )


def classify(hosts: list[HostRecord], cfg: Config) -> list[HostRecord]:
    """Set each host's initial coverage status from its discovery fingerprint.

    When ``cfg.treat_unknown_linux_as_ubuntu`` is truthy (read defensively;
    defaults to False so current behavior is preserved), hosts that look like
    some non-specific Linux are promoted to Ubuntu *candidates*. They are NOT
    asserted to be Ubuntu — the SSH detect stage remains authoritative and will
    reclassify any that are not actually Ubuntu as NON_UBUNTU.
    """
    # Read the optional knob defensively: config.py does not (yet) define it,
    # and we must not edit config.py. Default preserves current behavior.
    promote_unknown_linux = bool(
        getattr(cfg, "treat_unknown_linux_as_ubuntu", False)
    )

    for host in hosts:
        is_ubuntu = _looks_ubuntu(host)
        candidate_reason = None  # set when promoted via the optional knob

        if not is_ubuntu and promote_unknown_linux and _looks_linux(host):
            is_ubuntu = True
            candidate_reason = (
                "unknown-Linux promoted to Ubuntu candidate (SSH detect is "
                "authoritative)"
            )

        host.is_ubuntu = is_ubuntu

        if not host.is_ubuntu:
            host.status = HostStatus.NON_UBUNTU
            host.detail = "no Ubuntu indicator in banners/OS fingerprint"
            continue

        group = cfg.credential_group_for(host.ip)
        if group is None:
            host.status = HostStatus.NO_CREDENTIALS
            host.detail = "Ubuntu host but no credential group matched its IP"
            continue

        host.credential_group = group.name
        if not _has_ssh(host):
            # Ubuntu-looking but no SSH port open: cannot deep-dive.
            host.status = HostStatus.UNREACHABLE
            host.detail = "no open SSH port (22) detected"
            continue

        # Ready for the reach stage; leave as DISCOVERED.
        host.status = HostStatus.DISCOVERED
        host.detail = candidate_reason

    summary = {}
    for h in hosts:
        summary[h.status.value] = summary.get(h.status.value, 0) + 1
    log.info("classify: %s", ", ".join(f"{k}={v}" for k, v in sorted(summary.items())))
    return hosts
