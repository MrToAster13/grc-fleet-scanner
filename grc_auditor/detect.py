"""Stage 5: confirm Ubuntu version and locate OpenSCAP + CIS content.

Authoritative determination over SSH:
  * read /etc/os-release -> confirm ID=ubuntu, capture VERSION_ID
  * confirm passwordless ``sudo -n`` is usable (scans need root)
  * confirm the ``oscap`` binary is present (capture its version)
  * confirm the matching SSG datastream exists for that exact version
  * confirm the resolved CIS profile id actually lives inside that datastream
    (via ``oscap info``) so a scan cannot fail mid-run on a missing profile

Honoring the approved design, this stage never installs anything. It only
classifies the host so the report is honest about coverage:
  * sudo password required / oscap missing / SSG content missing -> SCANNER_ABSENT
  * version (or its profile) has no SSG content -> UNSUPPORTED_VERSION
  * otherwise returns a ready ScanPlan
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import profiles
from .config import Config
from .logging_setup import get_logger
from .models import HostRecord, HostStatus
from .remote import RemoteHost

log = get_logger()

# apt package that ships the Ubuntu SSG datastreams; named in operator-facing
# details so a human can see exactly what is missing (we never install it).
_SSG_APT_PACKAGE = "ssg-base"
_OSCAP_APT_PACKAGE = "libopenscap8"  # provides the 'oscap' binary on Ubuntu


@dataclass
class ScanPlan:
    """Everything scan.py needs to evaluate one host."""

    datastream_path: str
    profile_id: str
    cis_level: int
    ubuntu_version: str


def _parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        out[key.strip()] = val.strip().strip('"').strip("'")
    return out


def _oscap_version(conn: RemoteHost) -> Optional[str]:
    """Best-effort capture of the remote oscap version string (first line)."""
    res = conn.run("oscap --version", timeout=30)
    if not res.ok or not res.stdout.strip():
        return None
    first = res.stdout.strip().splitlines()[0].strip()
    return first or None


def _sudo_available(conn: RemoteHost, group_uses_sudo: bool) -> bool:
    """True if passwordless ``sudo -n`` works (or sudo is not required).

    Scans run with ``sudo -n``; if the credential group disables sudo we assume
    the login user is already root and skip the probe.
    """
    if not group_uses_sudo:
        return True
    return conn.run("true", sudo=True, timeout=30).ok


def detect(host: HostRecord, conn: RemoteHost, cfg: Config) -> Optional[ScanPlan]:
    """Inspect a connected host; update its status; return a ScanPlan if scannable."""
    res = conn.run("cat /etc/os-release", timeout=30)
    if not res.ok:
        host.status = HostStatus.SCAN_ERROR
        host.detail = f"could not read /etc/os-release (exit {res.exit_code})"
        return None

    osr = _parse_os_release(res.stdout)
    distro = osr.get("ID", "").lower()
    version = osr.get("VERSION_ID", "")

    if distro != "ubuntu":
        host.is_ubuntu = False
        host.status = HostStatus.NON_UBUNTU
        host.detail = f"os-release ID={distro or 'unknown'} (not Ubuntu)"
        return None

    host.is_ubuntu = True
    host.ubuntu_version = version

    ds_path = profiles.datastream_path(version, cfg.ssg_dir)
    if ds_path is None:
        host.status = HostStatus.UNSUPPORTED_VERSION
        host.detail = (
            f"Ubuntu {version}: no SSG CIS profile available "
            f"(supported: {', '.join(profiles.supported_versions())})"
        )
        return None

    group = cfg.credential_group_for(host.ip)
    level = cfg.cis_level_for(group)
    resolved_profile = profiles.profile_id(level)
    group_uses_sudo = group.sudo if group is not None else True

    # (a) sudo password required: distinguish this from a missing scanner so the
    # operator fixes credentials/sudoers rather than chasing a phantom install.
    if not _sudo_available(conn, group_uses_sudo):
        host.status = HostStatus.SCANNER_ABSENT
        host.detail = (
            "passwordless sudo unavailable ('sudo -n' failed); the CIS scan "
            "needs root. Grant NOPASSWD sudo for oscap or set sudo: false for "
            "a root login. Not installing anything (audit integrity)."
        )
        return None

    # (b) oscap binary missing.
    if not conn.run("command -v oscap", timeout=30).ok:
        host.status = HostStatus.SCANNER_ABSENT
        host.detail = (
            f"oscap binary not found (likely apt package '{_OSCAP_APT_PACKAGE}'); "
            f"not installing - audit integrity"
        )
        return None

    oscap_ver = _oscap_version(conn)

    # (c) oscap present but the SSG content package is absent on this host.
    if not conn.run_argv(["test", "-f", ds_path], timeout=30).ok:
        host.status = HostStatus.SCANNER_ABSENT
        host.detail = (
            f"oscap present but SSG content missing at {ds_path} "
            f"(likely apt package '{_SSG_APT_PACKAGE}'); not installing"
        )
        return None

    # Verify the resolved profile actually exists *inside* the datastream before
    # we declare the host scannable -- otherwise the scan fails mid-run. We ask
    # oscap itself (authoritative) and match the id as a whole token.
    info = conn.run_argv(["oscap", "info", ds_path], timeout=60)
    if not info.ok:
        host.status = HostStatus.SCAN_ERROR
        detail = info.stderr.strip() or info.stdout.strip()
        host.detail = f"oscap info failed on {ds_path}: {detail[:200]}"
        return None
    if not profiles.profile_present_in_info(info.stdout, resolved_profile):
        host.status = HostStatus.UNSUPPORTED_VERSION
        host.detail = (
            f"profile {resolved_profile} not present in {ds_path} "
            f"(SSG content for Ubuntu {version} ships no CIS L{level} server "
            f"profile); flagged, not mis-scanned"
        )
        return None

    if oscap_ver:
        host.detail = f"Ubuntu {version}, {oscap_ver}, CIS L{level} ready"

    plan = ScanPlan(
        datastream_path=ds_path,
        profile_id=resolved_profile,
        cis_level=level,
        ubuntu_version=version,
    )
    log.info("detect[%s]: Ubuntu %s, CIS L%d ready (%s)",
             host.ip, version, level, oscap_ver or "oscap version unknown")
    return plan
