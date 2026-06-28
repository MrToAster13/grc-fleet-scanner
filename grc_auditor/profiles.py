"""SCAP Security Guide content registry for Ubuntu.

Maps an Ubuntu VERSION_ID to the SSG datastream that ships its CIS content, and
builds the CIS profile id for a given level. This is the single place that
encodes the profile-version match rule: a host is only ever scanned with the
datastream/profile that matches its exact Ubuntu release. Anything not in this
table is treated as an unsupported version and flagged, never mis-scanned.
"""

from __future__ import annotations

from typing import Optional

# Default install location of SSG content on Ubuntu (ssg-base / scap-security-guide).
DEFAULT_SSG_DIR = "/usr/share/xml/scap/ssg/content"

# Ubuntu VERSION_ID -> SSG datastream filename.
#
# Filenames verified against current scap-security-guide releases: the Ubuntu
# content ships one combined datastream per LTS, named ``ssg-ubuntu<NNNN>-ds.xml``
# where ``<NNNN>`` is the release with the dot removed (e.g. 22.04 -> 2204).
# These are the four LTS releases that carry an upstream CIS profile.
_DATASTREAM_BY_VERSION: dict[str, str] = {
    "18.04": "ssg-ubuntu1804-ds.xml",
    "20.04": "ssg-ubuntu2004-ds.xml",
    "22.04": "ssg-ubuntu2204-ds.xml",
    "24.04": "ssg-ubuntu2404-ds.xml",
}


def normalize_version(version_id: str) -> str:
    """Reduce a VERSION_ID to the ``MAJOR.MINOR`` SSG keys understood by this table.

    Ubuntu's ``VERSION_ID`` in /etc/os-release is ``MAJOR.MINOR`` for an LTS
    (e.g. ``"22.04"``), but a point release or a re-spun image can carry a
    third component (``"22.04.3"``) and some images quote or pad it. SSG keys
    its content by the LTS ``MAJOR.MINOR`` only, so we keep the first two
    dotted components and drop anything after them.

    Examples: ``"22.04.3"`` -> ``"22.04"``; ``" 20.04 "`` -> ``"20.04"``;
    ``"24"`` -> ``"24"`` (left as-is; an unknown key is simply unsupported).
    """
    cleaned = version_id.strip().strip('"').strip("'").strip()
    if not cleaned:
        return ""
    parts = cleaned.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return cleaned


def datastream_for_version(version_id: str) -> Optional[str]:
    """Return the SSG datastream filename for an Ubuntu version, or None.

    The version is normalized to its ``MAJOR.MINOR`` LTS key first, so point
    releases such as ``"22.04.3"`` resolve to the ``22.04`` datastream.
    """
    return _DATASTREAM_BY_VERSION.get(normalize_version(version_id))


def datastream_path(version_id: str, ssg_dir: str = DEFAULT_SSG_DIR) -> Optional[str]:
    """Absolute path of the datastream on the target host, or None if unsupported."""
    ds = datastream_for_version(version_id)
    if ds is None:
        return None
    return f"{ssg_dir.rstrip('/')}/{ds}"


def profile_id(level: int) -> str:
    """CIS profile id for the given level (server baseline).

    SSG profile ids follow the form
    ``xccdf_org.ssgproject.content_profile_cis_level{N}_server``.

    TODO(server-vs-workstation): we deliberately resolve to the *server*
    baseline. SSG also ships ``cis_level{N}_workstation`` profiles, which relax
    or drop a number of server-oriented controls (e.g. some network-daemon and
    GUI-hardening rules). The fleet this tool audits is server infrastructure,
    so the server profile is the audit-defensible default. If workstation
    coverage is ever needed, expose it as a per-credential-group choice (mirror
    ``cis_level``) rather than guessing from the host -- the profile-version
    match rule means a wrong baseline is a mis-scan, not a partial scan.
    """
    if level not in (1, 2):
        raise ValueError(f"CIS level must be 1 or 2, got {level!r}")
    return f"xccdf_org.ssgproject.content_profile_cis_level{level}_server"


def profile_present_in_info(oscap_info_output: str, profile_id_: str) -> bool:
    """Confirm a profile id is advertised by a datastream's ``oscap info`` output.

    The actual ``oscap info <datastream>`` call runs on the target host (see
    detect.py); this helper only inspects the captured text so the decision is
    testable offline. ``oscap info`` prints each available profile on its own
    line as ``<id>\\n        Title: ...`` (the id may be indented and may carry
    a trailing ``(default)`` marker), so we match the id as a whole token rather
    than a loose substring to avoid a ``level1`` prefix matching ``level2``.

    Returns False for empty/None inputs so an unreadable datastream is treated
    as "profile not confirmed present" by the caller.
    """
    if not oscap_info_output or not profile_id_:
        return False
    for raw in oscap_info_output.splitlines():
        for token in raw.replace("\t", " ").split():
            if token == profile_id_:
                return True
    return False


def supported_versions() -> list[str]:
    return sorted(_DATASTREAM_BY_VERSION)
