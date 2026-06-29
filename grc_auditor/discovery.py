"""Stage 1-2: active network discovery via nmap.

Sweeps the in-scope CIDRs with cautious timing, fingerprints services, and
returns a HostRecord per live host. OS detection (-O) is best-effort (it needs
root on the run host); authoritative Ubuntu detection happens later over SSH.
Every invocation is logged with its exact argument vector.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional

try:
    from defusedxml.ElementTree import fromstring as _safe_xml_fromstring
    from defusedxml.common import DefusedXmlException
except ImportError as exc:  # pragma: no cover - dependency guard
    raise SystemExit(
        "defusedxml is required. Install dependencies: pip install -r requirements.txt"
    ) from exc

from .config import ScanScope
from .logging_setup import get_logger
from .models import HostRecord

log = get_logger()

# Valid nmap timing templates. Anything else is rejected so a typo'd or
# injected token (e.g. "-T9" or an unrelated flag) never reaches the binary.
_VALID_TIMING = {"-T0", "-T1", "-T2", "-T3", "-T4", "-T5"}
_DEFAULT_TIMING = "-T3"  # SPEC: cautious default.

# Default number of CIDR targets per nmap invocation. A single nmap process can
# scan an arbitrary number of targets, but very large scopes (e.g. hundreds of
# CIDRs) produce one huge XML blob held entirely in memory, make failures
# all-or-nothing, and delay the first results. Chunking the target list into a
# handful of smaller runs keeps memory bounded, isolates a failing batch from
# the rest, and still returns a single combined list. The default is generous
# so typical "tens-low hundreds of hosts" scopes (SPEC) run as one batch.
_DEFAULT_BATCH_SIZE = 64


class DiscoveryError(Exception):
    pass


def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _safe_timing(timing: Optional[str]) -> str:
    """Validate the configured nmap timing token, falling back to the default.

    Only -T0..-T5 are accepted; anything else is logged and replaced so a bad
    config value can never inject an arbitrary nmap flag.
    """
    token = (timing or "").strip()
    if token in _VALID_TIMING:
        return token
    log.warning(
        "discovery: ignoring invalid nmap timing %r (expected -T0..-T5); "
        "using %s", timing, _DEFAULT_TIMING,
    )
    return _DEFAULT_TIMING


def _chunk(items: list, size: int) -> list:
    """Split ``items`` into consecutive sublists of at most ``size`` elements."""
    if size <= 0:
        return [list(items)] if items else []
    return [items[i:i + size] for i in range(0, len(items), size)]


def build_nmap_args(scope: ScanScope, want_os: bool,
                    cidrs: Optional[list] = None) -> list[str]:
    """Build the nmap argument vector for ``scope``.

    ``cidrs`` overrides the targets scanned (used when scanning the scope in
    batches); when omitted the full ``scope.cidrs`` list is used so the public
    single-batch behavior is unchanged.
    """
    args = ["nmap", _safe_timing(scope.nmap_timing), "-sV", "-oX", "-"]
    if want_os:
        args.append("-O")
    for ex in scope.exclude:
        args += ["--exclude", ex]
    args += list(scope.nmap_extra_args)
    args += list(scope.cidrs if cidrs is None else cidrs)
    return args


def _run_nmap(scope: ScanScope, want_os: bool, cidrs: list) -> list[HostRecord]:
    """Run one nmap batch over ``cidrs`` and parse it into HostRecords.

    Raises DiscoveryError distinguishing the three failure outcomes:
      * nmap binary missing
      * nmap errored producing no usable output
    A successful run that simply finds nothing returns an empty list (that is a
    valid result, not an error).
    """
    args = build_nmap_args(scope, want_os, cidrs=cidrs)
    log.info("discovery: running %s", " ".join(args))
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, check=False,
            timeout=max(scope.host_timeout_seconds * 4, 600),
        )
    except subprocess.TimeoutExpired as exc:
        raise DiscoveryError(f"nmap timed out: {exc}") from exc

    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()

    # nmap errored AND gave us nothing to parse: a hard failure.
    if proc.returncode != 0 and not out:
        raise DiscoveryError(
            "nmap failed (exit {code}) and produced no output. stderr:\n{err}".format(
                code=proc.returncode, err=err or "(none)",
            )
        )
    # Ran (exit 0) but emitted no XML at all: distinct from "ran, zero hosts".
    if not out:
        raise DiscoveryError(
            "nmap exited cleanly but produced no output to parse. stderr:\n"
            + (err or "(none)")
        )
    if proc.returncode != 0:
        # Non-zero exit but we still got XML (e.g. some targets unresolved):
        # parse what we have, but surface the warning.
        log.warning("discovery: nmap exited %d but produced output; "
                    "parsing partial results. stderr: %s",
                    proc.returncode, err or "(none)")
    elif err:
        log.debug("discovery: nmap stderr: %s", err)

    return parse_nmap_xml(out)


def discover(scope: ScanScope, *, want_os: bool = False,
             _xml_override: Optional[str] = None,
             batch_size: int = _DEFAULT_BATCH_SIZE) -> list[HostRecord]:
    """Run nmap over the scope and parse results into HostRecords.

    ``_xml_override`` lets tests/offline runs feed nmap XML directly without
    invoking the binary.

    ``batch_size`` caps how many CIDR targets are handed to a single nmap
    invocation; large scopes are scanned in consecutive batches and the live
    hosts are merged into one combined, de-duplicated list. The default keeps
    typical scopes as a single batch (see ``_DEFAULT_BATCH_SIZE``).
    """
    if _xml_override is not None:
        return parse_nmap_xml(_xml_override)

    if not _nmap_available():
        raise DiscoveryError(
            "nmap not found on the run host. Install it (apt install nmap) or run "
            "from a host that has it."
        )

    cidrs = list(scope.cidrs)
    batches = _chunk(cidrs, batch_size) or [[]]
    if len(batches) > 1:
        log.info("discovery: scanning %d CIDR(s) in %d batch(es) of up to %d",
                 len(cidrs), len(batches), batch_size)

    # Merge across batches, de-duplicating by chosen IP. A host could in
    # principle surface in two batches if CIDRs overlap; keep the first record.
    merged: dict = {}
    order: list = []
    for batch in batches:
        for host in _run_nmap(scope, want_os, batch):
            if host.ip not in merged:
                merged[host.ip] = host
                order.append(host.ip)

    hosts = [merged[ip] for ip in order]
    if not hosts:
        log.info("discovery: nmap ran but found 0 live host(s) in scope")
    else:
        log.info("discovery: %d live host(s) found", len(hosts))
    return hosts


def _pick_address(host_el) -> Optional[str]:
    """Choose the host's address, preferring IPv4 then IPv6.

    Real-world nmap emits several <address> elements per host (e.g. IPv4 + MAC,
    or IPv4 + IPv6). We record exactly one routable IP and prefer IPv4.
    """
    ipv4 = None
    ipv6 = None
    for addr in host_el.findall("address"):
        addrtype = addr.get("addrtype")
        value = addr.get("addr")
        if not value:
            continue
        if addrtype == "ipv4" and ipv4 is None:
            ipv4 = value
        elif addrtype == "ipv6" and ipv6 is None:
            ipv6 = value
    return ipv4 or ipv6


def _pick_hostname(host_el) -> Optional[str]:
    """Choose the most authoritative hostname.

    nmap can report several <hostname> entries with a ``type`` attribute:
    ``user`` (supplied on the command line) and ``PTR`` (reverse DNS). Prefer
    user, then PTR, then any named entry, so we record the most meaningful one.
    """
    names = host_el.findall("hostnames/hostname")
    if not names:
        return None
    by_type: dict = {}
    fallback = None
    for hn in names:
        name = hn.get("name")
        if not name:
            continue
        htype = (hn.get("type") or "").lower()
        by_type.setdefault(htype, name)
        if fallback is None:
            fallback = name
    for preferred in ("user", "ptr"):
        if preferred in by_type:
            return by_type[preferred]
    return fallback


def _service_banner(svc_el) -> str:
    """Assemble a banner from a <service> element, tolerating missing fields.

    Any of product / version / extrainfo may be absent; we also fold in the
    service ``name`` and the negotiated OS hint (``ostype``) so an Ubuntu/Debian
    marker on a bare service still survives for the classify stage.
    """
    if svc_el is None:
        return ""
    parts = [
        svc_el.get("product"),
        svc_el.get("version"),
        svc_el.get("extrainfo"),
        svc_el.get("ostype"),
    ]
    banner = " ".join(p for p in parts if p).strip()
    if banner:
        return banner
    # Nothing descriptive; fall back to the bare service name if present.
    return (svc_el.get("name") or "").strip()


def parse_nmap_xml(xml_text: str) -> list[HostRecord]:
    """Parse nmap -oX output into HostRecords (live hosts only).

    Tolerant of real-world nmap XML: multiple <address>/<hostname> entries,
    services missing product/version/extrainfo, ``open|filtered`` ports, and
    absent <os> blocks. Hosts whose status is not ``up`` (down/filtered) are
    excluded.
    """
    try:
        root = _safe_xml_fromstring(xml_text)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise DiscoveryError(f"could not parse nmap XML output: {exc}") from exc

    hosts: list[HostRecord] = []

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        # Only keep hosts nmap considers up. Missing <status> is treated as up
        # (some minimal XML omits it); explicit down/filtered/unknown is skipped.
        if status_el is not None and status_el.get("state") != "up":
            continue

        ip = _pick_address(host_el)
        if not ip:
            continue

        hostname = _pick_hostname(host_el)

        open_ports: list[int] = []
        banners: dict[str, str] = {}
        for port_el in host_el.findall("ports/port"):
            st = port_el.find("state")
            state = st.get("state") if st is not None else None
            # Count a port as reachable when it is "open" or "open|filtered"
            # (nmap's ambiguous verdict when it cannot fully confirm). We skip
            # closed/filtered. The downstream reach stage still verifies SSH.
            if state not in ("open", "open|filtered"):
                continue
            try:
                portnum = int(port_el.get("portid"))
            except (TypeError, ValueError):
                continue
            proto = port_el.get("protocol", "tcp")
            open_ports.append(portnum)
            banner = _service_banner(port_el.find("service"))
            if banner:
                banners[f"{portnum}/{proto}"] = banner

        os_guess = None
        os_match = host_el.find("os/osmatch")
        if os_match is not None:
            os_guess = os_match.get("name")

        hosts.append(HostRecord(
            ip=ip,
            hostname=hostname,
            os_guess=os_guess,
            open_ports=sorted(set(open_ports)),
            banners=banners,
        ))

    return hosts


# Exposed so other modules / tests can reason about which timings are accepted
# without importing the private set name directly.
def valid_timing(token: str) -> bool:
    """Return True if ``token`` is an accepted nmap timing template (-T0..-T5)."""
    return bool(token) and token.strip() in _VALID_TIMING
