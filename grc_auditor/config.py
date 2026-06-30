"""Configuration: YAML schema, validation, and CLI override merge.

The config is a hard precondition for running: the tool refuses to scan without
an explicitly populated scope. Credential groups map host ranges to the SSH
identity + privilege used to audit them.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from typing import Optional

from .models import DEFAULT_LOW_CONFIDENCE_THRESHOLD

try:
    import yaml
except ImportError as exc:  # pragma: no cover - dependency guard
    raise SystemExit(
        "PyYAML is required. Install dependencies: pip install -r requirements.txt"
    ) from exc


class ConfigError(Exception):
    """Raised for any invalid or missing configuration."""


@dataclass
class BastionConfig:
    host: str
    user: str
    port: int = 22
    key_path: Optional[str] = None


@dataclass
class CredentialGroup:
    """How to reach and authenticate to a set of hosts."""

    name: str
    ssh_user: str
    targets: list[str]                       # CIDRs, or ["default"] / ["*"] catch-all
    key_path: Optional[str] = None           # explicit key; else rely on agent
    use_agent: bool = True
    ssh_port: int = 22
    sudo: bool = True                        # use 'sudo -n' for root-only checks
    cis_level: Optional[int] = None          # per-group override of the global level
    bastion: Optional[BastionConfig] = None

    def matches(self, ip: str) -> bool:
        # Catch-all tokens match any address -- including IPv6, which the literal
        # "0.0.0.0/0" network would not. Everything else routes through the one
        # shared membership helper so network matching lives in a single place.
        if any(t.strip() in ("default", "*", "0.0.0.0/0") for t in self.targets):
            return True
        return ip_in_networks(ip, self.targets)


@dataclass
class ScanScope:
    cidrs: list[str]
    exclude: list[str] = field(default_factory=list)
    nmap_timing: str = "-T3"
    nmap_extra_args: list[str] = field(default_factory=list)
    ssh_concurrency: int = 10
    host_timeout_seconds: int = 600


@dataclass
class Config:
    scope: ScanScope
    credential_groups: list[CredentialGroup]
    output_dir: str = "./grc-output"
    known_hosts: Optional[str] = None        # path; None -> system + ~/.ssh/known_hosts
    cis_level: int = 1                        # global default (per spec)
    ssg_dir: str = "/usr/share/xml/scap/ssg/content"
    # Below this % of the benchmark producing a verdict, a host's score is
    # flagged LOW CONFIDENCE in the report (guards against a high score that
    # only reflects the few checks that actually ran).
    low_confidence_threshold: float = DEFAULT_LOW_CONFIDENCE_THRESHOLD
    # When true, hosts whose fingerprint looks like some non-specific Linux (but
    # not clearly non-Linux) are promoted to Ubuntu *candidates* so the SSH detect
    # stage -- which stays authoritative -- gets to confirm or reject them. Default
    # off: a host must show an Ubuntu marker to be probed. Affects which hosts are
    # connected to, so it is part of the run's canonical (hashed) behavior.
    treat_unknown_linux_as_ubuntu: bool = False
    raw: dict = field(default_factory=dict)   # original parsed document

    def cis_level_for(self, group: Optional[CredentialGroup]) -> int:
        if group is not None and group.cis_level is not None:
            return group.cis_level
        return self.cis_level

    def credential_group_for(self, ip: str) -> Optional[CredentialGroup]:
        for g in self.credential_groups:
            if g.matches(ip):
                return g
        return None

    @staticmethod
    def _group_canonical(g: "CredentialGroup") -> dict:
        return {
            "name": g.name, "ssh_user": g.ssh_user, "targets": sorted(g.targets),
            "key_path": g.key_path, "use_agent": g.use_agent,
            "ssh_port": g.ssh_port, "sudo": g.sudo, "cis_level": g.cis_level,
            "bastion": None if g.bastion is None else {
                "host": g.bastion.host, "user": g.bastion.user,
                "port": g.bastion.port, "key_path": g.bastion.key_path,
            },
        }

    def canonical(self) -> dict:
        """The EFFECTIVE configuration that determines a run's behavior -- the
        basis for ``config_hash`` and the sealed per-run provenance artifact.

        Computed from the resolved dataclass fields AFTER overrides (not the raw
        YAML), so a ``--cis-level`` / ``--cidr`` / ``--concurrency`` override is
        reflected; two runs hash the same iff they would behave the same.
        ``output_dir`` is excluded (a destination, not a behavior input)."""
        return {
            "scope": {
                "cidrs": sorted(self.scope.cidrs),
                "exclude": sorted(self.scope.exclude),
                "nmap_timing": self.scope.nmap_timing,
                "nmap_extra_args": list(self.scope.nmap_extra_args),
                "ssh_concurrency": self.scope.ssh_concurrency,
                "host_timeout_seconds": self.scope.host_timeout_seconds,
            },
            "cis_level": self.cis_level,
            "ssg_dir": self.ssg_dir,
            "known_hosts": self.known_hosts,
            "low_confidence_threshold": self.low_confidence_threshold,
            "treat_unknown_linux_as_ubuntu": self.treat_unknown_linux_as_ubuntu,
            "credential_groups": sorted(
                (self._group_canonical(g) for g in self.credential_groups),
                key=lambda d: d["name"],
            ),
        }

    def hash(self) -> str:
        blob = json.dumps(self.canonical(), sort_keys=True, default=str).encode()
        return hashlib.sha256(blob).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Loading + validation
# --------------------------------------------------------------------------- #
def _require(doc: dict, key: str, where: str):
    if key not in doc:
        raise ConfigError(f"Missing required key '{key}' in {where}")
    return doc[key]


def _validate_threshold(value) -> float:
    """Coerce + bounds-check a low-confidence threshold (single rule for both
    the config file and CLI overrides)."""
    try:
        v = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            f"low_confidence_threshold must be a number (got {value!r})"
        ) from exc
    if not 0.0 <= v <= 100.0:
        raise ConfigError("low_confidence_threshold must be between 0 and 100")
    return v


# Blast-radius guard: refuse a single scope CIDR larger than this. A typo'd /8 or
# 0.0.0.0/0 would actively scan far outside any authorized range. The tool's stated
# scale is tens-low hundreds of hosts; split a genuinely large scope into explicit
# CIDRs rather than sweeping a /8.
_MIN_IPV4_PREFIX = 16
_MIN_IPV6_PREFIX = 112
_MAX_SSH_CONCURRENCY = 100

# nmap extra-args we refuse: they add targets, redirect output, or run scripts --
# all of which can broaden the blast radius or defeat the configured scope/exclude.
_FORBIDDEN_NMAP_ARGS = {
    "-iL", "--excludefile", "--exclude", "-oA", "-oN", "-oG", "-oX", "-oS",
    "--script", "--interactive", "--resume", "--datadir",
}


def _validate_cidrs(cidrs, where: str) -> list:
    """Validate scope CIDRs: well-formed AND not over-broad (blast-radius guard).
    Shared by the file path and the --cidr override so neither can bypass it."""
    if not cidrs:
        raise ConfigError(
            "scope.cidrs is empty. Active scanning requires an explicit, "
            "authorized target scope. Refusing to run."
        )
    out = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError as exc:
            raise ConfigError(f"Invalid CIDR in {where}: {c!r} ({exc})") from exc
        floor = _MIN_IPV4_PREFIX if net.version == 4 else _MIN_IPV6_PREFIX
        if net.prefixlen < floor:
            raise ConfigError(
                f"{where}: {c} is too broad (/{net.prefixlen}, {net.num_addresses} "
                f"addresses). As a blast-radius guard the tool refuses a scope wider "
                f"than /{floor}; narrow the range or split it into explicit CIDRs."
            )
        out.append(str(c))
    return out


def _validate_exclude(exclude, where: str) -> list:
    out = []
    for c in exclude or []:
        try:
            ipaddress.ip_network(c, strict=False)
        except ValueError as exc:
            raise ConfigError(f"Invalid CIDR in {where}: {c!r} ({exc})") from exc
        out.append(str(c))
    return out


def _validate_concurrency(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"ssh_concurrency must be an integer (got {value!r})") from exc
    if not 1 <= n <= _MAX_SSH_CONCURRENCY:
        raise ConfigError(
            f"ssh_concurrency must be between 1 and {_MAX_SSH_CONCURRENCY} (got {n})"
        )
    return n


def _validate_nmap_extra_args(args) -> list:
    out = []
    for a in args or []:
        a = str(a)
        if not a.startswith("-"):
            raise ConfigError(
                f"nmap_extra_args may only contain flags, not bare targets (got "
                f"{a!r}); targets come from scope.cidrs."
            )
        if a.split("=", 1)[0] in _FORBIDDEN_NMAP_ARGS:
            raise ConfigError(
                f"nmap_extra_args: {a!r} is not allowed -- it could add targets, "
                f"redirect output, or defeat the configured scope/exclusions."
            )
        out.append(a)
    return out


def ip_in_networks(ip: str, networks) -> bool:
    """True if ``ip`` falls within any CIDR / exact-IP literal in ``networks``.
    Used to re-enforce scope.exclude after discovery (defense in depth)."""
    for n in networks or []:
        n = str(n).strip()
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            if n == ip:
                return True
    return False


def _parse_bastion(doc: Optional[dict]) -> Optional[BastionConfig]:
    if not doc:
        return None
    return BastionConfig(
        host=_require(doc, "host", "bastion"),
        user=_require(doc, "user", "bastion"),
        port=int(doc.get("port", 22)),
        key_path=doc.get("key_path"),
    )


def _parse_credential_group(doc: dict) -> CredentialGroup:
    name = _require(doc, "name", "credential_groups[]")
    where = f"credential_group '{name}'"
    level = doc.get("cis_level")
    if level is not None and int(level) not in (1, 2):
        raise ConfigError(f"{where}: cis_level must be 1 or 2")
    targets = doc.get("targets") or ["default"]
    if not isinstance(targets, list):
        raise ConfigError(f"{where}: 'targets' must be a list")
    return CredentialGroup(
        name=name,
        ssh_user=_require(doc, "ssh_user", where),
        targets=targets,
        key_path=doc.get("key_path"),
        use_agent=bool(doc.get("use_agent", True)),
        ssh_port=int(doc.get("ssh_port", 22)),
        sudo=bool(doc.get("sudo", True)),
        cis_level=None if level is None else int(level),
        bastion=_parse_bastion(doc.get("bastion")),
    )


def load_config(path: str) -> Config:
    """Parse and validate a YAML config file into a Config."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(doc, dict):
        raise ConfigError("Top-level config must be a mapping")

    scope_doc = _require(doc, "scope", "config")
    scope = ScanScope(
        cidrs=_validate_cidrs(scope_doc.get("cidrs") or [], "scope.cidrs"),
        exclude=_validate_exclude(scope_doc.get("exclude", []), "scope.exclude"),
        nmap_timing=scope_doc.get("nmap_timing", "-T3"),
        nmap_extra_args=_validate_nmap_extra_args(scope_doc.get("nmap_extra_args", [])),
        ssh_concurrency=_validate_concurrency(scope_doc.get("ssh_concurrency", 10)),
        host_timeout_seconds=int(scope_doc.get("host_timeout_seconds", 600)),
    )

    groups_doc = doc.get("credential_groups") or []
    credential_groups = [_parse_credential_group(g) for g in groups_doc]

    level = int(doc.get("cis_level", 1))
    if level not in (1, 2):
        raise ConfigError("cis_level must be 1 or 2")

    threshold = _validate_threshold(
        doc.get("low_confidence_threshold", DEFAULT_LOW_CONFIDENCE_THRESHOLD))

    return Config(
        scope=scope,
        credential_groups=credential_groups,
        output_dir=doc.get("output_dir", "./grc-output"),
        known_hosts=doc.get("known_hosts"),
        cis_level=level,
        ssg_dir=doc.get("ssg_dir", "/usr/share/xml/scap/ssg/content"),
        low_confidence_threshold=threshold,
        treat_unknown_linux_as_ubuntu=bool(
            doc.get("treat_unknown_linux_as_ubuntu", False)),
        raw=doc,
    )


def apply_overrides(cfg: Config, *, cidrs=None, exclude=None, output_dir=None,
                    cis_level=None, ssh_concurrency=None,
                    low_confidence_threshold=None) -> Config:
    """Apply CLI overrides onto a loaded Config (CLI wins over file).

    Every override runs through the SAME validators as the file path -- a --cidr
    override is no longer a way to slip a malformed or over-broad (blast-radius)
    range past the checks that load_config enforces.
    """
    if cidrs:
        cfg.scope.cidrs = _validate_cidrs(list(cidrs), "--cidr")
    if exclude is not None:
        cfg.scope.exclude = _validate_exclude(list(exclude), "--exclude")
    if output_dir:
        cfg.output_dir = output_dir
    if cis_level is not None:
        if cis_level not in (1, 2):
            raise ConfigError("--cis-level must be 1 or 2")
        cfg.cis_level = cis_level
    if ssh_concurrency is not None:
        cfg.scope.ssh_concurrency = _validate_concurrency(ssh_concurrency)
    if low_confidence_threshold is not None:
        cfg.low_confidence_threshold = _validate_threshold(low_confidence_threshold)
    return cfg
