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
        for t in self.targets:
            t = t.strip()
            if t in ("default", "*", "0.0.0.0/0"):
                return True
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(t, strict=False):
                    return True
            except ValueError:
                # Allow an exact IP literal as a target.
                if t == ip:
                    return True
        return False


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

    def hash(self) -> str:
        blob = json.dumps(self.raw, sort_keys=True, default=str).encode()
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
    cidrs = scope_doc.get("cidrs") or []
    if not cidrs:
        raise ConfigError(
            "scope.cidrs is empty. Active scanning requires an explicit, "
            "authorized target scope. Refusing to run."
        )
    for c in cidrs:
        try:
            ipaddress.ip_network(c, strict=False)
        except ValueError as exc:
            raise ConfigError(f"Invalid CIDR in scope.cidrs: {c!r} ({exc})") from exc

    scope = ScanScope(
        cidrs=list(cidrs),
        exclude=list(scope_doc.get("exclude", [])),
        nmap_timing=scope_doc.get("nmap_timing", "-T3"),
        nmap_extra_args=list(scope_doc.get("nmap_extra_args", [])),
        ssh_concurrency=int(scope_doc.get("ssh_concurrency", 10)),
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
        raw=doc,
    )


def apply_overrides(cfg: Config, *, cidrs=None, exclude=None, output_dir=None,
                    cis_level=None, ssh_concurrency=None,
                    low_confidence_threshold=None) -> Config:
    """Apply CLI overrides onto a loaded Config (CLI wins over file)."""
    if cidrs:
        cfg.scope.cidrs = list(cidrs)
        cfg.raw.setdefault("scope", {})["cidrs"] = list(cidrs)
    if exclude:
        cfg.scope.exclude = list(exclude)
    if output_dir:
        cfg.output_dir = output_dir
    if cis_level is not None:
        if cis_level not in (1, 2):
            raise ConfigError("--cis-level must be 1 or 2")
        cfg.cis_level = cis_level
    if ssh_concurrency is not None:
        cfg.scope.ssh_concurrency = ssh_concurrency
    if low_confidence_threshold is not None:
        cfg.low_confidence_threshold = _validate_threshold(low_confidence_threshold)
        # Mirror into raw so config_hash() reflects the override (like cidrs).
        cfg.raw["low_confidence_threshold"] = cfg.low_confidence_threshold
    return cfg
