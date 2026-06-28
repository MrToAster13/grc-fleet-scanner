"""Shared data contracts.

These three types are the seams the rest of the system is built around:
  * HostStatus  - the coverage classification for every discovered host
  * HostRecord  - one row of fleet inventory + (optional) scan result
  * RunRecord   - one immutable audit run

When the build later fans out to a team, these definitions are frozen first so
each module can be developed independently against a stable contract.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional


class HostStatus(str, Enum):
    """Coverage classification. The report is honest about every one of these."""

    DISCOVERED = "discovered"                    # alive, not yet processed
    NON_UBUNTU = "non_ubuntu"                     # alive but not Ubuntu -> inventory only
    NO_CREDENTIALS = "no_credentials"            # Ubuntu, alive, no cred group matched
    UNREACHABLE = "unreachable"                   # expected reachable but SSH failed
    SCANNER_ABSENT = "scanner_absent"            # reachable Ubuntu, oscap/SSG missing
    UNSUPPORTED_VERSION = "unsupported_version"  # no SSG profile for this Ubuntu version
    HOST_KEY_MISMATCH = "host_key_mismatch"      # SSH host key != pinned key (security finding)
    SCANNED = "scanned"                           # audited successfully
    SCAN_ERROR = "scan_error"                     # scan attempted but errored

    @property
    def is_assessed(self) -> bool:
        return self is HostStatus.SCANNED

    @property
    def is_coverage_gap(self) -> bool:
        """True for Ubuntu hosts we could not fully assess (the honest-gap set)."""
        return self in {
            HostStatus.NO_CREDENTIALS,
            HostStatus.UNREACHABLE,
            HostStatus.SCANNER_ABSENT,
            HostStatus.UNSUPPORTED_VERSION,
            HostStatus.HOST_KEY_MISMATCH,
            HostStatus.SCAN_ERROR,
        }


@dataclass
class RuleResult:
    """A single CIS rule outcome (only fails are retained in summaries)."""

    rule_id: str
    result: str                       # pass | fail | error | notapplicable | ...
    severity: Optional[str] = None    # low | medium | high | unknown
    title: Optional[str] = None


@dataclass
class ScanResult:
    """Parsed outcome of one OpenSCAP evaluation."""

    profile_id: str
    datastream: str
    benchmark_version: Optional[str] = None
    passed: int = 0
    failed: int = 0
    error: int = 0
    not_applicable: int = 0
    not_checked: int = 0
    other: int = 0
    score: Optional[float] = None             # XCCDF score, percentage 0..100
    failed_rules: list[RuleResult] = field(default_factory=list)
    arf_path: Optional[str] = None            # retained raw evidence (ARF)
    html_path: Optional[str] = None           # human-readable OpenSCAP report
    results_xml_path: Optional[str] = None    # raw XCCDF results

    @property
    def total_evaluated(self) -> int:
        return self.passed + self.failed + self.error

    @property
    def total_outcomes(self) -> int:
        """Every rule-result oscap emitted, regardless of verdict."""
        return (self.passed + self.failed + self.error
                + self.not_applicable + self.not_checked + self.other)

    @property
    def inconclusive(self) -> int:
        """Rules with no clean determination (couldn't be evaluated)."""
        return self.error + self.not_checked + self.other

    @property
    def assessment_confidence(self) -> Optional[float]:
        """Percent of the benchmark that produced a definitive verdict
        (pass / fail / notapplicable).

        A high ``not_checked`` count -- typically insufficient privilege so the
        check never ran -- drives this DOWN. It is the guard against the worst
        outcome for a compliance tool: a high score that reflects only the few
        checks that actually executed. ``None`` when nothing was evaluated.
        """
        total = self.total_outcomes
        if total == 0:
            return None
        definitive = self.passed + self.failed + self.not_applicable
        return round(100.0 * definitive / total, 1)


@dataclass
class HostRecord:
    """One host of fleet inventory plus, if applicable, its scan result."""

    ip: str
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    open_ports: list[int] = field(default_factory=list)
    banners: dict[str, str] = field(default_factory=dict)   # "port/proto" -> banner
    is_ubuntu: bool = False
    ubuntu_version: Optional[str] = None                    # e.g. "22.04"
    credential_group: Optional[str] = None
    status: HostStatus = HostStatus.DISCOVERED
    detail: Optional[str] = None                            # why it has this status
    scan: Optional[ScanResult] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class RunRecord:
    """One immutable audit run. Persisted whole; never mutated after finish."""

    run_id: str                  # timestamp-based, sortable
    started_at: str              # ISO 8601
    finished_at: Optional[str] = None
    scope: list[str] = field(default_factory=list)   # the CIDRs scanned
    config_hash: Optional[str] = None
    hosts: list[HostRecord] = field(default_factory=list)

    # --- convenience aggregates used by the report -----------------------
    def counts_by_status(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for h in self.hosts:
            out[h.status.value] = out.get(h.status.value, 0) + 1
        return out

    def scanned_hosts(self) -> list[HostRecord]:
        return [h for h in self.hosts if h.status is HostStatus.SCANNED and h.scan]

    def coverage_gaps(self) -> list[HostRecord]:
        return [h for h in self.hosts if h.status.is_coverage_gap]

    def fleet_pass_rate(self) -> Optional[float]:
        """Aggregate pass percentage across all scanned hosts, or None."""
        passed = sum(h.scan.passed for h in self.scanned_hosts())
        evaluated = sum(h.scan.total_evaluated for h in self.scanned_hosts())
        if evaluated == 0:
            return None
        return round(100.0 * passed / evaluated, 1)

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "scope": self.scope,
            "config_hash": self.config_hash,
            "hosts": [h.to_dict() for h in self.hosts],
        }
