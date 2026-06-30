"""Shared data contracts.

These three types are the seams the rest of the system is built around:
  * HostStatus  - the coverage classification for every discovered host
  * HostRecord  - one row of fleet inventory + (optional) scan result
  * RunRecord   - one immutable audit run

When the build later fans out to a team, these definitions are frozen first so
each module can be developed independently against a stable contract.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional

# Single source of truth for the low-confidence threshold default (config and
# report both reference this; do not restate the literal elsewhere).
DEFAULT_LOW_CONFIDENCE_THRESHOLD = 90.0

# A hard, NON-overridable floor. If less than this % of the benchmark produced a
# definitive verdict, the scan is too incomplete to certify as SCANNED, no matter
# how the operator tunes low_confidence_threshold (which only controls the badge).
# This is the structural backstop against a near-empty scan reading as a clean
# host; see finalize_scan_status.
HARD_CONFIDENCE_FLOOR = 50.0


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
    # not_checked / other are Optional so a row persisted before these columns
    # existed reloads as None ("unknown coverage") rather than a fabricated 0 --
    # a 0 would silently inflate assessment_confidence on an old low-privilege scan
    # (the never-false-pass failure mode). Fresh scans always set real integers.
    not_checked: Optional[int] = 0
    other: Optional[int] = 0
    score: Optional[float] = None             # XCCDF score, percentage 0..100
    failed_rules: list[RuleResult] = field(default_factory=list)
    arf_path: Optional[str] = None            # retained raw evidence (ARF)
    html_path: Optional[str] = None           # human-readable OpenSCAP report
    results_xml_path: Optional[str] = None    # raw XCCDF results

    @property
    def total_evaluated(self) -> int:
        return self.passed + self.failed + self.error

    @property
    def total_outcomes(self) -> Optional[int]:
        """Every rule-result oscap emitted, regardless of verdict. ``None`` when
        coverage is unknown (a pre-migration row reloaded with NULL counts)."""
        if self.not_checked is None or self.other is None:
            return None
        return (self.passed + self.failed + self.error
                + self.not_applicable + self.not_checked + self.other)

    @property
    def undetermined(self) -> Optional[int]:
        """Rule results that produced no definitive verdict (error / notchecked
        / other) -- the checks that drag ``assessment_confidence`` down. ``None``
        when coverage is unknown."""
        if self.not_checked is None or self.other is None:
            return None
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
        if not total:                       # None (unknown) or 0 (nothing ran)
            return None
        definitive = self.passed + self.failed + self.not_applicable
        return round(100.0 * definitive / total, 1)

    def is_low_confidence(
        self, threshold: float = DEFAULT_LOW_CONFIDENCE_THRESHOLD
    ) -> bool:
        """The single definition of the low-confidence rule, shared by the
        report's host list, the per-host badge, and the styling -- so they can
        never disagree about which scans are untrustworthy."""
        c = self.assessment_confidence
        return c is not None and c < threshold


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
        if self.scan is not None:
            # asdict() emits only dataclass fields, not @property values, so the
            # nested scan dict would otherwise omit confidence -- mirror the CSV
            # export and surface it here too.
            d["scan"]["assessment_confidence"] = self.scan.assessment_confidence
            d["scan"]["total_outcomes"] = self.scan.total_outcomes
        return d


def finalize_scan_status(host: HostRecord, scan: ScanResult,
                         hard_floor: float = HARD_CONFIDENCE_FLOOR) -> None:
    """The single chokepoint deciding whether a parsed scan is trustworthy enough
    to record as SCANNED -- the structural enforcement of the never-false-pass
    directive. The evidence is always attached; only the *status* is gated:

      * a scan that evaluated NOTHING (``total_outcomes == 0``) -- e.g. an empty
        or rule-result-less results.xml that ``parse_xccdf_results`` returns as
        all-zeros without raising -- becomes SCAN_ERROR, never a clean SCANNED.
      * a scan whose ``assessment_confidence`` falls below the NON-overridable
        ``hard_floor`` (independent of the operator-tunable low-confidence badge)
        becomes SCAN_ERROR: too little of the benchmark ran to certify a verdict.

    Anything that clears both bars is recorded SCANNED.
    """
    host.scan = scan
    if not scan.total_outcomes:
        host.status = HostStatus.SCAN_ERROR
        host.detail = "oscap produced results.xml with no rule outcomes to assess"
        return
    conf = scan.assessment_confidence
    if conf is not None and conf < hard_floor:
        host.status = HostStatus.SCAN_ERROR
        host.detail = (
            f"assessment incomplete: only {conf:.0f}% of the benchmark produced a "
            f"verdict (below the {hard_floor:.0f}% hard floor) -- evidence retained "
            f"but not certifiable; check the scan account's sudo/privilege"
        )
        return
    host.status = HostStatus.SCANNED


def status_counts(hosts: list[HostRecord]) -> dict[str, int]:
    """Tally hosts by their status value -- the single home for this idiom,
    shared by classify (a bare host list) and RunRecord (its own hosts)."""
    return dict(Counter(h.status.value for h in hosts))


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
        return status_counts(self.hosts)

    def scanned_hosts(self) -> list[HostRecord]:
        return [h for h in self.hosts if h.status is HostStatus.SCANNED and h.scan]

    def coverage_gaps(self) -> list[HostRecord]:
        return [h for h in self.hosts if h.status.is_coverage_gap]

    def fleet_pass_rate(self) -> Optional[float]:
        """Aggregate pass percentage across all scanned hosts, or None."""
        scanned = self.scanned_hosts()
        passed = sum(h.scan.passed for h in scanned)
        evaluated = sum(h.scan.total_evaluated for h in scanned)
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
