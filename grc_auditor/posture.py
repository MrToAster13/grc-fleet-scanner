"""Fleet posture: the one place for the run-level rating rules.

Owns, for one run:
  * scan_candidates  - the hosts in scope for scanning (all but NON_UBUNTU)
  * assessed_share   - percent of scan candidates that reached SCANNED
  * zero_scanned     - whether the run should be flagged as having scanned nothing
  * fleet_posture    - the posture ladder (no-data, weak, incomplete, strong,
                       moderate) and its headline sentence

The report, the console summary and the exit code all read these, so the
rules can't drift apart between surfaces. See docs/design.md section 4.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .models import HostRecord, HostStatus, RunRecord

# Pass-rate cutoffs for the ladder. A fleet pass rate below WEAK_PASS_RATE is
# weak at any coverage; STRONG_PASS_RATE or above can read strong when the
# coverage gate below also allows it.
WEAK_PASS_RATE = 75.0
STRONG_PASS_RATE = 90.0

# Fleet-level coverage gates on the executive posture (ELI-166). The share is
# scanned hosts over scan candidates (every host except NON_UBUNTU inventory).
# Below MIN_COVERAGE_FOR_POSTURE the posture is "incomplete": the pass rate
# describes less than half the in-scope fleet, mirroring the per-host 50% hard
# confidence floor. "strong" additionally needs STRONG_COVERAGE_THRESHOLD.
# See docs/design.md section 4.
MIN_COVERAGE_FOR_POSTURE = 50.0
STRONG_COVERAGE_THRESHOLD = 90.0


@dataclass(frozen=True)
class Posture:
    """The fleet posture level and the headline sentence that explains it.

    ``level`` is one of ``no-data``, ``weak``, ``incomplete``, ``strong`` or
    ``moderate``.
    """

    level: str
    headline: str


def scan_candidates(run: RunRecord) -> list[HostRecord]:
    """Hosts in scope for scanning: every host except NON_UBUNTU inventory."""
    return [h for h in run.hosts if h.status is not HostStatus.NON_UBUNTU]


def assessed_share(run: RunRecord) -> Optional[float]:
    """Percent of scan candidates (non-NON_UBUNTU hosts) that reached SCANNED.

    None when the run has no scan candidates at all. Hosts still DISCOVERED
    count as unassessed, so an unfinished run can never inflate the share.
    This is deliberately not the coverage sentence's denominator
    (``len(run.hosts)``): out-of-scope inventory must not drag posture down.
    """
    candidates = scan_candidates(run)
    if not candidates:
        return None
    return round(100.0 * len(run.scanned_hosts()) / len(candidates), 1)


def zero_scanned(run: RunRecord) -> bool:
    """True when this run should be flagged as having scanned nothing.

    `no_credentials`, `unreachable`, and `scanner_absent` (among other
    coverage gaps) can each absorb every host in a run silently: the run
    still completes and a report still gets written. This is the single home
    for that "nothing was scanned" predicate, shared by the console summary,
    the report banner, and the exit code, so the three surfaces can't drift
    apart.

    Two cases are deliberately excluded, because scanning nothing is their
    contract, not a gap:

    * a dry run (``run.dry_run`` is true). ``--dry-run`` discovers and
      classifies only and never scans by design, so it must never trip this
      alarm. A run with no recorded marker (``dry_run`` is None, as for a run
      loaded from before the marker existed) counts as a real run.
    * a fleet that is entirely ``non_ubuntu``. Those hosts were never scan
      candidates in the first place, so scanning none of them is not the same
      failure as every credential or SSH path being wrong.

    A run that discovered zero hosts at all still alarms: the operator
    expected to scan something.
    """
    if bool(run.dry_run):
        return False
    if run.scanned_hosts():
        return False
    if not run.hosts:
        return True
    return bool(scan_candidates(run))


def fleet_posture(run: RunRecord) -> Posture:
    """Rate the fleet: the posture ladder over pass rate and assessed share.

    In order: nothing scanned or nothing evaluable is ``no-data``; a pass rate
    below WEAK_PASS_RATE is ``weak`` at any coverage; an assessed share below
    MIN_COVERAGE_FOR_POSTURE is ``incomplete``; a pass rate of at least
    STRONG_PASS_RATE with a share of at least STRONG_COVERAGE_THRESHOLD is
    ``strong``; anything else is ``moderate``.
    """
    scanned = run.scanned_hosts()
    rate = run.fleet_pass_rate()
    share = assessed_share(run)
    n_candidates = len(scan_candidates(run))
    n_excluded = len(run.hosts) - n_candidates
    # Only spell out the candidate math when it differs from the coverage
    # sentence's "of discovered hosts" denominator -- otherwise the two
    # percentages already agree and the extra clause would be noise.
    if n_excluded:
        candidate_detail = (
            " (%d of %d; %d non-Ubuntu host%s excluded)"
            % (len(scanned), n_candidates, n_excluded,
               "" if n_excluded == 1 else "s")
        )
    else:
        candidate_detail = ""

    if not scanned:
        return Posture(
            "no-data",
            "No hosts were successfully scanned this run; compliance posture "
            "cannot be assessed. Resolve the coverage gaps below.",
        )
    if rate is None:
        return Posture(
            "no-data", "Hosts were scanned but produced no evaluable results.")
    if rate < WEAK_PASS_RATE:
        # Weak is already a non-clean verdict; low coverage can only make the
        # real picture worse, so it does not soften it.
        return Posture(
            "weak", "Fleet compliance is weak; broad remediation is required.")
    if share is not None and share < MIN_COVERAGE_FOR_POSTURE:
        # The scanned-host pass rate says nothing reliable about a fleet that
        # was mostly never reached. Mirrors HARD_CONFIDENCE_FLOOR per host.
        return Posture(
            "incomplete",
            "Only %.1f%% of scan candidates were assessed%s, too little of "
            "the fleet to rate its compliance. Close the coverage gaps below "
            "before relying on the pass rate." % (share, candidate_detail),
        )
    if rate >= STRONG_PASS_RATE and share >= STRONG_COVERAGE_THRESHOLD:
        # share can't be None here: scanned is non-empty (the `not scanned`
        # branch above already handled the empty case), and every SCANNED
        # host is by definition not NON_UBUNTU, so the candidate set that
        # assessed_share divides by is non-empty too.
        return Posture(
            "strong",
            "Fleet compliance is strong, with only isolated gaps to close.")
    if rate >= STRONG_PASS_RATE:
        # High pass rate, but too many candidates unassessed to call it strong.
        return Posture(
            "moderate",
            "Assessed hosts score well, but only %.1f%% of scan candidates "
            "were assessed%s; posture is capped at moderate until coverage "
            "gaps are closed." % (share, candidate_detail),
        )
    return Posture(
        "moderate",
        "Fleet compliance is moderate; several controls need attention.")
