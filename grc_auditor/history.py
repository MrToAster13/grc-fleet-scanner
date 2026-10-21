"""Comparable-run history: drift baselines and the fleet trend line.

This module is the one home for "which earlier runs may this run be compared
against". Drift (``report.compute_drift``) and the trend line
(``report.fleet_trend``) both read it, so the two posture displays cannot
disagree on what counts as a run. ``store.Store.run_summaries`` supplies the raw
rows and applies no rule of its own. See docs/design.md "Drift baselines and
scope" and docs/adr/0001-comparable-run-history.md.

A prior run is **comparable** to the current run when all of these hold:

* It finished. A run that crashed mid-fleet has ``finished_at`` NULL and only
  part of its hosts; comparing against it reports a spurious improvement or
  regression versus a truncated baseline.
* It was not a dry run (see ``is_dry_run``).
* Its ``config_hash`` equals the current run's. ``config_hash`` encodes scope
  (CIDRs and exclude), credential groups, CIS level and every other
  behavior-affecting setting (``Config.canonical``), so a narrowed CIDR or a
  changed credential group is never diffed against as if it were a posture
  change. A current run with no ``config_hash`` (only test fixtures build
  one) skips this filter.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .models import RunRecord, pass_rate
from .store import RunSummary, Store


def is_dry_run(summary: RunSummary) -> bool:
    """Whether a persisted run was a ``--dry-run`` pass.

    The explicit ``runs.dry_run`` marker (ELI-341) wins whenever it was
    recorded. A dry run that discovered zero candidates leaves no host rows at
    all, so the structural signature below cannot see it; only the marker can.

    For rows written before the marker existed (``dry_run`` is None) this falls
    back to the structural signature: a finished run holds a host row still in
    ``HostStatus.DISCOVERED`` only when it was a dry run with at least one
    candidate. A real run moves every candidate to a terminal status before
    ``save_host`` persists it. A dry run skips that processing and persists
    candidates as discovery and classify left them. Old history.db files keep
    classifying as before, with no backfill.

    A dry run is never a drift or trend baseline. It performed no scan, its
    pass rate is always None, and comparing against it either blocks a real
    comparable run or silently does nothing.
    """
    if summary.dry_run is not None:
        return summary.dry_run
    return summary.discovered_hosts > 0


@dataclass(frozen=True)
class Baseline:
    """The drift baseline for one run.

    ``run`` is the most recent comparable prior run, loaded whole, or None.
    ``scope_changed`` is True only when ``run`` is None and an earlier
    finished, non-dry run exists whose ``config_hash`` differs. The report
    uses it to tell "first recorded run" apart from "history exists but
    audited a different scope"."""

    run: Optional[RunRecord]
    scope_changed: bool = False

    @property
    def run_id(self) -> Optional[str]:
        return self.run.run_id if self.run else None


@dataclass(frozen=True)
class TrendPoint:
    """One run on the fleet trend line."""

    run_id: str
    started_at: Optional[str]
    scanned: int
    pass_rate: Optional[float]
    is_current: bool


class RunHistory:
    """Answers comparable-run questions about one store's history."""

    def __init__(self, store: Store):
        self._store = store

    def _prior_runs(self, run: RunRecord,
                    match_config: bool = True) -> list[RunSummary]:
        """Finished, non-dry runs older than ``run``, newest first. With
        ``match_config`` they must also share ``run.config_hash``."""
        return [
            s for s in self._store.run_summaries()
            if s.run_id < run.run_id
            and s.finished
            and not is_dry_run(s)
            and (not match_config or run.config_hash is None
                 or s.config_hash == run.config_hash)
        ]

    def baseline(self, run: RunRecord) -> Baseline:
        """The most recent comparable prior run. When none exists this returns
        an empty baseline rather than falling back to the nearest run of any
        scope: no trend is a legitimate result, a fabricated one is not."""
        prior = self._prior_runs(run)
        if prior:
            return Baseline(self._store.load_run(prior[0].run_id))
        if run.config_hash is None:
            return Baseline(None)
        return Baseline(None,
                        scope_changed=bool(self._prior_runs(run, match_config=False)))

    def trend(self, run: RunRecord, n: int = 8) -> list[TrendPoint]:
        """Points oldest first: up to ``n - 1`` of the most recent comparable
        prior runs, then ``run`` itself. The current point is always present,
        even when ``n`` is below 1.

        The current point always comes from the live ``run`` object, never the
        store, so it is right whether or not ``run`` has been persisted or
        finished yet, and even when ``run`` is a dry run."""
        prior = self._prior_runs(run)[:max(n - 1, 0)]
        points = [
            TrendPoint(run_id=s.run_id, started_at=s.started_at,
                       scanned=s.scanned,
                       pass_rate=pass_rate(s.passed, s.evaluated),
                       is_current=False)
            for s in reversed(prior)
        ]
        points.append(current_point(run))
        return points


def current_point(run: RunRecord) -> TrendPoint:
    """The trend point for ``run`` alone, read from the live object."""
    return TrendPoint(run_id=run.run_id, started_at=run.started_at,
                      scanned=len(run.scanned_hosts()),
                      pass_rate=run.fleet_pass_rate(), is_current=True)
