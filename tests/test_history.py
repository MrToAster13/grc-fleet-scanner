"""Tests for grc_auditor.history.RunHistory: which prior runs are comparable,
the drift baseline, and the trend points. Every test goes through a real
``Store`` on ``tmp_path``."""

from __future__ import annotations

import pytest

from grc_auditor.history import RunHistory
from grc_auditor.models import HostRecord, HostStatus, RunRecord, pass_rate
from grc_auditor.store import Store

from conftest import fabricate_scanned_host


def _make_run(run_id, started_at, hosts, config_hash="deadbeefcafef00d",
              dry_run=None):
    return RunRecord(
        run_id=run_id, started_at=started_at, finished_at=started_at,
        scope=["10.0.10.0/24"], config_hash=config_hash, hosts=hosts,
        dry_run=dry_run,
    )


def _dry_signature_run(run_id, started_at, config_hash):
    """A dry run as persisted before the ELI-341 marker: no marker, and a
    candidate host left in DISCOVERED."""
    return _make_run(run_id, started_at,
                     [HostRecord(ip="10.0.10.21", status=HostStatus.DISCOVERED)],
                     config_hash=config_hash)


@pytest.fixture
def store(tmp_path):
    s = Store(str(tmp_path))
    yield s
    s.close()


def _prior_ids(history, run):
    return [p.run_id for p in history.trend(run) if not p.is_current]


# --- baseline --------------------------------------------------------------- #

def test_baseline_is_most_recent_earlier_run(store):
    first = _make_run("20260601T000000Z", "2026-06-01T00:00:00+00:00",
                      [fabricate_scanned_host()])
    second = _make_run("20260627T000000Z", "2026-06-27T00:00:00+00:00",
                       [fabricate_scanned_host()])
    store.save_run(first)
    store.save_run(second)
    history = RunHistory(store)

    baseline = history.baseline(second)
    assert baseline.run_id == "20260601T000000Z"
    assert baseline.run.hosts[0].ip == first.hosts[0].ip
    assert baseline.scope_changed is False
    # Nothing before the earliest run.
    assert history.baseline(first).run is None
    assert history.baseline(first).scope_changed is False


def test_unfinished_run_is_neither_baseline_nor_trend_point(store):
    # A run that crashed mid-fleet (finished_at NULL, partial hosts) must never
    # be the baseline or a trend point: deltas against a truncated run are
    # spurious.
    store.save_run(_make_run("20260101T000000Z", "2026-01-01T00:00:00+00:00", []))
    store.begin_run(RunRecord(
        run_id="20260102T000000Z", started_at="2026-01-02T00:00:00+00:00",
        scope=["10.0.10.0/24"], config_hash="deadbeefcafef00d", hosts=[],
    ))
    current = _make_run("20260103T000000Z", "2026-01-03T00:00:00+00:00", [])
    history = RunHistory(store)

    assert history.baseline(current).run_id == "20260101T000000Z"
    assert _prior_ids(history, current) == ["20260101T000000Z"]


def test_baseline_requires_matching_config_hash(store):
    store.save_run(_make_run("20260601T000000Z", "2026-06-01T00:00:00+00:00",
                             [fabricate_scanned_host()], config_hash="same-scope"))
    current = _make_run("20260627T000000Z", "2026-06-27T00:00:00+00:00",
                        [fabricate_scanned_host()], config_hash="same-scope")

    assert RunHistory(store).baseline(current).run_id == "20260601T000000Z"


def test_differing_config_hash_is_scope_changed_not_baseline(store):
    # A prior run against a different scope or config is never the baseline.
    # It only tells the report that history exists under another scope.
    store.save_run(_make_run("20260601T000000Z", "2026-06-01T00:00:00+00:00",
                             [fabricate_scanned_host()], config_hash="narrowed-cidr"))
    current = _make_run("20260627T000000Z", "2026-06-27T00:00:00+00:00",
                        [fabricate_scanned_host()], config_hash="full-scope")
    store.save_run(current)
    history = RunHistory(store)

    baseline = history.baseline(current)
    assert baseline.run is None
    assert baseline.scope_changed is True
    assert _prior_ids(history, current) == []


def test_no_config_hash_skips_the_config_filter(store):
    store.save_run(_make_run("20260601T000000Z", "2026-06-01T00:00:00+00:00",
                             [fabricate_scanned_host()], config_hash="anything"))
    current = _make_run("20260627T000000Z", "2026-06-27T00:00:00+00:00",
                        [fabricate_scanned_host()], config_hash=None)
    history = RunHistory(store)

    assert history.baseline(current).run_id == "20260601T000000Z"
    assert _prior_ids(history, current) == ["20260601T000000Z"]


# --- dry runs ----------------------------------------------------------------- #

def test_structural_dry_run_is_excluded_even_with_matching_hash(store):
    # dry_run is not part of config_hash, so a dry run shares the hash of a
    # later real run. It scanned nothing and must not be compared against.
    store.save_run(_dry_signature_run("20260601T000000Z",
                                      "2026-06-01T00:00:00+00:00", "shared-hash"))
    current = _make_run("20260627T000000Z", "2026-06-27T00:00:00+00:00",
                        [fabricate_scanned_host()], config_hash="shared-hash")
    store.save_run(current)
    history = RunHistory(store)

    baseline = history.baseline(current)
    assert baseline.run is None
    # A dry run is not comparable history at all, so it does not count as
    # "history under another scope" either.
    assert baseline.scope_changed is False
    assert _prior_ids(history, current) == []


def test_marked_dry_run_with_zero_candidates_is_excluded(store):
    # Zero candidates leaves no DISCOVERED row, so only the ELI-341 marker can
    # identify this as a dry run.
    store.save_run(_make_run("20260601T000000Z", "2026-06-01T00:00:00+00:00", [],
                             config_hash="shared-hash", dry_run=True))
    current = _make_run("20260627T000000Z", "2026-06-27T00:00:00+00:00",
                        [fabricate_scanned_host()], config_hash="shared-hash")
    store.save_run(current)
    history = RunHistory(store)

    assert history.baseline(current).run is None
    assert history.baseline(current).scope_changed is False
    assert _prior_ids(history, current) == []


def test_marker_false_wins_over_structural_signature(store):
    # An explicit dry_run=False marks a real run even if a DISCOVERED row
    # exists; the structural fallback applies only when the marker is NULL.
    real = _dry_signature_run("20260601T000000Z", "2026-06-01T00:00:00+00:00",
                              "shared-hash")
    real.dry_run = False
    store.save_run(real)
    current = _make_run("20260627T000000Z", "2026-06-27T00:00:00+00:00",
                        [fabricate_scanned_host()], config_hash="shared-hash")

    assert RunHistory(store).baseline(current).run_id == "20260601T000000Z"


# --- trend -------------------------------------------------------------------- #

def test_trend_orders_prior_runs_oldest_first_and_ends_with_current(store):
    ids = ["20260601T000000Z", "20260602T000000Z", "20260603T000000Z"]
    for run_id in ids:
        store.save_run(_make_run(run_id, run_id, [fabricate_scanned_host()]))
    current = _make_run("20260604T000000Z", "2026-06-04T00:00:00+00:00",
                        [fabricate_scanned_host()])

    points = RunHistory(store).trend(current, n=8)
    assert [p.run_id for p in points] == ids + ["20260604T000000Z"]
    assert [p.is_current for p in points] == [False, False, False, True]


def test_trend_keeps_n_minus_one_most_recent_prior_runs(store):
    for day in range(1, 6):
        run_id = f"2026060{day}T000000Z"
        store.save_run(_make_run(run_id, run_id, [fabricate_scanned_host()]))
    current = _make_run("20260610T000000Z", "2026-06-10T00:00:00+00:00", [])
    history = RunHistory(store)

    assert [p.run_id for p in history.trend(current, n=3)] == [
        "20260604T000000Z", "20260605T000000Z", "20260610T000000Z"]
    # The current point survives any n.
    assert [p.run_id for p in history.trend(current, n=1)] == ["20260610T000000Z"]
    assert [p.run_id for p in history.trend(current, n=0)] == ["20260610T000000Z"]


def test_trend_ignores_runs_newer_than_current(store):
    older = _make_run("20260601T000000Z", "2026-06-01T00:00:00+00:00",
                      [fabricate_scanned_host()])
    current = _make_run("20260602T000000Z", "2026-06-02T00:00:00+00:00",
                        [fabricate_scanned_host()])
    newer = _make_run("20260603T000000Z", "2026-06-03T00:00:00+00:00",
                      [fabricate_scanned_host()])
    for run in (older, current, newer):
        store.save_run(run)

    points = RunHistory(store).trend(current)
    assert [p.run_id for p in points] == ["20260601T000000Z", "20260602T000000Z"]
    assert points[-1].is_current


def test_current_point_comes_from_the_live_run(store):
    # The current run need not be persisted or finished, and its live values
    # win over anything stored under the same run_id.
    host = fabricate_scanned_host()
    current = RunRecord(run_id="20260701T000000Z",
                        started_at="2026-07-01T00:00:00+00:00",
                        scope=["10.0.10.0/24"], config_hash="deadbeefcafef00d",
                        hosts=[host])

    point = RunHistory(store).trend(current)[-1]
    assert point.is_current
    assert point.started_at == "2026-07-01T00:00:00+00:00"
    assert point.scanned == 1
    assert point.pass_rate == current.fleet_pass_rate()


# --- pass rate: one formula --------------------------------------------------- #

def test_prior_point_pass_rate_matches_the_run_model(store):
    """A stored run's trend point and RunRecord.fleet_pass_rate() go through
    the same models.pass_rate formula, so they must agree."""
    prior = _make_run("20260701T000000Z", "2026-07-01T00:00:00+00:00",
                      [fabricate_scanned_host(), fabricate_scanned_host()])
    prior.hosts[1].ip = "10.0.10.22"
    prior.hosts[1].scan.passed, prior.hosts[1].scan.failed = 40, 10
    store.save_run(prior)
    current = _make_run("20260702T000000Z", "2026-07-02T00:00:00+00:00", [])

    point = RunHistory(store).trend(current)[0]
    assert point.run_id == prior.run_id
    assert point.scanned == 2
    assert point.pass_rate == prior.fleet_pass_rate() == 88.0  # 220 / 250


def test_pass_rate_is_none_when_nothing_was_evaluated(store):
    store.save_run(_make_run("20260701T000000Z", "2026-07-01T00:00:00+00:00", []))
    current = _make_run("20260702T000000Z", "2026-07-02T00:00:00+00:00", [])

    points = RunHistory(store).trend(current)
    assert [p.pass_rate for p in points] == [None, None]
    assert [p.scanned for p in points] == [0, 0]


def test_pass_rate_formula():
    assert pass_rate(225, 250) == 90.0
    assert pass_rate(1, 3) == 33.3
    assert pass_rate(0, 0) is None
