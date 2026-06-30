"""Tests for grc_auditor.store.Store: immutable run persistence + round-trip."""

from __future__ import annotations

from grc_auditor.models import HostRecord, HostStatus, RunRecord
from grc_auditor.store import Store

from conftest import fabricate_scanned_host


def _make_run(run_id, started_at, hosts, scope=None):
    return RunRecord(
        run_id=run_id,
        started_at=started_at,
        finished_at=started_at,
        scope=scope or ["10.0.10.0/24"],
        config_hash="deadbeefcafef00d",
        hosts=hosts,
    )


def test_save_and_load_round_trip_including_findings(tmp_path):
    store = Store(str(tmp_path))
    try:
        scanned = fabricate_scanned_host()
        non_ubuntu = HostRecord(
            ip="10.0.10.30", hostname="db01.lab",
            status=HostStatus.NON_UBUNTU, detail="Debian, not Ubuntu",
        )
        run = _make_run("20260627T000000Z", "2026-06-27T00:00:00+00:00",
                        [scanned, non_ubuntu])
        store.save_run(run)

        loaded = store.load_run("20260627T000000Z")
        assert loaded is not None
        assert loaded.run_id == run.run_id
        assert loaded.started_at == run.started_at
        assert loaded.scope == ["10.0.10.0/24"]
        assert loaded.config_hash == "deadbeefcafef00d"

        by_ip = {h.ip: h for h in loaded.hosts}
        assert set(by_ip) == {"10.0.10.21", "10.0.10.30"}

        # non-Ubuntu host: no scan persisted
        db = by_ip["10.0.10.30"]
        assert db.status is HostStatus.NON_UBUNTU
        assert db.scan is None

        # scanned host: scan + findings round-trip
        web = by_ip["10.0.10.21"]
        assert web.status is HostStatus.SCANNED
        assert web.scan is not None
        assert web.scan.passed == 180
        assert web.scan.failed == 20
        assert web.scan.score == 90.0
        assert web.scan.benchmark_version == "0.1.70"
        assert web.scan.profile_id == (
            "xccdf_org.ssgproject.content_profile_cis_level1_server"
        )

        findings = {fr.rule_id: fr for fr in web.scan.failed_rules}
        assert len(findings) == 2
        root = findings["xccdf_org.ssgproject.content_rule_sshd_disable_root_login"]
        assert root.severity == "high"
        assert root.title == "Disable SSH root login"
        assert root.result == "fail"
    finally:
        store.close()


def test_load_unknown_run_returns_none(tmp_path):
    store = Store(str(tmp_path))
    try:
        assert store.load_run("nope") is None
    finally:
        store.close()


def test_previous_run_id_returns_earlier_run(tmp_path):
    store = Store(str(tmp_path))
    try:
        store.save_run(_make_run("20260601T000000Z", "2026-06-01T00:00:00+00:00",
                                 [fabricate_scanned_host()]))
        store.save_run(_make_run("20260627T000000Z", "2026-06-27T00:00:00+00:00",
                                 [fabricate_scanned_host()]))

        assert store.previous_run_id("20260627T000000Z") == "20260601T000000Z"
        # nothing before the earliest run
        assert store.previous_run_id("20260601T000000Z") is None
    finally:
        store.close()


def test_list_runs_ordering_newest_first(tmp_path):
    store = Store(str(tmp_path))
    try:
        for rid, ts in [
            ("20260601T000000Z", "2026-06-01T00:00:00+00:00"),
            ("20260615T000000Z", "2026-06-15T00:00:00+00:00"),
            ("20260627T000000Z", "2026-06-27T00:00:00+00:00"),
        ]:
            store.save_run(_make_run(rid, ts, [fabricate_scanned_host()]))

        runs = store.list_runs()
        ids = [r["run_id"] for r in runs]
        assert ids == ["20260627T000000Z", "20260615T000000Z", "20260601T000000Z"]
        # scope is stored as JSON; surfaced as the raw string by list_runs
        assert "10.0.10.0/24" in runs[0]["scope"]
    finally:
        store.close()


def test_store_creates_output_layout(tmp_path):
    out = tmp_path / "grc-output"
    store = Store(str(out))
    try:
        assert (out / "history.db").exists()
        assert (out / "runs").is_dir()
    finally:
        store.close()


def test_not_checked_and_other_round_trip(tmp_path):
    # The coverage counts that feed assessment_confidence must survive persistence,
    # otherwise a low-confidence scan would look clean after a reload.
    store = Store(str(tmp_path))
    try:
        host = fabricate_scanned_host()
        host.scan.not_checked = 190
        host.scan.other = 3
        store.save_run(_make_run("20260627T000000Z", "2026-06-27T00:00:00+00:00",
                                 [host]))
        loaded = store.load_run("20260627T000000Z")
        s = loaded.hosts[0].scan
        assert s.not_checked == 190
        assert s.other == 3
        # confidence is recomputable from the persisted counts
        assert s.assessment_confidence is not None
    finally:
        store.close()


def test_incremental_persistence_leaves_a_visible_unfinished_run(tmp_path):
    # begin_run + save_host persist a run before it finishes, so a crash mid-scan
    # leaves a visibly-incomplete run (finished_at NULL) with the hosts done so far
    # -- not orphaned evidence with no DB row.
    store = Store(str(tmp_path))
    try:
        run = _make_run("20260627T000000Z", "2026-06-27T00:00:00+00:00", [])
        run.finished_at = None
        store.begin_run(run)
        store.save_host(run.run_id, fabricate_scanned_host(ip="10.0.10.21"))

        loaded = store.load_run("20260627T000000Z")
        assert loaded is not None
        assert loaded.finished_at is None           # visibly incomplete
        assert [h.ip for h in loaded.hosts] == ["10.0.10.21"]

        store.finish_run("20260627T000000Z", "2026-06-27T00:05:00+00:00")
        assert store.load_run("20260627T000000Z").finished_at == \
            "2026-06-27T00:05:00+00:00"
    finally:
        store.close()


def test_begin_run_is_idempotent_and_clears_prior_hosts(tmp_path):
    # Re-calling begin_run for the same run_id (a resumed / retried run reusing
    # the id) must clear the prior hosts AND their findings before the second
    # pass, so the run can't accumulate duplicate rows. Both passes persist the
    # SAME host IP so that, were the clear missing, the host would duplicate AND
    # its findings would double -- both are asserted below.
    store = Store(str(tmp_path))
    try:
        run = _make_run("20260627T000000Z", "2026-06-27T00:00:00+00:00", [])
        run.finished_at = None
        store.begin_run(run)
        store.save_host(run.run_id, fabricate_scanned_host(ip="10.0.10.21"))

        # resume: begin again for the same id, re-persist the same host
        store.begin_run(run)
        store.save_host(run.run_id, fabricate_scanned_host(ip="10.0.10.21"))
        store.finish_run(run.run_id, "2026-06-27T00:05:00+00:00")

        loaded = store.load_run("20260627T000000Z")
        # exactly ONE host row survives -- the first pass was cleared, not appended
        assert [h.ip for h in loaded.hosts] == ["10.0.10.21"]
        # and exactly its 2 findings exist table-wide -- the first pass's findings
        # were deleted, not left orphaned/doubled (would be 4 without the clear)
        total_findings = store._conn.execute(
            "SELECT COUNT(*) FROM findings").fetchone()[0]
        assert total_findings == 2
    finally:
        store.close()


def test_pre_migration_null_counts_reload_as_unknown_not_clean(tmp_path):
    # A row written before the not_checked/other columns existed holds NULL. It
    # must reload as "unknown" confidence (None), never a fabricated 0 that would
    # make an old low-privilege scan look fully and cleanly assessed.
    store = Store(str(tmp_path))
    try:
        host = fabricate_scanned_host()
        host.scan.not_checked = 190           # genuinely low coverage at scan time
        store.save_run(_make_run("20260627T000000Z", "2026-06-27T00:00:00+00:00",
                                 [host]))
        # Simulate a pre-migration row: blank out the migrated columns.
        store._conn.execute("UPDATE hosts SET not_checked=NULL, other=NULL")
        store._conn.commit()

        s = store.load_run("20260627T000000Z").hosts[0].scan
        assert s.not_checked is None
        assert s.other is None
        assert s.total_outcomes is None             # coverage unknown
        assert s.assessment_confidence is None      # NOT a falsely-high 100%
        assert s.is_low_confidence() is False        # unknown != low (and != clean)
    finally:
        store.close()
