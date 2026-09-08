"""Stage 7: immutable run persistence (SQLite + on-disk artifacts).

Each run appends three rows-sets - runs, hosts, findings - and never mutates a
prior run. Raw OpenSCAP artifacts live alongside under runs/<run_id>/<ip>/.
History enables the drift comparison in the report stage.

Schema (the third shared contract):
  runs(run_id PK, started_at, finished_at, scope, config_hash)
  hosts(id PK, run_id FK, ip, hostname, os_guess, is_ubuntu, ubuntu_version,
        credential_group, status, detail, profile_id, benchmark_version,
        passed, failed, error, not_applicable, not_checked, other, score,
        arf_path, html_path)
  findings(id PK, host_id FK, rule_id, result, severity, title)
"""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Optional

from .logging_setup import get_logger
from .models import HostRecord, HostStatus, RunRecord, RuleResult, ScanResult

log = get_logger()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id       TEXT PRIMARY KEY,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    scope        TEXT,
    config_hash  TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            TEXT NOT NULL REFERENCES runs(run_id),
    ip                TEXT NOT NULL,
    hostname          TEXT,
    os_guess          TEXT,
    is_ubuntu         INTEGER,
    ubuntu_version    TEXT,
    credential_group  TEXT,
    status            TEXT NOT NULL,
    detail            TEXT,
    profile_id        TEXT,
    benchmark_version TEXT,
    passed            INTEGER,
    failed            INTEGER,
    error             INTEGER,
    not_applicable    INTEGER,
    not_checked       INTEGER,
    other             INTEGER,
    score             REAL,
    arf_path          TEXT,
    html_path         TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id   INTEGER NOT NULL REFERENCES hosts(id),
    rule_id   TEXT NOT NULL,
    result    TEXT NOT NULL,
    severity  TEXT,
    title     TEXT
);
CREATE INDEX IF NOT EXISTS idx_hosts_run ON hosts(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host_id);
"""


class Store:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.db_path = os.path.join(output_dir, "history.db")
        self.artifacts_root = os.path.join(output_dir, "runs")
        os.makedirs(self.artifacts_root, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._ensure_columns()
        self._conn.commit()

    # Columns added after the original schema. Forward-safe migration so an
    # existing history.db gains them without being recreated.
    _HOST_COLUMNS_ADDED = {"not_checked": "INTEGER", "other": "INTEGER"}

    def _ensure_columns(self):
        existing = {row["name"] for row in
                    self._conn.execute("PRAGMA table_info(hosts)").fetchall()}
        for col, decl in self._HOST_COLUMNS_ADDED.items():
            if col not in existing:
                self._conn.execute(f"ALTER TABLE hosts ADD COLUMN {col} {decl}")

    def close(self):
        self._conn.close()

    # -- write -------------------------------------------------------------
    def begin_run(self, run: RunRecord):
        """Insert the run row (``finished_at`` may be NULL) BEFORE hosts are
        processed, so an interrupted run leaves a visibly-incomplete record in
        history rather than orphaned on-disk evidence with no row at all.

        Idempotent: any hosts/findings already recorded for this run_id are
        cleared first, so re-running (a resumed or retried run reusing the id)
        cannot double-insert. With a collision-resistant run id this is
        belt-and-suspenders, but it keeps begin_run safe to call twice."""
        self._conn.execute(
            "DELETE FROM findings WHERE host_id IN "
            "(SELECT id FROM hosts WHERE run_id = ?)", (run.run_id,))
        self._conn.execute("DELETE FROM hosts WHERE run_id = ?", (run.run_id,))
        self._conn.execute(
            "INSERT OR REPLACE INTO runs(run_id, started_at, finished_at, scope, "
            "config_hash) VALUES (?,?,?,?,?)",
            (run.run_id, run.started_at, run.finished_at,
             json.dumps(run.scope), run.config_hash),
        )
        self._conn.commit()

    def save_host(self, run_id: str, h: HostRecord):
        """Persist one host (and its findings) immediately, so partial results
        survive a crash partway through a fleet run."""
        cur = self._conn.cursor()
        s = h.scan
        cur.execute(
            "INSERT INTO hosts(run_id, ip, hostname, os_guess, is_ubuntu, "
            "ubuntu_version, credential_group, status, detail, profile_id, "
            "benchmark_version, passed, failed, error, not_applicable, "
            "not_checked, other, score, "
            "arf_path, html_path) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                run_id, h.ip, h.hostname, h.os_guess, int(h.is_ubuntu),
                h.ubuntu_version, h.credential_group, h.status.value, h.detail,
                s.profile_id if s else None,
                s.benchmark_version if s else None,
                s.passed if s else None,
                s.failed if s else None,
                s.error if s else None,
                s.not_applicable if s else None,
                s.not_checked if s else None,
                s.other if s else None,
                s.score if s else None,
                s.arf_path if s else None,
                s.html_path if s else None,
            ),
        )
        host_id = cur.lastrowid
        if s:
            cur.executemany(
                "INSERT INTO findings(host_id, rule_id, result, severity, title) "
                "VALUES (?,?,?,?,?)",
                [(host_id, fr.rule_id, fr.result, fr.severity, fr.title)
                 for fr in s.failed_rules],
            )
        self._conn.commit()

    def finish_run(self, run_id: str, finished_at: Optional[str]):
        """Stamp the run complete once every host has been persisted."""
        self._conn.execute(
            "UPDATE runs SET finished_at = ? WHERE run_id = ?",
            (finished_at, run_id),
        )
        self._conn.commit()

    def save_run(self, run: RunRecord):
        """Persist a whole run at once (begin -> per-host -> finish). Convenience
        for callers/tests that build the full RunRecord before persisting."""
        self.begin_run(run)
        for h in run.hosts:
            self.save_host(run.run_id, h)
        self.finish_run(run.run_id, run.finished_at)
        log.info("store: persisted run %s (%d hosts)", run.run_id, len(run.hosts))

    # -- read --------------------------------------------------------------
    def list_runs(self, limit: int = 50) -> list[dict]:
        cur = self._conn.execute(
            "SELECT run_id, started_at, finished_at, scope, config_hash "
            "FROM runs ORDER BY run_id DESC LIMIT ?", (limit,),
        )
        return [dict(r) for r in cur.fetchall()]

    def previous_run_id(self, before_run_id: str) -> Optional[str]:
        # Only a FINISHED run is a valid drift baseline. A run that crashed
        # mid-fleet has finished_at NULL and only a partial set of hosts
        # persisted; comparing against it would compute deltas versus a
        # truncated baseline and report a spurious improvement/regression.
        cur = self._conn.execute(
            "SELECT run_id FROM runs WHERE run_id < ? AND finished_at IS NOT NULL "
            "ORDER BY run_id DESC LIMIT 1",
            (before_run_id,),
        )
        row = cur.fetchone()
        return row["run_id"] if row else None

    def load_run(self, run_id: str) -> Optional[RunRecord]:
        run_row = self._conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if not run_row:
            return None
        run = RunRecord(
            run_id=run_row["run_id"],
            started_at=run_row["started_at"],
            finished_at=run_row["finished_at"],
            scope=json.loads(run_row["scope"] or "[]"),
            config_hash=run_row["config_hash"],
        )
        host_rows = self._conn.execute(
            "SELECT * FROM hosts WHERE run_id = ? ORDER BY ip", (run_id,)
        ).fetchall()
        for hr in host_rows:
            host = HostRecord(
                ip=hr["ip"], hostname=hr["hostname"], os_guess=hr["os_guess"],
                is_ubuntu=bool(hr["is_ubuntu"]), ubuntu_version=hr["ubuntu_version"],
                credential_group=hr["credential_group"],
                status=HostStatus(hr["status"]), detail=hr["detail"],
            )
            if hr["status"] == HostStatus.SCANNED.value:
                findings = self._conn.execute(
                    "SELECT rule_id, result, severity, title FROM findings "
                    "WHERE host_id = ?", (hr["id"],)
                ).fetchall()
                host.scan = ScanResult(
                    profile_id=hr["profile_id"] or "",
                    datastream="",
                    benchmark_version=hr["benchmark_version"],
                    passed=hr["passed"] or 0,
                    failed=hr["failed"] or 0,
                    error=hr["error"] or 0,
                    not_applicable=hr["not_applicable"] or 0,
                    # Preserve NULL-vs-0 faithfully: rows written before the
                    # not_checked/other migration hold NULL, and coercing that to 0
                    # would fabricate full coverage and inflate assessment_confidence
                    # on an old low-privilege scan. Loading NULL as None makes
                    # confidence report honestly as "unknown" instead.
                    not_checked=hr["not_checked"],
                    other=hr["other"],
                    score=hr["score"],
                    failed_rules=[RuleResult(f["rule_id"], f["result"],
                                             f["severity"], f["title"])
                                  for f in findings],
                    arf_path=hr["arf_path"], html_path=hr["html_path"],
                )
            run.hosts.append(host)
        return run
