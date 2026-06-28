"""Stage 7: immutable run persistence (SQLite + on-disk artifacts).

Each run appends three rows-sets - runs, hosts, findings - and never mutates a
prior run. Raw OpenSCAP artifacts live alongside under runs/<run_id>/<ip>/.
History enables the drift comparison in the report stage.

Schema (the third shared contract):
  runs(run_id PK, started_at, finished_at, scope, config_hash)
  hosts(id PK, run_id FK, ip, hostname, os_guess, is_ubuntu, ubuntu_version,
        credential_group, status, detail, profile_id, benchmark_version,
        passed, failed, error, not_applicable, score,
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
        self._conn.commit()

    def close(self):
        self._conn.close()

    # -- write -------------------------------------------------------------
    def save_run(self, run: RunRecord):
        cur = self._conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO runs(run_id, started_at, finished_at, scope, "
            "config_hash) VALUES (?,?,?,?,?)",
            (run.run_id, run.started_at, run.finished_at,
             json.dumps(run.scope), run.config_hash),
        )
        for h in run.hosts:
            s = h.scan
            cur.execute(
                "INSERT INTO hosts(run_id, ip, hostname, os_guess, is_ubuntu, "
                "ubuntu_version, credential_group, status, detail, profile_id, "
                "benchmark_version, passed, failed, error, not_applicable, score, "
                "arf_path, html_path) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    run.run_id, h.ip, h.hostname, h.os_guess, int(h.is_ubuntu),
                    h.ubuntu_version, h.credential_group, h.status.value, h.detail,
                    s.profile_id if s else None,
                    s.benchmark_version if s else None,
                    s.passed if s else None,
                    s.failed if s else None,
                    s.error if s else None,
                    s.not_applicable if s else None,
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
        log.info("store: persisted run %s (%d hosts)", run.run_id, len(run.hosts))

    # -- read --------------------------------------------------------------
    def list_runs(self, limit: int = 50) -> list[dict]:
        cur = self._conn.execute(
            "SELECT run_id, started_at, finished_at, scope, config_hash "
            "FROM runs ORDER BY run_id DESC LIMIT ?", (limit,),
        )
        return [dict(r) for r in cur.fetchall()]

    def previous_run_id(self, before_run_id: str) -> Optional[str]:
        cur = self._conn.execute(
            "SELECT run_id FROM runs WHERE run_id < ? ORDER BY run_id DESC LIMIT 1",
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
                    score=hr["score"],
                    failed_rules=[RuleResult(f["rule_id"], f["result"],
                                             f["severity"], f["title"])
                                  for f in findings],
                    arf_path=hr["arf_path"], html_path=hr["html_path"],
                )
            run.hosts.append(host)
        return run

    # -- read: multi-run trend (read-only; schema unchanged) ---------------
    def fleet_pass_rate_history(self, n: int = 10) -> list[dict]:
        """Fleet pass-rate per run for the most recent ``n`` runs.

        Aggregates the persisted per-host passed/failed/error counts across the
        SCANNED hosts of each run and derives the same fleet pass rate the
        report shows (``100 * passed / (passed+failed+error)``). Runs with no
        scanned hosts yield ``pass_rate=None`` and ``scanned=0`` so the report
        can still place them on the timeline honestly.

        Returned oldest-first (chronological) so it can be charted left-to-right.
        Each item::

            {"run_id", "started_at", "scanned", "passed", "evaluated",
             "pass_rate"}
        """
        if n <= 0:
            return []
        run_rows = self._conn.execute(
            "SELECT run_id, started_at FROM runs ORDER BY run_id DESC LIMIT ?",
            (n,),
        ).fetchall()
        out: list[dict] = []
        for rr in run_rows:
            agg = self._conn.execute(
                "SELECT COUNT(*) AS scanned, "
                "COALESCE(SUM(passed),0) AS passed, "
                "COALESCE(SUM(failed),0) AS failed, "
                "COALESCE(SUM(error),0)  AS error "
                "FROM hosts WHERE run_id = ? AND status = ?",
                (rr["run_id"], HostStatus.SCANNED.value),
            ).fetchone()
            evaluated = (agg["passed"] or 0) + (agg["failed"] or 0) + (agg["error"] or 0)
            pass_rate = (
                round(100.0 * (agg["passed"] or 0) / evaluated, 1)
                if evaluated > 0 else None
            )
            out.append({
                "run_id": rr["run_id"],
                "started_at": rr["started_at"],
                "scanned": agg["scanned"] or 0,
                "passed": agg["passed"] or 0,
                "evaluated": evaluated,
                "pass_rate": pass_rate,
            })
        out.reverse()  # oldest-first for charting
        return out

    def recent_scores_for_host(self, ip: str, n: int = 10) -> list[dict]:
        """The most recent ``n`` XCCDF scores recorded for a single host IP.

        Only rows where the host was actually SCANNED (so a score exists) are
        returned. Oldest-first. Each item::

            {"run_id", "started_at", "score", "passed", "failed"}
        """
        if n <= 0:
            return []
        rows = self._conn.execute(
            "SELECT h.run_id AS run_id, r.started_at AS started_at, "
            "h.score AS score, h.passed AS passed, h.failed AS failed "
            "FROM hosts h JOIN runs r ON r.run_id = h.run_id "
            "WHERE h.ip = ? AND h.status = ? "
            "ORDER BY h.run_id DESC LIMIT ?",
            (ip, HostStatus.SCANNED.value, n),
        ).fetchall()
        out = [
            {
                "run_id": row["run_id"],
                "started_at": row["started_at"],
                "score": row["score"],
                "passed": row["passed"],
                "failed": row["failed"],
            }
            for row in rows
        ]
        out.reverse()  # oldest-first
        return out
