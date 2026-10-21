# Handoff 005: grc-1, comparable-run history module

Status: complete for grc-1. grc-2 is in progress and grc-3 has not started.

## Goal
Carry out the three architecture fixes Elijah approved from the 2026-10-21 review, one commit per candidate. The review report is `C:\Users\Elijah\AppData\Local\Temp\architecture-review-20261021-012113.html` (cards grc-1 to grc-3) and its notes are in `C:\Users\Elijah\AppData\Local\Temp\arch-review\grc.md`. Both are local temp files and are not in the repo. This handoff covers grc-1.

## Done
- grc-1 landed as commit `d315a16`, merged into `main` by PR #23 as `ea12baa`. All four CI jobs passed.
- New `grc_auditor/history.py`. `RunHistory.baseline()` and `RunHistory.trend()` are now the only place that decides whether a prior run is comparable: finished, not a dry run, same `config_hash`. `is_dry_run()` checks the ELI-341 marker first and falls back to the structural signature.
- `Store.run_summaries()` returns raw per-run rows with no filtering. `previous_run_id`, `fleet_pass_rate_history` and `_DRY_RUN_SIGNATURE` are gone.
- `models.pass_rate()` is the only copy of the pass rate formula. `report.compute_drift` and `report.fleet_trend` call `RunHistory`.
- New `CONTEXT.md` glossary and `docs/adr/0001-comparable-run-history.md`. Updated docs/design.md sections 4 and 9, the CHANGELOG, `README.md` and `tests/README.md`.
- Tests: the new `tests/test_history.py` has 15 tests. Nine history tests left `test_store.py` and `test_report.py`, and two dry-run marker tests joined `test_store.py`. On `main` after the merge, pytest gives 206 passed, 0 failed on Python 3.13 and 3.8. The shell integrity check gives 11 passed, 0 failed.
- Audit: three Opus rounds. Round 1 ran a differential test over 300 random history DBs, and the behavior matched the old code apart from the intended change below. Rounds 1 and 2 found six Low issues in total, all wording or comments, and all fixed. Round 3 came back clean.

## Behavior changes
- The trend no longer charts runs newer than the run being reported. Before, it could, if you re-rendered an old run. This change was intended, and the CHANGELOG records it.
- `fleet_trend(run, n)` with `n < 0` now returns the current point alone. It used to return an empty list. No caller passes a negative `n`, so I kept the new behavior.

## Next (in order)
1. grc-2: per-host assessment module. An Opus agent is implementing it in its own worktree. The design: a new `grc_auditor/assess.py` that is the only writer of post-triage `HostStatus`. `detect` returns a verdict, `scan_host` raises `ScanFailed` instead of setting status then raising, and tests drive `assess_host` with `FakeRemoteHost` through a `connect` seam instead of monkeypatching. `classify.py` stays out of scope and keeps its four triage writes, because it decides before any connection and the review's file list for grc-2 leaves it out.
2. grc-3: fleet posture module ("Worth exploring" in the review). Evidence from the notes: the scan-candidate rule appears twice (`report.py` `_scan_candidates` and `models.py`), and `dry_run` is both stored on the run and passed separately as `args.dry_run` in `cli.py`. Re-check every line number first.
3. The two questions from handoff 004 are still open (`.claude/agents/` and the `AGENTS.md:10` Layout bullet).

## Relevant files
- `grc_auditor/history.py`, `grc_auditor/store.py` (`RunSummary`, `run_summaries`), `grc_auditor/models.py` (`pass_rate`), `grc_auditor/report.py` (`compute_drift`, `fleet_trend`).
- `tests/test_history.py`.
- `CONTEXT.md`, `docs/adr/0001-comparable-run-history.md`, `docs/design.md` sections 4 and 9.

## Gotchas
- A history lookup runs one aggregate query over every run, then filters in Python. One report runs up to three. ADR 0001 says to measure a slow real history.db before moving the filters back into SQL.
- To see the pytest counts, add `-o addopts=""`.
