# Handoff 006: grc-2, per-host assessment module

Status: complete for grc-2. grc-3 is in progress.

## Goal
Carry out the three architecture fixes Elijah approved from the 2026-10-21 review, one commit per candidate. Handoff 005 has the review paths and grc-1. This handoff covers grc-2.

## Done
- grc-2 landed as commit `47596f9`, merged into `main` by PR #25 as `087a836`. All four CI jobs passed.
- New `grc_auditor/assess.py`. `assess_host` runs reach, detect and scan for one host and is the only code after triage that writes `host.status` and `host.detail`. Status assignments in the package went from 26 to 5: one in `assess.py` (`_record`) and the four triage writes in `classify.py`.
- `detect` returns a `ScanPlan` or a `Verdict`. `scan_host` returns a `ScanResult` or raises `ScanFailed`, and no longer sets SCAN_ERROR before raising. `assess.scan_verdict` replaces `models.finalize_scan_status` with the same rules and detail text. `cli._process_host` is gone.
- `assess_host` takes a `connect` factory. `tests/test_assess.py` (27 tests) drives the real detect and scan code against `FakeRemoteHost` with no monkeypatching.
- New `docs/adr/0002-one-writer-per-host-verdict.md` and the glossary terms Triage, Assessment and Verdict in `CONTEXT.md`. Updated the CHANGELOG, `README.md`, `docs/design.md` and `tests/README.md`.
- Tests on `main` after the merge: 222 passed, 0 failed on Python 3.13 and 3.8. The shell integrity check gives 11 passed, 0 failed.
- Audit: three Opus rounds. Round 1 found a Medium: when oscap failed and the `rm -rf` cleanup then failed over SSH, the cleanup error replaced the oscap detail. It also found a Low: a cleanup failure after a finished scan dropped the parsed scan. Round 2 found a Low: the cleanup caught only `RemoteError`, and `RemoteHost.run` leaves a reset transport's `OSError` or `EOFError` unwrapped. All three are fixed in `scan.py`'s cleanup block and covered by tests that fail on the old code. Round 3 came back clean.

## Behavior changes
- If the scan raises an unexpected error and the cleanup then fails too, the detail names the scan's error. Before, it named the cleanup's.
- The per-host scan log line now comes after cleanup.
- In every other cleanup case the recorded status, detail and attached scan match the old pipeline. The round 3 audit checked each case against main.

## Next (in order)
1. grc-3: fleet posture module. An Opus agent is implementing it on branch `arch-grc-3-posture` in its own worktree. The design: a new `grc_auditor/posture.py` that holds the coverage thresholds, `scan_candidates`, `assessed_share`, `zero_scanned` and the posture ladder from `report.executive_summary`. `zero_scanned` reads `run.dry_run`, so `cli.py`, `write_reports` and the template stop passing `args.dry_run` separately, and `RunRecord.zero_scanned` goes away.
2. The two questions from handoff 004 are still open (`.claude/agents/` and the `AGENTS.md:10` Layout bullet).

## Relevant files
- `grc_auditor/assess.py`, `grc_auditor/detect.py`, `grc_auditor/scan.py` (`ScanFailed`, the cleanup block in `scan_host`), `grc_auditor/cli.py`.
- `tests/test_assess.py`.
- `CONTEXT.md`, `docs/adr/0002-one-writer-per-host-verdict.md`.

## Gotchas
- `classify.py` keeps its four status writes on purpose. Triage decides from nmap evidence before any connection, and the review's file list for grc-2 left it out.
- The cleanup block in `scan_host` catches every `Exception`. When the scan did not finish, a programming error in the cleanup call becomes a logged warning and the scan's own error still propagates. The code comment explains why.
- `py -3.13` on this machine has no PyYAML. Use `.venv/Scripts/python.exe` for Python 3.13 runs, and add `-o addopts=""` to see the pytest counts.
