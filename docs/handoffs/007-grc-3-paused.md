# Handoff 007: grc-3 paused under the new TDD rule

Status: grc-3 is committed locally and not pushed, because it never went through `tdd-loop`. It waits on a decision from Elijah. This handoff and a script-permissions commit went up through a PR under the later rule.

## Goal
Carry out the three architecture fixes Elijah approved from the 2026-10-21 review. grc-1 (handoff 005) and grc-2 (handoff 006) are merged. This handoff covers grc-3 and the rule change that paused it.

## Rule change
On 2026-10-21, after grc-3 was committed, Elijah replaced the audit loop with the `tdd-loop` skill. Every code change now runs that skill: baseline, failing tests that map 1:1 to the ticket's acceptance criteria, at most 10 logged iterations, an Opus adversarial review, a failing regression test before each fix, the security stage, and a commit only when every gate passes. Docs-only changes run only the security stage.

The first version of the rule said to commit only, and Elijah pushes. Later the same day Elijah replaced that: work that passes `tdd-loop` is pushed, goes through a PR, and is merged once CI is green, without asking. If CI fails, the work goes back through `tdd-loop`. Never force-push, and never push `--all` or `--mirror`. Anything that hit a hard stop or has an open finding stays unpushed. The full text is in `~/.claude/CLAUDE.md` under "Test-driven loop before anything lands".

## Done
- Before the rule change, everything was pushed and merged: PR #23 (grc-1), #24 (handoff 005), #25 (grc-2, merged as `087a836`) and #26 (handoff 006, merged as `bbddeb1`).
- grc-3 is commit `5bd0bce` on local branch `arch-grc-3-posture`, rebased onto `bbddeb1`. It lives in the worktree `.claude/worktrees/agent-a804f963dac594eb5`. It is not on the remote.
  - New `grc_auditor/posture.py` holds the coverage thresholds, `scan_candidates`, `assessed_share`, `zero_scanned` and the posture ladder that was in `report.executive_summary`.
  - `zero_scanned` reads `run.dry_run`, so `RunRecord.zero_scanned` is gone and `write_reports`, `cli._print_summary` and `cli._exit_code_for_run` no longer take a `dry_run` argument.
  - New `tests/test_posture.py`. CONTEXT.md gains Scan candidate, Assessed share, Posture and Zero-scanned run.
  - The implementing agent reports 249 passed on Python 3.13 and 3.8, 11 passed in the shell check, and no differences in a snapshot comparison against the old code. I have not rerun these myself.
- `tdd-loop` Stage 5 found four tracked scripts at mode 100644. Commit `860bae1` marks them executable: `bin/_grc-common.sh`, `install.ps1`, `smoketest.py` and `tests/shell/test_target_setup_integrity.sh`. The pre-commit suite passed 222 tests, and the shell check passed 11 of 11.
- The Opus audit of `5bd0bce` was still running its own differential check when the rule changed. It had exited by the time I tried to stop it, and I never received its result. Treat `5bd0bce` as unaudited.

## Why it is paused
grc-3 did not go through `tdd-loop`, and it has no vault ticket, so it has no acceptance criteria. The new rule says to ask Elijah when a ticket has none.

## Next
1. Elijah decides how grc-3 proceeds. The options are in the final chat reply of this session.
2. The two questions from handoff 004 are still open (`.claude/agents/` and the `AGENTS.md:10` Layout bullet).

## Gotchas
- `tdd-loop` Stage 1 wants every new test to fail on a real assertion. grc-3 is a pure move with no new behavior, so tests against the new `posture` module fail on an import error first. Its acceptance criteria need to be written so they can fail on assertions against the current code, for example "`write_reports` takes no `dry_run` argument".
- The design.md module table has no `history.py` row. That gap predates grc-3.
- `arch-grc-3-posture` stays local. Under the later rule, only work that passed `tdd-loop` is pushed, and `5bd0bce` did not go through it.
