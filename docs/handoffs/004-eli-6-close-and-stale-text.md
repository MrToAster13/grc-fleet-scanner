# Handoff 004: close ELI-6, fix stale text from the ELI-501 audit

Status: blocked (on two answers from Elijah; no work in flight)

## Goal
Finish everything in this repo that could be done without Elijah: sync with `origin/main`, fix the stale text the ELI-501 audit found, close umbrella ticket ELI-6, run the full suite, and decide what to do with the untracked `.claude/` folder.

## Done
- Local `main` fast-forwarded to `origin/main` (`f4fcd5b`, which includes PRs #19 and #20).
- `docs/handoffs/001-mvp-carve.md:161` fixed on branch `eli-501-followup-stale-text` (commits `527876c`, `cadaef5`, `f55d08e`). The bullet now says what `AGENTS.md` (`525ce08`) said when 001 was written, gives the global `CLAUDE.md` as the source of the em-dash and hyphenated-compound bans, and notes the ELI-498 change. PR #21 merged into `main` as `141211d`, and all four CI jobs passed.
- The audit loop ran three Opus rounds. Round 1 found a false hyphen-ban attribution and round 2 a false em-dash-ban attribution, both fixed. Round 3 passed with one Low note, left as is because 003 records that history.
- Suite on `main`: pytest 198 passed, 0 failed. `bash tests/shell/test_target_setup_integrity.sh` gave 11 passed, 0 failed.
- ELI-6 got a closing comment with the evidence (14 children Done, carve on `main`, suite counts) and is now set to Done in the vault.
- ELI-501 got a progress comment on 2026-10-21 (UTC) that points to PR #21 and this handoff.
- In the untracked `.claude/agents/` (local only), `factory-builder-cli.md:10` lost the trailing slash on `grc-target-setup`, and `factory-builder-report.md:10` lost `crosswalk.py`. Originals are at `C:\Users\Elijah\grc-fleet-scanner-claude-agents-backup-2026-10-20\agents\`.

## Next (in order)
1. Wait for Elijah's reply to the two questions below. His expected reply format is `1A 2A`.
2. Question 1 on `.claude/agents/`: if A, draft the updated agent files and show them before committing. The draft uses `main` as the base, vault `ticket.py` in place of Linear, real baselines (198 and 11), and a secret scan against `origin/main`. If B, commit them as they are now on a branch. If C, do nothing. If D, delete them only on his explicit yes.
3. Question 2 on the `AGENTS.md` Layout bullet: if A, change "design and validation notes" for `docs/` to "design, operating and validation notes, and handoffs" in a Tier 1 PR.
4. Nothing else in this repo is doable without those answers. This handoff reaches `main` through its own audited PR from branch `handoff-004-eli-6-close`.

## Key decisions
- `.claude/agents/` stays uncommitted, because the files point builders at `factory/eli-142-carve` (merged by PR #14 on 2026-10-01), close Linear tickets (Linear is retired), and quote stale baselines (196 and 4). Two other repos of Elijah's do track factory agents in `.claude/agents/`: `job-search` (six files, added in `8a3cb61`) and `ebay-sheet` (five files on `origin/master` since `06aaa06`). That precedent favors committing once the files are updated.
- I annotated the 001 handoff rather than rewriting it, because it is marked Historical and PR #19 set that precedent.
- I closed ELI-6 because Elijah asked for it directly and every child is Done. I also confirmed the code reached `main`, since the 2026-10-01 comment showed "Done" had been wrong once before.
- The audits ran on Opus even though the diff counts as Tier 1, because Elijah's message asked for Opus on audits.

## Relevant files
- `docs/handoffs/001-mvp-carve.md:161-165`, the fixed bullet.
- `docs/handoffs/002-audit-findings.md:289-298` and `003-standards-cleanup.md:25-28,94-97`, the source for which rules came from the global `CLAUDE.md`.
- `.claude/agents/*.md`, untracked factory agents, the subject of question 1.
- `AGENTS.md:10`, the Layout bullet, the subject of question 2.
- `C:\Users\Elijah\obsidian-vault\Tickets\_tools\ticket.py`, the only way to write tickets.

## Gotchas / open questions
- Question 1: commit `.claude/agents/`? A, update then commit (recommended). B, commit as they are now. C, leave untracked. D, delete.
- Question 2: fix the `docs/` description in the `AGENTS.md` Layout bullet? A, fix. B, leave the ELI-498 approved text as it is.
- T3 Code still lists PR #21 as open, but GitHub reports it merged.
- `pytest -q` with the `pyproject.toml` addopts (`-ra -q`) hides the summary line. Add `-o addopts=""` to see the counts.
- Elijah lifted the 2026-10-20 one-subagent cap, so normal `CLAUDE.md` subagent use applies again.
