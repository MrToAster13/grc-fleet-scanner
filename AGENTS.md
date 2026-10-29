# AGENTS.md

Guidance for AI agents working in this repo. Writing style: load the `unslop` skill and follow it. No other style rules.

## Setup and checks
- Install: `pip install -r requirements.txt`. The tool needs Python 3.10+; the test suite also runs on 3.8 (CI matrix: Python 3.8, 3.11, 3.13).
- Tests: `python -m pytest -q` (tests in `tests/`, config in `pyproject.toml`).
- Shell harnesses: `bash tests/shell/run-all.sh` runs every `tests/shell/test_*.sh`.
- CI runs both on every PR (`.github/workflows/tests.yml`). The pre-commit hook runs both on every commit once enabled with `git config core.hooksPath .githooks`. Run both before you push.
- Layout: `grc_auditor/` package, `bin/` entry points, `grc-target-setup` target setup script, `docs/` design and validation notes.

## Organization
- One topic per file, named `lowercase-with-hyphens.md`. Put new content next to similar content. Update the README index on add or rename. Link instead of duplicating.

## Boundaries
- Never commit secrets, keys, tokens or private data.
- Only document what is real and verifiable. Never invent facts, sources or results.
- Do not delete or restructure existing files unless asked. Ask before adding top-level folders or dependencies.

## Subagents
- Use subagents freely. Split independent work across parallel subagents and hand off research, review and large reads. State the model at the call site.

## Commits
- Small commits, one logical change each, present tense (`add ssh brute-force writeup`).
