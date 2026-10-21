# Comparable-run rules live in history.py, not in store SQL

Drift and the trend line must agree on which earlier runs count as comparable runs (finished, not a dry run, same `config_hash`). Those rules used to be two SQL queries in `store.py` that shared a dry-run fragment, and each new rule had to be added to both. We moved them into one Python module, `history.RunHistory`, and reduced the store to an adapter: `Store.run_summaries()` returns raw per-run facts with no filtering, and `history.py` decides. The store can now change its storage without touching the rules, and the tests exercise the rules through `RunHistory` alone.

## Consequences

- Each history lookup runs one query that aggregates every run's host rows into one summary row per run, then filters in Python, where the old queries filtered in SQL with `LIMIT`. One report runs up to three such queries: `baseline()` runs a second one when no comparable run matches, and `trend()` runs one. That is cheap at the fleet and history sizes the tool targets. Do not move the filters back into SQL for speed without first measuring a real history.db that is slow.
- The pass rate formula exists once, in `models.pass_rate`. The store returns the passed and evaluated sums and never computes a rate.
- The current run's trend point always comes from the live `RunRecord`, never from the store.
