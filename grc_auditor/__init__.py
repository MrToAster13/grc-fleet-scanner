"""GRC Fleet Auditor.

Discovers hosts on an authorized network, audits reachable Ubuntu hosts against
the CIS Benchmark via OpenSCAP, and produces a fleet compliance report with
drift history. See SPEC.md for the approved design.

This package is a walking skeleton: every pipeline stage is present and wired
end-to-end for a single host, with the shared contracts (config, host model,
SQLite schema) made concrete so individual modules can later be hardened in
parallel.
"""

__version__ = "0.1.0"
