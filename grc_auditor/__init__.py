"""GRC Fleet Auditor.

Discovers hosts on an authorized network, audits reachable Ubuntu hosts against
the CIS Benchmark via OpenSCAP, and produces a fleet compliance report with
drift history. See docs/design.md for the design and docs/operating.md for
how to run it.
"""

__version__ = "0.1.0"
