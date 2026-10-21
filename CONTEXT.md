# GRC Fleet Auditor

Audits a fleet of Ubuntu hosts against CIS benchmarks and reports compliance posture per run and across runs.

## Language

### Runs and history

**Run**:
One execution of the auditor against a configured scope, ordered by when it started.
_Avoid_: Scan (a scan is one host's assessment inside a run), job

**Dry run**:
A run that discovers and classifies candidate hosts but scans none of them, so it holds no compliance evidence.
_Avoid_: Preview run, test run

**Comparable run**:
An earlier run that finished, was not a dry run, and audited the same scope and configuration as the run being reported.
_Avoid_: Previous run, prior run (when comparability is meant)

**Baseline**:
The most recent comparable run, the one drift is measured against.
_Avoid_: Previous run, reference run

**Scope changed**:
The state where no baseline exists but an earlier finished, non-dry run audited a different scope or configuration.
_Avoid_: Config drift

**Drift**:
The change in fleet pass rate and per-host score between a run and its baseline.
_Avoid_: Delta (for the whole comparison), regression

**Trend point**:
One run's fleet pass rate on the trend line: a comparable run, or the run being reported.
_Avoid_: History entry, data point

### Hosts

**Triage**:
The pre-connection classification of a discovered host from discovery evidence alone (OS hint, open SSH port, matching credential group), which decides whether the host is a scan candidate.
_Avoid_: Classification pass, pre-scan

**Assessment**:
The per-host pass that reaches a scan candidate over SSH, detects its OS and scanner, runs the scan, and ends in a verdict.
_Avoid_: Scan (a scan is only the oscap step inside an assessment), audit (for one host)

**Verdict**:
A host status plus the detail that explains it.
_Avoid_: Result, outcome (a rule outcome is one check's result inside a scan)

### Posture

**Fleet pass rate**:
Passed checks as a percentage of evaluated checks (passed, failed and error) summed across scanned hosts, or none when nothing was evaluated.
_Avoid_: Compliance score, fleet score
