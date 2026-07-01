"""Stage 8: reporting - HTML dashboard, machine exports, drift.

Produces, for one run:
  * report.html  - consolidated fleet dashboard (coverage map, pass/fail,
                   top fleet-wide failing controls, per-host drill-down, drift)
  * report.json  - the full RunRecord for GRC-platform ingestion
  * hosts.csv    - per-host summary
  * findings.csv - per-failed-control rows

Drift compares this run to the immediately prior run in the history store.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
from collections import Counter
from dataclasses import dataclass
from typing import Optional

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError as exc:  # pragma: no cover - dependency guard
    raise SystemExit(
        "Jinja2 is required. Install dependencies: pip install -r requirements.txt"
    ) from exc

from . import crosswalk
from .logging_setup import get_logger
from .models import DEFAULT_LOW_CONFIDENCE_THRESHOLD, RunRecord
from .store import Store

log = get_logger()

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

# Severity ranking for sorting/weighting. Higher = worse.
_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "unknown": 0}


def _sev_rank(severity: Optional[str]) -> int:
    return _SEVERITY_RANK.get((severity or "unknown").lower(), 0)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_manifest(run: RunRecord, run_dir: str) -> str:
    """Seal the run's artifacts with a SHA-256 manifest (chain of custody).

    Hashes every top-level run artifact (report files, ``audit.log``,
    ``effective-config.json``) and every retained per-host evidence file, so an
    auditor can later prove the bytes on disk are the ones this run produced --
    any post-hoc edit changes the recorded digest. (This protects evidence *at
    rest*; it cannot detect a host that forged its own results before the tool
    pulled them -- see design.md on residual trust.)
    """
    entries = []
    for name in sorted(os.listdir(run_dir)):
        fp = os.path.join(run_dir, name)
        if os.path.isfile(fp) and name != "manifest.json":
            entries.append({"file": name, "kind": "run",
                            "sha256": _sha256_file(fp), "bytes": os.path.getsize(fp)})
        elif os.path.isdir(fp):  # per-host evidence directory (named by IP)
            for sub in sorted(os.listdir(fp)):
                ef = os.path.join(fp, sub)
                if os.path.isfile(ef):
                    entries.append({
                        "file": f"{name}/{sub}", "kind": "evidence", "host": name,
                        "sha256": _sha256_file(ef), "bytes": os.path.getsize(ef),
                    })
    manifest = {
        "run_id": run.run_id,
        "config_hash": run.config_hash,
        "artifacts": entries,
    }
    mpath = os.path.join(run_dir, "manifest.json")
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return mpath


def _csv_safe(value) -> str:
    """Neutralize spreadsheet formula injection in a CSV cell.

    A cell that begins with ``= + - @`` (or a leading tab/CR) is evaluated as a
    formula by Excel/LibreOffice/Sheets. Target-derived fields (rule titles/ids
    from a host's oscap content, os-release strings) reach these exports, so a
    malicious host could ship ``=HYPERLINK(...)`` / DDE payloads to the analyst's
    workstation. Prefix a single quote so the cell is rendered literally.
    """
    s = "" if value is None else str(value)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


# Threshold below which a host's score is treated as low-confidence. The value
# of record lives on Config; this is the shared default for direct callers/tests.
LOW_CONFIDENCE_THRESHOLD = DEFAULT_LOW_CONFIDENCE_THRESHOLD


def low_confidence_hosts(run: RunRecord,
                         threshold: float = LOW_CONFIDENCE_THRESHOLD) -> list[dict]:
    """Scanned hosts whose assessment confidence is below ``threshold``.

    These are the dangerous ones for a compliance read: a clean-looking score
    that covers only the fraction of the benchmark that actually executed.
    Uses ScanResult.is_low_confidence so the rule is defined in exactly one place.
    The extra fields (not_checked/score) enrich the JSON export for downstream
    GRC platforms.
    """
    out: list[dict] = []
    for h in run.scanned_hosts():
        if h.scan.is_low_confidence(threshold):
            out.append({
                "ip": h.ip,
                "confidence": h.scan.assessment_confidence,
                "not_checked": h.scan.not_checked,
                "score": h.scan.score,
            })
    out.sort(key=lambda r: r["confidence"])
    return out


@dataclass
class HostDrift:
    ip: str
    prev_score: Optional[float]
    curr_score: Optional[float]

    @property
    def delta(self) -> Optional[float]:
        if self.prev_score is None or self.curr_score is None:
            return None
        return round(self.curr_score - self.prev_score, 1)


@dataclass
class Drift:
    prev_run_id: Optional[str]
    prev_pass_rate: Optional[float]
    curr_pass_rate: Optional[float]
    per_host: list[HostDrift]

    @property
    def fleet_delta(self) -> Optional[float]:
        if self.prev_pass_rate is None or self.curr_pass_rate is None:
            return None
        return round(self.curr_pass_rate - self.prev_pass_rate, 1)


def compute_drift(run: RunRecord, store: Store) -> Drift:
    prev_id = store.previous_run_id(run.run_id)
    if prev_id is None:
        return Drift(None, None, run.fleet_pass_rate(), [])

    prev = store.load_run(prev_id)
    prev_scores = {
        h.ip: h.scan.score for h in prev.scanned_hosts()
    } if prev else {}

    per_host: list[HostDrift] = []
    for h in run.scanned_hosts():
        per_host.append(HostDrift(
            ip=h.ip,
            prev_score=prev_scores.get(h.ip),
            curr_score=h.scan.score,
        ))

    return Drift(
        prev_run_id=prev_id,
        prev_pass_rate=prev.fleet_pass_rate() if prev else None,
        curr_pass_rate=run.fleet_pass_rate(),
        per_host=per_host,
    )


def top_failing_controls(run: RunRecord, limit: int = 20) -> list[dict]:
    """Fleet-wide failing controls, severity-weighted and host-linked.

    Aggregates each failing rule across scanned hosts, then sorts by
    **severity first, then host-count** so the most dangerous, most widespread
    gaps surface at the top. Each row also carries the list of failing host IPs
    and an indicative framework cross-walk (NIST 800-53 / ISO 27001) from
    :mod:`grc_auditor.crosswalk`.

    Each item::

        {"rule_id", "count", "title", "severity", "severity_rank",
         "hosts": [ip, ...], "stem", "nist": [...], "iso": [...],
         "mapped": bool}
    """
    counter: Counter = Counter()
    titles: dict[str, str] = {}
    severities: dict[str, str] = {}
    hosts_by_rule: dict[str, list] = {}
    for h in run.scanned_hosts():
        for fr in h.scan.failed_rules:
            counter[fr.rule_id] += 1
            if fr.title:
                titles[fr.rule_id] = fr.title
            # Keep the most severe label ever seen for this rule.
            if fr.severity and _sev_rank(fr.severity) >= _sev_rank(severities.get(fr.rule_id)):
                severities[fr.rule_id] = fr.severity
            bucket = hosts_by_rule.setdefault(fr.rule_id, [])
            if h.ip not in bucket:
                bucket.append(h.ip)

    rows: list[dict] = []
    for rid, n in counter.items():
        sev = severities.get(rid, "unknown")
        cw = crosswalk.map_rule_verbose(rid)
        rows.append({
            "rule_id": rid,
            "stem": crosswalk.rule_stem(rid),
            "count": n,
            "title": titles.get(rid, ""),
            "severity": sev,
            "severity_rank": _sev_rank(sev),
            "hosts": sorted(hosts_by_rule.get(rid, [])),
            "nist": cw["nist"],
            "iso": cw["iso"],
            "mapped": cw["mapped"],
        })

    # Sort: severity desc, then host-count desc, then rule id for stability.
    rows.sort(key=lambda r: (-r["severity_rank"], -r["count"], r["rule_id"]))
    return rows[:limit]


def controls_by_severity(run: RunRecord) -> dict:
    """Breakdown of failing-control findings grouped by severity.

    Counts both *distinct failing rules* and *total host-findings* (one rule
    failing on three hosts counts as three findings) per severity bucket, so
    the report can show both "how many kinds of gaps" and "how much exposure".

    Returns::

        {"order": ["high","medium","low","unknown"],
         "by_severity": {sev: {"rules": int, "findings": int}},
         "total_rules": int, "total_findings": int}
    """
    order = ["high", "medium", "low", "unknown"]
    rule_sev: dict[str, str] = {}
    findings: Counter = Counter()
    for h in run.scanned_hosts():
        for fr in h.scan.failed_rules:
            sev = (fr.severity or "unknown").lower()
            if sev not in _SEVERITY_RANK:
                sev = "unknown"
            findings[sev] += 1
            # Track the most severe label seen per rule for the distinct count.
            if _sev_rank(sev) >= _sev_rank(rule_sev.get(fr.rule_id)):
                rule_sev[fr.rule_id] = sev

    rules: Counter = Counter(rule_sev.values())
    by_sev = {
        sev: {"rules": rules.get(sev, 0), "findings": findings.get(sev, 0)}
        for sev in order
    }
    return {
        "order": order,
        "by_severity": by_sev,
        "total_rules": sum(rules.values()),
        "total_findings": sum(findings.values()),
    }


def fleet_trend(run: RunRecord, store: Store, n: int = 8) -> dict:
    """Fleet pass-rate trend across the last ``n`` runs (incl. this one).

    Pulls history from :meth:`Store.fleet_pass_rate_history`. Gracefully reports
    a single-point "first run" when there is no prior history. The current run
    is reconciled in from the live ``run`` object so the latest point reflects
    this in-progress run even before/independent of persistence.

    Returns::

        {"points": [{"run_id","label","pass_rate","scanned","is_current"}],
         "first_run": bool, "min": float|None, "max": float|None,
         "spark": "▁▂▅█..."}
    """
    history = store.fleet_pass_rate_history(n) if store else []

    # Ensure the current run is represented and authoritative for its own point.
    curr_rate = run.fleet_pass_rate()
    curr_scanned = len(run.scanned_hosts())
    found_current = False
    for h in history:
        if h["run_id"] == run.run_id:
            h["pass_rate"] = curr_rate
            h["scanned"] = curr_scanned
            found_current = True
    if not found_current:
        history.append({
            "run_id": run.run_id,
            "started_at": run.started_at,
            "scanned": curr_scanned,
            "pass_rate": curr_rate,
        })
        history.sort(key=lambda r: r["run_id"])
        history = history[-n:]

    points = []
    for h in history:
        points.append({
            "run_id": h["run_id"],
            "label": (h.get("started_at") or h["run_id"])[:16],
            "pass_rate": h.get("pass_rate"),
            "scanned": h.get("scanned", 0),
            "is_current": h["run_id"] == run.run_id,
        })

    rated = [p["pass_rate"] for p in points if p["pass_rate"] is not None]
    return {
        "points": points,
        "first_run": len(rated) <= 1,
        "min": min(rated) if rated else None,
        "max": max(rated) if rated else None,
        "spark": _sparkline([p["pass_rate"] for p in points]),
    }


_SPARK_CHARS = "▁▂▃▄▅▆▇█"


def _sparkline(values: list) -> str:
    """A tiny inline unicode sparkline scaled to 0..100. None -> gap (' ')."""
    present = [v for v in values if v is not None]
    if not present:
        return ""
    lo, hi = min(present), max(present)
    span = (hi - lo) or 1.0
    out = []
    last = len(_SPARK_CHARS) - 1
    for v in values:
        if v is None:
            out.append(" ")
            continue
        idx = int(round((v - lo) / span * last))
        out.append(_SPARK_CHARS[max(0, min(last, idx))])
    return "".join(out)


def executive_summary(run: RunRecord, drift: Drift, top: list, sev: dict,
                      low_confidence_threshold: float = LOW_CONFIDENCE_THRESHOLD) -> dict:
    """A plain-language posture block for non-technical readers.

    Synthesizes overall posture, scanned-vs-gap coverage, the trend direction,
    and the biggest risks (top high-severity, widespread controls). Robust when
    nothing was scanned or there is no prior run.
    """
    scanned = run.scanned_hosts()
    gaps = run.coverage_gaps()
    total = len(run.hosts)
    rate = run.fleet_pass_rate()

    if not scanned:
        posture = "no-data"
        headline = (
            "No hosts were successfully scanned this run; compliance posture "
            "cannot be assessed. Resolve the coverage gaps below."
        )
    elif rate is None:
        posture = "no-data"
        headline = "Hosts were scanned but produced no evaluable results."
    elif rate >= 90:
        posture = "strong"
        headline = "Fleet compliance is strong, with only isolated gaps to close."
    elif rate >= 75:
        posture = "moderate"
        headline = "Fleet compliance is moderate; several controls need attention."
    else:
        posture = "weak"
        headline = "Fleet compliance is weak; broad remediation is required."

    # Trend sentence. fleet_delta is None both when there is genuinely no prior
    # run AND when a delta can't be computed because this run (or the prior one)
    # produced no pass rate -- so distinguish them rather than always claiming
    # "first recorded run", which would misstate the audit history.
    delta = drift.fleet_delta
    if delta is None:
        if drift.prev_run_id is None:
            trend = "No prior run to compare against (first recorded run)."
        elif drift.curr_pass_rate is None:
            trend = ("No hosts scored this run, so posture can't be compared "
                     "against the prior run.")
        else:
            trend = ("The prior run produced no pass rate, so there is nothing "
                     "to compare against.")
    elif delta > 0:
        trend = "Posture improved %.1f points versus the prior run." % delta
    elif delta < 0:
        trend = "Posture regressed %.1f points versus the prior run." % abs(delta)
    else:
        trend = "Posture is unchanged versus the prior run."

    # Coverage sentence.
    if total:
        cov_pct = round(100.0 * len(scanned) / total, 1)
    else:
        cov_pct = 0.0
    coverage = (
        "%d of %d discovered hosts assessed (%.1f%%); %d coverage gap%s remain%s."
        % (len(scanned), total, cov_pct, len(gaps),
           "" if len(gaps) == 1 else "s", "s" if len(gaps) == 1 else "")
    )

    # Biggest risks: prefer high severity, then widest blast radius.
    biggest = []
    for c in top:
        if c["severity"] == "high" or c["count"] > 1:
            biggest.append({
                "stem": c["stem"],
                "severity": c["severity"],
                "count": c["count"],
                "title": c["title"],
            })
        if len(biggest) >= 5:
            break
    if not biggest:
        biggest = [{
            "stem": c["stem"], "severity": c["severity"],
            "count": c["count"], "title": c["title"],
        } for c in top[:3]]

    # Low-confidence warning: scores that reflect only part of the benchmark.
    low_conf = low_confidence_hosts(run, low_confidence_threshold)
    if low_conf:
        confidence_note = (
            "%d scanned host%s returned LOW assessment confidence -- much of "
            "the benchmark did not run (likely insufficient privilege), so "
            "their high scores are NOT trustworthy. Investigate before relying "
            "on them."
            % (len(low_conf), "" if len(low_conf) == 1 else "s")
        )
    else:
        confidence_note = None

    high_rules = sev["by_severity"].get("high", {}).get("rules", 0)
    return {
        "posture": posture,
        "headline": headline,
        "trend": trend,
        "coverage": coverage,
        "fleet_pass_rate": rate,
        "high_severity_rules": high_rules,
        "biggest_risks": biggest,
        "low_confidence_count": len(low_conf),
        "low_confidence_note": confidence_note,
        "low_confidence_hosts": low_conf,
    }


def _summary(run: RunRecord, drift: Drift) -> dict:
    scanned = run.scanned_hosts()
    return {
        "run_id": run.run_id,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "scope": run.scope,
        "total_hosts": len(run.hosts),
        "scanned": len(scanned),
        "coverage_gaps": len(run.coverage_gaps()),
        "counts_by_status": run.counts_by_status(),
        "fleet_pass_rate": run.fleet_pass_rate(),
        "fleet_delta": drift.fleet_delta,
        "prev_run_id": drift.prev_run_id,
    }


def write_reports(run: RunRecord, store: Store, run_dir: str,
                  low_confidence_threshold: float = LOW_CONFIDENCE_THRESHOLD
                  ) -> dict[str, str]:
    """Render all report artifacts into run_dir. Returns {kind: path}."""
    os.makedirs(run_dir, exist_ok=True)
    drift = compute_drift(run, store)
    summary = _summary(run, drift)
    top = top_failing_controls(run)
    severity = controls_by_severity(run)
    trend = fleet_trend(run, store)
    exec_summary = executive_summary(run, drift, top, severity,
                                     low_confidence_threshold)
    # The template renders the low-confidence decision by IP membership, so the
    # rule (ScanResult.is_low_confidence) stays the single source — the template
    # does no threshold arithmetic of its own.
    low_conf_ips = {d["ip"] for d in exec_summary["low_confidence_hosts"]}

    # --- HTML dashboard ---
    # autoescape=True unconditionally. The report renders target-DERIVED strings
    # (hostnames, banners, os-release, oscap rule titles/ids -- all controllable by
    # a malicious host) into HTML an analyst opens, so escaping is mandatory.
    # NOTE: select_autoescape keys off the filename, and "report.html.j2" ends in
    # ".j2" (not ".html"), so it would resolve to False -- a silent stored-XSS
    # hole. Forcing True removes that footgun.
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=True,
    )
    template = env.get_template("report.html.j2")
    html = template.render(
        run=run, summary=summary, drift=drift, top=top,
        severity=severity, trend=trend, exec_summary=exec_summary,
        crosswalk_label=crosswalk.CROSSWALK_LABEL,
        low_conf_ips=low_conf_ips,
    )
    html_path = os.path.join(run_dir, "report.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    # --- JSON export ---
    json_path = os.path.join(run_dir, "report.json")
    payload = run.to_dict()
    payload["summary"] = summary
    payload["executive_summary"] = exec_summary
    payload["top_failing_controls"] = top
    payload["controls_by_severity"] = severity
    payload["fleet_trend"] = trend
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    # --- per-host CSV ---
    hosts_csv = os.path.join(run_dir, "hosts.csv")
    with open(hosts_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ip", "hostname", "status", "ubuntu_version",
                    "credential_group", "passed", "failed", "not_checked",
                    "score", "confidence", "detail"])
        for h in run.hosts:
            s = h.scan
            conf = s.assessment_confidence if s else None
            w.writerow([
                _csv_safe(h.ip), _csv_safe(h.hostname or ""), h.status.value,
                _csv_safe(h.ubuntu_version or ""), h.credential_group or "",
                s.passed if s else "", s.failed if s else "",
                s.not_checked if s else "",
                f"{s.score:.1f}" if s and s.score is not None else "",
                f"{conf:.1f}" if conf is not None else "",
                _csv_safe(h.detail or ""),
            ])

    # --- per-finding CSV ---
    findings_csv = os.path.join(run_dir, "findings.csv")
    with open(findings_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ip", "rule_id", "result", "severity", "title",
                    "nist_800_53", "iso_27001"])
        for h in run.scanned_hosts():
            for fr in h.scan.failed_rules:
                cw = crosswalk.map_rule(fr.rule_id)
                w.writerow([_csv_safe(h.ip), _csv_safe(fr.rule_id), fr.result,
                            _csv_safe(fr.severity or ""), _csv_safe(fr.title or ""),
                            ";".join(cw["nist"]), ";".join(cw["iso"])])

    paths = {
        "html": html_path, "json": json_path,
        "hosts_csv": hosts_csv, "findings_csv": findings_csv,
    }
    # Seal all artifacts last, so the manifest covers the finished report files
    # plus every retained per-host evidence file.
    paths["manifest"] = _write_manifest(run, run_dir)
    log.info("report: wrote %s", html_path)
    return paths
