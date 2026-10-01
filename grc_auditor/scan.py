"""Stage 6: run OpenSCAP on a host and retrieve raw evidence.

Runs ``oscap xccdf eval`` remotely with the resolved CIS profile/datastream,
writes results to a per-run temp dir on the target, pulls the artifacts (XCCDF
results, ARF, HTML) plus the scanner's stdout/stderr back via SFTP, then removes
the temp dir on every code path. The scanner's own files are inherent to
scanning; the binary/content are never installed by this tool (see detect.py).

OpenSCAP ``xccdf eval`` exit codes:
  * 0 = evaluation completed, every rule passed              -> SCANNED
  * 2 = evaluation completed, at least one rule did not pass -> SCANNED
  * 1 = tooling error (bad profile, unreadable content, ...) -> SCAN_ERROR
Any other non-zero code is treated as a tooling error.
"""

from __future__ import annotations

import os
import posixpath
import re
import xml.etree.ElementTree as ET
from typing import Optional

try:
    # Parse target-supplied XML with entity/DTD/external-reference defenses on.
    # results.xml is written by the (possibly hostile) target, so the stdlib
    # parser's billion-laughs exposure is a real DoS vector on the run host.
    from defusedxml.ElementTree import parse as _safe_xml_parse
    from defusedxml.common import DefusedXmlException
except ImportError as exc:  # pragma: no cover - dependency guard
    raise SystemExit(
        "defusedxml is required. Install dependencies: pip install -r requirements.txt"
    ) from exc

from .detect import ScanPlan
from .logging_setup import get_logger
from .models import (
    HostRecord, HostStatus, RuleResult, ScanResult, finalize_scan_status,
    UNDETERMINED_VERDICTS, VERDICT_FAIL, VERDICT_NOT_APPLICABLE, VERDICT_PASS,
)
from .remote import RemoteHostProtocol
from .scap_xml import localname

log = get_logger()

# Exit codes that mean "the evaluation ran and produced results" (0 = all pass,
# 2 = some rules failed). Both are successful scans for our purposes.
_OSCAP_SUCCESS_CODES = (0, 2)

# Guard parse_xccdf_results against a pathological/oversized results file. A real
# Ubuntu CIS results.xml is a few MB; anything past this is almost certainly not
# a results document we should be loading into memory.
_MAX_RESULTS_BYTES = 256 * 1024 * 1024  # 256 MiB

# Max gap (percentage points) between oscap's weighted <score> and a flat
# pass-ratio before we warn of a likely mis-parse. Wide on purpose: CIS weighted
# scoring routinely diverges from the flat ratio (a real ~3 pass / 2 fail slice
# scores ~86 vs a flat ~60), so only an opposite-story gap this large is a signal.
_SCORE_RECONCILE_TOLERANCE = 40.0

# The only shape we accept back from the target's `mktemp -d /tmp/grc_audit.XXXXXX`.
# Anything else (a crafted path with shell metacharacters from a hostile host) is
# refused before it can be interpolated into a sudo command. See scan_host.
_SAFE_REMOTE_DIR = re.compile(r"^/tmp/grc_audit\.[A-Za-z0-9]{6,}$")


# Cap on any single target-supplied string (rule id / title / severity) before it
# enters the report model. A real CIS rule id/title is well under this.
_MAX_FIELD_LEN = 1024


def _clean_field(text: Optional[str], maxlen: int = _MAX_FIELD_LEN) -> Optional[str]:
    """Bound a target-supplied string: drop control characters and cap length.

    A hostile results.xml fully controls rule ids/titles. HTML-escaping and
    CSV-safety happen at render time; this is defense in depth so such a string
    cannot smuggle layout-breaking control bytes or bloat the report. ``None``
    stays ``None``.
    """
    if text is None:
        return None
    return "".join(ch for ch in str(text) if ch.isprintable())[:maxlen]


def _build_oscap_argv(plan: ScanPlan, r_results: str, r_arf: str,
                      r_report: str) -> list[str]:
    """The ``oscap xccdf eval`` argv for one host.

    High-assurance mode adds ``--fetch-remote-resources`` so checks whose OVAL/CVE
    content lives off-box are actually evaluated (higher coverage/confidence)
    rather than returning notchecked. It makes the TARGET reach out to the
    network, which is why it is opt-in (config ``fetch_remote_resources``).
    The flag is placed before the datastream positional so it applies
    to the whole evaluation.
    """
    argv = ["oscap", "xccdf", "eval", "--profile", plan.profile_id]
    if plan.fetch_remote_resources:
        argv.append("--fetch-remote-resources")
    argv += [
        "--results", r_results,
        "--results-arf", r_arf,
        "--report", r_report,
        plan.datastream_path,
    ]
    return argv


def scan_host(host: HostRecord, conn: RemoteHostProtocol, plan: ScanPlan,
              run_id: str, artifacts_root: str,
              timeout: int = 600) -> ScanResult:
    """Evaluate one host and return a parsed ScanResult; updates host.status."""
    mk = conn.run("mktemp -d /tmp/grc_audit.XXXXXX", timeout=30)
    remote_dir = mk.stdout.strip()
    if not mk.ok or not remote_dir:
        host.status = HostStatus.SCAN_ERROR
        host.detail = "could not create remote temp dir"
        raise RuntimeError(host.detail)
    # SECURITY: `remote_dir` is the stdout of a command run on the TARGET, which
    # may be hostile (it controls its own `mktemp` / PATH). It is interpolated
    # into commands run as root via sudo, so a crafted value would be shell
    # injection -> root RCE. Refuse anything that is not exactly our temp path
    # shape; downstream commands additionally go through run_argv (quoted).
    if not _SAFE_REMOTE_DIR.match(remote_dir):
        host.status = HostStatus.SCAN_ERROR
        host.detail = "mktemp returned an unexpected path; refusing to proceed"
        raise RuntimeError(host.detail)

    r_results = posixpath.join(remote_dir, "results.xml")
    r_arf = posixpath.join(remote_dir, "arf.xml")
    r_report = posixpath.join(remote_dir, "report.html")

    # Built as an argv list so every token is shell-quoted (run_argv) -- no value
    # interpolated into a remote shell command is ever unquoted (defense in depth
    # alongside the _SAFE_REMOTE_DIR check above).
    oscap_argv = _build_oscap_argv(plan, r_results, r_arf, r_report)

    local_dir = os.path.join(artifacts_root, run_id, host.ip)
    local_results = os.path.join(local_dir, "results.xml")
    local_arf = os.path.join(local_dir, "arf.xml")
    local_report = os.path.join(local_dir, "report.html")

    try:
        log.info("scan[%s]: evaluating CIS L%d (%s)",
                 host.ip, plan.cis_level, plan.ubuntu_version)
        res = conn.run_argv(oscap_argv, sudo=plan.sudo, timeout=timeout)

        # Persist the scanner's own output as evidence regardless of outcome --
        # this is what an auditor reads to understand an error or partial run.
        _write_local(local_dir, "oscap.stdout.txt", res.stdout)
        _write_local(local_dir, "oscap.stderr.txt", res.stderr)

        if res.exit_code not in _OSCAP_SUCCESS_CODES:
            host.status = HostStatus.SCAN_ERROR
            detail = (res.stderr.strip() or res.stdout.strip())[:300]
            host.detail = f"oscap error (exit {res.exit_code}): {detail}"
            raise RuntimeError(host.detail)

        # A success exit code with no results.xml means the scan did not produce
        # what we need to parse; treat as an error rather than reporting zeros.
        if not conn.run_argv(["test", "-f", r_results], timeout=30).ok:
            host.status = HostStatus.SCAN_ERROR
            host.detail = (
                f"oscap exited {res.exit_code} but produced no results.xml at "
                f"{r_results} (see oscap.stderr.txt)"
            )
            raise RuntimeError(host.detail)

        # Pull artifacts back into the immutable per-run evidence store. The
        # results file is mandatory; ARF/HTML are best-effort evidence.
        conn.get_file(r_results, local_results)
        _get_file_best_effort(conn, r_arf, local_arf, host.ip, "ARF")
        _get_file_best_effort(conn, r_report, local_report, host.ip, "HTML report")

        scan = parse_xccdf_results(local_results)
        scan.profile_id = plan.profile_id
        scan.datastream = plan.datastream_path
        scan.results_xml_path = local_results
        scan.arf_path = local_arf if os.path.exists(local_arf) else None
        scan.html_path = local_report if os.path.exists(local_report) else None

        # Chokepoint: a successful oscap exit + a parseable file is NOT enough to
        # certify SCANNED -- a zero-outcome or sub-floor scan is recorded as a gap
        # (SCAN_ERROR), never a clean pass. This is where never-false-pass is
        # structurally enforced rather than left to convention.
        finalize_scan_status(host, scan)
        log.info("scan[%s]: %d pass / %d fail (score %s) -> %s",
                 host.ip, scan.passed, scan.failed,
                 f"{scan.score:.1f}" if scan.score is not None else "n/a",
                 host.status.value)
        return scan
    finally:
        # Guarantee remote temp cleanup on every path (success, oscap error,
        # parse failure, transfer failure). Best-effort: never mask the original
        # error and never fail the run on a leftover temp dir.
        cleanup = conn.run_argv(["rm", "-rf", remote_dir], sudo=plan.sudo, timeout=30)
        if not cleanup.ok:
            log.warning("scan[%s]: could not remove remote temp %s (exit %d)",
                        host.ip, remote_dir, cleanup.exit_code)


def _write_local(local_dir: str, name: str, text: str) -> None:
    """Write a small text artifact into the per-host evidence dir (best effort)."""
    try:
        os.makedirs(local_dir, exist_ok=True)
        with open(os.path.join(local_dir, name), "w",
                  encoding="utf-8", errors="replace") as fh:
            fh.write(text or "")
    except OSError as exc:  # pragma: no cover - disk/permission edge
        log.warning("scan: could not write %s: %s", name, exc)


def _get_file_best_effort(conn: RemoteHostProtocol, remote: str, local: str,
                          ip: str, label: str) -> None:
    try:
        conn.get_file(remote, local)
    except Exception as exc:  # noqa: BLE001 - evidence is best-effort
        log.warning("scan[%s]: could not retrieve %s (%s): %s",
                    ip, label, remote, exc)


def parse_xccdf_results(path: str) -> ScanResult:
    """Parse an XCCDF results file into a ScanResult (counts, score, failures).

    Expected input shape (namespaces are stripped before matching, so any XCCDF
    namespace/version works; matching is by element *local-name*):

      * A ``<TestResult>`` element somewhere in the document containing the
        per-rule outcomes. (We scan the whole tree, so a results-only file or a
        full benchmark+results file both parse.)
      * Each rule outcome is a ``<rule-result idref="..." severity="...">``
        element whose direct child ``<result>`` carries the verdict text, one
        of: ``pass`` | ``fail`` | ``error`` | ``notapplicable`` | ``notchecked``.
        ``unknown`` (ran but reached no verdict) counts with ``error``; anything
        else (``notselected`` / ``informational`` / ``fixed``, i.e. out of scope)
        goes to ``other`` and is excluded from assessment confidence. The ``idref``
        and ``severity`` attributes are optional (default to ``"unknown"``).
      * An optional ``<score>`` element whose text is the XCCDF percentage
        (0..100). The first one found wins; a missing/non-numeric score yields
        ``score=None``.
      * An optional ``<version>`` element supplies ``benchmark_version`` (first
        non-empty one wins).
      * Optional ``<Rule id="...">`` definitions, each with a child ``<title>``,
        supply human-readable titles for failed rules. Absent titles are fine
        (``RuleResult.title`` stays None).

    Resilience: tolerates a missing ``<score>``, namespace variations, absent
    titles, and an empty file (returns an all-zero ScanResult). An unreadable,
    malformed, or oversized (> ~256 MiB) file raises ValueError so the caller
    records a SCAN_ERROR rather than silently reporting zeros.
    """
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise ValueError(f"results file not accessible: {path} ({exc})") from exc

    if size == 0:
        # An empty results file is degenerate but not corrupt; report zeros so
        # the caller can still distinguish it from a parse crash if it chooses.
        log.warning("parse: empty results file %s", path)
        return ScanResult(profile_id="", datastream="")
    if size > _MAX_RESULTS_BYTES:
        raise ValueError(
            f"results file too large to parse safely: {path} ({size} bytes)"
        )

    try:
        tree = _safe_xml_parse(path)
        root = tree.getroot()
    except DefusedXmlException as exc:
        raise ValueError(
            f"hostile XCCDF results (entity/DTD/external-ref blocked): {path} ({exc})"
        ) from exc
    except ET.ParseError as exc:
        raise ValueError(f"malformed XCCDF results: {path} ({exc})") from exc

    scan = ScanResult(profile_id="", datastream="")
    failed_rules: list[RuleResult] = []

    for el in root.iter():
        name = localname(el.tag)
        if name == "rule-result":
            result_el = None
            for child in el:
                if localname(child.tag) == "result":
                    result_el = child
                    break
            if result_el is None or result_el.text is None:
                continue
            # Normalize case so the buckets match regardless of how the
            # benchmark emits the verdict text (oscap uses lowercase; rmf.py
            # lowercases too -- keep the two parsers in agreement).
            outcome = result_el.text.strip().lower()
            if outcome == VERDICT_PASS:
                scan.passed += 1
            elif outcome == VERDICT_FAIL:
                scan.failed += 1
                failed_rules.append(RuleResult(
                    rule_id=_clean_field(el.get("idref")) or "unknown",
                    result=outcome,
                    severity=_clean_field(el.get("severity")) or "unknown",
                ))
            elif outcome in UNDETERMINED_VERDICTS:
                # A selected check that OWED a verdict but produced none. 'error'
                # and 'unknown' RAN but reached none (OVAL probe error, missing
                # dependency); 'notchecked' was not evaluated. All lower
                # assessment_confidence -- never-false-pass: an unanswered check is
                # not a trustworthy one. They are NOT out-of-scope like
                # 'notselected'/'informational' (which fall through to `other`,
                # excluded from the confidence denominator). 'notchecked' keeps its
                # own field; 'error'/'unknown' share the error probe-failure bucket.
                if outcome == "notchecked":
                    scan.not_checked += 1
                else:
                    scan.error += 1
            elif outcome == VERDICT_NOT_APPLICABLE:
                scan.not_applicable += 1
            else:
                scan.other += 1
        elif name == "score" and scan.score is None:
            try:
                scan.score = float((el.text or "").strip())
            except (TypeError, ValueError):
                pass
        elif name == "version" and scan.benchmark_version is None:
            scan.benchmark_version = (el.text or "").strip() or None

    # Attach human-readable titles to failed rules where the benchmark defines
    # them. Skip the second full-tree walk entirely when there are no fails.
    titles = _rule_titles(root) if failed_rules else {}
    for fr in failed_rules:
        fr.title = titles.get(fr.rule_id)
    scan.failed_rules = failed_rules

    # Soft reconciliation: catch a gross mis-parse where oscap's own <score>
    # and our parsed pass/fail tell opposite stories. CIS uses a *weighted*
    # default scoring model, so the score legitimately diverges from a flat
    # 100 * pass / (pass + fail) ratio by a wide margin -- only a contradiction
    # this large signals a likely parse error, not normal weighting. Non-fatal;
    # the raw evidence remains the authority.
    if scan.score is not None and (scan.passed + scan.failed) > 0:
        implied = 100.0 * scan.passed / (scan.passed + scan.failed)
        if abs(implied - scan.score) > _SCORE_RECONCILE_TOLERANCE:
            log.warning(
                "parse: %s reported score %.1f grossly disagrees with parsed "
                "counts (%d pass / %d fail => ~%.1f); verify raw evidence",
                path, scan.score, scan.passed, scan.failed, implied,
            )
    return scan


def _rule_titles(root: ET.Element) -> dict[str, str]:
    titles: dict[str, str] = {}
    for el in root.iter():
        if localname(el.tag) != "Rule":
            continue
        rid = _clean_field(el.get("id"))
        if not rid:
            continue
        for child in el:
            if localname(child.tag) == "title":
                titles[rid] = _clean_field((child.text or "").strip()) or ""
                break
    return titles
