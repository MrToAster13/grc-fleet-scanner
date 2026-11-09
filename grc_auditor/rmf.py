"""RMF / NIST 800-53 control rollup from OpenSCAP ARF evidence.

Bridges a scan run to the RMF SSP: for every 800-53 control the CIS benchmark's
rules map to, report how many underlying checks pass vs fail and a suggested
implementation status, so an ISSO can fill the DSS SecCtrl tab from real
evidence instead of by hand.

The source of truth is the datastream's OWN per-rule 800-53 references embedded
in the ARF (authoritative). This is control-by-control evidence you can defend.

Honesty, stated in the output (never hidden):
  * Ubuntu SSG content typically maps rules to 800-53 **Rev 4**; a DoD SSP
    baseline is Rev 5. The revision is read from each reference's href, reported
    as-is, and shown as ``unspecified`` when no marker is present -- never
    assumed. Most controls carry over 1:1.
  * "Implemented"/"Planned" are SUGGESTIONS from automated config checks, not an
    authorization decision -- the ISSO still writes the control narrative.
  * These are CIS-profile results, not a DISA STIG.
"""

from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass, field
from typing import Optional

from .models import (
    OUT_OF_SCOPE_VERDICTS, VERDICT_FAIL, VERDICT_NOT_APPLICABLE, VERDICT_PASS,
)
from .scap_xml import ScapXmlError, clean_field, read_results


class RmfError(Exception):
    """A run's ARF evidence could not be parsed into a control rollup."""


# A control reference looks like "AC-17", "AC-17(2)", "CM-6(a)", "AU-9(3).1".
# We roll up to the base control (family + number); the enhancement is dropped
# because the SSP row set is usually managed at the control level.
_CONTROL_RE = re.compile(r"^\s*([A-Z]{2})-(\d+)")

def _base_control(text: str) -> Optional[str]:
    m = _CONTROL_RE.match(text or "")
    return f"{m.group(1)}-{m.group(2)}" if m else None


def _control_num(control: str) -> int:
    m = re.search(r"-(\d+)", control)
    return int(m.group(1)) if m else 0


def _format_revisions(revisions) -> str:
    """Render a set of 800-53 revision markers as a display string: ``unspecified``
    if empty, the lone value if one, else ``Rev 4 / Rev 5 (mixed)``."""
    revs = sorted(revisions)
    if not revs:
        return "unspecified"
    if len(revs) == 1:
        return revs[0]
    return " / ".join(revs) + " (mixed)"


@dataclass
class ControlRow:
    """Aggregated pass/fail of the CIS checks that map to one 800-53 control."""

    control: str
    family: str
    passed: int = 0
    failed: int = 0
    not_applicable: int = 0
    unverified: int = 0                  # error / notchecked / unknown -- ran, no verdict
    rules: set = field(default_factory=set)
    revisions: set = field(default_factory=set)  # 800-53 revisions seen in the refs

    @property
    def revision(self) -> str:
        """The 800-53 revision(s) the mapped references declare, read from evidence
        (never assumed). ``unspecified`` if no ref carried an rN marker; a merged
        fleet spanning revisions reads ``Rev 4 / Rev 5 (mixed)``."""
        return _format_revisions(self.revisions)

    @property
    def status(self) -> str:
        """Suggested Implementation Status for the DSS SecCtrl tab."""
        if self.failed > 0:
            return "Planned"                  # a failing check -> remediate + POA&M
        if self.unverified > 0:
            # A mapped check ran or was attempted but produced no verdict (error /
            # not-checked / unknown -- typically insufficient privilege). Coverage is
            # incomplete, so passes alone can't certify the control Implemented.
            return "Planned" if self.passed > 0 else "Not Assessed"
        if self.passed > 0:
            return "Implemented"              # every mapped check ran and passed
        return "Not Assessed"                 # only not-applicable / nothing evaluated

    @property
    def justification(self) -> str:
        """A draft Explanation/Justification sentence, grounded in the counts.

        Always discloses unverified checks so a control can't read as fully covered
        when mapped checks silently produced no verdict."""
        c = self.control
        if self.failed > 0:
            base = (f"{self.passed}/{self.passed + self.failed} CIS check(s) mapping to "
                    f"{c} pass; {self.failed} fail (tracked in POA&M).")
        elif self.passed > 0 and self.unverified == 0:
            base = f"All {self.passed} CIS check(s) mapping to {c} pass."
        elif self.passed > 0:
            base = f"{self.passed} CIS check(s) mapping to {c} pass, but coverage is incomplete."
        elif self.not_applicable > 0 and self.unverified == 0:
            base = f"All {self.not_applicable} CIS check(s) mapping to {c} are not applicable."
        else:
            base = f"No CIS check mapping to {c} produced a compliance verdict."
        if self.unverified:
            base += (f" {self.unverified} check(s) could not be verified "
                     f"(error/not-checked/unknown -- check the scan account's privilege).")
        return base + " Automated OpenSCAP CIS scan; evidence retained (ARF)."


def _detect_revision(href: str) -> Optional[str]:
    h = href.lower()
    if "800-53r5" in h:
        return "Rev 5"
    if "800-53r4" in h:
        return "Rev 4"
    return None


def _parse_one(path: str):
    """Return (rule_id -> {control refs}, rule_id -> result, detected revision).

    ``scap_xml.read_results`` reads the file, so a repeated idref already
    resolves to its most decision-critical verdict and the size cap applies."""
    try:
        evidence = read_results(path)
    except ScapXmlError as exc:
        raise RmfError(f"cannot parse ARF {path}: {exc}") from exc
    if evidence.empty:
        raise RmfError(f"cannot parse ARF {path}: empty file")

    rule_controls: dict[str, set] = {}
    revision: Optional[str] = None
    for rid, info in evidence.rules.items():
        for text, href in info.references:
            if "800-53" not in href:
                continue
            if _base_control(text) is None:
                continue  # e.g. the "nist" publisher reference -- not a control
            rule_controls.setdefault(rid, set()).add(text)
            revision = revision or _detect_revision(href)
    rule_results = {rid: o.verdict for rid, o in evidence.outcomes.items()}
    return rule_controls, rule_results, revision


def rollup_from_arf(paths) -> list[ControlRow]:
    """Aggregate CIS rule pass/fail by 800-53 control across one or more ARF files.

    Merging multiple ARFs gives a fleet view: a control reads ``Implemented``
    only if every mapped check passes on every host (one failing host makes it
    ``Planned``). Pass a single ARF for a per-host rollup.
    """
    rows: dict[str, ControlRow] = {}
    for path in paths:
        rule_controls, rule_results, rev = _parse_one(path)
        for rid, controls in rule_controls.items():
            result = rule_results.get(rid)
            if result is None or result in OUT_OF_SCOPE_VERDICTS:
                continue  # not evaluated this run, or out of profile -> not evidence
            # Collapse enhancement refs to distinct base controls so one rule counts
            # ONCE per control, not once per reference string (AC-17(1)+AC-17(2)).
            bases = {b for b in (_base_control(c) for c in controls) if b}
            for base in bases:
                row = rows.get(base)
                if row is None:
                    row = ControlRow(control=base, family=base.split("-", 1)[0])
                    rows[base] = row
                if result == VERDICT_PASS:
                    row.passed += 1
                elif result == VERDICT_FAIL:
                    row.failed += 1
                elif result == VERDICT_NOT_APPLICABLE:
                    row.not_applicable += 1
                else:
                    # error / notchecked / unknown: a selected check that ran or was
                    # attempted but reached no verdict -- the never-false-pass danger
                    # signal. Must NOT read as "Implemented"; distinct from not-applicable.
                    row.unverified += 1
                row.rules.add(clean_field(rid))
                if rev:
                    row.revisions.add(rev)
    return sorted(rows.values(), key=lambda r: (r.family, _control_num(r.control)))


def summarize_revisions(rows: list[ControlRow]) -> str:
    """Fleet-wide 800-53 revision summary, computed once from the raw revision sets
    rather than by re-collapsing the per-row ``revision`` display strings."""
    seen: set = set()
    for r in rows:
        seen |= r.revisions
    return _format_revisions(seen)


def write_rollup_csv(rows: list[ControlRow], out_path: str) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        # umask covers only a new file; a rollup from an earlier run keeps
        # its old mode, so tighten it before any row is written.
        os.chmod(out_path, 0o600)
        w = csv.writer(fh)
        w.writerow(["control", "family", "nist_800_53_rev", "rules_mapped",
                    "pass", "fail", "not_applicable", "unverified",
                    "implementation_status_suggestion", "draft_justification"])
        for r in rows:
            # Every cell is a regex-normalized control id, a fixed-vocabulary status,
            # an integer, or a template over those -- no raw target text reaches the
            # CSV, so the _csv_safe formula-injection guard is not needed here.
            w.writerow([r.control, r.family, r.revision, len(r.rules),
                        r.passed, r.failed, r.not_applicable, r.unverified,
                        r.status, r.justification])
