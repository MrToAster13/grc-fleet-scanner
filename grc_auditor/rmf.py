"""RMF / NIST 800-53 control rollup from OpenSCAP ARF evidence.

Bridges a scan run to the RMF SSP: for every 800-53 control the CIS benchmark's
rules map to, report how many underlying checks pass vs fail and a suggested
implementation status, so an ISSO can fill the DSS SecCtrl tab from real
evidence instead of by hand.

The source of truth is the datastream's OWN per-rule 800-53 references embedded
in the ARF (authoritative), NOT the indicative family cross-walk in
`crosswalk.py`. `crosswalk.py` is for orienting the HTML report; this is for
control-by-control evidence you can defend.

Honesty, stated in the output (never hidden):
  * Ubuntu SSG content maps rules to 800-53 **Rev 4**; a DoD SSP baseline is
    Rev 5. Most controls carry over 1:1, but the revision is reported.
  * "Implemented"/"Planned" are SUGGESTIONS from automated config checks, not an
    authorization decision -- the ISSO still writes the control narrative.
  * These are CIS-profile results, not a DISA STIG.
"""

from __future__ import annotations

import csv
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

try:
    from defusedxml.ElementTree import parse as _safe_xml_parse
    from defusedxml.common import DefusedXmlException
except ImportError as exc:  # pragma: no cover - dependency guard
    raise SystemExit(
        "defusedxml is required. Install dependencies: pip install -r requirements.txt"
    ) from exc


class RmfError(Exception):
    """A run's ARF evidence could not be parsed into a control rollup."""


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


# A control reference looks like "AC-17", "AC-17(2)", "CM-6(a)", "AU-9(3).1".
# We roll up to the base control (family + number); the enhancement is dropped
# because the SSP row set is usually managed at the control level.
_CONTROL_RE = re.compile(r"^\s*([A-Z]{2})-(\d+)")

_PASS, _FAIL = "pass", "fail"


def _base_control(text: str) -> Optional[str]:
    m = _CONTROL_RE.match(text or "")
    return f"{m.group(1)}-{m.group(2)}" if m else None


def _control_num(control: str) -> int:
    m = re.search(r"-(\d+)", control)
    return int(m.group(1)) if m else 0


@dataclass
class ControlRow:
    """Aggregated pass/fail of the CIS checks that map to one 800-53 control."""

    control: str
    family: str
    revision: str
    passed: int = 0
    failed: int = 0
    other: int = 0                       # notchecked / notapplicable / error / informational
    rules: set = field(default_factory=set)

    @property
    def total(self) -> int:
        return self.passed + self.failed + self.other

    @property
    def status(self) -> str:
        """Suggested Implementation Status for the DSS SecCtrl tab."""
        if self.failed > 0:
            return "Planned"          # at least one check fails -> remediate + POA&M
        if self.passed > 0:
            return "Implemented"      # every evaluated check passes
        return "Not Assessed"         # only not-checked / not-applicable

    @property
    def justification(self) -> str:
        """A draft Explanation/Justification sentence, grounded in the counts."""
        if self.failed > 0:
            return (f"{self.passed}/{self.passed + self.failed} CIS check(s) mapping to "
                    f"{self.control} pass; {self.failed} fail (tracked in POA&M). "
                    f"Automated OpenSCAP CIS scan.")
        if self.passed > 0:
            return (f"All {self.passed} CIS check(s) mapping to {self.control} pass. "
                    f"Automated OpenSCAP CIS scan; evidence retained (ARF).")
        return (f"No CIS check mapping to {self.control} produced a pass/fail verdict "
                f"(not checked / not applicable in this profile).")


def _detect_revision(href: str) -> Optional[str]:
    h = href.lower()
    if "800-53r5" in h:
        return "Rev 5"
    if "800-53r4" in h:
        return "Rev 4"
    return None


def _parse_one(path: str):
    """Return (rule_id -> {control refs}, rule_id -> result, detected revision)."""
    try:
        root = _safe_xml_parse(path).getroot()
    except (DefusedXmlException, ET.ParseError, OSError) as exc:
        raise RmfError(f"cannot parse ARF {path}: {exc}") from exc

    rule_controls: dict[str, set] = {}
    rule_results: dict[str, str] = {}
    revision: Optional[str] = None

    for el in root.iter():
        name = _localname(el.tag)
        if name == "Rule":
            rid = el.get("id")
            if not rid:
                continue
            for child in el:
                if _localname(child.tag) != "reference":
                    continue
                href = child.get("href") or ""
                if "800-53" not in href:
                    continue
                text = (child.text or "").strip()
                if _base_control(text) is None:
                    continue  # e.g. the "nist" publisher reference -- not a control
                rule_controls.setdefault(rid, set()).add(text)
                revision = revision or _detect_revision(href)
        elif name == "rule-result":
            idref = el.get("idref")
            if not idref:
                continue
            for child in el:
                if _localname(child.tag) == "result":
                    rule_results[idref] = (child.text or "").strip().lower()
                    break

    return rule_controls, rule_results, revision


def rollup_from_arf(paths) -> list[ControlRow]:
    """Aggregate CIS rule pass/fail by 800-53 control across one or more ARF files.

    Merging multiple ARFs gives a fleet view: a control reads ``Implemented``
    only if every mapped check passes on every host (one failing host makes it
    ``Planned``). Pass a single ARF for a per-host rollup.
    """
    rows: dict[str, ControlRow] = {}
    revision = "Rev 4"  # SSG-Ubuntu default; overridden if the href says otherwise
    for path in paths:
        rule_controls, rule_results, rev = _parse_one(path)
        if rev:
            revision = rev
        for rid, controls in rule_controls.items():
            result = rule_results.get(rid)
            if result is None:
                continue  # a Rule with no evaluated result this run -> skip
            for ctrl in controls:
                base = _base_control(ctrl)
                if base is None:
                    continue
                row = rows.get(base)
                if row is None:
                    row = ControlRow(control=base, family=base.split("-", 1)[0],
                                     revision=revision)
                    rows[base] = row
                if result == _PASS:
                    row.passed += 1
                elif result == _FAIL:
                    row.failed += 1
                else:
                    row.other += 1
                row.rules.add(rid)

    for row in rows.values():
        row.revision = revision
    return sorted(rows.values(), key=lambda r: (r.family, _control_num(r.control)))


def write_rollup_csv(rows: list[ControlRow], out_path: str) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["control", "family", "nist_800_53_rev", "rules_total",
                    "pass", "fail", "other", "implementation_status_suggestion",
                    "draft_justification"])
        for r in rows:
            w.writerow([r.control, r.family, r.revision, r.total, r.passed,
                        r.failed, r.other, r.status, r.justification])
