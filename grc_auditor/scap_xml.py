"""The one reader of SCAP evidence, shared by the scan parser and the RMF rollup.

Both consume the same oscap-emitted XML (an XCCDF results file, or an ARF
wrapping one), which is namespaced, deeply nested and fully controlled by the
target. ``read_results`` is the only code that opens and walks it. It parses
safely, refuses an oversized file, cleans every target-supplied string, and
resolves a repeated rule to one rule outcome. ``scan`` maps the result onto a
``ScanResult`` and ``rmf`` onto ``ControlRow``s, so the two cannot disagree on
what the evidence says.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

from .models import (
    OUT_OF_SCOPE_VERDICTS, UNDETERMINED_VERDICTS, VERDICT_FAIL,
    VERDICT_NOT_APPLICABLE, VERDICT_PASS,
)
from .remote import MAX_EVIDENCE_BYTES

try:
    from defusedxml.ElementTree import parse as _safe_xml_parse
    from defusedxml.common import DefusedXmlException
except ImportError as exc:  # pragma: no cover - dependency guard
    raise SystemExit(
        "defusedxml is required. Install dependencies: pip install -r requirements.txt"
    ) from exc


# Refuse to parse a file larger than what remote.get_file will pull, so an
# evidence file on disk is bounded the same way whichever command reads it.
MAX_RESULTS_BYTES = MAX_EVIDENCE_BYTES

# Cap on any single target-supplied string (rule id / title / severity) before it
# enters the report model. A real CIS rule id/title is well under this.
MAX_FIELD_LEN = 1024

# SSG fix text kept per failed rule. Of the 563 shell fixes in the v0.1.74
# Ubuntu 22.04 datastream, 15 exceed this; the retained results.xml keeps them whole.
_MAX_FIX_LEN = 16384
_FIX_TRUNCATED = "\n[truncated; the full fix is in this host's retained results.xml]"
# The longest SSG v0.1.74 Ubuntu 22.04 rationale is 1138 chars; 3 exceed 1024.
_MAX_RATIONALE_LEN = 4096
_FIX_SYSTEMS = ("urn:xccdf:fix:script:sh", "urn:xccdf:fix:script:ansible")

# When the evidence repeats an idref (a merged or multi-TestResult file, or a
# hostile target padding its counts), keep the most decision-critical verdict
# instead of last-write-wins or counting each copy. Rank high-to-low: a fail,
# then an undetermined verdict (error/notchecked/unknown -- incomplete coverage
# must not read as a pass), then an empty or unrecognized verdict (see
# result_rank), then pass, then not-applicable, then out of scope. A later pass
# can't bury an earlier fail or error, an empty <result/> can't bury an error
# the scan would count, an out-of-scope marker can't bury a real verdict, and
# five copies of a pass count as one.
RESULT_RANK = {
    VERDICT_FAIL: 6,
    **{v: 5 for v in UNDETERMINED_VERDICTS},
    VERDICT_PASS: 3,
    VERDICT_NOT_APPLICABLE: 2,
    **{v: 1 for v in OUT_OF_SCOPE_VERDICTS},
}


class ScapXmlError(ValueError):
    """The evidence file is unreadable, oversized, hostile or malformed."""


@dataclass
class RuleOutcome:
    """One rule's verdict, lowercased, the severity the target declared, and
    the rule id cleaned for display (``unknown`` when the idref is missing)."""

    verdict: str
    severity: str = "unknown"
    rule_id: str = "unknown"


@dataclass
class RuleInfo:
    """What the benchmark says about one rule.

    ``references`` holds every ``(text, href)`` reference pair. ``rationale``
    and ``fix_text`` are read only for rules whose outcome is a fail, since only
    those are shown; the fix is display text and nothing runs it."""

    title: Optional[str] = None
    rationale: Optional[str] = None
    fix_text: Optional[str] = None
    references: list = field(default_factory=list)


@dataclass
class ScapResults:
    """Everything the consumers need from one evidence file."""

    empty: bool = False
    # Both dicts are keyed by the raw id, so two ids that clean to the same text
    # stay two rules and outcomes join rules exactly. Each rule-result with no
    # idref gets its own key that no Rule id can match, so nameless results are
    # never merged.
    outcomes: dict = field(default_factory=dict)   # idref -> RuleOutcome
    rules: dict = field(default_factory=dict)      # rule id -> RuleInfo
    score: Optional[float] = None
    benchmark_version: Optional[str] = None


def localname(tag: str) -> str:
    """The local element name with any ``{namespace}`` prefix stripped, so a walk
    can match ``rule-result`` / ``result`` regardless of the declared namespace."""
    return tag.rsplit("}", 1)[-1]


def result_rank(verdict: str) -> float:
    # An empty or unrecognized verdict ranks above a pass, so a novel marker is
    # never overwritten by a pass, and below a known undetermined verdict, so it
    # never hides an error the scan would count. An empty verdict carries the
    # least information of the two, so it ranks just under an unrecognized one
    # and the kept copy does not depend on document order.
    if verdict == "":
        return 3.5
    return RESULT_RANK.get(verdict, 4)


def clean_field(text: Optional[str], maxlen: int = MAX_FIELD_LEN) -> Optional[str]:
    """Bound a target-supplied string: drop control characters and cap length.

    A hostile results.xml fully controls rule ids/titles. HTML-escaping and
    CSV-safety happen at render time; this is defense in depth so such a string
    cannot smuggle layout-breaking control bytes or bloat the report. ``None``
    stays ``None``.
    """
    if text is None:
        return None
    return "".join(ch for ch in str(text) if ch.isprintable())[:maxlen]


def _clean_fix(text: str) -> Optional[str]:
    """Like ``clean_field`` but keeps newlines and tabs, since a fix is a script."""
    text = "".join(ch for ch in text if ch.isprintable() or ch in "\n\t").strip()
    if not text:
        return None
    if len(text) > _MAX_FIX_LEN:
        text = text[:_MAX_FIX_LEN] + _FIX_TRUNCATED
    return text


def _xml_text(el: ET.Element) -> str:
    """All text under ``el``, with each XCCDF ``<sub idref>`` variable shown as
    ``[value: idref]``: the value is set by the profile, not in the Rule."""
    # An explicit stack, not recursion: a hostile file can nest thousands deep.
    parts: list[str] = []
    stack: list = [el]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            parts.append(node)
            continue
        if node is not el and localname(node.tag) == "sub":
            parts.append("[value: %s]" % node.get("idref", ""))
        else:
            parts.append(node.text or "")
            for child in reversed(node):
                stack.append(child.tail or "")
                stack.append(child)
    return "".join(parts)


def _parse(path: str) -> Optional[ET.Element]:
    """The document root, or None for an empty file. Raises ScapXmlError."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise ScapXmlError(f"results file not accessible: {path} ({exc})") from exc
    if size == 0:
        return None
    if size > MAX_RESULTS_BYTES:
        raise ScapXmlError(
            f"results file too large to parse safely: {path} ({size} bytes)"
        )
    try:
        return _safe_xml_parse(path).getroot()
    except DefusedXmlException as exc:
        raise ScapXmlError(
            f"hostile XCCDF results (entity/DTD/external-ref blocked): {path} ({exc})"
        ) from exc
    except ET.ParseError as exc:
        raise ScapXmlError(f"malformed XCCDF results: {path} ({exc})") from exc
    except OSError as exc:
        raise ScapXmlError(f"results file not readable: {path} ({exc})") from exc


def _read_outcome(el: ET.Element) -> Optional[str]:
    """The lowercased verdict, ``""`` for an empty ``<result/>``, or None when
    the rule-result has no ``<result>`` child at all."""
    for child in el:
        if localname(child.tag) == "result":
            return (child.text or "").strip().lower()
    return None


def _read_rule(els: list, with_text: bool) -> RuleInfo:
    """One RuleInfo from every ``<Rule>`` element that shares an id: the first
    title, rationale and fix win, and references from all of them are kept."""
    info = RuleInfo()
    fixes: dict[str, str] = {}
    for child in (c for el in els for c in el):
        name = localname(child.tag)
        if name == "title" and info.title is None:
            info.title = clean_field((child.text or "").strip()) or ""
        elif name == "reference":
            info.references.append(((child.text or "").strip(), child.get("href") or ""))
        elif not with_text:
            continue
        elif name == "rationale" and info.rationale is None:
            info.rationale = clean_field(" ".join(_xml_text(child).split()),
                                         _MAX_RATIONALE_LEN) or None
        elif name == "fix":
            fixes.setdefault(child.get("system", ""), _xml_text(child))
    for system in _FIX_SYSTEMS:
        if system in fixes:
            info.fix_text = _clean_fix(fixes[system])
            break
    return info


def read_results(path: str) -> ScapResults:
    """Read one SCAP evidence file (XCCDF results or ARF).

    Matching is by element local name, so any XCCDF namespace or version works
    and a results-only file or a full benchmark+results file both read:

      * each ``<rule-result idref severity>`` with a child ``<result>`` gives a
        rule outcome (an empty ``<result/>`` reads as ``""``); a missing idref
        or severity shows as ``unknown``; a repeated idref keeps the verdict
        ranked highest by ``result_rank``, with that copy's severity;
      * the first ``<score>`` that parses as a number gives ``score``;
      * the first non-empty ``<version>`` gives ``benchmark_version``;
      * each ``<Rule id>`` gives a ``RuleInfo``.

    ``outcomes`` and ``rules`` are keyed by the raw id; ``RuleOutcome.rule_id``
    is the cleaned id to show.

    An empty file returns ``ScapResults(empty=True)``. An unreadable, oversized,
    hostile or malformed file raises ``ScapXmlError``.
    """
    root = _parse(path)
    if root is None:
        return ScapResults(empty=True)

    res = ScapResults()
    rule_els: dict[str, list] = {}
    for el in root.iter():
        name = localname(el.tag)
        if name == "rule-result":
            verdict = _read_outcome(el)
            if verdict is None:
                continue
            idref = el.get("idref")
            if not idref:
                # NUL cannot appear in an XML attribute, so this key is unique
                # and never joins a Rule.
                idref = "\0%d" % len(res.outcomes)
                shown = "unknown"
            else:
                shown = clean_field(idref) or "unknown"
            prev = res.outcomes.get(idref)
            if prev is None or result_rank(verdict) > result_rank(prev.verdict):
                res.outcomes[idref] = RuleOutcome(
                    verdict, clean_field(el.get("severity")) or "unknown", shown)
        elif name == "Rule":
            rid = el.get("id")
            if rid:
                rule_els.setdefault(rid, []).append(el)
        elif name == "score" and res.score is None:
            try:
                res.score = float((el.text or "").strip())
            except (TypeError, ValueError):
                pass
        elif name == "version" and res.benchmark_version is None:
            res.benchmark_version = (el.text or "").strip() or None

    # Rules are read after the walk because a Rule usually precedes its result,
    # and its rationale and fix are wanted only when the outcome is a fail.
    for rid, els in rule_els.items():
        outcome = res.outcomes.get(rid)
        res.rules[rid] = _read_rule(els, outcome is not None and outcome.verdict == VERDICT_FAIL)
    return res
