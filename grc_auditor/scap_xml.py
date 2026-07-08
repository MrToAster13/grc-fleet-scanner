"""SCAP / XCCDF XML helpers shared by the scan parser and the RMF rollup.

Both walk the same oscap-emitted XML (an ARF wrapping XCCDF results), which is
namespaced and deeply nested. This is the one home for those XML-shape quirks --
starting with the namespace-stripping local name, the primitive both parsers key
their element dispatch on. New SCAP-XML helpers used by more than one module
belong here rather than being copied into each parser.
"""

from __future__ import annotations


def localname(tag: str) -> str:
    """The local element name with any ``{namespace}`` prefix stripped, so a walk
    can match ``rule-result`` / ``result`` regardless of the declared namespace."""
    return tag.rsplit("}", 1)[-1]
