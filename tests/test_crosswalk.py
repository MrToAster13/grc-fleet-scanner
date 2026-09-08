"""Tests for grc_auditor.crosswalk: CIS/SSG rule id -> NIST/ISO orientation.

The module is a pure lookup table with two matching passes (specific stems,
then coarse prefixes). These tests pin the parts that would break silently:
stem extraction, match precedence, the "unmapped" contract, and the fact that
callers cannot corrupt the shared table through a returned list.
"""

from __future__ import annotations

import pytest

from grc_auditor import crosswalk


# --------------------------------------------------------------------------
# rule_stem
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "rule_id, expected",
    [
        # The ordinary case: a full SSG rule id.
        (
            "xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
            "sshd_disable_root_login",
        ),
        # Already a bare stem: passed through untouched.
        ("sshd_disable_root_login", "sshd_disable_root_login"),
        # An xccdf id with no content_rule_ marker: trailing dotted segment.
        ("xccdf_org.ssgproject.rule_something_odd", "rule_something_odd"),
        # Surrounding whitespace is stripped before anything else.
        ("  sshd_use_strong_macs  ", "sshd_use_strong_macs"),
        ("", ""),
    ],
)
def test_rule_stem_extracts_the_stem(rule_id, expected):
    assert crosswalk.rule_stem(rule_id) == expected


def test_rule_stem_splits_on_the_first_marker_only():
    """A stem that itself contains the marker must not be truncated twice."""
    rid = "xccdf_org.ssgproject.content_rule_content_rule_weird"
    assert crosswalk.rule_stem(rid) == "content_rule_weird"


# --------------------------------------------------------------------------
# map_rule: matching and precedence
# --------------------------------------------------------------------------

def test_map_rule_matches_an_exact_specific_stem():
    m = crosswalk.map_rule(
        "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
    )
    assert m == {"nist": ["AC", "IA"], "iso": ["A.8.2", "A.8.5"]}


def test_map_rule_matches_a_specific_stem_by_prefix():
    """`sshd_use_strong_macs` is a key; a longer real rule id still hits it."""
    m = crosswalk.map_rule("sshd_use_strong_macs_and_kex")
    assert m == {"nist": ["SC"], "iso": ["A.8.24"]}


def test_longer_specific_key_wins_over_a_shorter_one():
    """`package_aide_installed` and `package_` both match; the longer wins.

    This is the whole reason _SPECIFIC_KEYS is sorted by length. If that sort
    is dropped or reversed, dict order decides and this assertion breaks.
    """
    m = crosswalk.map_rule("package_aide_installed")
    assert m == {"nist": ["SI", "CM"], "iso": ["A.8.8"]}
    # ...and is distinguishable from what the generic `package_` key gives.
    assert m != crosswalk.map_rule("package_openssh_server_installed")


def test_specific_stem_wins_over_the_coarse_prefix_pass():
    """`file_permissions` (specific) beats the `file_` prefix fallback."""
    specific = crosswalk.map_rule("file_permissions_etc_shadow")
    fallback = crosswalk.map_rule("file_groupownership_etc_passwd")
    assert specific == {"nist": ["AC", "CM"], "iso": ["A.8.3", "A.8.9"]}
    assert fallback == {"nist": ["AC", "CM"], "iso": ["A.8.3"]}
    assert specific != fallback


def test_map_rule_falls_back_to_a_coarse_prefix():
    """No specific stem matches, but the `pam_` prefix does."""
    m = crosswalk.map_rule("pam_unix_something_not_enumerated")
    assert m == {"nist": ["IA", "AC"], "iso": ["A.8.5", "A.5.17"]}


@pytest.mark.parametrize(
    "rule_id",
    [
        "zzz_totally_unknown_rule",
        "",
        "xccdf_org.ssgproject.content_rule_",
    ],
)
def test_unmapped_rules_return_empty_lists(rule_id):
    """Unmapped must be empty, never a guess. The report renders this as
    'unmapped'; a silent wrong mapping would be worse than none."""
    assert crosswalk.map_rule(rule_id) == {"nist": [], "iso": []}


def test_map_rule_returns_copies_the_caller_cannot_corrupt():
    """The table is module-level state shared across every finding in a run.

    map_rule copies its lists on the way out. If that copy is ever dropped,
    one caller mutating a result would poison the mapping for the rest of the
    report, and nothing else in the suite would notice.
    """
    first = crosswalk.map_rule("sshd_disable_root_login")
    first["nist"].append("CORRUPTED")
    second = crosswalk.map_rule("sshd_disable_root_login")
    assert "CORRUPTED" not in second["nist"]
    assert second["nist"] == ["AC", "IA"]


# --------------------------------------------------------------------------
# describe_* label lookups
# --------------------------------------------------------------------------

def test_describe_nist_known_and_unknown():
    assert crosswalk.describe_nist("AC") == "Access Control"
    # An unknown code degrades to itself rather than raising or returning "".
    assert crosswalk.describe_nist("XX") == "XX"


def test_describe_iso_known_and_unknown():
    assert crosswalk.describe_iso("A.8.2") == "Privileged access rights"
    assert crosswalk.describe_iso("A.99.9") == "A.99.9"


# --------------------------------------------------------------------------
# map_rule_verbose: the shape report.py renders
# --------------------------------------------------------------------------

def test_map_rule_verbose_labels_a_mapped_rule():
    v = crosswalk.map_rule_verbose(
        "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
    )
    assert v["mapped"] is True
    assert v["nist"] == [
        {"code": "AC", "name": "Access Control"},
        {"code": "IA", "name": "Identification and Authentication"},
    ]
    assert v["iso"] == [
        {"code": "A.8.2", "name": "Privileged access rights"},
        {"code": "A.8.5", "name": "Secure authentication"},
    ]


def test_map_rule_verbose_marks_an_unmapped_rule():
    v = crosswalk.map_rule_verbose("zzz_totally_unknown_rule")
    assert v == {"nist": [], "iso": [], "mapped": False}


# --------------------------------------------------------------------------
# Table integrity: catches a typo in the data, which is how this file rots
# --------------------------------------------------------------------------

def _all_table_entries():
    for key, m in crosswalk._SPECIFIC.items():
        yield key, m
    for prefix, m in crosswalk._PREFIX:
        yield prefix, m


def test_every_referenced_nist_code_has_a_family_name():
    for key, m in _all_table_entries():
        for code in m["nist"]:
            assert code in crosswalk.NIST_FAMILIES, (
                f"{key!r} maps to NIST {code!r}, which has no name in "
                f"NIST_FAMILIES: the report would print a bare code"
            )


def test_every_referenced_iso_code_has_a_control_name():
    for key, m in _all_table_entries():
        for code in m["iso"]:
            assert code in crosswalk.ISO_CONTROLS, (
                f"{key!r} maps to ISO {code!r}, which has no name in "
                f"ISO_CONTROLS: the report would print a bare code"
            )


def test_no_table_entry_maps_to_nothing():
    """An entry with two empty lists is indistinguishable from unmapped and
    is almost certainly an editing mistake."""
    for key, m in _all_table_entries():
        assert m["nist"] or m["iso"], f"{key!r} maps to nothing at all"


def test_specific_keys_are_sorted_longest_first():
    lengths = [len(k) for k in crosswalk._SPECIFIC_KEYS]
    assert lengths == sorted(lengths, reverse=True)
    assert set(crosswalk._SPECIFIC_KEYS) == set(crosswalk._SPECIFIC)


def test_label_names_the_frameworks_and_admits_the_limitation():
    """report.py captions the column with this string. It must keep saying
    the mapping is indicative, or the report overstates its own authority."""
    label = crosswalk.CROSSWALK_LABEL
    assert "800-53" in label
    assert "27001" in label
    assert "non-exhaustive" in label.lower()
