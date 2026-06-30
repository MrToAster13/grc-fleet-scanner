"""Framework cross-walk: CIS / SSG rule -> NIST 800-53 Rev5 + ISO 27001:2022.

PURPOSE
-------
The auditor's compliance verdicts come from OpenSCAP against the CIS Benchmark.
GRC analysts, however, usually have to report against *control frameworks*
(NIST 800-53, ISO 27001) rather than against individual CIS rule ids. This
module provides a lightweight, transparent mapping so the report can show, for
each failing control, which framework control *families* it touches.

SCOPE & LIMITATIONS  (read this before trusting the output)
-----------------------------------------------------------
This mapping is **STATIC, HAND-CURATED, and DELIBERATELY NON-EXHAUSTIVE.**

  * It maps SSG/CIS rule-id *stems* (e.g. ``sshd_disable_root_login``) and, as a
    fallback, broad *topic prefixes* (e.g. ``sshd_``, ``audit_``) to the NIST
    800-53 Rev5 and ISO/IEC 27001:2022 control **families/clauses** they most
    directly relate to. It maps to families, NOT to specific control
    enhancements, and it is one-directional (rule -> framework).
  * It is NOT an authoritative or certified cross-walk. The definitive mappings
    are published by the rule authors (the SCAP Security Guide ships per-rule
    ``references`` to NIST 800-53 inside the datastream/ARF; CIS publishes its
    own mapping documents). When precise, defensible evidence is required,
    use those source references, not this table.
  * Coverage is partial: only common CIS hardening areas are enumerated. A rule
    with no specific or prefix match returns empty lists and is surfaced in the
    report as "unmapped" rather than guessed at.
  * Framework versions targeted: NIST SP 800-53 **Rev. 5** control families and
    ISO/IEC **27001:2022** Annex A control groupings (the 2022 four-theme set:
    Organizational / People / Physical / Technological controls).

The intent is *orientation* for an analyst ("which framework areas is the fleet
weak in?"), not a substitute for the authoritative per-rule SCAP references.
"""

from __future__ import annotations

# Human-readable label for the data so the report can caption it honestly.
CROSSWALK_LABEL = "Indicative CIS -> NIST 800-53 Rev5 / ISO 27001:2022 (non-exhaustive)"

# NIST 800-53 Rev5 family code -> name (the families we reference here).
NIST_FAMILIES: dict[str, str] = {
    "AC": "Access Control",
    "AU": "Audit and Accountability",
    "CM": "Configuration Management",
    "IA": "Identification and Authentication",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "MP": "Media Protection",
    "AT": "Awareness and Training",
}

# ISO/IEC 27001:2022 Annex A control id -> short name (the ones we reference).
ISO_CONTROLS: dict[str, str] = {
    "A.5.15": "Access control",
    "A.5.16": "Identity management",
    "A.5.17": "Authentication information",
    "A.5.18": "Access rights",
    "A.8.2": "Privileged access rights",
    "A.8.3": "Information access restriction",
    "A.8.5": "Secure authentication",
    "A.8.7": "Protection against malware",
    "A.8.8": "Management of technical vulnerabilities",
    "A.8.9": "Configuration management",
    "A.8.15": "Logging",
    "A.8.16": "Monitoring activities",
    "A.8.20": "Networks security",
    "A.8.24": "Use of cryptography",
}


# Most specific first: exact-ish rule-id stems (the suffix after
# ``...content_rule_``). Matched by exact stem OR stem-startswith.
_SPECIFIC: dict[str, dict[str, list]] = {
    "sshd_disable_root_login":      {"nist": ["AC", "IA"], "iso": ["A.8.2", "A.8.5"]},
    "sshd_set_idle_timeout":        {"nist": ["AC"], "iso": ["A.8.15", "A.5.15"]},
    "sshd_disable_empty_passwords": {"nist": ["IA", "AC"], "iso": ["A.8.5", "A.5.17"]},
    "sshd_use_strong_macs":         {"nist": ["SC"], "iso": ["A.8.24"]},
    "sshd_use_strong_ciphers":      {"nist": ["SC"], "iso": ["A.8.24"]},
    "accounts_password":            {"nist": ["IA", "AC"], "iso": ["A.5.17", "A.8.5"]},
    "accounts_passwords":           {"nist": ["IA", "AC"], "iso": ["A.5.17", "A.8.5"]},
    "accounts_maximum_age":         {"nist": ["IA", "AC"], "iso": ["A.5.18", "A.8.5"]},
    "accounts_tmout":               {"nist": ["AC"], "iso": ["A.8.15"]},
    "no_empty_passwords":           {"nist": ["IA"], "iso": ["A.8.5"]},
    "audit_rules_time_change":      {"nist": ["AU"], "iso": ["A.8.15", "A.8.16"]},
    "audit_rules_login":            {"nist": ["AU", "AC"], "iso": ["A.8.15"]},
    "audit_rules_session":          {"nist": ["AU"], "iso": ["A.8.15"]},
    "audit_rules_privileged":       {"nist": ["AU", "AC"], "iso": ["A.8.15", "A.8.2"]},
    "package_aide_installed":       {"nist": ["SI", "CM"], "iso": ["A.8.8"]},
    "aide_":                        {"nist": ["SI"], "iso": ["A.8.8"]},
    "firewall":                     {"nist": ["SC"], "iso": ["A.8.20"]},
    "ufw_":                         {"nist": ["SC"], "iso": ["A.8.20"]},
    "iptables":                     {"nist": ["SC"], "iso": ["A.8.20"]},
    "sysctl_net":                   {"nist": ["SC"], "iso": ["A.8.20"]},
    "mount_option":                 {"nist": ["CM", "AC"], "iso": ["A.8.9", "A.8.3"]},
    "partition_for":                {"nist": ["CM"], "iso": ["A.8.9"]},
    "file_permissions":             {"nist": ["AC", "CM"], "iso": ["A.8.3", "A.8.9"]},
    "file_owner":                   {"nist": ["AC"], "iso": ["A.8.3"]},
    "dir_perms":                    {"nist": ["AC"], "iso": ["A.8.3"]},
    "service_":                     {"nist": ["CM"], "iso": ["A.8.9"]},
    "package_":                     {"nist": ["CM"], "iso": ["A.8.9", "A.8.8"]},
    "kernel_module":                {"nist": ["CM", "SC"], "iso": ["A.8.9"]},
    "grub2":                        {"nist": ["CM", "AC"], "iso": ["A.8.9", "A.5.15"]},
    "bootloader":                   {"nist": ["CM", "AC"], "iso": ["A.8.9", "A.5.15"]},
    "selinux":                      {"nist": ["AC", "SC"], "iso": ["A.8.3"]},
    "apparmor":                     {"nist": ["AC", "SC"], "iso": ["A.8.3"]},
    "banner":                       {"nist": ["AC"], "iso": ["A.5.15"]},
    "chrony":                       {"nist": ["AU"], "iso": ["A.8.15"]},
    "timesync":                     {"nist": ["AU"], "iso": ["A.8.15"]},
    "rsyslog":                      {"nist": ["AU"], "iso": ["A.8.15", "A.8.16"]},
    "journald":                     {"nist": ["AU"], "iso": ["A.8.15", "A.8.16"]},
    "auditd":                       {"nist": ["AU"], "iso": ["A.8.15", "A.8.16"]},
    "umask":                        {"nist": ["AC", "CM"], "iso": ["A.8.3"]},
    "sudo":                         {"nist": ["AC", "IA"], "iso": ["A.8.2"]},
    "cron":                         {"nist": ["AC", "CM"], "iso": ["A.8.3"]},
    "crypto_policy":                {"nist": ["SC"], "iso": ["A.8.24"]},
}

# Longest stem first (precedence). The set is fixed, so sort once at import
# instead of re-sorting on every map_rule call (per-finding, per-host hot path).
_SPECIFIC_KEYS = sorted(_SPECIFIC, key=len, reverse=True)

# Broad topic prefixes used only when no specific stem matched. Keep coarse.
_PREFIX: list = [
    ("sshd_",     {"nist": ["AC", "SC"], "iso": ["A.8.5", "A.8.20"]}),
    ("ssh_",      {"nist": ["AC", "SC"], "iso": ["A.8.5", "A.8.20"]}),
    ("accounts_", {"nist": ["IA", "AC"], "iso": ["A.5.16", "A.8.5"]}),
    ("audit_",    {"nist": ["AU"], "iso": ["A.8.15", "A.8.16"]}),
    ("auditd_",   {"nist": ["AU"], "iso": ["A.8.15", "A.8.16"]}),
    ("pam_",      {"nist": ["IA", "AC"], "iso": ["A.8.5", "A.5.17"]}),
    ("network_",  {"nist": ["SC"], "iso": ["A.8.20"]}),
    ("net_",      {"nist": ["SC"], "iso": ["A.8.20"]}),
    ("file_",     {"nist": ["AC", "CM"], "iso": ["A.8.3"]}),
    ("mount_",    {"nist": ["CM", "AC"], "iso": ["A.8.9"]}),
    ("partition", {"nist": ["CM"], "iso": ["A.8.9"]}),
    ("kernel",    {"nist": ["CM", "SC"], "iso": ["A.8.9"]}),
    ("package",   {"nist": ["CM"], "iso": ["A.8.9", "A.8.8"]}),
    ("service",   {"nist": ["CM"], "iso": ["A.8.9"]}),
    ("disable",   {"nist": ["CM"], "iso": ["A.8.9"]}),
]


def rule_stem(rule_id: str) -> str:
    """Reduce a full SSG rule id to its bare stem.

    ``xccdf_org.ssgproject.content_rule_sshd_disable_root_login``
        -> ``sshd_disable_root_login``

    Tolerates ids that are already stems or use a different marker.
    """
    if not rule_id:
        return ""
    rid = rule_id.strip()
    marker = "content_rule_"
    if marker in rid:
        rid = rid.split(marker, 1)[1]
    elif rid.startswith("xccdf_"):
        # Unknown-shaped xccdf id: take the trailing dotted segment.
        rid = rid.rsplit(".", 1)[-1]
    return rid


def map_rule(rule_id: str) -> dict:
    """Map a CIS/SSG rule id to indicative framework control families.

    Returns ``{"nist": [...], "iso": [...]}`` of control-family codes. Both
    lists are de-duplicated and order-stable. An unmapped rule returns empty
    lists (callers should treat that as "unmapped", not "compliant").

    NON-EXHAUSTIVE / indicative only -- see module docstring.
    """
    stem = rule_stem(rule_id)
    if not stem:
        return {"nist": [], "iso": []}

    # 1) Specific stems (exact or startswith), longest key first for precedence.
    for key in _SPECIFIC_KEYS:
        if stem == key or stem.startswith(key):
            m = _SPECIFIC[key]
            return {"nist": list(m["nist"]), "iso": list(m["iso"])}

    # 2) Coarse topic prefixes as a fallback.
    for prefix, m in _PREFIX:
        if stem.startswith(prefix):
            return {"nist": list(m["nist"]), "iso": list(m["iso"])}

    return {"nist": [], "iso": []}


def describe_nist(code: str) -> str:
    """Family name for a NIST code, or the code itself if unknown."""
    return NIST_FAMILIES.get(code, code)


def describe_iso(code: str) -> str:
    """Short name for an ISO 27001:2022 control, or the code if unknown."""
    return ISO_CONTROLS.get(code, code)


def map_rule_verbose(rule_id: str) -> dict:
    """Like :func:`map_rule` but with human labels, for report rendering.

    Returns::

        {"nist": [{"code": "AC", "name": "Access Control"}, ...],
         "iso":  [{"code": "A.8.2", "name": "Privileged access rights"}, ...],
         "mapped": bool}
    """
    m = map_rule(rule_id)
    return {
        "nist": [{"code": c, "name": describe_nist(c)} for c in m["nist"]],
        "iso": [{"code": c, "name": describe_iso(c)} for c in m["iso"]],
        "mapped": bool(m["nist"] or m["iso"]),
    }
