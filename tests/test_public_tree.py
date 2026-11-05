"""The public tree carries no private paths, stale status text, or private
example ranges.

Acceptance criteria map:
  AC1 -> test_no_tracked_file_names_a_windows_home_directory
  AC2 -> test_no_public_doc_says_grc3_is_blocked_or_local_only
  AC3 -> test_design_doc_does_not_call_the_thresholds_pending
  AC4 -> test_examples_docs_and_tests_avoid_the_old_private_range,
         test_example_config_scope_is_a_documentation_range
  AC5 -> test_readme_documentation_table_lists_only_product_docs
  review -> test_operator_docs_and_shipped_code_carry_no_tracker_ids
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Built from parts so this file never matches its own searches.
WINDOWS_HOME = re.compile(r"[A-Za-z]:(?:\\{1,2}|/)" + "Users" + r"(?:\\{1,2}|/)",
                          re.IGNORECASE)
OLD_RANGE = re.compile(r"(?<![\d.])10\.0\.(?:1|2)" + r"0\.")
DOC_RANGES = [ipaddress.ip_network(n)
              for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _tracked_files():
    if shutil.which("git") is None or not os.path.isdir(os.path.join(ROOT, ".git")) \
            and not os.path.isfile(os.path.join(ROOT, ".git")):
        pytest.skip("needs a git checkout")
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True,
                         stdout=subprocess.PIPE).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def _text(rel):
    try:
        with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            return fh.read()
    except (UnicodeDecodeError, FileNotFoundError):
        return ""


def test_no_tracked_file_names_a_windows_home_directory():
    hits = [rel for rel in _tracked_files() if WINDOWS_HOME.search(_text(rel))]
    assert hits == []


def test_no_public_doc_says_grc3_is_blocked_or_local_only():
    hits = []
    for rel in _tracked_files():
        if not rel.endswith(".md"):
            continue
        flat = " ".join(_text(rel).split()).lower()
        if re.search(r"grc-3[^.|]*(?:blocked|local[\s-]+only)", flat):
            hits.append(rel)
    assert hits == []


def test_design_doc_does_not_call_the_thresholds_pending():
    text = " ".join(_text("docs/design.md").split()).lower()
    assert not re.search(r"pending[^.]*confirmation", text)
    assert "proposed values" not in text


def test_examples_docs_and_tests_avoid_the_old_private_range():
    hits = []
    for rel in _tracked_files():
        if rel.startswith(("docs/", "tests/")) or rel in (
                "config.example.yaml", "smoketest.py", "README.md",
                "grc-target-setup", "grc_auditor/cli.py", "grc_auditor/config.py"):
            for n, line in enumerate(_text(rel).splitlines(), 1):
                if OLD_RANGE.search(line):
                    hits.append(f"{rel}:{n}")
    assert hits == []


def test_example_config_scope_is_a_documentation_range():
    with open(os.path.join(ROOT, "config.example.yaml"), encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    nets = [ipaddress.ip_network(c) for c in doc["scope"]["cidrs"]]
    nets += [ipaddress.ip_network(e) for e in doc["scope"].get("exclude", [])]
    assert nets
    for net in nets:
        assert any(net.subnet_of(d) for d in DOC_RANGES), net


def _readme_doc_links():
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
        section = fh.read().split("## Documentation", 1)[1].split("\n## ", 1)[0]
    return re.findall(r"^\| \[[^\]]+\]\(([^)]+)\)", section, re.MULTILINE)


def test_readme_documentation_table_lists_only_product_docs():
    links = _readme_doc_links()
    assert "docs/operating.md" in links and "docs/design.md" in links
    process = [l for l in links if "handoffs" in l.lower()
               or os.path.basename(l.rstrip("/")).lower() == "agents.md"]
    assert process == []


def test_handoffs_are_not_in_the_tree():
    assert not [rel for rel in _tracked_files() if rel.startswith("docs/handoffs/")]


def test_operator_docs_and_shipped_code_carry_no_tracker_ids():
    shipped = [rel for rel in _tracked_files()
               if rel.startswith(("grc_auditor/", "bin/"))
               or rel in ("install.sh", "grc-target-setup")]
    hits = []
    for rel in ["README.md", "CONTEXT.md", "docs/operating.md", "docs/design.md",
                "docs/validation.md", "config.example.yaml"] + shipped:
        for n, line in enumerate(_text(rel).splitlines(), 1):
            if re.search(r"\bELI-\d+", line):
                hits.append(f"{rel}:{n}")
    assert hits == []
