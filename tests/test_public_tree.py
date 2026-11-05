"""The public tree carries no private paths, stale status text, or private
example ranges.

Acceptance criteria map:
  AC1 -> test_no_tracked_file_names_a_windows_home_directory
  AC2 -> test_no_public_doc_says_grc3_is_blocked_or_local_only
  AC3 -> test_design_doc_does_not_call_the_thresholds_pending
  AC4 -> test_no_tracked_text_file_holds_the_old_private_range,
         test_example_config_scope_is_a_documentation_range
  AC5 -> test_readme_documentation_table_lists_only_product_docs
  review -> test_no_tracked_text_file_outside_the_exclusions_carries_a_tracker_id,
            test_every_exclusion_still_matches_a_tracked_file

Every tracked text file is searched, so a new file cannot slip past a path
allowlist. The tmp_repo tests prove the search on a scratch checkout: files
outside the old allowlist, a file with a NUL byte, a cp1252 file, and the
tracker-id exclusions.
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
TRACKER_ID = re.compile(r"\bEL" + r"I-\d+")
DOC_RANGES = [ipaddress.ip_network(n)
              for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _tracked_files(root=ROOT):
    if shutil.which("git") is None or not os.path.exists(os.path.join(root, ".git")):
        pytest.skip("needs a git checkout")
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True,
                         stdout=subprocess.PIPE).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def _read(path):
    """Return the file as text, or None if it is missing or binary.

    A NUL byte marks a file as binary. Anything else decodes with
    errors="replace", so a cp1252 script is still searched.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except (FileNotFoundError, IsADirectoryError):
        return None
    if b"\0" in data:
        return None
    return data.decode("utf-8", errors="replace")


def _text(rel):
    return _read(os.path.join(ROOT, rel)) or ""


def _tracked_text(root=ROOT):
    for rel in _tracked_files(root):
        text = _read(os.path.join(root, rel))
        if text is not None:
            yield rel, text


def _line_hits(pattern, root=ROOT, exclude=None):
    skip = tuple(exclude or ())
    hits = []
    for rel, text in _tracked_text(root):
        if rel.startswith(skip):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                hits.append(f"{rel}:{n}")
    return sorted(hits)


def _stale_prefixes(prefixes, root=ROOT):
    tracked = _tracked_files(root)
    return [p for p in prefixes if not any(rel.startswith(p) for rel in tracked)]


TRACKER_ID_EXCLUSIONS = {
    "tests/": "test docstrings map each acceptance criterion to the ticket that asked for it",
    ".factory/log/": "decision logs are named after the ticket they record and cite it",
    "CHANGELOG.md": "entries cite the ticket that shipped them",
}


def test_no_tracked_file_names_a_windows_home_directory():
    hits = [rel for rel, text in _tracked_text() if WINDOWS_HOME.search(text)]
    assert hits == []


def test_no_public_doc_says_grc3_is_blocked_or_local_only():
    hits = []
    for rel, text in _tracked_text():
        if not rel.endswith(".md"):
            continue
        flat = " ".join(text.split()).lower()
        if re.search(r"grc-3[^.|]*(?:blocked|local[\s-]+only)", flat):
            hits.append(rel)
    assert hits == []


def test_design_doc_does_not_call_the_thresholds_pending():
    text = " ".join(_text("docs/design.md").split()).lower()
    assert not re.search(r"pending[^.]*confirmation", text)
    assert "proposed values" not in text


def test_no_tracked_text_file_holds_the_old_private_range():
    assert _line_hits(OLD_RANGE) == []


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


def test_no_tracked_text_file_outside_the_exclusions_carries_a_tracker_id():
    assert _line_hits(TRACKER_ID, exclude=TRACKER_ID_EXCLUSIONS) == []


def test_every_exclusion_still_matches_a_tracked_file():
    assert _stale_prefixes(TRACKER_ID_EXCLUSIONS) == []


@pytest.fixture
def tmp_repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("needs git")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)

    def add(rel, data):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        subprocess.run(["git", "add", "--", rel], cwd=str(tmp_path), check=True)

    add.root = str(tmp_path)
    return add


PRIVATE_IP = ("10.0.1" + "0.7").encode("ascii")
TRACKER_ID_TEXT = ("EL" + "I-1").encode("ascii")


def test_range_guard_reports_files_outside_the_old_allowlist(tmp_repo):
    tmp_repo("grc_auditor/new_module.py", b"x = 1\nHOST = '" + PRIVATE_IP + b"'\n")
    tmp_repo("bin/new-tool", b"#!/bin/sh\n\nping " + PRIVATE_IP + b"\n")
    tmp_repo("grc_auditor/clean.py", b"HOST = '192.0.2.7'\n")
    assert _line_hits(OLD_RANGE, root=tmp_repo.root) == [
        "bin/new-tool:3", "grc_auditor/new_module.py:2"]


def test_range_guard_skips_a_file_holding_a_nul_byte(tmp_repo):
    tmp_repo("docs/diagram.png", b"PNG\x00\x01" + PRIVATE_IP + b"\n")
    tmp_repo("docs/notes.txt", PRIVATE_IP + b"\n")
    assert _line_hits(OLD_RANGE, root=tmp_repo.root) == ["docs/notes.txt:1"]


def test_range_guard_reads_text_that_is_not_utf8(tmp_repo):
    tmp_repo("install.ps1", b"# caf\xe9\n$h = '" + PRIVATE_IP + b"'\n")
    tmp_repo("docs/legacy.txt", b"r\xe9sum\xe9 " + PRIVATE_IP + b"\n")
    assert _line_hits(OLD_RANGE, root=tmp_repo.root) == [
        "docs/legacy.txt:1", "install.ps1:2"]


def test_tracker_id_guard_reports_docs_and_skips_exclusions(tmp_repo):
    tmp_repo("docs/new.md", b"# New\n\nSee " + TRACKER_ID_TEXT + b".\n")
    tmp_repo("tests/x.py", b'"""AC1 from ' + TRACKER_ID_TEXT + b'."""\n')
    tmp_repo("CHANGELOG.md", b"- add x (" + TRACKER_ID_TEXT + b")\n")
    hits = _line_hits(TRACKER_ID, root=tmp_repo.root, exclude=TRACKER_ID_EXCLUSIONS)
    assert hits == ["docs/new.md:3"]


def test_stale_prefixes_names_an_exclusion_with_no_tracked_file(tmp_repo):
    tmp_repo("tests/x.py", b"pass\n")
    tmp_repo("CHANGELOG.md", b"# Changelog\n")
    assert _stale_prefixes(["tests/", "CHANGELOG.md", "gone/"],
                           root=tmp_repo.root) == ["gone/"]
