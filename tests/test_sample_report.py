"""ELI-927: the committed sample report matches what the smoketest renders.

Acceptance criteria map:
  AC1, AC2 -> test_committed_sample_matches_the_smoketest_render
  AC3      -> test_readme_links_the_sample_and_says_the_data_is_fabricated
  AC4      -> test_readme_screenshot_is_committed

If the template or the smoketest fixture changes, regenerate the sample with
`python smoketest.py --write-sample` and commit docs/sample/.
"""

from __future__ import annotations

import os
import logging
import re

import smoketest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(ROOT, "docs", "sample", "report.html")


def _readme() -> str:
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
        return fh.read()


def _render_isolated(out_dir: str) -> dict:
    """render_sample calls setup_logging, which turns off propagation and adds
    a stderr and a file handler to the grc_auditor logger. Put the logger back
    afterwards so later tests see it as they would have, and close the file
    handler so Windows can remove the tmp dir."""
    lg = logging.getLogger("grc_auditor")
    saved = (lg.propagate, list(lg.handlers), lg.level)
    try:
        return smoketest.render_sample(out_dir)
    finally:
        for h in lg.handlers:
            if h not in saved[1]:
                h.close()
        lg.propagate, lg.handlers[:] = saved[0], saved[1]
        lg.setLevel(saved[2])


def test_committed_sample_matches_the_smoketest_render(tmp_path):
    paths = _render_isolated(str(tmp_path))
    with open(paths["html"], encoding="utf-8") as fh:
        rendered = fh.read()
    with open(SAMPLE, encoding="utf-8") as fh:
        committed = fh.read()
    assert rendered == committed, (
        "docs/sample/report.html is stale; run `python smoketest.py "
        "--write-sample` and commit the result")


def test_readme_links_the_sample_and_says_the_data_is_fabricated():
    text = _readme()
    assert "docs/sample/report.html" in text
    assert re.search(r"fabricated", text, re.IGNORECASE)


def test_readme_screenshot_is_committed():
    match = re.search(r"\]\((docs/sample/[^)]+\.png)\)", _readme())
    assert match, "README has no screenshot under docs/sample/"
    assert os.path.getsize(os.path.join(ROOT, match.group(1))) > 10_000


# Adversarial review regressions (ELI-927).

def _logger_state():
    lg = logging.getLogger("grc_auditor")
    return lg.propagate, list(lg.handlers), lg.level


def test_rendering_the_sample_leaves_the_logger_as_it_found_it(tmp_path):
    before = _logger_state()
    _render_isolated(str(tmp_path))
    assert _logger_state() == before


def test_readme_documentation_index_lists_the_sample():
    index = _readme().split("## Documentation", 1)[1]
    assert "docs/sample/" in index
