"""Repo metadata matches what ships: the CLI's program name, the CI runner
pins, the split between run-host and test dependencies, and the tests/README.md
index (ELI-1067).

Acceptance criteria map:
  item 1 -> test_cli_names_the_real_entry_point
  item 2 -> test_every_ci_job_runs_on_a_pinned_runner
  item 3 -> test_run_host_requirements_carry_no_test_tools,
            test_dev_requirements_add_pytest_to_the_run_host_set,
            test_ci_installs_the_dev_requirements
  item 5 -> test_every_test_module_has_a_readme_row
"""

from __future__ import annotations

import glob
import os
import re

import pytest
import yaml

from grc_auditor import __version__
from grc_auditor.cli import build_parser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _requirement_name(line: str) -> str:
    return re.match(r"[A-Za-z0-9._-]*", line).group(0).lower()


def _requirement_lines(rel: str) -> list:
    lines = []
    for raw in _read(rel).splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    return lines


def _workflow() -> dict:
    return yaml.safe_load(_read(".github/workflows/tests.yml"))


def test_cli_names_the_real_entry_point(capsys):
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--version"])
    assert capsys.readouterr().out.strip() == f"python -m grc_auditor {__version__}"


def test_every_ci_job_runs_on_a_pinned_runner():
    runners = {name: job["runs-on"] for name, job in _workflow()["jobs"].items()}
    assert runners, "no jobs in tests.yml"
    for name, runner in runners.items():
        assert re.fullmatch(r"ubuntu-\d+\.\d+", runner), f"{name} runs on {runner}"
    assert len(set(runners.values())) == 1, runners


def test_run_host_requirements_carry_no_test_tools():
    lines = _requirement_lines("requirements.txt")
    assert not [line for line in lines if _requirement_name(line).startswith("pytest")]
    assert not [line for line in lines if line.startswith("-r")]


@pytest.mark.parametrize("line, name", [
    ("pytest>=7.0", "pytest"),
    ("pytest;python_version>='3.8'", "pytest"),
    ("pytest\t>=7", "pytest"),
    ("pytest[testing] ~= 8.0", "pytest"),
    ("pytest-cov>=4", "pytest-cov"),
])
def test_requirement_name_parses_pip_spellings(line, name):
    assert _requirement_name(line) == name


def test_dev_requirements_add_pytest_to_the_run_host_set():
    lines = _requirement_lines("requirements-dev.txt")
    assert "-r requirements.txt" in lines
    assert "pytest" in [_requirement_name(line) for line in lines]


def test_ci_installs_the_dev_requirements():
    steps = _workflow()["jobs"]["pytest"]["steps"]
    commands = [line.strip() for step in steps
                for line in step.get("run", "").splitlines()]
    assert "pip install -r requirements-dev.txt" in commands


def test_every_test_module_has_a_readme_row():
    rows = set(re.findall(r"^\| `([^`]+)` \|", _read("tests/README.md"), re.M))
    modules = {os.path.basename(p)
               for p in glob.glob(os.path.join(ROOT, "tests", "test_*.py"))}
    assert modules, "no test modules found"
    assert sorted(modules - rows) == []
    stale = rows - modules - {"conftest.py"}
    assert sorted(stale) == [], "rows for files that do not exist"
