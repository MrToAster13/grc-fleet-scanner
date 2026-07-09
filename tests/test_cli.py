"""Tests for grc_auditor.cli helpers: run-id collision resistance and the
config scaffold-or-refuse behavior of `run` when no config file exists."""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest
import yaml

from grc_auditor.cli import (
    _example_config_path, _run_id, _scaffold_config, _starter_config_text, cmd_run,
)
from grc_auditor.config import ConfigError, load_config


def test_run_id_is_timestamp_sortable_with_random_suffix():
    # 20260629T161000Z-ab12cd : a sortable UTC stamp (history ordering relies on
    # `run_id < ?` string comparison) plus a short random hex suffix.
    rid = _run_id()
    assert re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{6}", rid), rid


def test_run_ids_are_unique_within_the_same_second():
    # Two runs started back-to-back in the same wall-clock second must still mint
    # distinct ids, so one can never overwrite another's evidence dir / DB row.
    # Uniqueness rests on the 24-bit random suffix (the timestamp prefix is
    # identical across microsecond-apart calls); asserting >= len-1 proves the
    # suffix genuinely varies (a constant/low-entropy suffix would collapse this
    # toward 1) without flaking on the ~1-in-13k birthday collision of two equal
    # suffixes -- losing two pairs at once is ~1e-8, effectively never.
    ids = {_run_id() for _ in range(50)}
    assert len(ids) >= 49


# --------------------------------------------------------------------------- #
# `run` config scaffold-or-refuse
# --------------------------------------------------------------------------- #
def test_example_config_is_locatable():
    # The scaffold source must exist regardless of cwd (package-relative lookup).
    assert _example_config_path() is not None


def test_starter_config_empties_scope_but_keeps_the_rest():
    example = _example_config_path()
    with open(example, "r", encoding="utf-8") as fh:
        starter = _starter_config_text(fh.read())
    doc = yaml.safe_load(starter)
    # Authorization guard: the scaffold ships an EMPTY scope so a blind re-run is
    # refused rather than scanning the example's sample range.
    assert doc["scope"]["cidrs"] == []
    # ...while the rest of the template survives (comments + other sections).
    assert "credential_groups" in doc
    assert "# " in starter  # comments preserved, not a stripped yaml round-trip


def test_starter_config_is_refused_by_the_authorization_guard(tmp_path):
    example = _example_config_path()
    with open(example, "r", encoding="utf-8") as fh:
        starter = _starter_config_text(fh.read())
    dest = tmp_path / "config.yaml"
    dest.write_text(starter, encoding="utf-8")
    # It parses fine but is refused on the empty scope -- proving the guard, not
    # a YAML error, is what stops it.
    with pytest.raises(ConfigError) as ei:
        load_config(str(dest))
    assert "empty" in str(ei.value).lower()


def test_scaffold_writes_starter_and_returns_two(tmp_path, capsys):
    dest = tmp_path / "config.yaml"
    rc = _scaffold_config(str(dest))
    assert rc == 2
    assert dest.exists()
    assert yaml.safe_load(dest.read_text(encoding="utf-8"))["scope"]["cidrs"] == []
    assert "starter" in capsys.readouterr().out.lower()


def test_cmd_run_scaffolds_when_config_missing(tmp_path, capsys):
    dest = tmp_path / "config.yaml"
    rc = cmd_run(SimpleNamespace(config=str(dest)))
    assert rc == 2                       # nothing scanned; operator must edit first
    assert dest.exists()
    # A blind re-run of the scaffolded config is still refused.
    with pytest.raises(ConfigError):
        load_config(str(dest))
