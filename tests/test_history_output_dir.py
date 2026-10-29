"""`history` finds runs through the configured output_dir and creates nothing
when there is no history to read (ELI-717).

AC1: with output_dir set in a config file, `history -c FILE` lists runs from
that directory. AC2: `history` in an empty directory creates no files."""

from __future__ import annotations

import os

from grc_auditor.cli import EXIT_CONFIG_ERROR, main
from grc_auditor.models import RunRecord
from grc_auditor.store import Store

RUN_ID = "20260629T161000Z-ab12cd"
STARTED = "2026-06-29T16:10:00+00:00"


def _seed_run(output_dir: str) -> None:
    store = Store(output_dir)
    store.save_run(RunRecord(
        run_id=RUN_ID, started_at=STARTED, finished_at=STARTED,
        scope=["10.0.10.0/24"], config_hash="deadbeefcafef00d", hosts=[],
        dry_run=False,
    ))
    store.close()


def _write_config(path, output_dir: str) -> None:
    path.write_text(
        "scope:\n"
        "  cidrs: [\"10.0.10.0/24\"]\n"
        f"output_dir: \"{output_dir}\"  # history.db lives here\n",
        encoding="utf-8",
    )


def _tree(root) -> list:
    return sorted(os.path.relpath(os.path.join(d, n), root)
                  for d, dirs, files in os.walk(root) for n in dirs + files)


def test_history_with_config_lists_runs_from_its_output_dir(tmp_path, monkeypatch, capsys):
    out = tmp_path / "audits"
    _seed_run(str(out))
    cfg = tmp_path / "etc" / "config.yaml"
    cfg.parent.mkdir()
    _write_config(cfg, str(out))
    elsewhere = tmp_path / "cron-cwd"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    assert main(["history", "-c", str(cfg)]) == 0
    assert RUN_ID in capsys.readouterr().out
    assert _tree(elsewhere) == []


def test_history_reads_dot_config_yaml_when_present(tmp_path, monkeypatch, capsys):
    out = tmp_path / "audits"
    _seed_run(str(out))
    work = tmp_path / "work"
    work.mkdir()
    _write_config(work / "config.yaml", str(out))
    monkeypatch.chdir(work)

    assert main(["history"]) == 0
    assert RUN_ID in capsys.readouterr().out
    assert _tree(work) == ["config.yaml"]


def test_history_output_flag_overrides_the_config(tmp_path, monkeypatch, capsys):
    real = tmp_path / "real"
    _seed_run(str(real))
    cfg = tmp_path / "config.yaml"
    _write_config(cfg, str(tmp_path / "configured-but-empty"))
    monkeypatch.chdir(tmp_path)

    assert main(["history", "-c", str(cfg), "-o", str(real)]) == 0
    assert RUN_ID in capsys.readouterr().out
    assert not (tmp_path / "configured-but-empty").exists()


def test_history_in_an_empty_directory_creates_no_files(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    assert main(["history"]) == 0
    assert "No runs recorded yet" in capsys.readouterr().out
    assert _tree(tmp_path) == []


def test_history_with_configured_dir_missing_creates_nothing(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.yaml"
    missing = tmp_path / "not-yet"
    _write_config(cfg, str(missing))
    monkeypatch.chdir(tmp_path)

    assert main(["history", "-c", str(cfg)]) == 0
    out = capsys.readouterr().out
    assert "No runs recorded yet" in out
    assert str(missing) in out
    assert not missing.exists()


def test_history_with_a_missing_explicit_config_is_a_config_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    assert main(["history", "-c", str(tmp_path / "nope.yaml")]) == EXIT_CONFIG_ERROR
    assert "nope.yaml" in capsys.readouterr().err
    assert _tree(tmp_path) == []
