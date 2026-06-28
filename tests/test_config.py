"""Tests for grc_auditor.config: load_config, validation, overrides, hashing."""

from __future__ import annotations

import textwrap

import pytest

from grc_auditor.config import (
    Config,
    ConfigError,
    CredentialGroup,
    ScanScope,
    apply_overrides,
    load_config,
)


def _write(tmp_path, text):
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(text), encoding="utf-8")
    return str(p)


VALID_YAML = """
    scope:
      cidrs:
        - 10.0.10.0/24
        - 10.0.20.0/24
      exclude:
        - 10.0.10.1
      ssh_concurrency: 8
    output_dir: ./out
    cis_level: 2
    credential_groups:
      - name: prod
        ssh_user: grc-scan
        targets:
          - 10.0.10.0/24
        cis_level: 2
      - name: lab
        ssh_user: ubuntu
        targets: ["default"]
"""


def test_valid_config_parses(tmp_path):
    cfg = load_config(_write(tmp_path, VALID_YAML))

    assert isinstance(cfg, Config)
    assert cfg.scope.cidrs == ["10.0.10.0/24", "10.0.20.0/24"]
    assert cfg.scope.exclude == ["10.0.10.1"]
    assert cfg.scope.ssh_concurrency == 8
    assert cfg.output_dir == "./out"
    assert cfg.cis_level == 2
    assert [g.name for g in cfg.credential_groups] == ["prod", "lab"]
    assert cfg.credential_groups[0].cis_level == 2
    assert cfg.credential_groups[0].ssh_user == "grc-scan"


def test_empty_scope_cidrs_raises(tmp_path):
    yaml_text = """
        scope:
          cidrs: []
        credential_groups:
          - name: lab
            ssh_user: ubuntu
            targets: ["default"]
    """
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, yaml_text))


def test_missing_scope_key_raises(tmp_path):
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, "credential_groups: []\n"))


def test_invalid_cidr_raises(tmp_path):
    yaml_text = """
        scope:
          cidrs:
            - not-a-cidr
        credential_groups: []
    """
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, yaml_text))


def test_missing_config_file_raises():
    with pytest.raises(ConfigError):
        load_config("does-not-exist-12345.yaml")


def test_credential_group_for_matches_by_cidr_then_default():
    prod = CredentialGroup(name="prod", ssh_user="u", targets=["10.0.10.0/24"])
    fallback = CredentialGroup(name="lab", ssh_user="u", targets=["default"])
    cfg = Config(
        scope=ScanScope(cidrs=["10.0.10.0/24"]),
        credential_groups=[prod, fallback],
    )

    # in-CIDR host hits the specific group (first match wins, top-down)
    assert cfg.credential_group_for("10.0.10.5").name == "prod"
    # out-of-CIDR host falls through to the "default" catch-all
    assert cfg.credential_group_for("10.99.0.5").name == "lab"


def test_credential_group_for_returns_none_when_nothing_matches():
    cfg = Config(
        scope=ScanScope(cidrs=["10.0.10.0/24"]),
        credential_groups=[
            CredentialGroup(name="prod", ssh_user="u", targets=["10.0.10.0/24"]),
        ],
    )
    assert cfg.credential_group_for("10.99.0.5") is None


def test_apply_overrides_cli_wins(tmp_path):
    cfg = load_config(_write(tmp_path, VALID_YAML))
    out = apply_overrides(
        cfg,
        cidrs=["192.168.0.0/24"],
        exclude=["192.168.0.1"],
        output_dir="./override-out",
        cis_level=1,
        ssh_concurrency=20,
    )
    assert out is cfg  # mutates and returns the same object
    assert cfg.scope.cidrs == ["192.168.0.0/24"]
    assert cfg.scope.exclude == ["192.168.0.1"]
    assert cfg.output_dir == "./override-out"
    assert cfg.cis_level == 1
    assert cfg.scope.ssh_concurrency == 20
    # cidrs override is also reflected into raw (so hash() sees it)
    assert cfg.raw["scope"]["cidrs"] == ["192.168.0.0/24"]


def test_apply_overrides_invalid_cis_level_raises(tmp_path):
    cfg = load_config(_write(tmp_path, VALID_YAML))
    with pytest.raises(ConfigError):
        apply_overrides(cfg, cis_level=3)


def test_hash_is_stable_for_equal_inputs(tmp_path):
    path = _write(tmp_path, VALID_YAML)
    a = load_config(path)
    b = load_config(path)
    assert a.hash() == b.hash()
    # determinism across repeated calls on the same object too
    assert a.hash() == a.hash()


def test_hash_changes_when_raw_changes(tmp_path):
    a = load_config(_write(tmp_path, VALID_YAML))
    before = a.hash()
    apply_overrides(a, cidrs=["192.168.0.0/24"])
    assert a.hash() != before
