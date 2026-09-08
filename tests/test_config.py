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
    ip_in_networks,
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


def test_apply_overrides_invalid_cis_level_raises(tmp_path):
    cfg = load_config(_write(tmp_path, VALID_YAML))
    with pytest.raises(ConfigError):
        apply_overrides(cfg, cis_level=3)


def test_os_detect_is_a_hashed_run_input(tmp_path):
    # OS detection changes discovery behavior (it feeds classify's Ubuntu hint),
    # so it must be part of the canonical config hash, not a loose CLI-only arg.
    cfg = load_config(_write(tmp_path, VALID_YAML))
    assert cfg.os_detect is False
    assert cfg.canonical()["os_detect"] is False
    before = cfg.hash()
    apply_overrides(cfg, os_detect=True)
    assert cfg.os_detect is True
    assert cfg.canonical()["os_detect"] is True
    assert cfg.hash() != before


def test_overrides_change_config_hash(tmp_path):
    # config_hash is computed from the EFFECTIVE config, so every run-affecting
    # override changes it -- including --cis-level, which previously hashed
    # identically to a default run (a provenance lie) because only cidrs/threshold
    # were mirrored into raw.
    for kwargs in (
        {"low_confidence_threshold": 75},
        {"cis_level": 1},                 # VALID_YAML sets cis_level: 2
        {"cidrs": ["192.168.5.0/24"]},
        {"ssh_concurrency": 30},
    ):
        cfg = load_config(_write(tmp_path, VALID_YAML))
        before = cfg.hash()
        apply_overrides(cfg, **kwargs)
        assert cfg.hash() != before, kwargs


def test_config_hash_is_stable_and_order_independent(tmp_path):
    # Same effective config -> same hash, regardless of CIDR ordering.
    a = load_config(_write(tmp_path, VALID_YAML))
    b = load_config(_write(tmp_path, VALID_YAML))
    apply_overrides(a, cidrs=["10.0.1.0/24", "10.0.2.0/24"])
    apply_overrides(b, cidrs=["10.0.2.0/24", "10.0.1.0/24"])
    assert a.hash() == b.hash()


def test_non_numeric_threshold_in_yaml_raises(tmp_path):
    yaml_text = """
        scope:
          cidrs:
            - 10.0.10.0/24
        low_confidence_threshold: "not a number"
        credential_groups: []
    """
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, yaml_text))


def test_out_of_range_threshold_raises(tmp_path):
    cfg = load_config(_write(tmp_path, VALID_YAML))
    with pytest.raises(ConfigError):
        apply_overrides(cfg, low_confidence_threshold=150)


# --- scope / blast-radius validation -------------------------------------- #

def test_cidr_override_is_validated(tmp_path):
    # The --cidr path must reject a malformed range, same as the file path
    # (previously it bypassed validation entirely).
    cfg = load_config(_write(tmp_path, VALID_YAML))
    with pytest.raises(ConfigError):
        apply_overrides(cfg, cidrs=["not-a-cidr"])


def test_overbroad_scope_is_refused_in_both_paths(tmp_path):
    # A typo'd /8 or 0.0.0.0/0 is an enormous blast radius -> refused.
    overbroad = """
        scope:
          cidrs: [10.0.0.0/8]
        credential_groups: []
    """
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, overbroad))

    cfg = load_config(_write(tmp_path, VALID_YAML))
    with pytest.raises(ConfigError):
        apply_overrides(cfg, cidrs=["0.0.0.0/0"])


def test_concurrency_bounds(tmp_path):
    cfg = load_config(_write(tmp_path, VALID_YAML))
    with pytest.raises(ConfigError):
        apply_overrides(cfg, ssh_concurrency=0)
    with pytest.raises(ConfigError):
        apply_overrides(cfg, ssh_concurrency=10_000)
    assert apply_overrides(cfg, ssh_concurrency=25).scope.ssh_concurrency == 25


def test_nmap_extra_args_rejects_targets_and_dangerous_flags(tmp_path):
    for bad in ("203.0.113.0/24", "-iL", "--exclude=10.0.0.5", "-oN"):
        yaml_text = f"""
            scope:
              cidrs: [10.0.10.0/24]
              nmap_extra_args: [{bad!r}]
            credential_groups: []
        """
        with pytest.raises(ConfigError):
            load_config(_write(tmp_path, yaml_text))


def test_ip_in_networks_helper():
    nets = ["10.0.10.0/24", "192.168.1.5"]
    assert ip_in_networks("10.0.10.7", nets) is True
    assert ip_in_networks("192.168.1.5", nets) is True
    assert ip_in_networks("10.0.20.7", nets) is False


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


def test_treat_unknown_linux_loads_and_affects_hash(tmp_path):
    # The knob loads from YAML (default False) and, because it changes which
    # hosts get probed, is part of the canonical (hashed) behavior -- two runs
    # that differ only by this flag must not share a config_hash.
    base = load_config(_write(tmp_path, VALID_YAML))
    assert base.treat_unknown_linux_as_ubuntu is False

    promoted = load_config(_write(
        tmp_path, VALID_YAML + "    treat_unknown_linux_as_ubuntu: true\n"))
    assert promoted.treat_unknown_linux_as_ubuntu is True
    assert promoted.hash() != base.hash()
