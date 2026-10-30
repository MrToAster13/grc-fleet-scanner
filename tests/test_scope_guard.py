"""ELI-926: nmap_extra_args cannot widen the scan, and discovery results
outside scope.cidrs never reach SSH.

Acceptance criteria map:
  AC1 -> test_nmap_extra_args_refuses_scope_output_and_script_flags
  AC2 -> test_nmap_extra_args_keeps_the_documented_flags
  AC3 -> test_cmd_run_drops_hosts_outside_scope_before_ssh
"""

from __future__ import annotations

import textwrap
from types import SimpleNamespace

import pytest
import yaml

import grc_auditor.cli as cli_mod
from grc_auditor import discovery
from grc_auditor.cli import _scaffold_config, cmd_run
from grc_auditor.config import ConfigError, load_config
from grc_auditor.models import HostRecord, HostStatus


def _cfg_with_args(tmp_path, arg):
    path = tmp_path / "config.yaml"
    path.write_text(textwrap.dedent(f"""
        scope:
          cidrs: [10.0.10.0/24]
          nmap_extra_args: [{arg!r}]
        credential_groups: []
    """), encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("bad", [
    "-sC",                 # default NSE scripts
    "-A",                  # aggressive mode runs NSE scripts
    "--script-args=x",
    "--script=default",
    "--excludefil=x",      # nmap accepts unambiguous long-option prefixes
    "--datadi=x",
    "-oNout.txt",          # short option with an attached value
    "-iLhosts.txt",
    "-iR100",              # random internet targets
    "--resume=x",
])
def test_nmap_extra_args_refuses_scope_output_and_script_flags(tmp_path, bad):
    with pytest.raises(ConfigError):
        load_config(_cfg_with_args(tmp_path, bad))


@pytest.mark.parametrize("good", [
    "-Pn", "-p22", "-p22,2222", "--open", "-T4", "--top-ports=100",
])
def test_nmap_extra_args_keeps_the_documented_flags(tmp_path, good):
    cfg = load_config(_cfg_with_args(tmp_path, good))
    assert cfg.scope.nmap_extra_args == [good]


def test_cmd_run_drops_hosts_outside_scope_before_ssh(tmp_path, monkeypatch):
    cfg_path = tmp_path / "config.yaml"
    _scaffold_config(str(cfg_path))
    doc = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    doc["scope"]["cidrs"] = ["10.0.10.0/29"]
    doc["output_dir"] = str(tmp_path / "out")
    cfg_path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    def fake_discover(scope, want_os=False):
        return [
            HostRecord(ip="10.0.10.3", status=HostStatus.DISCOVERED),
            HostRecord(ip="198.51.100.7", status=HostStatus.DISCOVERED),
        ]

    assessed = []

    def fake_assess(host, cfg, run_id, artifacts_root):
        assessed.append(host.ip)
        host.status = HostStatus.UNREACHABLE
        host.detail = "ssh refused"
        return host

    monkeypatch.setattr(discovery, "discover", fake_discover)
    monkeypatch.setattr(cli_mod.classify_mod, "classify", lambda hosts, cfg: None)
    monkeypatch.setattr(cli_mod, "assess_host", fake_assess)

    args = SimpleNamespace(
        config=str(cfg_path), cidr=None, exclude=None, output=None, cis_level=None,
        concurrency=None, low_confidence_threshold=None, os_detect=False,
        dry_run=False, verbose=False,
    )
    cmd_run(args)

    assert assessed == ["10.0.10.3"]
    run_dir = next((tmp_path / "out" / "runs").iterdir())
    log_text = (run_dir / "audit.log").read_text(encoding="utf-8")
    assert "outside scope.cidrs" in log_text
    assert "198.51.100.7" not in (run_dir / "hosts.csv").read_text(encoding="utf-8")


# Adversarial review regressions (ELI-926).

@pytest.mark.parametrize("good", [
    "-6",                     # the only way to run an IPv6 scope
    "-PR", "-PO", "-PO1,6", "--disable-arp-ping", "-sP",
    "--exclude-ports=25",
])
def test_nmap_extra_args_keeps_discovery_flags_that_cannot_widen_scope(tmp_path, good):
    cfg = load_config(_cfg_with_args(tmp_path, good))
    assert cfg.scope.nmap_extra_args == [good]


def test_nmap_extra_args_refuses_an_option_nmap_does_not_have(tmp_path):
    # nmap has --max-retries but no --min-retries; it would die at discovery.
    with pytest.raises(ConfigError):
        load_config(_cfg_with_args(tmp_path, "--min-retries=2"))
