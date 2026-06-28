"""Tests for grc_auditor.classify.classify (Ubuntu hint + cred-group matching)."""

from __future__ import annotations

from grc_auditor.classify import classify
from grc_auditor.config import CredentialGroup
from grc_auditor.models import HostRecord, HostStatus


def _ubuntu_ssh_host(ip="10.0.10.21"):
    return HostRecord(
        ip=ip,
        hostname="web01.lab",
        open_ports=[22, 80],
        banners={"22/tcp": "OpenSSH 8.9p1 Ubuntu-3ubuntu0.6 Ubuntu Linux"},
    )


def test_ubuntu_with_matching_group_stays_discovered(config_factory):
    cfg = config_factory()  # default lab group is a "default" catch-all
    host = _ubuntu_ssh_host()
    classify([host], cfg)

    assert host.is_ubuntu is True
    assert host.status is HostStatus.DISCOVERED   # ready for the reach stage
    assert host.credential_group == "lab"


def test_non_ubuntu_marked_non_ubuntu(config_factory):
    cfg = config_factory()
    host = HostRecord(
        ip="10.0.10.30",
        open_ports=[22],
        banners={"22/tcp": "OpenSSH 9.2p1 Debian"},  # no "ubuntu" anywhere
    )
    classify([host], cfg)

    assert host.is_ubuntu is False
    assert host.status is HostStatus.NON_UBUNTU
    assert host.credential_group is None


def test_ubuntu_without_ssh_port_is_unreachable(config_factory):
    # Ubuntu hint present but no open SSH port (22) -> cannot deep-dive.
    cfg = config_factory()
    host = HostRecord(
        ip="10.0.10.21",
        open_ports=[80],
        banners={"80/tcp": "nginx 1.18.0 (Ubuntu)"},  # ubuntu hint, but on 80
    )
    classify([host], cfg)

    assert host.is_ubuntu is True
    assert host.status is HostStatus.UNREACHABLE
    # group still matched before the SSH check
    assert host.credential_group == "lab"


def test_ubuntu_with_no_matching_group_is_no_credentials():
    # Ubuntu host whose IP matches no credential group -> NO_CREDENTIALS.
    # Use a group that targets a different subnet so nothing matches.
    from grc_auditor.config import Config, ScanScope

    cfg = Config(
        scope=ScanScope(cidrs=["10.0.10.0/24"]),
        credential_groups=[
            CredentialGroup(name="other", ssh_user="ubuntu",
                            targets=["10.99.0.0/24"]),
        ],
    )
    host = _ubuntu_ssh_host(ip="10.0.10.21")
    classify([host], cfg)

    assert host.is_ubuntu is True
    assert host.status is HostStatus.NO_CREDENTIALS
    assert host.credential_group is None


def test_classify_returns_the_same_list_mutated_in_place(config_factory):
    cfg = config_factory()
    hosts = [_ubuntu_ssh_host()]
    out = classify(hosts, cfg)
    assert out is hosts
