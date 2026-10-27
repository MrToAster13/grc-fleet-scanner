"""Tests for grc_auditor.classify.classify (Ubuntu hint + cred-group matching)."""

from __future__ import annotations

from grc_auditor.classify import classify
from grc_auditor.config import CredentialGroup
from grc_auditor.models import HostRecord, HostStatus

from conftest import make_config


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


# --- treat_unknown_linux_as_ubuntu (optional candidate promotion) ---------- #

def _linux_only_host(ip="10.0.10.40"):
    # Generic Linux SSH banner with NO Ubuntu marker anywhere.
    return HostRecord(
        ip=ip, open_ports=[22],
        banners={"22/tcp": "OpenSSH 9.0 (Linux)"},
    )


def _promoting_cfg():
    # Same shape as the default config, with unknown-Linux promotion enabled.
    return make_config(treat_unknown_linux_as_ubuntu=True)


def test_unknown_linux_stays_non_ubuntu_by_default(config_factory):
    # Knob defaults False -> an unknown-Linux host (no Ubuntu marker) is
    # inventory-only, never probed.
    cfg = config_factory()
    host = _linux_only_host()
    classify([host], cfg)
    assert host.is_ubuntu is False
    assert host.status is HostStatus.NON_UBUNTU


def test_unknown_linux_promoted_to_candidate_when_enabled():
    cfg = _promoting_cfg()
    host = _linux_only_host()
    classify([host], cfg)
    # Promoted to an Ubuntu *candidate*: it proceeds to the authoritative SSH
    # detect stage (which can still reclassify it), so status is DISCOVERED.
    assert host.is_ubuntu is True
    assert host.status is HostStatus.DISCOVERED
    assert host.credential_group == "lab"


def test_promotion_never_touches_clearly_non_linux():
    # Even with promotion enabled, a clearly non-Linux fingerprint is never made
    # an Ubuntu candidate.
    cfg = _promoting_cfg()
    host = HostRecord(ip="10.0.10.50", open_ports=[22],
                      banners={"22/tcp": "Microsoft Windows Server 2019"})
    classify([host], cfg)
    assert host.is_ubuntu is False
    assert host.status is HostStatus.NON_UBUNTU


# --- ELI-630: the matched credential group's ssh_port drives the SSH gate --- #

def _ssh_port_cfg(port):
    # One catch-all group that connects on `port` (remote.py dials g.ssh_port).
    from grc_auditor.config import Config, ScanScope

    return Config(
        scope=ScanScope(cidrs=["10.0.10.0/24"]),
        credential_groups=[
            CredentialGroup(name="lab", ssh_user="ubuntu",
                            targets=["default"], ssh_port=port),
        ],
    )


def test_group_ssh_port_open_is_discovered_without_port_22():
    # AC1: sshd on 2222 only. The group says 2222, so the host is reachable.
    cfg = _ssh_port_cfg(2222)
    host = HostRecord(
        ip="10.0.10.21", open_ports=[2222, 80],
        banners={"80/tcp": "nginx 1.18.0 (Ubuntu)"},
    )
    classify([host], cfg)

    assert host.is_ubuntu is True
    assert host.status is HostStatus.DISCOVERED
    assert host.credential_group == "lab"


def test_group_ssh_port_banner_key_counts_as_ssh_evidence():
    # AC2: the only SSH evidence is a banner keyed on the group's port.
    cfg = _ssh_port_cfg(2222)
    host = HostRecord(
        ip="10.0.10.21", open_ports=[],
        banners={"2222/tcp": "OpenSSH 8.9p1 Ubuntu-3ubuntu0.6"},
    )
    classify([host], cfg)

    assert host.status is HostStatus.DISCOVERED


def test_group_port_unseen_by_nmap_is_left_for_the_reach_stage():
    # Regression (ELI-630 review): nmap scans only its default port set, so a
    # non-22 group port that nmap did not report may still be open. Classify
    # must not gate on it; the SSH reach stage decides with a real connect.
    cfg = _ssh_port_cfg(2222)
    host = HostRecord(
        ip="10.0.10.21", open_ports=[22, 80],
        banners={"22/tcp": "OpenSSH 8.9p1 Ubuntu-3ubuntu0.6"},
    )
    classify([host], cfg)

    assert host.is_ubuntu is True
    assert host.status is HostStatus.DISCOVERED
    assert host.credential_group == "lab"


def test_default_group_port_22_open_is_discovered(config_factory):
    # AC4: default group (ssh_port 22) with port 22 open. Unchanged behavior.
    cfg = config_factory()
    host = _ubuntu_ssh_host()
    classify([host], cfg)

    assert host.status is HostStatus.DISCOVERED


def test_default_group_only_port_2222_open_is_unreachable():
    # AC5: default group checks 22. An open 2222 does not count.
    cfg = _ssh_port_cfg(22)
    host = HostRecord(
        ip="10.0.10.21", open_ports=[2222],
        banners={"2222/tcp": "OpenSSH 8.9p1 Ubuntu-3ubuntu0.6"},
    )
    classify([host], cfg)

    assert host.status is HostStatus.UNREACHABLE


def test_non_ubuntu_host_with_open_2222_stays_non_ubuntu():
    # AC6: the port change does not touch the Ubuntu hint.
    cfg = _ssh_port_cfg(2222)
    host = HostRecord(
        ip="10.0.10.30", open_ports=[2222],
        banners={"2222/tcp": "OpenSSH 9.2p1 Debian"},
    )
    classify([host], cfg)

    assert host.is_ubuntu is False
    assert host.status is HostStatus.NON_UBUNTU
