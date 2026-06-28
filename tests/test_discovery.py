"""Tests for grc_auditor.discovery.parse_nmap_xml (pure XML parsing)."""

from __future__ import annotations

from grc_auditor.discovery import parse_nmap_xml


def test_parses_up_hosts_ip_hostname_ports_banners(sample_nmap_xml):
    hosts = parse_nmap_xml(sample_nmap_xml)
    assert len(hosts) == 2

    by_ip = {h.ip: h for h in hosts}
    assert set(by_ip) == {"10.0.10.21", "10.0.10.30"}

    web = by_ip["10.0.10.21"]
    assert web.hostname == "web01.lab"
    assert web.open_ports == [22, 80]            # sorted
    # banner is "product version extrainfo" joined, keyed by "port/proto"
    assert web.banners["22/tcp"] == "OpenSSH 8.9p1 Ubuntu-3ubuntu0.6 Ubuntu Linux"
    assert web.banners["80/tcp"] == "nginx 1.18.0"

    deb = by_ip["10.0.10.30"]
    assert deb.hostname is None                  # no <hostnames> element
    assert deb.open_ports == [22]
    assert deb.banners["22/tcp"] == "OpenSSH 9.2p1 Debian"


def test_down_host_is_skipped():
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="down"/>
        <address addr="10.0.10.99" addrtype="ipv4"/>
      </host>
      <host>
        <status state="up"/>
        <address addr="10.0.10.21" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    hosts = parse_nmap_xml(xml)
    assert [h.ip for h in hosts] == ["10.0.10.21"]


def test_host_with_missing_service_fields():
    # A port open with NO <service> element at all -> no banner for that port.
    # A closed port is excluded entirely. Only open ports are counted.
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="10.0.10.50" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
          </port>
          <port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="https" product="Apache httpd" version="2.4.52"/>
          </port>
          <port protocol="tcp" portid="3306">
            <state state="closed"/>
            <service name="mysql" product="MySQL"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    hosts = parse_nmap_xml(xml)
    assert len(hosts) == 1
    h = hosts[0]
    assert h.ip == "10.0.10.50"
    assert h.hostname is None
    # closed port excluded; only the two open ports remain.
    assert h.open_ports == [22, 443]
    # port 22 has no <service> element at all -> no banner key for it.
    assert "22/tcp" not in h.banners
    # port 443 has descriptive service fields -> a banner is recorded.
    assert h.banners["443/tcp"] == "Apache httpd 2.4.52"


def test_os_match_populates_os_guess():
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="10.0.10.60" addrtype="ipv4"/>
        <os><osmatch name="Linux 5.X" accuracy="95"/></os>
      </host>
    </nmaprun>
    """
    hosts = parse_nmap_xml(xml)
    assert hosts[0].os_guess == "Linux 5.X"


def test_host_without_ip_address_is_skipped():
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
      </host>
    </nmaprun>
    """
    assert parse_nmap_xml(xml) == []
