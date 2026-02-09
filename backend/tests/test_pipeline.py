"""Pipeline unit tests — mock external tools, verify data flow."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.scanner import (
    DiscoveredHost,
    stage1_ping_sweep,
    stage2_arp_lookup,
    stage3_port_scan,
    stage4_deep_scan,
    run_full_pipeline,
)


NMAP_PING_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:01" addrtype="mac" vendor="Cisco"/>
    <hostnames><hostname name="gateway.local"/></hostnames>
    <times srtt="1500"/>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames><hostname name="server.local"/></hostnames>
    <times srtt="2000"/>
  </host>
</nmaprun>"""


NMAP_DEEP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="gateway.local"/></hostnames>
    <os>
      <osmatch name="Cisco IOS 15.x" accuracy="95">
        <osclass osfamily="IOS"><cpe>cpe:/o:cisco:ios</cpe></osclass>
      </osmatch>
    </os>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


@pytest.mark.asyncio
class TestStage1PingSweep:
    @patch("app.services.scanner._run_cmd")
    async def test_returns_live_hosts(self, mock_cmd):
        mock_cmd.return_value = (NMAP_PING_XML, "", 0)
        hosts = await stage1_ping_sweep("192.168.1.0/24")
        assert len(hosts) == 2
        assert hosts[0].ip == "192.168.1.1"
        assert hosts[0].mac == "AA:BB:CC:DD:EE:01"
        assert hosts[0].vendor == "Cisco"
        assert hosts[1].ip == "192.168.1.10"

    @patch("app.services.scanner._run_cmd")
    async def test_empty_on_failure(self, mock_cmd):
        mock_cmd.return_value = ("", "Error", 1)
        hosts = await stage1_ping_sweep("10.0.0.0/24")
        assert hosts == []


@pytest.mark.asyncio
class TestStage2ARPLookup:
    async def test_passthrough_with_mac(self):
        hosts = [DiscoveredHost(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")]
        result = await stage2_arp_lookup(hosts)
        assert len(result) == 1
        assert result[0].mac == "AA:BB:CC:DD:EE:FF"

    async def test_empty_list(self):
        result = await stage2_arp_lookup([])
        assert result == []


@pytest.mark.asyncio
class TestStage3PortScan:
    @patch("app.services.scanner._run_cmd")
    async def test_parses_rustscan_output(self, mock_cmd):
        mock_cmd.return_value = ("192.168.1.1 -> [22, 80, 443]", "", 0)
        hosts = [DiscoveredHost(ip="192.168.1.1")]
        result = await stage3_port_scan(hosts)
        assert len(result) == 1
        assert 22 in result[0].open_ports
        assert 80 in result[0].open_ports

    async def test_empty_list(self):
        result = await stage3_port_scan([])
        assert result == []


@pytest.mark.asyncio
class TestStage4DeepScan:
    @patch("app.services.scanner._run_cmd")
    async def test_parses_os_and_services(self, mock_cmd):
        mock_cmd.return_value = (NMAP_DEEP_XML, "", 0)
        hosts = [DiscoveredHost(ip="192.168.1.1", open_ports=[22, 80])]
        result = await stage4_deep_scan(hosts)
        assert len(result) == 1
        assert result[0].os_name == "Cisco IOS 15.x"
        assert result[0].os_accuracy == 95
        assert 22 in result[0].services
        assert result[0].services[22]["name"] == "ssh"

    async def test_skips_hosts_without_ports(self):
        hosts = [DiscoveredHost(ip="10.0.0.1", open_ports=[])]
        result = await stage4_deep_scan(hosts)
        assert result[0].os_name is None


@pytest.mark.asyncio
class TestFullPipeline:
    @patch("app.services.scanner.stage4_deep_scan")
    @patch("app.services.scanner.stage3_port_scan")
    @patch("app.services.scanner.stage2_arp_lookup")
    @patch("app.services.scanner.stage1_ping_sweep")
    async def test_pipeline_chains_stages(self, mock_s1, mock_s2, mock_s3, mock_s4):
        hosts = [DiscoveredHost(ip="10.0.0.1", open_ports=[22])]
        mock_s1.return_value = hosts
        mock_s2.return_value = hosts
        mock_s3.return_value = hosts
        mock_s4.return_value = hosts

        result = await run_full_pipeline("10.0.0.0/24")
        assert len(result) == 1
        mock_s1.assert_called_once()
        mock_s2.assert_called_once()
        mock_s3.assert_called_once()
        mock_s4.assert_called_once()

    @patch("app.services.scanner.stage1_ping_sweep")
    async def test_pipeline_empty_on_no_hosts(self, mock_s1):
        mock_s1.return_value = []
        result = await run_full_pipeline("10.0.0.0/24")
        assert result == []
