"""Network discovery endpoints — auto-detect local subnets."""

from __future__ import annotations

import asyncio
import ipaddress
import re

from fastapi import APIRouter

from app.utils.logging import get_logger

router = APIRouter(prefix="/network", tags=["network"])
log = get_logger("api.network")


async def _detect_interfaces() -> list[dict]:
    """Parse `ip -o addr show` to discover local network interfaces and their subnets.

    Returns a list of dicts:
        { interface, ip_address, cidr, subnet, prefix_length, is_private, gateway }
    """
    results: list[dict] = []
    seen_subnets: set[str] = set()

    try:
        proc = await asyncio.create_subprocess_exec(
            "ip", "-o", "-4", "addr", "show",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        output = stdout.decode(errors="replace")

        # Example line:
        # 2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0
        pattern = re.compile(
            r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)",
            re.MULTILINE,
        )

        for match in pattern.finditer(output):
            iface = match.group(1)
            ip_addr = match.group(2)
            prefix = int(match.group(3))

            try:
                network = ipaddress.IPv4Network(f"{ip_addr}/{prefix}", strict=False)
            except ValueError:
                continue

            subnet_str = str(network)
            if subnet_str in seen_subnets:
                continue
            seen_subnets.add(subnet_str)

            addr_obj = ipaddress.IPv4Address(ip_addr)

            results.append({
                "interface": iface,
                "ip_address": ip_addr,
                "cidr": subnet_str,
                "subnet": str(network.network_address),
                "prefix_length": prefix,
                "num_hosts": network.num_addresses - 2 if prefix < 31 else network.num_addresses,
                "is_private": addr_obj.is_private,
                "is_loopback": addr_obj.is_loopback,
            })

    except (asyncio.TimeoutError, FileNotFoundError, OSError) as exc:
        log.warning("interface_detection_failed", error=str(exc))
        # Fallback: try parsing /proc/net/fib_trie or socket
        results = await _fallback_detect()

    return results


async def _fallback_detect() -> list[dict]:
    """Fallback detection using `hostname -I` and /24 assumption."""
    results: list[dict] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            "hostname", "-I",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        ips = stdout.decode(errors="replace").strip().split()

        for ip_str in ips:
            ip_str = ip_str.strip()
            if not ip_str or ":" in ip_str:  # skip IPv6
                continue
            try:
                addr = ipaddress.IPv4Address(ip_str)
                network = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
            except ValueError:
                continue

            results.append({
                "interface": "unknown",
                "ip_address": ip_str,
                "cidr": str(network),
                "subnet": str(network.network_address),
                "prefix_length": 24,
                "num_hosts": 254,
                "is_private": addr.is_private,
                "is_loopback": addr.is_loopback,
            })

    except (asyncio.TimeoutError, FileNotFoundError, OSError):
        pass

    return results


async def _detect_gateway() -> str | None:
    """Try to detect the default gateway."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "ip", "route", "show", "default",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        output = stdout.decode(errors="replace")
        # "default via 192.168.1.1 dev eth0 ..."
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", output)
        if m:
            return m.group(1)
    except (asyncio.TimeoutError, FileNotFoundError, OSError):
        pass
    return None


@router.get("/subnets")
async def detect_subnets():
    """Auto-detect local network interfaces and their subnets.

    Returns a ranked list of subnets with a recommended default.
    """
    interfaces = await _detect_interfaces()
    gateway = await _detect_gateway()

    # Filter out loopback and docker/virtual interfaces for the recommendation
    candidates = [
        iface for iface in interfaces
        if not iface["is_loopback"]
        and iface["prefix_length"] <= 24  # skip /32 point-to-point
    ]

    # Score each candidate for recommendation ranking
    for iface in candidates:
        score = 0
        # Prefer private networks
        if iface["is_private"]:
            score += 10
        # Prefer interfaces on the same subnet as the gateway
        if gateway:
            try:
                gw_net = ipaddress.IPv4Network(f"{gateway}/{iface['prefix_length']}", strict=False)
                iface_net = ipaddress.IPv4Network(iface["cidr"], strict=False)
                if gw_net == iface_net:
                    score += 20
            except ValueError:
                pass
        # Prefer common LAN interfaces
        name = iface["interface"].lower()
        if name.startswith(("eth", "en", "wlan", "wl")):
            score += 5
        # Deprioritise docker / veth / br- / virbr
        if name.startswith(("docker", "veth", "br-", "virbr", "vbox", "vmnet")):
            score -= 15
        iface["score"] = score

    candidates.sort(key=lambda x: x["score"], reverse=True)
    recommended = candidates[0]["cidr"] if candidates else None

    return {
        "subnets": [
            {
                "interface": c["interface"],
                "ip_address": c["ip_address"],
                "cidr": c["cidr"],
                "prefix_length": c["prefix_length"],
                "num_hosts": c["num_hosts"],
                "is_private": c["is_private"],
            }
            for c in candidates
        ],
        "recommended": recommended,
        "gateway": gateway,
        "all_interfaces": [
            {
                "interface": i["interface"],
                "ip_address": i["ip_address"],
                "cidr": i["cidr"],
                "prefix_length": i["prefix_length"],
                "is_loopback": i["is_loopback"],
            }
            for i in interfaces
        ],
    }
