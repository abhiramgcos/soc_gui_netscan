"""
Async 4-Stage Network Scanning Pipeline
========================================
Stage 1 — nmap ping sweep  : discover live hosts (-sn)
Stage 2 — ARP MAC lookup   : concurrent MAC + vendor resolution
Stage 3 — RustScan ports   : all 65 535 ports, 3 000 parallel connections (batched)
Stage 4 — nmap deep scan   : SYN + version + scripts + OS on hosts with open ports

Each stage filters targets for the next. Orchestrated with
asyncio.gather(), semaphores, and per-host timeouts.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

import os
import signal

from app.config import settings
from app.utils.logging import get_logger

log = get_logger("scanner")

# ────────────────────────────────────────────────
# Data containers passed between stages
# ────────────────────────────────────────────────

@dataclass
class DiscoveredHost:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    is_up: bool = True
    response_time_ms: int | None = None
    open_ports: list[int] = field(default_factory=list)
    os_name: str | None = None
    os_family: str | None = None
    os_accuracy: int | None = None
    os_cpe: str | None = None
    services: dict[int, dict] = field(default_factory=dict)  # port -> service info
    nmap_xml: str | None = None


# ────────────────────────────────────────────────
# Helper: run a subprocess with timeout
# ────────────────────────────────────────────────

async def _run_cmd(cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
    """Run a command asynchronously and return (stdout, stderr, returncode).
    
    Uses process groups so sudo + child processes are all killed on timeout.
    """
    log.debug("exec_cmd", cmd=" ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,  # create a new process group
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode or 0
    except asyncio.TimeoutError:
        # Kill the entire process group (sudo + its children)
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        try:
            await asyncio.wait_for(proc.communicate(), timeout=5)
        except (asyncio.TimeoutError, ProcessLookupError):
            pass
        log.warning("cmd_timeout", cmd=cmd[0], timeout=timeout)
        return "", f"Command timed out after {timeout}s", -1


def _find_binary(name: str) -> str:
    """Locate a binary on PATH, falling back to common locations."""
    path = shutil.which(name)
    if path:
        return path
    for p in [f"/usr/bin/{name}", f"/usr/local/bin/{name}", f"/snap/bin/{name}"]:
        if shutil.which(p):
            return p
    return name  # hope it's on PATH


# ────────────────────────────────────────────────
# Helper: estimate target size for dynamic timeouts
# ────────────────────────────────────────────────

def _estimate_host_count(target: str) -> int:
    """Estimate the number of hosts in a target spec.

    Handles CIDR (192.168.1.0/24), single IPs, and ranges.
    Returns a conservative estimate used for timeout scaling.
    """
    target = target.strip()
    try:
        net = ipaddress.IPv4Network(target, strict=False)
        return max(net.num_addresses - 2, 1)  # subtract network + broadcast
    except ValueError:
        pass
    # Range like 10.0.0.1-50
    if "-" in target:
        return 256  # assume small range
    # Single host or hostname
    return 1


def _ping_sweep_timeout(target: str, base: int = 120) -> int:
    """Calculate a dynamic timeout for the ping sweep based on target size."""
    hosts = _estimate_host_count(target)
    if hosts <= 1:
        return base
    if hosts <= 254:       # /24
        return max(base, 180)
    if hosts <= 510:       # /23
        return max(base, 300)
    if hosts <= 2046:      # /21
        return max(base, 600)
    # Anything bigger
    return max(base, 900)


# ────────────────────────────────────────────────
# STAGE 1 — nmap Ping Sweep
# ────────────────────────────────────────────────

async def stage1_ping_sweep(
    target: str,
    timeout: int | None = None,
    on_progress=None,
) -> list[DiscoveredHost]:
    """
    Run nmap -sn (ping sweep) to find live hosts.
    Returns a list of DiscoveredHost with ip + basic info.

    Uses ARP ping (-PR) for local-network speed, plus ICMP echo
    as fallback, with aggressive timing and dynamic timeout.
    """
    if timeout is None:
        timeout = _ping_sweep_timeout(target)

    host_count = _estimate_host_count(target)
    nmap = _find_binary("nmap")

    # Build optimised nmap command
    cmd = [
        "sudo", nmap,
        "-sn",             # ping sweep only
        "-PR",             # ARP ping  (fastest for local subnets)
        "-PE",             # ICMP echo (fallback for remote)
        "-T4",             # aggressive timing template
        "--max-retries", "1",
        "--min-rate", "300" if host_count > 64 else "100",
        "-oX", "-",
    ]

    # Parallel host-group for large scans
    if host_count > 128:
        cmd += ["--min-hostgroup", "64"]
    if host_count > 512:
        cmd += ["--min-hostgroup", "128"]

    cmd.append(target)

    if on_progress:
        await on_progress(
            f"Stage 1: Starting ping sweep ({host_count} hosts, timeout {timeout}s)",
            {"target": target, "estimated_hosts": host_count, "timeout": timeout},
        )

    stdout, stderr, rc = await _run_cmd(cmd, timeout)

    if rc != 0 and not stdout:
        log.warning("ping_sweep_failed", stderr=stderr, rc=rc)
        if on_progress:
            await on_progress(f"Stage 1: Ping sweep failed — {stderr[:200]}", {"error": True})
        return []

    hosts: list[DiscoveredHost] = []
    try:
        root = ET.fromstring(stdout)
        for host_el in root.findall(".//host"):
            status = host_el.find("status")
            if status is None or status.get("state") != "up":
                continue

            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue

            ip = addr_el.get("addr", "")
            h = DiscoveredHost(ip=ip)

            # MAC if present
            mac_el = host_el.find("address[@addrtype='mac']")
            if mac_el is not None:
                h.mac = mac_el.get("addr")
                h.vendor = mac_el.get("vendor")

            # Hostname
            hn_el = host_el.find(".//hostname")
            if hn_el is not None:
                h.hostname = hn_el.get("name")

            # Response time
            times_el = host_el.find("times")
            if times_el is not None:
                srtt = times_el.get("srtt")
                if srtt:
                    h.response_time_ms = int(srtt) // 1000

            hosts.append(h)
    except ET.ParseError as e:
        log.error("xml_parse_error_stage1", error=str(e))

    if on_progress:
        await on_progress(f"Stage 1: Found {len(hosts)} live hosts", {"count": len(hosts)})

    log.info("stage1_complete", live_hosts=len(hosts), target=target)
    return hosts


# ────────────────────────────────────────────────
# STAGE 2 — ARP MAC Lookup (concurrent)
# ────────────────────────────────────────────────

async def _arp_lookup_single(host: DiscoveredHost, semaphore: asyncio.Semaphore, timeout: int) -> DiscoveredHost:
    """Resolve MAC + vendor for one host via arp-scan or arping."""
    if host.mac:
        return host

    async with semaphore:
        # Try arp-scan first
        arp_scan = _find_binary("arp-scan")
        cmd = ["sudo", arp_scan, "-I", "eth0", "-q", host.ip]
        stdout, stderr, rc = await _run_cmd(cmd, timeout)

        if rc == 0 and stdout.strip():
            for line in stdout.strip().splitlines():
                parts = line.split("\t")
                if len(parts) >= 2 and host.ip in parts[0]:
                    host.mac = parts[1].strip()
                    if len(parts) >= 3:
                        host.vendor = parts[2].strip()
                    break

        # Fallback: nmap ARP ping
        if not host.mac:
            nmap = _find_binary("nmap")
            cmd = ["sudo", nmap, "-sn", "-PR", "-oX", "-", host.ip]
            stdout, stderr, rc = await _run_cmd(cmd, timeout)
            if rc == 0:
                try:
                    root = ET.fromstring(stdout)
                    mac_el = root.find(".//address[@addrtype='mac']")
                    if mac_el is not None:
                        host.mac = mac_el.get("addr")
                        host.vendor = mac_el.get("vendor")
                except ET.ParseError:
                    pass

    return host


async def stage2_arp_lookup(
    hosts: list[DiscoveredHost],
    concurrency: int = 50,
    timeout_per_host: int = 15,
    on_progress=None,
) -> list[DiscoveredHost]:
    """Concurrent ARP/MAC resolution for all discovered hosts."""
    if not hosts:
        return hosts

    if on_progress:
        await on_progress(f"Stage 2: ARP lookup for {len(hosts)} hosts", {"count": len(hosts)})

    sem = asyncio.Semaphore(concurrency)
    tasks = [_arp_lookup_single(h, sem, timeout_per_host) for h in hosts]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    resolved = []
    for r in results:
        if isinstance(r, DiscoveredHost):
            resolved.append(r)
        elif isinstance(r, Exception):
            log.warning("arp_lookup_error", error=str(r))

    macs_found = sum(1 for h in resolved if h.mac)
    if on_progress:
        await on_progress(f"Stage 2: Resolved {macs_found}/{len(resolved)} MACs", {"macs": macs_found})

    log.info("stage2_complete", total=len(resolved), macs_resolved=macs_found)
    return resolved


# ────────────────────────────────────────────────
# STAGE 3 — Port Scan (RustScan → nmap fallback)
# ────────────────────────────────────────────────

async def _rustscan_single(
    host: DiscoveredHost,
    semaphore: asyncio.Semaphore,
    batch_size: int,
    timeout: int,
) -> DiscoveredHost:
    """RustScan top ports on a single host with short timeout + nmap fallback."""
    async with semaphore:
        rustscan = _find_binary("rustscan")

        # RustScan phase — short timeout (30s)
        rs_timeout = min(timeout, 30)
        cmd = [
            "sudo", rustscan,
            "-a", host.ip,
            "--top",
            "-b", str(batch_size),
            "--ulimit", "5000",
            "--timeout", str(rs_timeout * 1000),
            "-g",  # greppable output
        ]

        stdout, stderr, rc = await _run_cmd(cmd, rs_timeout + 5)

        if rc == 0 and stdout.strip():
            for line in stdout.strip().splitlines():
                match = re.search(r"->\s*\[(.+?)\]", line)
                if match:
                    ports_str = match.group(1)
                    host.open_ports = [
                        int(p.strip())
                        for p in ports_str.split(",")
                        if p.strip().isdigit()
                    ]

        # Fallback: nmap SYN scan top 1000 — aggressive timing, short timeout
        if rc != 0 or not host.open_ports:
            nmap = _find_binary("nmap")
            nmap_timeout = min(timeout, 45)
            cmd = [
                "sudo", nmap,
                "-sS",
                "--top-ports", "1000",
                "--min-rate", "5000",
                "--max-retries", "1",
                "-T4",
                "--host-timeout", f"{nmap_timeout}s",
                "-oX", "-",
                host.ip,
            ]
            stdout, stderr, rc = await _run_cmd(cmd, nmap_timeout + 10)
            if rc == 0 and stdout.strip():
                try:
                    root = ET.fromstring(stdout)
                    for port_el in root.findall(".//port"):
                        state_el = port_el.find("state")
                        if state_el is not None and state_el.get("state") == "open":
                            portid = port_el.get("portid")
                            if portid:
                                host.open_ports.append(int(portid))
                except ET.ParseError:
                    pass

    return host


async def stage3_port_scan(
    hosts: list[DiscoveredHost],
    batch_size: int | None = None,
    concurrency: int = 20,
    timeout_per_host: int | None = None,
    on_progress=None,
) -> list[DiscoveredHost]:
    """Run port scans on all hosts with high concurrency and progress reporting."""
    if not hosts:
        return hosts

    batch_size = batch_size or settings.rustscan_batch_size
    # Use a shorter per-host timeout for port scanning (not the global one)
    timeout_per_host = min(timeout_per_host or settings.scan_timeout_per_host, 60)

    if on_progress:
        await on_progress(
            f"Stage 3: Port scanning {len(hosts)} hosts (top 1000 ports, {concurrency} parallel)",
            {"count": len(hosts)},
        )

    sem = asyncio.Semaphore(concurrency)
    completed = [0]  # mutable counter for progress

    async def _scan_with_progress(host: DiscoveredHost) -> DiscoveredHost:
        result = await _rustscan_single(host, sem, batch_size, timeout_per_host)
        completed[0] += 1
        # Report progress every 10 hosts or at the end
        if on_progress and (completed[0] % 10 == 0 or completed[0] == len(hosts)):
            await on_progress(
                f"Stage 3: Scanned {completed[0]}/{len(hosts)} hosts",
                {"completed": completed[0], "total": len(hosts)},
            )
        return result

    tasks = [_scan_with_progress(h) for h in hosts]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    scanned = []
    total_ports = 0
    for r in results:
        if isinstance(r, DiscoveredHost):
            scanned.append(r)
            total_ports += len(r.open_ports)
        elif isinstance(r, Exception):
            log.warning("port_scan_error", error=str(r))

    with_ports = [h for h in scanned if h.open_ports]

    if on_progress:
        await on_progress(
            f"Stage 3: {total_ports} open ports across {len(with_ports)}/{len(scanned)} hosts",
            {"total_ports": total_ports, "hosts_with_ports": len(with_ports)},
        )

    log.info("stage3_complete", total_ports=total_ports, hosts_with_ports=len(with_ports))
    return scanned


# ────────────────────────────────────────────────
# STAGE 4 — nmap Deep Scan (SYN + version + scripts + OS)
# ────────────────────────────────────────────────

async def _deep_scan_single(host: DiscoveredHost, semaphore: asyncio.Semaphore, timeout: int) -> DiscoveredHost:
    """Deep nmap scan: SYN + service version + default scripts + OS detection in one pass."""
    if not host.open_ports:
        return host

    async with semaphore:
        nmap = _find_binary("nmap")
        ports_str = ",".join(str(p) for p in sorted(host.open_ports))
        cmd = [
            "sudo", nmap,
            "-sS",           # SYN scan
            "-sV",           # Service version detection
            "-sC",           # Default scripts
            "-O",            # OS detection
            "--osscan-guess",
            "-p", ports_str,
            "-T4",
            "--max-retries", "2",
            "-oX", "-",
            host.ip,
        ]

        stdout, stderr, rc = await _run_cmd(cmd, timeout)

        if rc != 0 and not stdout:
            log.warning("deep_scan_failed", ip=host.ip, stderr=stderr[:200])
            return host

        host.nmap_xml = stdout

        try:
            root = ET.fromstring(stdout)
            host_el = root.find(".//host")
            if host_el is None:
                return host

            # OS detection
            osmatch = host_el.find(".//osmatch")
            if osmatch is not None:
                host.os_name = osmatch.get("name")
                host.os_accuracy = int(osmatch.get("accuracy", 0))
                osclass = osmatch.find("osclass")
                if osclass is not None:
                    host.os_family = osclass.get("osfamily")
                    cpe_el = osclass.find("cpe")
                    if cpe_el is not None and cpe_el.text:
                        host.os_cpe = cpe_el.text

            # Hostname update
            hn_el = host_el.find(".//hostname")
            if hn_el is not None:
                host.hostname = hn_el.get("name")

            # Ports + services
            host.services = {}
            for port_el in host_el.findall(".//port"):
                portid = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")

                state_el = port_el.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"

                service_el = port_el.find("service")
                svc = {
                    "port": portid,
                    "protocol": protocol,
                    "state": state,
                    "name": service_el.get("name") if service_el is not None else None,
                    "product": service_el.get("product") if service_el is not None else None,
                    "version": service_el.get("version") if service_el is not None else None,
                    "extra_info": service_el.get("extrainfo") if service_el is not None else None,
                    "cpe": None,
                }

                if service_el is not None:
                    cpe_el = service_el.find("cpe")
                    if cpe_el is not None and cpe_el.text:
                        svc["cpe"] = cpe_el.text

                # Script output
                scripts = []
                for script_el in port_el.findall("script"):
                    scripts.append(f"{script_el.get('id', '')}: {script_el.get('output', '')}")
                svc["scripts"] = "\n".join(scripts) if scripts else None

                host.services[portid] = svc

        except ET.ParseError as e:
            log.error("xml_parse_error_stage4", ip=host.ip, error=str(e))

    return host


async def stage4_deep_scan(
    hosts: list[DiscoveredHost],
    concurrency: int = 5,
    timeout_per_host: int | None = None,
    on_progress=None,
    existing_hosts: dict[str, int] | None = None,
) -> list[DiscoveredHost]:
    """Deep nmap scan on hosts that have open ports.
    
    If existing_hosts is provided (MAC → port_count), hosts whose MAC
    matches and whose open port count is identical are skipped.
    """
    if not hosts:
        return hosts

    timeout = timeout_per_host or settings.scan_timeout_per_host
    candidates = [h for h in hosts if h.open_ports]

    # Skip optimization: if a device already has the same number of open ports, skip deep scan
    skipped = 0
    targets = []
    if existing_hosts:
        for h in candidates:
            mac = h.mac or f"00:00:{h.ip.replace('.', ':')[:8]}"
            existing_count = existing_hosts.get(mac, -1)
            if existing_count == len(h.open_ports) and existing_count > 0:
                skipped += 1
                log.info("stage4_skip", ip=h.ip, mac=mac, ports=existing_count)
            else:
                targets.append(h)
    else:
        targets = candidates

    if on_progress:
        msg = f"Stage 4: Deep scanning {len(targets)} hosts"
        if skipped:
            msg += f" ({skipped} skipped — unchanged port count)"
        await on_progress(msg, {"count": len(targets), "skipped": skipped})

    if not targets:
        if on_progress:
            await on_progress("Stage 4: No hosts need deep scanning — all skipped or no open ports", {})
        return hosts

    sem = asyncio.Semaphore(concurrency)
    tasks = [_deep_scan_single(h, sem, timeout) for h in targets]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Merge deep scan results back
    deep_map: dict[str, DiscoveredHost] = {}
    for r in results:
        if isinstance(r, DiscoveredHost):
            deep_map[r.ip] = r
        elif isinstance(r, Exception):
            log.warning("deep_scan_error", error=str(r))

    final = []
    for h in hosts:
        if h.ip in deep_map:
            final.append(deep_map[h.ip])
        else:
            final.append(h)

    os_count = sum(1 for h in final if h.os_name)
    if on_progress:
        await on_progress(
            f"Stage 4: OS identified on {os_count}/{len(targets)} hosts",
            {"os_identified": os_count},
        )

    log.info("stage4_complete", deep_scanned=len(targets), os_identified=os_count)
    return final


# ────────────────────────────────────────────────
# Full Pipeline Orchestrator
# ────────────────────────────────────────────────

async def run_full_pipeline(
    target: str,
    on_progress=None,
    existing_hosts: dict[str, int] | None = None,
) -> list[DiscoveredHost]:
    """
    Execute the complete 4-stage pipeline:
      1. Ping sweep → 2. ARP lookup → 3. Port scan → 4. Deep scan
    """
    log.info("pipeline_start", target=target)
    start = datetime.now(timezone.utc)

    # Stage 1
    hosts = await stage1_ping_sweep(target, on_progress=on_progress)
    if not hosts:
        if on_progress:
            await on_progress("Pipeline complete: No live hosts found", {"total": 0})
        return []

    # Stage 2
    hosts = await stage2_arp_lookup(hosts, on_progress=on_progress)

    # Stage 3
    hosts = await stage3_port_scan(hosts, on_progress=on_progress)

    # Stage 4
    hosts = await stage4_deep_scan(hosts, on_progress=on_progress, existing_hosts=existing_hosts)

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    total_ports = sum(len(h.open_ports) for h in hosts)

    if on_progress:
        await on_progress(
            f"Pipeline complete: {len(hosts)} hosts, {total_ports} open ports in {elapsed:.1f}s",
            {"total_hosts": len(hosts), "total_ports": total_ports, "elapsed": elapsed},
        )

    log.info("pipeline_complete", hosts=len(hosts), ports=total_ports, elapsed_s=elapsed)
    return hosts
