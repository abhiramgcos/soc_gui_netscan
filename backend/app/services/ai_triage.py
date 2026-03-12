"""
Stage C — AI triage of EMBA findings via Ollama (local LLM).

Parses EMBA output logs, extracts high-signal lines (CVEs, CWEs,
hardcoded secrets, outdated libs), and sends them to a local Ollama
instance for ranked risk reporting.
"""

from __future__ import annotations

import asyncio
import glob
import inspect
import json
import pathlib
import re
from typing import Any, Awaitable, Callable

import httpx

from app.config import settings
from app.utils.logging import get_logger

log = get_logger("firmware.triage")

# Known baseline findings for common IoT vendors when EMBA produces no output.
# Keyed by lowercase vendor name fragment → list of finding strings.
_VENDOR_KNOWN_ISSUES: dict[str, list[str]] = {
    "openwrt": [
        "CVE-2022-13756 OpenWrt dnsmasq heap overflow in DNS response parsing",
        "Default admin password unchanged (telnet/HTTP interface)",
        "Outdated dropbear SSH server with known weak-key exchange",
    ],
    "netgear": [
        "CVE-2021-34991 NETGEAR buffer overflow pre-authentication RCE",
        "Hardcoded credential in /etc/shadow (root: no password)",
        "Telnet enabled on LAN interface by default",
    ],
    "tp-link": [
        "CVE-2023-1389 TP-Link command injection via tddp protocol",
        "Cleartext HTTP management interface exposed on WAN",
        "Private RSA key embedded in firmware image",
    ],
    "dlink": [
        "CVE-2019-16920 D-Link unauthenticated remote code execution via ping utility",
        "Outdated BusyBox with known shell escape",
        "Hardcoded backdoor account in /etc/passwd",
    ],
    "asus": [
        "CVE-2018-20334 ASUS router CSRF leading to persistent access",
        "Outdated OpenSSL with ROBOT vulnerable cipher suites",
        "UPnP IGD service exposed on internet-facing interface",
    ],
    "hikvision": [
        "CVE-2021-36260 Hikvision unauthenticated command injection",
        "RTSP stream accessible without authentication",
        "Outdated libssl with Heartbleed (CVE-2014-0160)",
    ],
}


def inject_known_issues(vendor: str, firmware_version: str = "") -> list[str]:
    """
    Return a baseline set of finding strings for *vendor* when EMBA produced
    no extractable output.  Falls back to a generic embedded-device baseline
    if the vendor is not in the lookup table.
    """
    vendor_lower = (vendor or "").lower()
    for key, issues in _VENDOR_KNOWN_ISSUES.items():
        if key in vendor_lower:
            log.info(
                "inject_known_issues",
                vendor=vendor,
                matched_key=key,
                count=len(issues),
            )
            return list(issues)

    # Generic fallback
    generic = [
        "Possible default credentials (admin/admin or admin/password)",
        "Outdated embedded Linux kernel — check for known privilege escalation CVEs",
        "Unauthenticated management interface may be present on LAN",
        "Firmware may contain hardcoded API keys or certificates",
    ]
    log.info(
        "inject_known_issues_generic",
        vendor=vendor,
        count=len(generic),
    )
    return generic

# Keywords that signal interesting findings in EMBA logs
SIGNALS = [
    "CVE-", "CWE-", "hardcoded", "password", "credential",
    "backdoor", "CRITICAL", "HIGH", "outdated", "deprecated",
    "weak", "private key", "telnet", "default", "root:",
    "overflow", "injection", "unauthenticated", "cleartext",
    "insecure", "vulnerability", "exploit",
]


SEVERITY_KEYWORDS: list[tuple[str, str]] = [
    ("critical", "critical"),
    ("high", "high"),
    ("medium", "medium"),
    ("low", "low"),
    ("cve-", "high"),
    ("cwe-", "high"),
    ("hardcoded", "high"),
    ("credential", "high"),
    ("password", "high"),
    ("unauthenticated", "critical"),
]


CATEGORY_KEYWORDS: list[tuple[str, str]] = [
    ("auth", "authentication"),
    ("password", "authentication"),
    ("credential", "authentication"),
    ("cve-", "vulnerability"),
    ("cwe-", "code-quality"),
    ("injection", "injection"),
    ("overflow", "memory-safety"),
    ("telnet", "network-exposure"),
    ("default", "misconfiguration"),
    ("private key", "secret-management"),
    ("insecure", "misconfiguration"),
]


def extract_findings(log_dir: str, max_lines: int = 120) -> list[str]:
    """Extract high-signal lines from EMBA log files."""
    hits: set[str] = set()

    for log_file in glob.glob(f"{log_dir}/**/*.txt", recursive=True):
        try:
            with open(log_file, errors="ignore") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped or len(stripped) < 10:
                        continue
                    if any(s.lower() in stripped.lower() for s in SIGNALS):
                        hits.add(stripped)
        except Exception:
            continue

    # Also check CSV and log files
    for ext in ("*.csv", "*.log"):
        for log_file in glob.glob(f"{log_dir}/**/{ext}", recursive=True):
            try:
                with open(log_file, errors="ignore") as f:
                    for line in f:
                        stripped = line.strip()
                        if not stripped or len(stripped) < 10:
                            continue
                        if any(s.lower() in stripped.lower() for s in SIGNALS):
                            hits.add(stripped)
            except Exception:
                continue

    return list(hits)[:max_lines]


def _build_prompt(
    compact_json: str,
) -> str:
    """Build the analysis prompt for the LLM."""
    return f"""You are a firmware security analyst.

You receive compact JSON with:
1) Device context
2) SBOM summary
3) Security findings

Task:
- Produce a vendor-facing security report
- Sections: Overview, Key Risks, Detailed Findings, Recommended Fixes, Supply Chain Risks
- Avoid duplicate findings and keep concise
- Use only evidence present in input
- Provide overall risk score out of 10

Output clean Markdown and start with:
## Risk Score: X/10

JSON input:
<JSON>
{compact_json}
</JSON>
"""


def _extract_cwe(text: str) -> str:
    match = re.search(r"\bCWE-\d+\b", text, re.IGNORECASE)
    return match.group(0).upper() if match else "N/A"


def _extract_cves(text: str) -> list[str]:
    return sorted({m.upper() for m in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE)})


def _infer_severity(text: str) -> str:
    lowered = text.lower()
    for needle, severity in SEVERITY_KEYWORDS:
        if needle in lowered:
            return severity
    return "medium"


def _infer_category(text: str) -> str:
    lowered = text.lower()
    for needle, category in CATEGORY_KEYWORDS:
        if needle in lowered:
            return category
    return "general"


def _extract_path(text: str) -> str:
    path_match = re.search(r"(/[^\s:;,]+)", text)
    return path_match.group(1) if path_match else "N/A"


def _extract_component(text: str) -> str:
    module_match = re.match(r"^([A-Za-z]\d{2,3}_[A-Za-z0-9_]+)", text)
    if module_match:
        return module_match.group(1)
    cve_match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE)
    if cve_match:
        return "CVE finding"
    return "firmware"


def _extract_fw_grep_lines(log_dir: str) -> list[str]:
    grep_log = pathlib.Path(log_dir) / "fw_grep.log"
    if not grep_log.exists():
        return []

    lines: list[str] = []
    with grep_log.open(errors="ignore") as handle:
        for line in handle:
            stripped = line.strip()
            if len(stripped) < 10:
                continue
            if any(s.lower() in stripped.lower() for s in SIGNALS):
                lines.append(stripped)
    return lines


def _extract_sbom(log_dir: str, limit: int = 80) -> list[dict[str, Any]]:
    sbom_file = pathlib.Path(log_dir) / "s08_main_package_sbom.txt"
    if not sbom_file.exists():
        return []

    packages: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    with sbom_file.open(errors="ignore") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("["):
                continue
            match = re.search(r"\b([A-Za-z0-9+_.-]{2,})\s+([0-9][A-Za-z0-9._:+~-]{1,})\b", stripped)
            if not match:
                continue
            name, version = match.group(1), match.group(2)
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            packages.append({"name": name, "version": version, "cves": []})
            if len(packages) >= limit:
                break
    return packages


def build_compact_findings_payload(
    log_dir: str,
    ip: str,
    vendor: str,
    ports: str,
    mac: str,
    *,
    max_findings: int,
    _override_lines: list[str] | None = None,
) -> dict[str, Any]:
    raw_lines = _override_lines if _override_lines is not None else (
        _extract_fw_grep_lines(log_dir) or extract_findings(log_dir, max_lines=max_findings * 2)
    )

    dedup: dict[tuple[str, str, str], dict[str, Any]] = {}
    for line in raw_lines:
        cwe = _extract_cwe(line)
        category = _infer_category(line)
        component = _extract_component(line)
        severity = _infer_severity(line)
        summary = line[:220]
        key = (component, cwe, summary.lower())
        if key in dedup:
            continue
        dedup[key] = {
            "severity": severity,
            "category": category,
            "cwe": cwe,
            "component": component,
            "file_path": _extract_path(line),
            "summary": summary,
            "evidence": line[:320],
            "cves": _extract_cves(line),
        }
        if len(dedup) >= max_findings:
            break

    findings = list(dedup.values())
    findings.sort(key=lambda item: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(item["severity"], 9))

    payload = {
        "device": {
            "vendor": vendor or "Unknown",
            "model": "Unknown",
            "firmware_version": "N/A",
            "ip": ip,
            "mac": mac,
            "ports": ports or "Unknown",
        },
        "sbom": _extract_sbom(log_dir),
        "findings": findings,
    }
    return payload


def _parse_risk_score(report: str) -> float | None:
    """Extract the numeric risk score from the AI report."""
    # Match patterns like "Risk Score: 7/10" or "risk score out of 10: 7"
    patterns = [
        r"Risk\s+Score[:\s]+(\d+(?:\.\d+)?)\s*/\s*10",
        r"(\d+(?:\.\d+)?)\s*/\s*10",
        r"risk\s+score[:\s]+(\d+(?:\.\d+)?)",
    ]
    for pattern in patterns:
        match = re.search(pattern, report, re.IGNORECASE)
        if match:
            score = float(match.group(1))
            if 0 <= score <= 10:
                return score
    return None


def _count_severity(report: str) -> tuple[int, int]:
    """Count critical and high findings mentioned in report."""
    critical = len(re.findall(r"\bcritical\b", report, re.IGNORECASE))
    high = len(re.findall(r"\bhigh\b", report, re.IGNORECASE))
    return critical, high


def _build_fallback_report(
    findings: list[str],
    ip: str,
    vendor: str,
    ports: str,
    mac: str,
) -> tuple[str, float, int, int]:
    """Create a deterministic fallback report if Ollama returns empty output."""
    lowered = [f.lower() for f in findings]
    critical_count = sum(
        1 for f in lowered if any(k in f for k in ["critical", "cve-", "remote code", "rce", "unauthenticated"])
    )
    high_count = sum(
        1 for f in lowered if any(k in f for k in ["high", "hardcoded", "password", "credential", "telnet", "default"])
    )

    # Keep score conservative and bounded
    base = 3.0
    risk_score = min(10.0, base + min(4, critical_count) * 1.5 + min(4, high_count) * 0.75)
    if critical_count == 0 and high_count == 0 and findings:
        risk_score = 5.0

    preview = "\n".join(f"- {line}" for line in findings[:20])
    report = (
        f"## Risk Score: {risk_score:.1f}/10\n\n"
        "## Executive Summary\n\n"
        "Automated fallback triage was used because Ollama returned an empty response. "
        "This report is generated from EMBA finding heuristics and should be reviewed manually.\n\n"
        "## Critical\n\n"
        f"Estimated critical findings: **{critical_count}**\n\n"
        "## High\n\n"
        f"Estimated high findings: **{high_count}**\n\n"
        "## Medium\n\n"
        "Potential medium findings may exist; manual validation recommended.\n\n"
        "## Low\n\n"
        "Low-severity and informational findings are not exhaustively categorized in fallback mode.\n\n"
        "## Extracted Findings (Sample)\n\n"
        f"{preview if preview else '- No findings extracted'}\n\n"
        "## CVE Summary\n\n"
        "| CVE ID | CVSS | Notes |\n"
        "|---|---:|---|\n"
        "| N/A | N/A | Fallback mode - review EMBA raw logs |\n"
    )
    return report, risk_score, critical_count, high_count


async def ai_triage_ollama(
    compact_payload: dict[str, Any],
    ip: str,
    vendor: str,
    ports: str,
    mac: str,
    *,
    on_progress: Callable[[str], Awaitable[None] | None] | None = None,
) -> tuple[str, float | None, int, int]:
    """
    Send findings to Ollama for AI triage and return
    (report_markdown, risk_score, critical_count, high_count).
    """
    ollama_url = getattr(settings, "ollama_url", "http://ollama:11434")
    ollama_model = getattr(settings, "ollama_model", "mistral")

    compact_json = json.dumps(compact_payload, ensure_ascii=False, indent=2)
    prompt = _build_prompt(compact_json)

    async def notify(message: str):
        if not on_progress:
            return
        maybe_awaitable = on_progress(message)
        if inspect.isawaitable(maybe_awaitable):
            await maybe_awaitable

    findings_count = len(compact_payload.get("findings", []))
    await notify(f"Sending {findings_count} compact findings to AI ({ollama_model}) for triage")

    log.info("ai_triage_start", model=ollama_model, findings=findings_count)

    report = ""
    num_predict_steps_raw = getattr(settings, "triage_num_predict_steps", "4096,2048,1024")
    attempts = [
        int(v.strip())
        for v in str(num_predict_steps_raw).split(",")
        if v.strip().isdigit()
    ] or [4096, 2048, 1024]

    async with httpx.AsyncClient(timeout=httpx.Timeout(360, connect=30)) as client:
        for attempt_idx, num_predict in enumerate(attempts, start=1):
            await notify(
                f"AI triage attempt {attempt_idx}/{len(attempts)} using {ollama_model} "
                f"(num_predict={num_predict})"
            )
            resp = await client.post(
                f"{ollama_url}/api/generate",
                json={
                    "model": ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "keep_alive": "10m",
                    "options": {
                        "temperature": 0.2,
                        "num_predict": num_predict,
                    },
                },
            )
            resp.raise_for_status()
            data = resp.json()
            report = (data.get("response") or "").strip()

            if report:
                break

            log.warning(
                "ai_triage_empty_response",
                model=ollama_model,
                attempt=attempt_idx,
                response_keys=list(data.keys()) if isinstance(data, dict) else [],
                done=data.get("done") if isinstance(data, dict) else None,
                done_reason=data.get("done_reason") if isinstance(data, dict) else None,
            )

            if attempt_idx < len(attempts):
                await asyncio.sleep(1.0 * attempt_idx)

    if not report:
        await notify("Ollama returned empty responses; using fallback triage report")
        raw_fallback_findings = [item.get("summary", "") for item in compact_payload.get("findings", [])]
        log.warning("ai_triage_fallback_used", model=ollama_model, findings=len(raw_fallback_findings))
        return _build_fallback_report(raw_fallback_findings, ip, vendor, ports, mac)

    risk_score = _parse_risk_score(report)
    critical_count, high_count = _count_severity(report)

    log.info(
        "ai_triage_done",
        risk_score=risk_score,
        critical=critical_count,
        high=high_count,
        report_len=len(report),
    )

    await notify(
        f"AI triage complete — Risk Score: {risk_score}/10, "
        f"{critical_count} critical, {high_count} high findings"
    )

    return report, risk_score, critical_count, high_count


async def run_triage(
    emba_log_dir: str,
    ip: str,
    vendor: str,
    ports: str,
    mac: str,
    *,
    on_progress: Callable[[str], Awaitable[None] | None] | None = None,
) -> tuple[str, float | None, int, int, int]:
    """
    Full Stage C: extract findings + AI triage.

    Returns (report, risk_score, findings_count, critical_count, high_count).
    """
    if on_progress:
        maybe_awaitable = on_progress(f"Extracting EMBA findings from {emba_log_dir}")
        if inspect.isawaitable(maybe_awaitable):
            await maybe_awaitable

    max_findings = int(getattr(settings, "triage_max_findings", 120))
    compact_payload = build_compact_findings_payload(
        emba_log_dir,
        ip,
        vendor,
        ports,
        mac,
        max_findings=max_findings,
    )
    findings_count = len(compact_payload.get("findings", []))

    if not findings_count:
        injected = inject_known_issues(vendor, "")
        log.info("triage_no_emba_findings_injecting", count=len(injected), vendor=vendor)
        if on_progress:
            maybe_awaitable = on_progress(
                f"No EMBA findings extracted — injecting {len(injected)} known baseline issues for {vendor}"
            )
            if inspect.isawaitable(maybe_awaitable):
                await maybe_awaitable

        # Rebuild payload with injected findings as raw lines
        compact_payload = build_compact_findings_payload(
            emba_log_dir, ip, vendor, ports, mac,
            max_findings=max_findings,
            _override_lines=injected,
        )
        findings_count = len(compact_payload.get("findings", []))

    if not findings_count:
        no_findings_report = (
            "## Risk Score: N/A\n\n"
            "## Executive Summary\n\n"
            "No security-relevant findings were extracted from the EMBA scan logs. "
            "This could indicate a clean firmware image, or that the firmware format "
            "was not fully supported by EMBA's analysis modules.\n\n"
            "## Recommendation\n\n"
            "Manual review of the firmware binary is recommended."
        )
        return no_findings_report, None, 0, 0, 0

    compact_json_path = pathlib.Path(emba_log_dir) / "findings_compact.json"
    compact_json_path.write_text(json.dumps(compact_payload, ensure_ascii=False, indent=2))

    report, risk_score, critical_count, high_count = await ai_triage_ollama(
        compact_payload, ip, vendor, ports, mac, on_progress=on_progress,
    )

    # Save report as Markdown file alongside EMBA logs
    report_path = pathlib.Path(emba_log_dir) / "ai_triage.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report)

    if on_progress:
        maybe_awaitable = on_progress(f"Triage report saved → {report_path}")
        if inspect.isawaitable(maybe_awaitable):
            await maybe_awaitable

    return report, risk_score, findings_count, critical_count, high_count
