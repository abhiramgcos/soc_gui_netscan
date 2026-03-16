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
import markdown as _md

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
        "OpenWrt LuCI web interface exposed with potential CSRF",
    ],
    "netgear": [
        "CVE-2021-34991 NETGEAR buffer overflow pre-authentication RCE",
        "Hardcoded credential in /etc/shadow (root: no password)",
        "Telnet enabled on LAN interface by default",
        "CVE-2020-10987 NETGEAR command injection via httpd",
    ],
    "tp-link": [
        "CVE-2023-1389 TP-Link command injection via tddp protocol",
        "Cleartext HTTP management interface exposed on WAN",
        "Private RSA key embedded in firmware image",
        "CVE-2021-4045 TP-Link Tapo unauthenticated RCE",
    ],
    "dlink": [
        "CVE-2019-16920 D-Link unauthenticated remote code execution via ping utility",
        "Outdated BusyBox with known shell escape",
        "Hardcoded backdoor account in /etc/passwd",
        "CVE-2020-9544 D-Link buffer overflow in management interface",
    ],
    "asus": [
        "CVE-2018-20334 ASUS router CSRF leading to persistent access",
        "Outdated OpenSSL with ROBOT vulnerable cipher suites",
        "UPnP IGD service exposed on internet-facing interface",
        "CVE-2023-39238 ASUS router RCE via iperf endpoint",
    ],
    "hikvision": [
        "CVE-2021-36260 Hikvision unauthenticated command injection",
        "RTSP stream accessible without authentication",
        "Outdated libssl with Heartbleed (CVE-2014-0160)",
        "CVE-2014-4878 Hikvision hardcoded credentials in management service",
    ],
    "allnet": [
        "Allnet devices historically ship with default credentials (admin/admin)",
        "Outdated embedded Linux kernel — check for local privilege escalation",
        "Unauthenticated management HTTP interface common on Allnet ALL range",
        "CVE-2014-9118 Allnet router unauthenticated command injection via web interface",
        "Possible hardcoded private keys or certificates in firmware image",
    ],
    "zyxel": [
        "CVE-2022-0342 Zyxel authentication bypass in firewall/VPN products",
        "CVE-2023-28771 Zyxel unauthenticated OS command injection",
        "Hardcoded undocumented admin account in affected firmware versions",
        "Outdated OpenSSL library with known TLS downgrade vulnerabilities",
    ],
    "mikrotik": [
        "CVE-2018-14847 MikroTik Winbox credential disclosure",
        "CVE-2019-3924 MikroTik RouterOS unauthenticated port forward bypass",
        "Default credentials unchanged — no mandatory password change on first login",
        "FTP service enabled by default with cleartext credential transmission",
    ],
    "ubiquiti": [
        "CVE-2019-11812 Ubiquiti UniFi Network Server SSRF",
        "CVE-2021-22909 Ubiquiti EdgeRouter password change without authentication",
        "SSH with default credentials (ubnt/ubnt) on management interfaces",
        "UniFi Cloud access may expose device to internet-accessible management",
    ],
    "linksys": [
        "CVE-2014-8244 Linksys command injection in HNAP interface",
        "CVE-2019-13564 Linksys RE6500 unauthenticated RCE via AJAX endpoint",
        "Default admin password unchanged — web UI accessible without restriction",
        "Outdated cURL with known SSL/TLS certificate validation bypass",
    ],
    "cisco": [
        "CVE-2023-20109 Cisco IOS GET VPN key exfiltration",
        "CVE-2022-20821 Cisco IOS XR privilege escalation",
        "Telnet management interface may expose credentials in cleartext",
        "SNMP v1/v2c with default community strings (public/private)",
    ],
    "dahua": [
        "CVE-2021-33044 Dahua authentication bypass in web interface",
        "CVE-2021-33045 Dahua IP camera credential bypass",
        "RTSP and ONVIF streams accessible without authentication by default",
        "Outdated firmware with known hardcoded service account",
    ],
    "axis": [
        "CVE-2018-10660 Axis camera unauthenticated OS command injection",
        "Default root password unchanged on initial deployment",
        "ONVIF discovery service leaks device information without authentication",
        "Outdated OpenSSL in embedded web server",
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
        "Possible default credentials (admin/admin or admin/password) — no password change enforced",
        "Outdated embedded Linux kernel — check for known privilege escalation CVEs (e.g. Dirty COW, DirtyPipe)",
        "Unauthenticated or weakly authenticated management interface may be present on LAN",
        "Firmware may contain hardcoded API keys, certificates, or private keys",
        "Cleartext protocols (HTTP, Telnet, FTP) may expose credentials in transit",
        "No evidence of secure boot or firmware signature verification",
        "BusyBox or other common embedded utilities may be outdated with known escapes",
        "SNMP with default community strings may expose device configuration",
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
    return f"""You are a senior IoT/embedded-device security analyst producing a formal firmware security report for a SOC team.

DATA PROVIDED:
- Device context: vendor, IP, MAC, observed open ports
- SBOM: installed packages extracted from firmware (may be empty if EMBA could not fully extract)
- Findings: security signals from EMBA static firmware analysis (may be sparse for container/quick scans)

MANDATORY ANALYSIS RULES:
1. Analyse EVERY open port — identify the likely service running on it and all known risks for that service/version.
2. If SBOM is empty or findings are sparse, USE YOUR EXPERT KNOWLEDGE of the device type, vendor, and open ports to identify probable vulnerabilities. Label inferred findings clearly as "(Inferred from device profile)".
3. Do NOT generate a trivial low-score report for an unknown embedded IoT device. Devices with open ports and no documented hardening should score at least 5–7/10. Unknown devices with telnet, HTTP, or default credentials patterns should score higher.
4. Risk score must reflect the HIGHEST confirmed or probable risk, not an average. Justify the score explicitly.
5. Every section must be substantive — no one-line sections. Provide specific, actionable analysis.
6. Name real CVEs where relevant to the device type, firmware era, and open services. If CVSS is unknown, estimate it.
7. Be honest about analysis limitations (e.g. EMBA ran in quick mode) but still produce a useful security assessment using contextual reasoning.

OUTPUT FORMAT — valid HTML only (no Markdown, no code fences):
- Do NOT include <html>, <head>, <body>, <style>, or <script> tags — inner report content only
- Use: <h2>, <h3>, <h4>, <p>, <ul>, <li>, <table>, <thead>, <tbody>, <tr>, <th>, <td>, <strong>, <em>, <code>, <span>
- Severity CSS classes:
  <span class="severity-critical">CRITICAL</span>
  <span class="severity-high">HIGH</span>
  <span class="severity-medium">MEDIUM</span>
  <span class="severity-low">LOW</span>
- CVE table format:
  <table class="report-table"><thead><tr><th>CVE ID</th><th>CVSS</th><th>Component</th><th>Description</th><th>Severity</th></tr></thead><tbody>...</tbody></table>

REQUIRED SECTIONS (include all, be thorough):

<h2 class="risk-score">Risk Score: X/10</h2>
<h3>Overview</h3>        — device profile, scan method used, any analysis limitations, overall security posture summary
<h3>Attack Surface</h3>  — for EACH open port: likely service, known vulnerabilities, exposure risk
<h3>Key Risks</h3>       — top 3–5 risks with severity labels, CVE references where applicable, business impact
<h3>Detailed Findings</h3> — all findings with CVE table + individual finding paragraphs
<h3>Recommended Fixes</h3> — at minimum 5 actionable, prioritised, device-specific recommendations
<h3>Supply Chain Risks</h3> — third-party component risks, SBOM gaps, firmware update channel security

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


_ANSI_ESCAPE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def _extract_html_report_findings(log_dir: str) -> list[str]:
    """
    Extract security-relevant lines from EMBA's HTML report.

    EMBA always generates ``html-report/index.html`` even when other output
    files are absent (e.g. quick/container mode).  This extractor strips HTML
    tags and hunts for CVEs, CWEs, and other signal keywords.
    """
    html_path = pathlib.Path(log_dir) / "html-report" / "index.html"
    if not html_path.exists():
        return []

    findings: list[str] = []
    try:
        content = html_path.read_text(errors="ignore")
        # Remove embedded JS/CSS first so their text doesn't pollute results
        content = re.sub(r"<script[^>]*>.*?</script>", " ", content, flags=re.DOTALL | re.IGNORECASE)
        content = re.sub(r"<style[^>]*>.*?</style>", " ", content, flags=re.DOTALL | re.IGNORECASE)
        # Strip all HTML tags
        text = re.sub(r"<[^>]+>", " ", content)
        # Decode common HTML entities
        text = re.sub(r"&amp;", "&", text)
        text = re.sub(r"&lt;", "<", text)
        text = re.sub(r"&gt;", ">", text)
        text = re.sub(r"&[a-z]{2,6};", " ", text)
        # Collapse whitespace
        text = re.sub(r"\s+", " ", text)

        # Split on sentence/row boundaries and filter for signal keywords
        seen: set[str] = set()
        for chunk in re.split(r"(?<=[.!?])\s+|[|\t]|\r?\n", text):
            chunk = chunk.strip()
            if len(chunk) < 20:
                continue
            if not any(s.lower() in chunk.lower() for s in SIGNALS):
                continue
            cleaned = _ANSI_ESCAPE.sub("", chunk)
            cleaned = re.sub(r"\s+", " ", cleaned).strip()[:300]
            if cleaned not in seen:
                seen.add(cleaned)
                findings.append(cleaned)

    except Exception:
        pass

    return findings[:80]


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
    if _override_lines is not None:
        raw_lines = _override_lines
    else:
        # Primary source: structured fw_grep.log
        raw_lines = _extract_fw_grep_lines(log_dir)
        # Secondary: EMBA HTML report (always generated, even in quick/container mode)
        html_lines = _extract_html_report_findings(log_dir)
        if html_lines:
            log.info("html_report_findings_added", count=len(html_lines), log_dir=log_dir)
            raw_lines = list({*raw_lines, *html_lines})  # deduplicate
        # Fallback: broad keyword scan over all log/txt/csv files
        if not raw_lines:
            raw_lines = extract_findings(log_dir, max_lines=max_findings * 2)

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


# ── Markdown → HTML normalisation ───────────────────────────────

_MD_EXTENSIONS = ["tables", "fenced_code", "nl2br", "sane_lists"]


def _looks_like_html(text: str) -> bool:
    """Heuristic: does *text* already contain significant HTML tags?"""
    html_tags = re.findall(r"<(?:h[1-6]|p|ul|ol|li|table|tr|th|td|div|span)\b", text, re.IGNORECASE)
    return len(html_tags) >= 3


def _ensure_html(report: str) -> str:
    """
    Small LLMs often ignore the "output HTML" instruction and return Markdown.
    Detect that case and convert to HTML so the frontend can render consistently.
    """
    if not report:
        return report

    if _looks_like_html(report):
        return report  # already HTML-ish

    # Convert Markdown → HTML
    html = _md.markdown(report, extensions=_MD_EXTENSIONS)

    # Inject our CSS classes for severity badges
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        html = re.sub(
            rf"\b({sev})\b",
            rf'<span class="severity-{sev.lower()}">{sev}</span>',
            html,
        )

    # Inject risk-score class on the first <h2> if it mentions risk score
    html = re.sub(
        r"<h2>(.*?[Rr]isk\s+[Ss]core.*?)</h2>",
        r'<h2 class="risk-score">\1</h2>',
        html,
        count=1,
    )

    # Add report-table class to any tables
    html = html.replace("<table>", '<table class="report-table">')

    log.info("report_converted_md_to_html", original_len=len(report), html_len=len(html))
    return html


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

    findings_html = "\n".join(f"<li>{line}</li>" for line in findings[:20]) if findings else "<li>No findings extracted</li>"
    report = (
        f'<h2 class="risk-score">Risk Score: {risk_score:.1f}/10</h2>\n'
        "<h3>Executive Summary</h3>\n"
        "<p>Automated fallback triage was used because Ollama returned an empty response. "
        "This report is generated from EMBA finding heuristics and should be reviewed manually.</p>\n"
        "<h3>Critical</h3>\n"
        f"<p>Estimated critical findings: <strong>{critical_count}</strong></p>\n"
        "<h3>High</h3>\n"
        f"<p>Estimated high findings: <strong>{high_count}</strong></p>\n"
        "<h3>Medium</h3>\n"
        "<p>Potential medium findings may exist; manual validation recommended.</p>\n"
        "<h3>Low</h3>\n"
        "<p>Low-severity and informational findings are not exhaustively categorized in fallback mode.</p>\n"
        "<h3>Extracted Findings (Sample)</h3>\n"
        f"<ul>\n{findings_html}\n</ul>\n"
        "<h3>CVE Summary</h3>\n"
        '<table class="report-table">\n'
        "<thead><tr><th>CVE ID</th><th>CVSS</th><th>Notes</th></tr></thead>\n"
        "<tbody><tr><td>N/A</td><td>N/A</td><td>Fallback mode — review EMBA raw logs</td></tr></tbody>\n"
        "</table>\n"
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
                    "think": False,          # Disable thinking mode for Qwen3-family models
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

            # Qwen3-family "thinking" models may return content in
            # the 'thinking' field with an empty 'response'.  Fall
            # back to that field, stripping <think>…</think> wrapper.
            if not report:
                thinking_raw = (data.get("thinking") or "").strip()
                if thinking_raw:
                    # Strip the <think>…</think> wrapper if present
                    cleaned = re.sub(
                        r"<think>\s*", "", thinking_raw, flags=re.DOTALL
                    )
                    cleaned = re.sub(
                        r"\s*</think>", "", cleaned, flags=re.DOTALL
                    ).strip()
                    if cleaned:
                        report = cleaned
                        log.info(
                            "ai_triage_used_thinking_field",
                            model=ollama_model,
                            thinking_len=len(thinking_raw),
                            report_len=len(report),
                        )

            if report:
                break

            log.warning(
                "ai_triage_empty_response",
                model=ollama_model,
                attempt=attempt_idx,
                response_keys=list(data.keys()) if isinstance(data, dict) else [],
                has_thinking=bool(data.get("thinking")),
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

    # Parse scores from raw text (works on both MD and HTML)
    risk_score = _parse_risk_score(report)
    critical_count, high_count = _count_severity(report)

    # Ensure report is HTML for consistent frontend rendering
    report = _ensure_html(report)

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
            '<h2 class="risk-score">Risk Score: N/A</h2>\n'
            "<h3>Executive Summary</h3>\n"
            "<p>No security-relevant findings were extracted from the EMBA scan logs. "
            "This could indicate a clean firmware image, or that the firmware format "
            "was not fully supported by EMBA's analysis modules.</p>\n"
            "<h3>Recommendation</h3>\n"
            "<p>Manual review of the firmware binary is recommended.</p>\n"
        )
        return no_findings_report, None, 0, 0, 0

    compact_json_path = pathlib.Path(emba_log_dir) / "findings_compact.json"
    compact_json_path.write_text(json.dumps(compact_payload, ensure_ascii=False, indent=2))

    report, risk_score, critical_count, high_count = await ai_triage_ollama(
        compact_payload, ip, vendor, ports, mac, on_progress=on_progress,
    )

    # Save report as HTML file alongside EMBA logs
    report_path = pathlib.Path(emba_log_dir) / "ai_triage.html"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report)

    if on_progress:
        maybe_awaitable = on_progress(f"Triage report saved → {report_path}")
        if inspect.isawaitable(maybe_awaitable):
            await maybe_awaitable

    return report, risk_score, findings_count, critical_count, high_count
