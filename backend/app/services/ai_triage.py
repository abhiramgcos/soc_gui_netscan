"""
Stage C — AI triage of EMBA findings via Ollama (local LLM).

Parses EMBA output logs, extracts high-signal lines (CVEs, CWEs,
hardcoded secrets, outdated libs), and sends them to a local Ollama
instance for ranked risk reporting.
"""

from __future__ import annotations

import glob
import pathlib
import re
from typing import Callable

import httpx

from app.config import settings
from app.utils.logging import get_logger

log = get_logger("firmware.triage")

# Keywords that signal interesting findings in EMBA logs
SIGNALS = [
    "CVE-", "CWE-", "hardcoded", "password", "credential",
    "backdoor", "CRITICAL", "HIGH", "outdated", "deprecated",
    "weak", "private key", "telnet", "default", "root:",
    "overflow", "injection", "unauthenticated", "cleartext",
    "insecure", "vulnerability", "exploit",
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
    findings: list[str],
    ip: str,
    vendor: str,
    ports: str,
    mac: str,
) -> str:
    """Build the analysis prompt for the LLM."""
    context = f"""
Device: {vendor or 'Unknown'} at IP {ip} (MAC: {mac})
Open ports: {ports or 'Unknown'}

EMBA Firmware Findings ({len(findings)} items):
{chr(10).join(f'- {f}' for f in findings)}
"""
    return f"""You are an IoT firmware security analyst. Analyse the findings below and:

1. Group by severity: Critical / High / Medium / Low
2. For Critical and High: explain root cause, realistic attack vector,
   and a concrete mitigation step (1-2 sentences each)
3. List any CVE IDs found and their CVSS scores if known
4. Give an overall risk score out of 10 with a one-line justification
5. Provide a brief executive summary (2-3 sentences) at the top

{context}

Output clean Markdown with headers per severity group.
Start with: ## Risk Score: X/10
Then: ## Executive Summary
Then severity groups: ## Critical, ## High, ## Medium, ## Low
End with: ## CVE Summary (table of CVE IDs found)
"""


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


async def ai_triage_ollama(
    findings: list[str],
    ip: str,
    vendor: str,
    ports: str,
    mac: str,
    *,
    on_progress: Callable[[str], None] | None = None,
) -> tuple[str, float | None, int, int]:
    """
    Send findings to Ollama for AI triage and return
    (report_markdown, risk_score, critical_count, high_count).
    """
    ollama_url = getattr(settings, "ollama_url", "http://localhost:11434")
    ollama_model = getattr(settings, "ollama_model", "mistral")

    prompt = _build_prompt(findings, ip, vendor, ports, mac)

    if on_progress:
        on_progress(f"Sending {len(findings)} findings to AI ({ollama_model}) for triage")

    log.info("ai_triage_start", model=ollama_model, findings=len(findings))

    async with httpx.AsyncClient(timeout=httpx.Timeout(300, connect=30)) as client:
        resp = await client.post(
            f"{ollama_url}/api/generate",
            json={
                "model": ollama_model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "num_predict": 4096,
                },
            },
        )
        resp.raise_for_status()
        data = resp.json()
        report = data.get("response", "")

    if not report.strip():
        raise RuntimeError("Ollama returned an empty response")

    risk_score = _parse_risk_score(report)
    critical_count, high_count = _count_severity(report)

    log.info(
        "ai_triage_done",
        risk_score=risk_score,
        critical=critical_count,
        high=high_count,
        report_len=len(report),
    )

    if on_progress:
        on_progress(
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
    on_progress: Callable[[str], None] | None = None,
) -> tuple[str, float | None, int, int, int]:
    """
    Full Stage C: extract findings + AI triage.

    Returns (report, risk_score, findings_count, critical_count, high_count).
    """
    if on_progress:
        on_progress(f"Extracting EMBA findings from {emba_log_dir}")

    findings = extract_findings(emba_log_dir)

    if not findings:
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

    report, risk_score, critical_count, high_count = await ai_triage_ollama(
        findings, ip, vendor, ports, mac, on_progress=on_progress,
    )

    # Save report as Markdown file alongside EMBA logs
    report_path = pathlib.Path(emba_log_dir) / "ai_triage.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report)

    if on_progress:
        on_progress(f"Triage report saved → {report_path}")

    return report, risk_score, len(findings), critical_count, high_count
