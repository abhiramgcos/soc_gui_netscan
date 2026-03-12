"""
Stage G — Alert dispatch.

Sends Slack webhooks (and stub email) on pipeline failure or high-risk
completion. All failures here are non-fatal: a failed alert never
propagates to the pipeline result.
"""

from __future__ import annotations

import json

import httpx

from app.config import settings
from app.utils.logging import get_logger

log = get_logger("firmware.alerting")


async def send_alert(
    *,
    level: str,
    device_ip: str,
    analysis_id: str,
    error: str | None = None,
    risk_score: float | None = None,
    findings_count: int | None = None,
) -> None:
    """
    Fire-and-forget alert. Logs a warning on delivery failure.

    Args:
        level: "FAILED", "TIMEOUT", or "HIGH_RISK".
        device_ip: IP address of the device being analysed.
        analysis_id: UUID string of the FirmwareAnalysis record.
        error: Error message (FAILED/TIMEOUT levels).
        risk_score: AI-assigned risk score out of 10 (HIGH_RISK level).
        findings_count: Total findings count from AI triage.
    """
    if level in {"FAILED", "TIMEOUT"}:
        text = (
            f":red_circle: *Firmware scan {level}* — `{device_ip}`\n"
            f"Analysis ID: `{analysis_id}`\n"
            f"Error: `{error or 'unknown'}`"
        )
    elif level == "HIGH_RISK":
        text = (
            f":warning: *High-risk firmware detected* — `{device_ip}`\n"
            f"Analysis ID: `{analysis_id}`\n"
            f"Risk score: *{risk_score}/10*  |  Findings: {findings_count}"
        )
    else:
        text = f":information_source: Firmware scan `{level}` — `{device_ip}` (`{analysis_id}`)"

    log.info("alert_dispatch", level=level, device_ip=device_ip, analysis_id=analysis_id)

    await _send_slack(text)
    # Email stub — implement when smtp settings are added
    # await _send_email(subject=f"[SOC] Firmware {level}: {device_ip}", body=text)


async def _send_slack(text: str) -> None:
    """POST a message to the configured Slack incoming webhook."""
    url = settings.slack_webhook_url
    if not url:
        return

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                url,
                content=json.dumps({"text": text}),
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
        log.info("slack_alert_sent")
    except Exception as exc:
        log.warning("slack_alert_failed", error=str(exc))
