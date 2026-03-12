"""
Prometheus metrics registry for the SOC firmware analysis pipeline.

Import the named metrics from this module to record observations in any
pipeline stage without re-declaring them.

Usage example:
    from app.utils.metrics import FW_PIPELINE_DURATION, FW_FINDINGS

    with FW_PIPELINE_DURATION.labels(stage="emba_scan").time():
        await run_emba(...)

    FW_FINDINGS.labels(severity="critical").inc(critical_count)
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram

FW_PIPELINE_DURATION: Histogram = Histogram(
    "firmware_pipeline_stage_duration_seconds",
    "Duration of each firmware pipeline stage in seconds",
    labelnames=["stage"],
)

FW_PIPELINE_FAILURES: Counter = Counter(
    "firmware_pipeline_failures_total",
    "Total firmware pipeline failures, labelled by stage and reason",
    labelnames=["stage", "reason"],
)

FW_FINDINGS: Counter = Counter(
    "firmware_findings_total",
    "Total firmware security findings extracted, labelled by severity",
    labelnames=["severity"],
)

FW_DOWNLOADS: Counter = Counter(
    "firmware_downloads_total",
    "Total firmware download attempts and outcomes",
    labelnames=["outcome"],   # success | retry | failed
)

FW_ALERTS_SENT: Counter = Counter(
    "firmware_alerts_sent_total",
    "Total alert notifications dispatched, labelled by level",
    labelnames=["level"],     # FAILED | TIMEOUT | HIGH_RISK
)
