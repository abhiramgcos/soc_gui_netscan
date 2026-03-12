"""Custom exceptions for the SOC firmware analysis pipeline."""

from __future__ import annotations


class DownloadError(RuntimeError):
    """Raised when firmware download fails after all retries."""


class FirmwareValidationError(ValueError):
    """Raised when a downloaded binary fails size/magic-byte validation."""


class EMBAScanError(RuntimeError):
    """Raised when the EMBA process exits with a non-zero code or produces no output."""


class EMBAScanTimeout(TimeoutError):
    """Raised when the EMBA process exceeds the configured timeout."""


class TriageError(RuntimeError):
    """Raised when AI triage fails after all Ollama retries and no fallback possible."""


class AlertError(RuntimeError):
    """Raised when sending an alert fails (non-fatal — logged only)."""
