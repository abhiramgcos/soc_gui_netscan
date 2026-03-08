"""
Stage B — Run EMBA firmware analysis.

Executes EMBA on a downloaded firmware binary and stores
the log directory path.  Supports optional GPT-assisted scanning.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import pathlib
import re
from typing import Awaitable, Callable

from app.config import settings
from app.utils.logging import get_logger

log = get_logger("firmware.emba")

ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

EMBA_LOGS = pathlib.Path(settings.emba_logs_dir)
EMBA_LOGS.mkdir(parents=True, exist_ok=True)


async def run_emba(
    fw_path: str,
    device_id: str,
    ip: str,
    *,
    gpt_level: str = "1",
    on_progress: Callable[[str], Awaitable[None] | None] | None = None,
    timeout: int = 7200,  # 2 hours max
) -> str:
    """
    Run EMBA against *fw_path* and return the log directory path.

    Args:
        fw_path: Absolute path to the firmware binary.
        device_id: Unique identifier (used for log folder naming).
        ip: Device IP address (for labelling).
        gpt_level: EMBA GPT_OPTION level (1=scripts/configs, 2=+binary).
        on_progress: Optional callback for status updates.
        timeout: Maximum EMBA runtime in seconds.

    Returns:
        Path to EMBA log directory.

    Raises:
        RuntimeError: If EMBA exits with a non-zero return code.
        asyncio.TimeoutError: If EMBA exceeds the timeout.
    """
    log_dir = str(EMBA_LOGS / f"device_{device_id}_{ip.replace('.', '_')}")
    emba_path = getattr(settings, "emba_path", "/opt/emba/emba")
    emba_home = getattr(settings, "emba_home", "/opt/emba")

    resolved_emba_path = pathlib.Path(emba_path)
    fallback_emba_path = pathlib.Path(emba_home) / "emba"
    if not (resolved_emba_path.exists() and os.access(resolved_emba_path, os.X_OK)):
        if fallback_emba_path.exists() and os.access(fallback_emba_path, os.X_OK):
            resolved_emba_path = fallback_emba_path
            emba_path = str(resolved_emba_path)
        else:
            message = (
                "EMBA binary not found or not executable. "
                f"Checked EMBA_PATH='{emba_path}' and fallback '{fallback_emba_path}'. "
                "Install EMBA (./install_emba_ollama.sh) and ensure EMBA_HOME is mounted to /opt/emba."
            )
            log.error("emba_binary_missing", emba_path=emba_path, emba_home=emba_home)
            raise RuntimeError(message)

    async def notify(message: str):
        if not on_progress:
            return
        maybe_awaitable = on_progress(message)
        if inspect.isawaitable(maybe_awaitable):
            await maybe_awaitable

    await notify(f"Starting EMBA scan on {ip} ({fw_path})")

    log.info("emba_start", fw_path=fw_path, log_dir=log_dir, gpt_level=gpt_level)

    env = os.environ.copy()
    env["GPT_OPTION"] = gpt_level
    env.setdefault("USER", "root")
    env.setdefault("SUDO_USER", "root")
    env.setdefault("SUDO_UID", "0")
    env.setdefault("SUDO_GID", "0")

    cmd = [emba_path, "-f", fw_path, "-l", log_dir, "-F", "-y"]

    # Check for profile availability and extend command if needed
    gpt_profile = pathlib.Path(emba_home) / "scan-profiles/default-scan-gpt.emba"
    default_profile = pathlib.Path(emba_home) / "scan-profiles/default-scan.emba"

    if gpt_profile.exists():
        cmd = [
            emba_path,
            "-f",
            fw_path,
            "-l",
            log_dir,
            "-p",
            "scan-profiles/default-scan-gpt.emba",
            "-F",
            "-y",
        ]
    elif default_profile.exists():
        cmd = [
            emba_path,
            "-f",
            fw_path,
            "-l",
            log_dir,
            "-p",
            "scan-profiles/default-scan.emba",
            "-F",
            "-y",
        ]

    await notify(f"EMBA running on {ip} (timeout: {timeout}s)")

    async def stream_output(stream: asyncio.StreamReader | None, prefix: str):
        if stream is None:
            return
        while True:
            line = await stream.readline()
            if not line:
                break
            text = line.decode(errors="replace").strip()
            if not text:
                continue
            text = ANSI_ESCAPE_RE.sub("", text)
            text = text[:300]
            await notify(f"{prefix} {text}")

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=emba_home,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout_task = asyncio.create_task(stream_output(proc.stdout, "[EMBA]"))
        stderr_task = asyncio.create_task(stream_output(proc.stderr, "[EMBA-ERR]"))

        await asyncio.wait_for(proc.wait(), timeout=timeout)
        await asyncio.gather(stdout_task, stderr_task)

        stderr_tail = ""
        if proc.stderr is not None:
            remaining = await proc.stderr.read()
            stderr_tail = remaining.decode(errors="replace")[:2000] if remaining else ""

        if proc.returncode != 0:
            err_msg = stderr_tail or "Unknown error"
            log.error("emba_failed", returncode=proc.returncode, stderr=err_msg[:500])
            raise RuntimeError(
                f"EMBA exited with code {proc.returncode}: {err_msg[:500]}"
            )

        log.info("emba_done", log_dir=log_dir)
        await notify(f"EMBA scan completed for {ip}")

    except asyncio.TimeoutError:
        log.error("emba_timeout", timeout=timeout)
        if proc and proc.returncode is None:
            proc.kill()
        await notify(f"EMBA scan timed out after {timeout}s")
        raise

    return log_dir
