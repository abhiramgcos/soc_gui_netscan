"""
Stage B — Run EMBA firmware analysis.

Executes EMBA on a downloaded firmware binary and stores
the log directory path.  Supports optional GPT-assisted scanning.
"""

from __future__ import annotations

import asyncio
import os
import pathlib
from typing import Callable

from app.config import settings
from app.utils.logging import get_logger

log = get_logger("firmware.emba")

EMBA_LOGS = pathlib.Path("/app/emba_logs")
EMBA_LOGS.mkdir(parents=True, exist_ok=True)


async def run_emba(
    fw_path: str,
    device_id: str,
    ip: str,
    *,
    gpt_level: str = "1",
    on_progress: Callable[[str], None] | None = None,
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

    if on_progress:
        on_progress(f"Starting EMBA scan on {ip} ({fw_path})")

    log.info("emba_start", fw_path=fw_path, log_dir=log_dir, gpt_level=gpt_level)

    env = os.environ.copy()
    env["GPT_OPTION"] = gpt_level

    # Build EMBA command
    cmd = [
        "sudo", emba_path,
        "-f", fw_path,
        "-l", log_dir,
    ]

    # Use GPT scan profile if available
    gpt_profile = "/opt/emba/scan-profiles/default-scan-gpt.emba"
    default_profile = "/opt/emba/scan-profiles/default-scan.emba"

    if pathlib.Path(gpt_profile).exists():
        cmd.extend(["-p", gpt_profile])
    elif pathlib.Path(default_profile).exists():
        cmd.extend(["-p", default_profile])

    cmd.append("-g")  # generate grep-able log

    if on_progress:
        on_progress(f"EMBA running: {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        if proc.returncode != 0:
            err_msg = stderr.decode(errors="replace")[:2000] if stderr else "Unknown error"
            log.error("emba_failed", returncode=proc.returncode, stderr=err_msg[:500])
            raise RuntimeError(
                f"EMBA exited with code {proc.returncode}: {err_msg[:500]}"
            )

        log.info("emba_done", log_dir=log_dir)
        if on_progress:
            on_progress(f"EMBA scan completed for {ip}")

    except asyncio.TimeoutError:
        log.error("emba_timeout", timeout=timeout)
        if proc and proc.returncode is None:
            proc.kill()
        raise

    return log_dir
