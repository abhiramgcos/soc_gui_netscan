"""
Stage A — Download firmware from fw_url.

Reads hosts that have a firmware_url, downloads the binary,
computes a SHA-256 hash, and records the local path.
"""

from __future__ import annotations

import hashlib
import inspect
import pathlib
from typing import Awaitable, Callable

import httpx

from app.config import settings
from app.utils.logging import get_logger

log = get_logger("firmware.download")

FW_DIR = pathlib.Path(settings.firmware_dir)
FW_DIR.mkdir(parents=True, exist_ok=True)


async def download_firmware(
    url: str,
    ip: str,
    mac: str,
    *,
    dest_dir: pathlib.Path = FW_DIR,
    on_progress: Callable[[str], Awaitable[None] | None] | None = None,
    timeout: int = 120,
) -> tuple[pathlib.Path, str, int]:
    """
    Download firmware from *url* and return (local_path, sha256_hex, size_bytes).

    Raises on failure (timeout, HTTP error, etc.).
    """
    # Sanitise filename from MAC + IP
    fname = f"{ip.replace('.', '_')}_{mac.replace(':', '')}.bin"
    dest = dest_dir / fname

    async def notify(message: str):
        if not on_progress:
            return
        maybe_awaitable = on_progress(message)
        if inspect.isawaitable(maybe_awaitable):
            await maybe_awaitable

    await notify(f"Downloading firmware from {url}")

    log.info("download_start", url=url, dest=str(dest))

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=30),
        follow_redirects=True,
    ) as client:
        async with client.stream(
            "GET",
            url,
            headers={"User-Agent": "Mozilla/5.0 (SOC-FirmwareDownloader)"},
        ) as resp:
            resp.raise_for_status()

            sha = hashlib.sha256()
            total = 0
            with open(dest, "wb") as f:
                async for chunk in resp.aiter_bytes(8192):
                    f.write(chunk)
                    sha.update(chunk)
                    total += len(chunk)

    hex_digest = sha.hexdigest()
    log.info("download_done", dest=str(dest), sha256=hex_digest[:16], size=total)

    await notify(f"Downloaded {total:,} bytes → {dest.name}  SHA256: {hex_digest[:16]}…")

    return dest, hex_digest, total
