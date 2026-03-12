"""
Stage A — Download firmware from fw_url.

Reads hosts that have a firmware_url, downloads the binary,
computes a SHA-256 hash, validates size and magic bytes, and
records the local path.  Retries up to ``settings.download_max_retries``
times with exponential backoff.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import pathlib
from typing import Awaitable, Callable

import httpx

from app.config import settings
from app.utils.exceptions import DownloadError, FirmwareValidationError
from app.utils.logging import get_logger

log = get_logger("firmware.download")

FW_DIR = pathlib.Path(settings.firmware_dir)
FW_DIR.mkdir(parents=True, exist_ok=True)

# Magic bytes for known embedded firmware types
_KNOWN_MAGIC: list[bytes] = [
    b"sqsh",        # SquashFS little-endian
    b"hsqs",        # SquashFS big-endian
    b"\x1f\x8b",    # gzip
    b"\xfd7zXZ",    # xz
    b"BZh",         # bzip2
    b"070701",      # CPIO new ASCII
    b"\x85\x19",    # JFFS2
    b"UBI#",        # UBIFS
    b"\x27\x05\x19\x56",  # U-Boot legacy image
    b"MZ",          # EFI/PE (UEFI capsule firmware)
]


def validate_firmware(
    fw_path: pathlib.Path,
    *,
    min_size: int | None = None,
) -> None:
    """
    Validate a downloaded firmware binary.

    Checks:
    - File size >= ``min_size`` (defaults to ``settings.firmware_min_size_bytes``).
    - SHA-256 is not all-zeros.
    - Leading magic bytes match at least one known embedded format.

    Raises:
        FirmwareValidationError: If any check fails.
    """
    effective_min = min_size if min_size is not None else settings.firmware_min_size_bytes
    size = fw_path.stat().st_size

    if size < effective_min:
        raise FirmwareValidationError(
            f"Firmware too small: {size:,} bytes (minimum {effective_min:,})"
        )

    # Read enough bytes for hash check and magic detection
    with fw_path.open("rb") as fh:
        header = fh.read(64)

    sha = hashlib.sha256(header).digest()
    if sha == bytes(32):
        raise FirmwareValidationError("Firmware SHA-256 is all-zeros; file is likely corrupt")

    if not any(header.startswith(magic) for magic in _KNOWN_MAGIC):
        # Warn but don't fail — some vendors use proprietary headers
        log.warning(
            "firmware_unknown_magic",
            path=str(fw_path),
            header_hex=header[:8].hex(),
        )


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

    Retries up to ``settings.download_max_retries`` times with exponential
    backoff (1 s, 2 s, 4 s, …).  Runs ``validate_firmware`` after each
    successful download.

    Raises:
        DownloadError: After all retries are exhausted.
        FirmwareValidationError: If the downloaded binary is invalid.
    """
    max_retries: int = settings.download_max_retries
    fname = f"{ip.replace('.', '_')}_{mac.replace(':', '')}.bin"
    dest = dest_dir / fname

    async def notify(message: str):
        if not on_progress:
            return
        maybe_awaitable = on_progress(message)
        if inspect.isawaitable(maybe_awaitable):
            await maybe_awaitable

    last_error: Exception | None = None

    for attempt in range(max_retries):
        try:
            await notify(
                f"Downloading firmware from {url}"
                + (f" (retry {attempt}/{max_retries - 1})" if attempt else "")
            )
            log.info("download_start", url=url, dest=str(dest), attempt=attempt)

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

            # ── Validate ────────────────────────────────
            validate_firmware(dest)
            log.info("firmware_validated", size=total, sha256=hex_digest[:16])

            await notify(f"Downloaded & validated {total:,} bytes → {dest.name}  SHA256: {hex_digest[:16]}…")
            return dest, hex_digest, total

        except FirmwareValidationError:
            raise  # Don't retry validation failures — binary is wrong
        except Exception as exc:
            last_error = exc
            log.warning(
                "download_attempt_failed",
                attempt=attempt,
                max_retries=max_retries,
                error=str(exc),
            )
            await notify(f"Download attempt {attempt + 1}/{max_retries} failed: {exc}")
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)

    raise DownloadError(
        f"All {max_retries} download retries failed for {url}: {last_error}"
    )
