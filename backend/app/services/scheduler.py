"""
Scan job scheduler — manages the queue of scan jobs and dispatches
them to the pipeline.  Uses Redis for cross-process coordination.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis

from app.config import settings
from app.utils.logging import get_logger

log = get_logger("scheduler")

SCAN_QUEUE_KEY = "soc:scan_queue"
CANCEL_SET_KEY = "soc:scan_cancel"


class ScanScheduler:
    """Lightweight async scheduler backed by Redis lists."""

    def __init__(self):
        self._redis: aioredis.Redis | None = None
        self._task: asyncio.Task | None = None
        self._running = False

    async def _get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        return self._redis

    async def start(self):
        """Start the background consumer loop (only in the API process for enqueuing)."""
        self._running = True
        log.info("scheduler_started")

    async def stop(self):
        self._running = False
        if self._redis:
            await self._redis.close()
        log.info("scheduler_stopped")

    async def enqueue_scan(self, scan_id: uuid.UUID):
        """Push a scan ID onto the Redis queue."""
        r = await self._get_redis()
        await r.rpush(SCAN_QUEUE_KEY, str(scan_id))
        log.info("scan_enqueued", scan_id=str(scan_id))

    async def dequeue_scan(self, timeout: int = 5) -> str | None:
        """Pop the next scan ID from the queue (blocking)."""
        r = await self._get_redis()
        result = await r.blpop(SCAN_QUEUE_KEY, timeout=timeout)
        if result:
            return result[1]
        return None

    async def cancel_scan(self, scan_id: uuid.UUID):
        """Mark a scan as cancelled."""
        r = await self._get_redis()
        await r.sadd(CANCEL_SET_KEY, str(scan_id))

    async def is_cancelled(self, scan_id: uuid.UUID) -> bool:
        r = await self._get_redis()
        return await r.sismember(CANCEL_SET_KEY, str(scan_id))

    async def clear_cancel(self, scan_id: uuid.UUID):
        r = await self._get_redis()
        await r.srem(CANCEL_SET_KEY, str(scan_id))

    async def publish_progress(self, scan_id: str, data: dict):
        """Publish scan progress to a Redis channel for WebSocket fanout."""
        r = await self._get_redis()
        import json
        await r.publish(f"soc:scan:{scan_id}", json.dumps(data))


scheduler = ScanScheduler()
