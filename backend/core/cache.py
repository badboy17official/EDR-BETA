import json
from typing import Any, Optional

import redis.asyncio as redis
import structlog

from core.config import settings

logger = structlog.get_logger()


class CacheClient:
    def __init__(self):
        self._client = redis.from_url(settings.REDIS_URL, decode_responses=True)
        self._fallback: dict[str, str] = {}

    async def get_json(self, key: str) -> Optional[dict[str, Any]]:
        try:
            raw = await self._client.get(key)
            if raw is None:
                return None
            return json.loads(raw)
        except Exception as exc:
            logger.warning("cache_get_failed_fallback", key=key, error=str(exc))
            raw = self._fallback.get(key)
            return json.loads(raw) if raw else None

    async def set_json(self, key: str, value: dict[str, Any], ttl_seconds: int = 3600) -> None:
        serialized = json.dumps(value)
        try:
            await self._client.set(key, serialized, ex=ttl_seconds)
        except Exception as exc:
            logger.warning("cache_set_failed_fallback", key=key, error=str(exc))
            self._fallback[key] = serialized


cache_client = CacheClient()
