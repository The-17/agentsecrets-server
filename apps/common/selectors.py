from typing import Tuple, Dict, Any
from asgiref.sync import sync_to_async
from django.core.cache import cache

from apps.common.services.health import SystemHealthService


class HealthSelector:
    """
    Selector for retrieving cached or live system health diagnostics.
    """

    CACHE_KEY = "status_check_result"
    CACHE_TIMEOUT_SECONDS = 10

    @classmethod
    async def get_system_status(cls, fresh: bool = False) -> Tuple[int, Dict[str, Any]]:
        """
        Retrieves the system status. Returns cached diagnostic if fresh is False and cache exists.
        Otherwise executes live diagnosis pipeline via SystemHealthService.
        """
        if not fresh:
            cached_data = cache.get(cls.CACHE_KEY)
            if cached_data:
                return cached_data["code"], cached_data["data"]

        code, status_data = await sync_to_async(SystemHealthService.diagnose_system)()

        if code == 200:
            cache.set(
                cls.CACHE_KEY,
                {"code": code, "data": status_data},
                timeout=cls.CACHE_TIMEOUT_SECONDS,
            )

        return code, status_data
