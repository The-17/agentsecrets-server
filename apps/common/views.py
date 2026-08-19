import logging
from ninja_extra import api_controller, route

from apps.common.response import CustomResponse
from apps.common.selectors import HealthSelector

logger = logging.getLogger("apps.common.status")


@api_controller("/status", tags=["Status"], auth=None)
class StatusController:
    """
    Public health and status endpoint checking all system capabilities.
    """

    @route.get("/", response={200: dict, 503: dict})
    async def status_root(self, request):
        return await self._get_status_response(request)

    @route.get("/health/", response={200: dict, 503: dict})
    async def status_health(self, request):
        return await self._get_status_response(request)

    async def _get_status_response(self, request):
        fresh = (
            request.GET.get("fresh", "false").lower() == "true"
            or request.headers.get("Cache-Control") == "no-cache"
        )
        status_code, data = await HealthSelector.get_system_status(fresh=fresh)
        return status_code, data
