import json
import logging
from ninja_extra import api_controller, route
from asgiref.sync import sync_to_async

from apps.common.response import CustomResponse
from .selectors import TelemetrySelector
from .services import TelemetryService

logger = logging.getLogger("apps.telemetry")


@api_controller("/", tags=["Telemetry"], auth=None)
class TelemetryController:
    """
    Telemetry ingestion and metrics reporting controller.
    Delegates all query logic to TelemetrySelector and mutation/cron logic to TelemetryService.
    """

    @route.post("/sync/", response={200: dict, 429: dict})
    async def sync(self, request):
        """
        Receive batched CLI telemetry data.
        """
        user = await sync_to_async(TelemetryService.soft_authenticate)(request)
        allowed = await sync_to_async(TelemetryService.check_rate_limit)(request, user)
        if not allowed:
            return CustomResponse.error(
                message="Rate limit exceeded. Try again tomorrow.",
                code="rate_limited",
                status_code=429,
            )

        body = json.loads(request.body)
        await TelemetryService.process_sync_payload(request_body=body, user=user)
        return CustomResponse.success(message="Telemetry synced successfully", status_code=200)

    @route.get("/metrics/", response={200: dict})
    async def metrics(self, request, bypass_cache: bool = False):
        """
        Public metrics endpoint for the AgentSecrets website and internal dashboards.
        """
        data = await TelemetrySelector.get_platform_metrics_report(bypass_cache=bypass_cache)
        return CustomResponse.success(message="Platform metrics report", data=data, status_code=200)

    @route.get("/internal/compute-metrics/", response={200: dict, 401: dict, 500: dict})
    async def compute_metrics_get(self, request):
        """Vercel cron calls GET by default."""
        return await self._handle_cron(request)

    @route.post("/internal/compute-metrics/", response={200: dict, 401: dict, 500: dict})
    async def compute_metrics_post(self, request):
        return await self._handle_cron(request)

    async def _handle_cron(self, request):
        if not TelemetryService.verify_cron_secret(request):
            return CustomResponse.error(message="Unauthorized cron trigger", status_code=401)

        try:
            await TelemetryService.execute_cron_metrics()
            return CustomResponse.success(message="Metrics calculated successfully")
        except Exception as e:
            logger.error("Cron metrics calculation failed: %s", type(e).__name__)
            return CustomResponse.error(message="Metrics calculation failed", status_code=500)
