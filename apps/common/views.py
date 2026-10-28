import logging
from django.http import JsonResponse
from ninja import Schema
from ninja_extra import api_controller, route

from apps.common.response import CustomResponse
from apps.common.selectors import HealthSelector
from apps.common.services.rewrap import check_rotation_token, rewrap_batch

logger = logging.getLogger("apps.common.status")


class SweepIn(Schema):
    """Cursor state for one rewrap batch. Cursors are the last processed pk."""

    secret_cursor: int = 0
    salt_cursor: int = 0
    limit: int = 200


@api_controller("/admin/rotation", tags=["Admin rotation"], auth=None)
class RotationController:
    """Operator-only endpoints for the platform key rotation sweep.

    POST /api/admin/rotation/rewrap/ with Authorization: Bearer <ROTATION_TOKEN>.
    Refused outright when the operator token is unset or wrong (fail closed)
    and with 409 when rotation is inactive, i.e. ENCRYPTION_KEY_NEXT is not
    configured. Secret values are never returned; only counts and primary keys.
    """

    @route.post("/rewrap/", response={200: dict, 403: dict, 409: dict})
    def rewrap(self, request, payload: SweepIn):
        auth = request.headers.get("Authorization") or ""
        presented = auth.removeprefix("Bearer ").strip()
        if not check_rotation_token(presented):
            return CustomResponse.error(
                message="Forbidden: missing or invalid operator token",
                code="forbidden",
                status_code=403,
            )
        try:
            result = rewrap_batch(
                payload.secret_cursor, payload.salt_cursor, payload.limit
            )
        except RuntimeError as exc:
            return CustomResponse.error(
                message=str(exc),
                code="rotation_inactive",
                status_code=409,
            )
        return CustomResponse.success(message="Rewrap batch complete", data=result)


def _is_fresh_request(request) -> bool:
    return (
        request.GET.get("fresh", "false").lower() == "true"
        or request.headers.get("Cache-Control") == "no-cache"
    )


async def health(request):
    """Root-level health alias for the CLI's ``/health`` probe."""
    status_code, data = await HealthSelector.get_system_status(
        fresh=_is_fresh_request(request)
    )
    return JsonResponse(data, status=status_code)


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
        status_code, data = await HealthSelector.get_system_status(
            fresh=_is_fresh_request(request)
        )
        return status_code, data
