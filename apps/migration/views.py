import logging
from typing import Optional

import requests
from asgiref.sync import sync_to_async
from django.conf import settings
from ninja_extra import api_controller, route

from apps.accounts.auth import JWTAuth
from apps.common.exceptions import AuthenticationError, BodyValidationError, NotFoundError
from apps.common.response import CustomResponse
from apps.common.schemas import DataResponse, ErrorResponse
from .schemas import (
    MigrationTokenResponseDataSchema,
    MigrationExportBundleSchema,
    MigrationImportRequestSchema,
    MigrationImportResponseDataSchema,
)
from .services import MigrationService

logger = logging.getLogger("apps.migration.views")


@api_controller("/migration", tags=["Migration"])
class MigrationController:

    @route.post("/token/", auth=JWTAuth(), response={200: DataResponse[MigrationTokenResponseDataSchema], 401: ErrorResponse})
    async def create_migration_token(self, request):
        """
        Generates a 30-minute signed migration token for the authenticated user.
        The token is restricted to exporting workspace and account credentials.
        """
        result = await MigrationService.generate_token(user=request.auth)
        return CustomResponse.success(
            message="Ephemeral migration token generated (valid for 30 minutes)",
            data=result,
        )

    @route.post("/export/", response={200: DataResponse[MigrationExportBundleSchema], 401: ErrorResponse})
    async def export_migration_data(self, request, data: Optional[MigrationImportRequestSchema] = None):
        """
        Exports the user's workspace and credential bundle.
        Requires a valid, unconsumed MigrationToken passed via 'token' field or Bearer header.
        Strips outer server Fernet encryption while keeping client AES ciphertexts intact.
        """
        token = None
        if data and data.token:
            token = data.token
        else:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ", 1)[1]

        if not token:
            raise AuthenticationError("Migration token is required")

        claims = await MigrationService.verify_token(token)
        user_email = claims.get("email")

        from apps.accounts.models import User
        try:
            user = await User.objects.aget(email=user_email)
        except User.DoesNotExist:
            raise NotFoundError("User associated with token not found")

        bundle = await MigrationService.export_bundle(user=user)
        return CustomResponse.success(
            message="Migration bundle exported successfully",
            data=bundle,
        )

    @route.post("/import/", auth=JWTAuth(), response={200: DataResponse[MigrationImportResponseDataSchema], 400: ErrorResponse, 401: ErrorResponse})
    async def import_migration_data(self, request, data: MigrationImportRequestSchema):
        """
        Imports a migration bundle into the target server.
        Can receive an inline 'bundle' payload or fetch it from 'source_url' using 'token'.
        Wraps client ciphertexts with target server's ENCRYPTION_KEY.
        """
        token_jti = None
        bundle_data = None

        if data.bundle:
            bundle_data = data.bundle.model_dump()
        elif data.source_url and data.token:
            claims = await MigrationService.verify_token(data.token)
            token_jti = claims.get("jti")

            export_endpoint = f"{data.source_url.rstrip('/')}/api/migration/export/"
            
            def fetch_remote():
                return requests.post(
                    export_endpoint,
                    json={"token": data.token},
                    headers={"Authorization": f"Bearer {data.token}"},
                    timeout=30.0,
                )

            resp = await sync_to_async(fetch_remote)()
            if resp.status_code != 200:
                raise AuthenticationError(f"Failed to fetch export bundle from source server ({resp.status_code}): {resp.text}")

            res_json = resp.json()
            bundle_data = res_json.get("data")
        else:
            raise BodyValidationError("Either 'bundle' payload or both 'source_url' and 'token' must be provided")

        if not bundle_data:
            raise BodyValidationError("Invalid or empty migration bundle")

        result = await MigrationService.import_bundle(
            requesting_user=request.auth,
            bundle_data=bundle_data,
            token_jti=token_jti,
        )

        return CustomResponse.success(
            message="Migration bundle imported successfully",
            data=result,
        )
