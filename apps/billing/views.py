import json
import uuid
from typing import List
from ninja_extra import api_controller, route
from apps.accounts.auth import JWTAuth
from apps.common.response import CustomResponse
from apps.common.schemas import SuccessResponse, DataResponse, ErrorResponse
from .schemas import (
    SubscriptionPlanItemSchema,
    WorkspaceSubscriptionSummarySchema,
    CheckoutRequestSchema,
    CheckoutResponseSchema,
    SpendLimitUpdateSchema,
)
from .selectors import BillingSelector
from .services import BillingService


@api_controller("/billing", tags=["Billing"])
class BillingController:
    """
    Commercial subscription, usage metering, and checkout controllers.
    """

    @route.get("/plans/", response={200: DataResponse[List[SubscriptionPlanItemSchema]]}, auth=None)
    async def list_plans(self, request):
        plans = await BillingSelector.list_active_plans()
        return CustomResponse.success(message="Plans retrieved successfully", data=plans)

    @route.get("/subscription/{workspace_id}/", response={200: DataResponse[WorkspaceSubscriptionSummarySchema], 404: ErrorResponse}, auth=JWTAuth())
    async def get_subscription(self, request, workspace_id: uuid.UUID):
        summary = await BillingSelector.get_subscription_summary(workspace_id=workspace_id)
        return CustomResponse.success(message="Subscription retrieved successfully", data=summary)

    @route.post("/checkout/", response={200: DataResponse[CheckoutResponseSchema], 400: ErrorResponse, 403: ErrorResponse}, auth=JWTAuth())
    async def create_checkout(self, request, data: CheckoutRequestSchema):
        url = await BillingService.create_checkout_session(
            user=request.auth,
            workspace_id=data.workspace_id,
            plan_name=data.plan_name,
            return_url=data.return_url,
        )
        return CustomResponse.success(message="Checkout session created", data={"checkout_url": url})

    @route.put("/spend-limit/{workspace_id}/", response={200: SuccessResponse, 403: ErrorResponse}, auth=JWTAuth())
    async def update_spend_limit(self, request, workspace_id: uuid.UUID, data: SpendLimitUpdateSchema):
        await BillingService.update_spend_limit(
            user=request.auth,
            workspace_id=workspace_id,
            spend_cap_dollars=data.spend_cap_dollars,
        )
        return CustomResponse.success(message="Spend limit updated successfully")

    @route.post("/webhook/{provider}/", response={200: dict}, auth=None)
    async def receive_webhook(self, request, provider: str):
        headers = {k: v for k, v in request.headers.items()}
        result = await BillingService.handle_provider_webhook(
            provider_name=provider,
            payload=request.body,
            headers=headers,
        )
        return 200, result
