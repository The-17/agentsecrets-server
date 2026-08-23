import uuid
import datetime
from django.utils import timezone
from django.db import transaction
from asgiref.sync import sync_to_async
from apps.common.exceptions import RequestError, NotFoundError, AuthorizationError, ErrorCode
from apps.workspaces.models import Workspace, Membership, MembershipRole
from .models import SubscriptionPlan, WorkspaceSubscription, WorkspaceUsageRecord
from .providers.factory import get_billing_provider

class BillingService:
    @staticmethod
    async def create_checkout_session(
        *,
        user,
        workspace_id: uuid.UUID,
        plan_name: str,
        return_url: str,
    ) -> str:
        ws = await Workspace.objects.filter(id=workspace_id).afirst()
        if not ws:
            raise NotFoundError("Workspace not found")

        # Verify user is Owner or Admin
        membership = await Membership.objects.filter(workspace=ws, user=user).afirst()
        if not membership or membership.role not in (MembershipRole.OWNER, MembershipRole.ADMIN):
            raise AuthorizationError("Only workspace owners or admins can manage subscriptions")

        plan = await SubscriptionPlan.objects.filter(name=plan_name).afirst()
        if not plan:
            raise NotFoundError(f"Plan '{plan_name}' not found")

        provider = get_billing_provider()
        checkout_url = await sync_to_async(provider.create_checkout_url)(
            workspace_id=str(ws.id),
            workspace_name=ws.name,
            plan_name=plan.name,
            email=user.email,
            amount_cents=plan.price_cents,
            return_url=return_url,
        )
        return checkout_url

    @staticmethod
    async def update_spend_limit(
        *,
        user,
        workspace_id: uuid.UUID,
        spend_cap_dollars: int,
    ) -> None:
        ws = await Workspace.objects.filter(id=workspace_id).afirst()
        if not ws:
            raise NotFoundError("Workspace not found")

        membership = await Membership.objects.filter(workspace=ws, user=user).afirst()
        if not membership or membership.role not in (MembershipRole.OWNER, MembershipRole.ADMIN):
            raise AuthorizationError("Only workspace owners or admins can update spend limits")

        sub, _ = await WorkspaceSubscription.objects.aget_or_create(
            workspace=ws,
            defaults={
                "plan": await SubscriptionPlan.objects.filter(name="free").afirst() or await SubscriptionPlan.objects.afirst(),
            }
        )
        sub.spend_cap_dollars = spend_cap_dollars
        await sub.asave(update_fields=["spend_cap_dollars", "updated_at"])

    @staticmethod
    @sync_to_async
    def record_usage_event(workspace_id: uuid.UUID, count: int = 1) -> None:
        now = timezone.now().date()
        start_of_month = now.replace(day=1)
        next_month = (start_of_month + datetime.timedelta(days=32)).replace(day=1)
        end_of_month = next_month - datetime.timedelta(days=1)

        with transaction.atomic():
            record, _ = WorkspaceUsageRecord.objects.select_for_update().get_or_create(
                workspace_id=workspace_id,
                billing_period_start=start_of_month,
                defaults={"billing_period_end": end_of_month},
            )
            record.event_count += count
            record.save(update_fields=["event_count", "updated_at"])

    @staticmethod
    async def handle_provider_webhook(
        *,
        provider_name: str,
        payload: bytes,
        headers: dict,
    ) -> dict:
        provider = get_billing_provider()
        event_data = await sync_to_async(provider.verify_webhook)(payload, headers)
        
        ws_id_str = event_data.get("workspace_id")
        if ws_id_str:
            try:
                ws_id = uuid.UUID(ws_id_str)
                status = event_data.get("status", "active")
                sub = await WorkspaceSubscription.objects.filter(workspace_id=ws_id).afirst()
                if sub:
                    sub.status = status
                    sub.provider_type = provider_name
                    if "customer_code" in event_data:
                        sub.external_customer_id = event_data["customer_code"]
                    if "subscription_code" in event_data:
                        sub.external_subscription_id = event_data["subscription_code"]
                    await sub.asave()
            except Exception:
                pass

        return {"received": True, "event": event_data.get("event")}
