import uuid
import datetime
from django.utils import timezone
from apps.common.exceptions import NotFoundError
from apps.workspaces.models import Workspace, Membership, MembershipStatus
from .models import SubscriptionPlan, WorkspaceSubscription, WorkspaceUsageRecord

class BillingSelector:
    @staticmethod
    async def list_active_plans() -> list[dict]:
        plans = []
        async for plan in SubscriptionPlan.objects.all().order_by('price_cents'):
            plans.append({
                "id": str(plan.id),
                "name": plan.name,
                "display_name": plan.display_name,
                "price_cents": plan.price_cents,
                "billing_interval": plan.billing_interval,
                "included_events": plan.included_events,
                "log_retention_days": plan.log_retention_days,
                "included_seats": plan.included_seats,
                "extra_seat_price_cents": plan.extra_seat_price_cents,
            })
        return plans

    @staticmethod
    async def get_subscription_summary(*, workspace_id: uuid.UUID) -> dict:
        ws = await Workspace.objects.filter(id=workspace_id).afirst()
        if not ws:
            raise NotFoundError("Workspace not found")

        sub = await WorkspaceSubscription.objects.select_related('plan').filter(workspace=ws).afirst()
        if not sub:
            # Return virtual free tier defaults if no record exists yet
            plan_name = "free"
            plan_display = "Free Developer"
            included_events = 10000
            included_seats = 3
            status = "active"
            period_end = None
            cancel_at_end = False
            spend_cap = 20
        else:
            plan_name = sub.plan.name
            plan_display = sub.plan.display_name
            included_events = sub.plan.included_events
            included_seats = sub.plan.included_seats
            status = sub.status
            period_end = sub.current_period_end.isoformat() if sub.current_period_end else None
            cancel_at_end = sub.cancel_at_period_end
            spend_cap = sub.spend_cap_dollars

        active_members = await Membership.objects.filter(workspace=ws, status=MembershipStatus.ACTIVE).acount()
        extra_seats = max(0, active_members - included_seats)

        # Get current month usage record
        now = timezone.now().date()
        start_of_month = now.replace(day=1)
        usage = await WorkspaceUsageRecord.objects.filter(workspace=ws, billing_period_start=start_of_month).afirst()
        events_used = usage.event_count if usage else 0
        percentage = round((events_used / included_events) * 100, 2) if included_events > 0 else 0.0

        return {
            "workspace_id": str(ws.id),
            "workspace_name": ws.name,
            "plan_name": plan_name,
            "plan_display_name": plan_display,
            "status": status,
            "is_active": status in ('active', 'trialing'),
            "current_period_end": period_end,
            "cancel_at_period_end": cancel_at_end,
            "included_seats": included_seats,
            "active_members_count": active_members,
            "extra_seats_billed": extra_seats,
            "usage_events_used": events_used,
            "usage_events_included": included_events,
            "usage_percentage": min(100.0, percentage),
            "spend_cap_dollars": spend_cap,
        }
