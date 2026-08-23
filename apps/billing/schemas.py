import uuid
from typing import Optional, List, Dict, Any
from ninja import Schema
from pydantic import Field

class SubscriptionPlanItemSchema(Schema):
    id: str
    name: str
    display_name: str
    price_cents: int
    billing_interval: str
    included_events: int
    log_retention_days: int
    included_seats: int
    extra_seat_price_cents: int

class WorkspaceSubscriptionSummarySchema(Schema):
    workspace_id: str
    workspace_name: str
    plan_name: str
    plan_display_name: str
    status: str
    is_active: bool
    current_period_end: Optional[str] = None
    cancel_at_period_end: bool = False
    included_seats: int
    active_members_count: int
    extra_seats_billed: int
    usage_events_used: int
    usage_events_included: int
    usage_percentage: float
    spend_cap_dollars: int

class CheckoutRequestSchema(Schema):
    workspace_id: uuid.UUID
    plan_name: str
    return_url: str

class CheckoutResponseSchema(Schema):
    checkout_url: str

class SpendLimitUpdateSchema(Schema):
    spend_cap_dollars: int = Field(ge=5, le=5000)
