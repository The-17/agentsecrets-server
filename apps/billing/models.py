import uuid
from django.db import models
from apps.common.models import BaseModel
from apps.workspaces.models import Workspace


class SubscriptionPlan(BaseModel):
    """Available subscription plans (Free, Pro Monthly, Pro Yearly)."""
    PLAN_CHOICES = [
        ('free', 'Free Developer'),
        ('pro_monthly', 'Pro Monthly ($19/mo)'),
        ('pro_yearly', 'Pro Annual ($180/yr)'),
    ]

    id = models.UUIDField(default=uuid.uuid4, primary_key=True, unique=True)
    name = models.CharField(max_length=50, choices=PLAN_CHOICES, unique=True)
    display_name = models.CharField(max_length=100)
    price_cents = models.IntegerField(default=0, help_text="Price in USD cents")
    billing_interval = models.CharField(max_length=20, choices=[('month', 'Month'), ('year', 'Year')], default='month')
    
    included_events = models.BigIntegerField(default=10000, help_text="Included monthly events & resolution calls")
    log_retention_days = models.IntegerField(default=3, help_text="Days of historical audit logs retained")
    included_seats = models.IntegerField(default=3, help_text="Team member seats included in base price (unlimited on Pro)")
    extra_seat_price_cents = models.IntegerField(default=0, help_text="Zero per-seat penalty on Pro plan")
    
    external_plan_id = models.CharField(max_length=100, null=True, blank=True, help_text="Gateway Plan Code (e.g. Paystack PLN_xxx)")

    class Meta:
        db_table = 'billing_plans'
        ordering = ['price_cents']

    def __str__(self):
        return f"{self.display_name} ({self.name})"


class WorkspaceSubscription(BaseModel):
    """Active subscription and payment gateway profile for a Workspace."""
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('trialing', 'Trialing'),
        ('past_due', 'Past Due'),
        ('canceled', 'Canceled'),
        ('unpaid', 'Unpaid'),
    ]

    PROVIDER_CHOICES = [
        ('dummy', 'Dummy / Local Sandbox'),
        ('paystack', 'Paystack'),
        ('flutterwave', 'Flutterwave'),
        ('dodo', 'Dodo Payments'),
        ('polar', 'Polar.sh'),
        ('custom', 'Custom Gateway'),
    ]

    id = models.UUIDField(default=uuid.uuid4, primary_key=True, unique=True)
    workspace = models.OneToOneField(Workspace, on_delete=models.CASCADE, related_name='subscription')
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.PROTECT, related_name='subscriptions')
    
    provider_type = models.CharField(max_length=30, choices=PROVIDER_CHOICES, default='dummy')
    external_customer_id = models.CharField(max_length=150, null=True, blank=True, db_index=True)
    external_subscription_id = models.CharField(max_length=150, null=True, blank=True, unique=True, db_index=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    
    current_period_start = models.DateTimeField(null=True, blank=True)
    current_period_end = models.DateTimeField(null=True, blank=True)
    cancel_at_period_end = models.BooleanField(default=False)
    
    spend_cap_dollars = models.IntegerField(default=20, help_text="Hard monthly spend limit in USD")

    class Meta:
        db_table = 'workspace_subscriptions'
        indexes = [
            models.Index(fields=['workspace', 'status']),
            models.Index(fields=['external_customer_id']),
        ]

    def __str__(self):
        return f"{self.workspace.name} - {self.plan.name} ({self.status})"

    @property
    def is_active(self) -> bool:
        return self.status in ('active', 'trialing')


class WorkspaceUsageRecord(BaseModel):
    """Tracks monthly secret resolution and container boot events per billing cycle."""
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, unique=True)
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE, related_name='usage_records')
    billing_period_start = models.DateField(db_index=True)
    billing_period_end = models.DateField(db_index=True)
    
    event_count = models.BigIntegerField(default=0, help_text="Total secret resolution & workload boot events")
    overage_units_billed = models.IntegerField(default=0, help_text="Number of 50k overage blocks billed")

    class Meta:
        db_table = 'workspace_usage_records'
        unique_together = ('workspace', 'billing_period_start')
        indexes = [
            models.Index(fields=['workspace', 'billing_period_start']),
        ]

    def __str__(self):
        return f"{self.workspace.name} Usage ({self.billing_period_start}): {self.event_count} events"
