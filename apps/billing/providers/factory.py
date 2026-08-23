import os
from django.conf import settings
from .base import BaseBillingProvider
from .dummy import DummyBillingProvider
from .paystack import PaystackBillingProvider
from .lemonsqueezy import LemonSqueezyBillingProvider

def get_billing_provider() -> BaseBillingProvider:
    provider_name = getattr(settings, "BILLING_PROVIDER", os.environ.get("BILLING_PROVIDER", "dummy")).lower()
    if provider_name == "paystack":
        return PaystackBillingProvider()
    elif provider_name == "lemonsqueezy":
        return LemonSqueezyBillingProvider()
    return DummyBillingProvider()
