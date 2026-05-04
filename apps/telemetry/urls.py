# Django
from django.urls import path

# Local
from .views import TelemetrySyncAPIView, PublicMetricsAPIView, InternalComputeMetricsAPIView

urlpatterns = [
    path('sync/', TelemetrySyncAPIView.as_view(), name='telemetry-sync'),
    path('metrics/', PublicMetricsAPIView.as_view(), name='public-metrics'),
    path('internal/compute-metrics/', InternalComputeMetricsAPIView.as_view(), name='internal-compute-metrics'),
]
