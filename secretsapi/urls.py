# Django
from django.contrib import admin
from django.urls import path, include

# Third-party
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    # API Documentation
    path("api/schema", SpectacularAPIView.as_view(), name="api_schema"),
    path("api/", SpectacularSwaggerView.as_view(url_name="api_schema")),

    # Admin
    path('admin/', admin.site.urls),
    
    # API Routes
    path('api/', include('apps.accounts.urls')),
    path('api/', include('apps.secrets_app.urls')),
    path('api/', include('apps.workspaces.urls')),

    # Telemetry (separate from main API — not in Swagger docs)
    path('telemetry/', include('apps.telemetry.urls')),
]

