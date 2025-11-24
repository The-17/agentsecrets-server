
from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path("api/schema", SpectacularAPIView.as_view(), name="api_schema"),
    path("api/", SpectacularSwaggerView.as_view(url_name="api_schema")),

    path('admin/', admin.site.urls),
    path('accounts/', include('apps.accounts.urls')),
]
