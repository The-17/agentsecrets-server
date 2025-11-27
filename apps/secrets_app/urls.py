from django.urls import path
from .views import (
    ProjectsListCreateAPIView,
    ProjectDetailAPIView,
    SecretsCreateAPIView,
    SecretsListAPIView,
    SecretDetailAPIView,
)

urlpatterns = [
    # Project endpoints
    path('projects/', ProjectsListCreateAPIView.as_view(), name='project-list-create'),
    path('projects/<uuid:project_id>/', ProjectDetailAPIView.as_view(), name='project-detail'),
    
    # Secret endpoints
    path('secrets/', SecretsCreateAPIView.as_view(), name='secrets-bulk-create'),
    path('secrets/<uuid:project_id>/', SecretsListAPIView.as_view(), name='secrets-list'),
    path('secrets/<uuid:project_id>/<str:key>/', SecretDetailAPIView.as_view(), name='secret-detail'),
]