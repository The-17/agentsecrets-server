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
    path('projects/<str:project_name>/', ProjectDetailAPIView.as_view(), name='project-detail'),
    
    # Secret endpoints
    path('secrets/', SecretsCreateAPIView.as_view(), name='secrets-bulk-create'),
    path('secrets/<str:project_name>/', SecretsListAPIView.as_view(), name='secrets-list'),
    path('secrets/<str:project_name>/<str:key>/', SecretDetailAPIView.as_view(), name='secret-detail'),
]