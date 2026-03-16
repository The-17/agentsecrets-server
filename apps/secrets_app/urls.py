# Django
from django.urls import path

# Local
from .views import (
    ProjectsListCreateAPIView,
    ProjectDetailAPIView,
    ProjectInviteAPIView,
    SecretsCreateAPIView,
    SecretsListAPIView,
    SecretDetailAPIView,
)

urlpatterns = [
    # Project endpoints
    path('projects/', ProjectsListCreateAPIView.as_view(), name='project-list-create'),
    path('projects/<str:project_name>/', ProjectDetailAPIView.as_view(), name='project-detail'),
    path('projects/<uuid:workspace_id>/<str:project_name>/', ProjectDetailAPIView.as_view(), name='project-detail-workspace'),
    path('projects/<uuid:workspace_id>/<str:project_name>/invite/', ProjectInviteAPIView.as_view(), name='project-invite'),

    # Secret endpoints
    path('secrets/', SecretsCreateAPIView.as_view(), name='secrets-bulk-create'),
    path('secrets/<uuid:project_id>/', SecretsListAPIView.as_view(), name='secrets-list'),
    path('secrets/<uuid:project_id>/<str:key>/', SecretDetailAPIView.as_view(), name='secret-detail'),
]