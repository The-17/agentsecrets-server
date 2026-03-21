# Django
from django.urls import path

# Local
from .views import (
    ProjectsListCreateAPIView,
    ProjectDetailAPIView,
    ProjectInviteAPIView,
    SecretsCreateAPIView,
    SecretSingleCreateAPIView,
    SecretsListAPIView,
    SecretDetailAPIView,
    ProjectEnvironmentsAPIView,
    ProjectSecretsCoverageAPIView,
    ProjectSecretsDiffAPIView,
)

urlpatterns = [
    # Project endpoints
    path('projects/', ProjectsListCreateAPIView.as_view(), name='project-list-create'),
    path('projects/<str:project_name>/', ProjectDetailAPIView.as_view(), name='project-detail'),
    path('projects/<uuid:workspace_id>/<str:project_name>/', ProjectDetailAPIView.as_view(), name='project-detail-workspace'),
    path('projects/<uuid:workspace_id>/<str:project_name>/invite/', ProjectInviteAPIView.as_view(), name='project-invite'),

    # Environment visualization endpoints
    path('projects/<uuid:project_id>/environments/', ProjectEnvironmentsAPIView.as_view(), name='project-environments'),
    path('projects/<uuid:project_id>/secrets/coverage/', ProjectSecretsCoverageAPIView.as_view(), name='project-secrets-coverage'),
    path('projects/<uuid:project_id>/secrets/diff/', ProjectSecretsDiffAPIView.as_view(), name='project-secrets-diff'),

    # Secret endpoints
    path('secrets/', SecretSingleCreateAPIView.as_view(), name='secrets-single-create'),
    path('secrets/bulk/', SecretsCreateAPIView.as_view(), name='secrets-bulk-create'),
    path('secrets/<uuid:project_id>/', SecretsListAPIView.as_view(), name='secrets-list'),
    path('secrets/<uuid:project_id>/<str:key>/', SecretDetailAPIView.as_view(), name='secret-detail'),
    path('secrets/<uuid:project_id>/<str:environment>/<str:key>/', SecretDetailAPIView.as_view(), name='secret-detail-env'),
]