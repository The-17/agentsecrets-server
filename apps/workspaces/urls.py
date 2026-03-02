# Django
from django.urls import path

# Local
from .views import (
    WorkspaceListCreateAPIView,
    WorkspaceDetailAPIView,
    WorkspaceMembersAPIView,
    WorkspaceMemberDetailAPIView,
    WorkspaceAllowlistAPIView,
    WorkspaceAllowlistDetailAPIView,
    WorkspaceAllowlistLogAPIView,
    WorkspaceMemberRoleAPIView,
)

urlpatterns = [
    # Workspace endpoints
    path('workspaces/', WorkspaceListCreateAPIView.as_view(), name='workspace-list-create'),
    path('workspaces/<uuid:workspace_id>/', WorkspaceDetailAPIView.as_view(), name='workspace-detail'),
    
    # Member endpoints
    path('workspaces/<uuid:workspace_id>/members/', WorkspaceMembersAPIView.as_view(), name='workspace-members'),
    path('workspaces/<uuid:workspace_id>/members/<uuid:user_id>/', WorkspaceMemberDetailAPIView.as_view(), name='workspace-member-detail'),
    path('workspaces/<uuid:workspace_id>/members/<uuid:user_id>/role/', WorkspaceMemberRoleAPIView.as_view(), name='workspace-member-role'),

    # Allowlist endpoints
    path('workspaces/<uuid:workspace_id>/allowlist/', WorkspaceAllowlistAPIView.as_view(), name='workspace-allowlist'),
    path('workspaces/<uuid:workspace_id>/allowlist/log/', WorkspaceAllowlistLogAPIView.as_view(), name='workspace-allowlist-log'),
    path('workspaces/<uuid:workspace_id>/allowlist/<str:domain>/', WorkspaceAllowlistDetailAPIView.as_view(), name='workspace-allowlist-detail'),
]
