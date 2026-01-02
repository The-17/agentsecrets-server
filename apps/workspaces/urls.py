# Django
from django.urls import path

# Local
from .views import (
    WorkspaceListCreateAPIView,
    WorkspaceDetailAPIView,
    WorkspaceMembersAPIView,
    WorkspaceMemberDetailAPIView,
)

urlpatterns = [
    # Workspace endpoints
    path('workspaces/', WorkspaceListCreateAPIView.as_view(), name='workspace-list-create'),
    path('workspaces/<uuid:workspace_id>/', WorkspaceDetailAPIView.as_view(), name='workspace-detail'),
    
    # Member endpoints
    path('workspaces/<uuid:workspace_id>/members/', WorkspaceMembersAPIView.as_view(), name='workspace-members'),
    path('workspaces/<uuid:workspace_id>/members/<uuid:user_id>/', WorkspaceMemberDetailAPIView.as_view(), name='workspace-member-detail'),
]
