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
    AgentListCreateAPIView,
    ProjectAgentListCreateAPIView,
    AgentTokenListCreateAPIView,
    AgentTokenDeleteView,
    AuditLogListAPIView,
    AuditLogDetailAPIView,
    AuditLogSummaryAPIView,
    AuditLogExportAPIView,
    InternalAgentVerifyAPIView,
    InternalAuditLogCreateAPIView,
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

    # Agent Identity endpoints
    path('workspaces/<uuid:workspace_id>/agents/', AgentListCreateAPIView.as_view(), name='agent-list-create'),
    path('workspaces/<uuid:workspace_id>/projects/<uuid:project_id>/agents/', ProjectAgentListCreateAPIView.as_view(), name='project-agent-list-create'),
    path('agents/<str:registration_id>/tokens/', AgentTokenListCreateAPIView.as_view(), name='agent-token-list-create'),
    path('agents/<str:registration_id>/tokens/<str:token_id>/', AgentTokenDeleteView.as_view(), name='agent-token-delete'),

    # Audit Log endpoints
    path('audit/logs/', AuditLogListAPIView.as_view(), name='audit-log-list'),
    path('audit/logs/<str:log_id>/', AuditLogDetailAPIView.as_view(), name='audit-log-detail'),
    path('audit/summary/', AuditLogSummaryAPIView.as_view(), name='audit-log-summary'),
    path('audit/export/', AuditLogExportAPIView.as_view(), name='audit-log-export'),

    # Internal API endpoints
    path('internal/agents/verify/', InternalAgentVerifyAPIView.as_view(), name='internal-agent-verify'),
    path('internal/audit/logs/', InternalAuditLogCreateAPIView.as_view(), name='internal-audit-log-create'),
]
