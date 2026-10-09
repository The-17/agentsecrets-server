from __future__ import annotations

import json

from django.test import TestCase
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.workspaces.models import (
    AuditLogEntry,
    Membership,
    MembershipRole,
    MembershipStatus,
    Workspace,
    WorkspaceType,
)


class AuditLogErrorCoercionTests(TestCase):
    """Regression: a structured (dict) `error` value must not 500 the list.

    `error` is a JSONField by design, so enforcement blocks land here as
    dicts. The list serializer declares `error: str`; uncoerced, a single
    structured row 500s the entire endpoint for the workspace.
    """

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(
            email="auditcoerce@example.com",
            password="SecurePassword123!",
            first_name="A",
            last_name="C",
        )
        self.workspace = Workspace.objects.create(
            name="Audit Coerce", owner=self.user, type=WorkspaceType.SHARED)
        Membership.objects.create(
            user=self.user, workspace=self.workspace, role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE, encrypted_workspace_key="d")
        self.auth = {"HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(self.user).access_token}"}
        base = dict(
            workspace=self.workspace, timestamp=timezone.now(),
            credential_ref="K", injection_style="direct",
            target_domain="api.example.com", target_url="https://api.example.com/x",
            target_path="/x", method="GET", status_code=403, duration_ms=3,
            redacted=False, resolution_path="direct_resolve",
        )
        AuditLogEntry.objects.create(
            **base, error={"decision": "blocked", "layer": "workspace_allowlist"})
        AuditLogEntry.objects.create(**base, error="plain string failure")

    def test_list_coerces_structured_error(self):
        res = self.client.get(
            f"/api/audit/logs/?workspace_id={self.workspace.id}&limit=10",
            **self.auth)
        self.assertEqual(res.status_code, 200)
        rows = res.json()["data"]
        self.assertEqual(len(rows), 2)
        errors = sorted(r["error"] for r in rows)
        self.assertEqual(errors[0], "plain string failure")
        structured = json.loads(errors[1])
        self.assertEqual(structured["decision"], "blocked")
