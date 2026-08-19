from __future__ import annotations

import uuid
from django.test import TestCase
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.workspaces.models import (
    Workspace,
    Membership,
    WorkspaceType,
    MembershipRole,
    MembershipStatus,
    WorkspaceAllowlist,
)


class WorkspacesAPITests(TestCase):
    def setUp(self):
        super().setUp()
        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="SecurePassword123!",
            first_name="Owner",
            last_name="User",
        )
        self.member = User.objects.create_user(
            email="member@example.com",
            password="SecurePassword123!",
            first_name="Member",
            last_name="User",
        )
        refresh = RefreshToken.for_user(self.owner)
        self.auth_headers = {"HTTP_AUTHORIZATION": f"Bearer {refresh.access_token}"}

    def test_workspace_and_member_lifecycle(self):
        """Test workspace creation, member invites, and allowlist operations."""
        # 1. Create Workspace
        ws_res = self.client.post(
            "/api/workspaces/",
            data={"name": "Engineering Team", "encrypted_workspace_key": "enc_key_123"},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(ws_res.status_code, 201)
        ws_id = ws_res.json()["data"]["id"]

        # 2. Invite Member
        invite_payload = {
            "invites": [
                {
                    "email": "member@example.com",
                    "role": "member",
                    "encrypted_workspace_key": "member_enc_key",
                }
            ]
        }
        inv_res = self.client.post(
            f"/api/workspaces/{ws_id}/members/",
            data=invite_payload,
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(inv_res.status_code, 201)

        # 3. Add to Allowlist
        al_res = self.client.post(
            f"/api/workspaces/{ws_id}/allowlist/",
            data={"domains": ["api.stripe.com", "https://api.github.com/v1"]},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(al_res.status_code, 201)
        self.assertEqual(len(al_res.json()["data"]), 2)

        # 4. Create Agent with Token
        agent_res = self.client.post(
            f"/api/workspaces/{ws_id}/agents/",
            data={"name": "CI Bot", "label": "GitHub Actions"},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(agent_res.status_code, 201)
        agent_data = agent_res.json()["data"]
        raw_token = agent_data["token"]

        # 5. Verify Agent Token via Internal Resolver
        verify_res = self.client.post(
            "/api/internal/agents/verify/",
            data={"token": raw_token},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(verify_res.status_code, 200)
        self.assertTrue(verify_res.json()["valid"])
        self.assertEqual(verify_res.json()["agent_name"], "CI Bot")
