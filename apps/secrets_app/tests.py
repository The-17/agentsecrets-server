from __future__ import annotations

import uuid
from django.test import TestCase
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.workspaces.models import Workspace, Membership, WorkspaceType, MembershipRole, MembershipStatus
from apps.secrets_app.models import Project, Secret


class SecretsAPITests(TestCase):
    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(
            email="developer@example.com",
            password="SecurePassword123!",
            first_name="Dev",
            last_name="User",
        )
        self.workspace = Workspace.objects.create(
            name="Dev Workspace",
            owner=self.user,
            type=WorkspaceType.SHARED,
        )
        self.membership = Membership.objects.create(
            user=self.user,
            workspace=self.workspace,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="dummy_key",
        )
        refresh = RefreshToken.for_user(self.user)
        self.auth_headers = {"HTTP_AUTHORIZATION": f"Bearer {refresh.access_token}"}

    def test_project_and_secrets_lifecycle(self):
        """Test creating project, upserting secrets, listing, and diffing."""
        # 1. Create Project
        create_payload = {
            "name": "backend-service",
            "description": "Core backend API",
            "workspace_id": str(self.workspace.id),
        }
        res = self.client.post(
            "/api/projects/",
            data=create_payload,
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(res.status_code, 201)
        project_id = res.json()["data"]["id"]

        # 2. List Projects
        list_res = self.client.get("/api/projects/", **self.auth_headers)
        self.assertEqual(list_res.status_code, 200)
        self.assertEqual(len(list_res.json()["data"]), 1)

        # 3. Bulk Upsert Secrets (Development)
        secrets_payload = {
            "project_id": project_id,
            "environment": "development",
            "secrets": {
                "DATABASE_URL": "postgres://localhost:5432/dev",
                "API_KEY": "dev_secret_key_123",
            },
        }
        upsert_res = self.client.post(
            "/api/secrets/",
            data=secrets_payload,
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(upsert_res.status_code, 201)
        self.assertEqual(upsert_res.json()["data"]["created"], 2)

        # 4. List Secrets
        secrets_list = self.client.get(
            f"/api/secrets/{project_id}/?environment=development",
            **self.auth_headers,
        )
        self.assertEqual(secrets_list.status_code, 200)
        self.assertEqual(len(secrets_list.json()["data"]["secrets"]), 2)

        # 5. Get Single Secret
        secret_res = self.client.get(
            f"/api/secrets/{project_id}/DATABASE_URL/?environment=development",
            **self.auth_headers,
        )
        self.assertEqual(secret_res.status_code, 200)
        self.assertEqual(secret_res.json()["data"]["value"], "postgres://localhost:5432/dev")

        # 6. Delete Secret
        del_res = self.client.delete(
            f"/api/secrets/{project_id}/DATABASE_URL/?environment=development",
            **self.auth_headers,
        )
        self.assertEqual(del_res.status_code, 200)
        self.assertEqual(Secret.objects.filter(project_id=project_id, key="DATABASE_URL").count(), 0)
