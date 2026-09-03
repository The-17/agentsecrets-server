from __future__ import annotations

import uuid
from django.test import TestCase
from rest_framework_simplejwt.tokens import RefreshToken

from django.utils import timezone
from apps.accounts.models import User
from apps.workspaces.models import (
    Workspace,
    Membership,
    WorkspaceType,
    MembershipRole,
    MembershipStatus,
    WorkspaceAllowlist,
    WorkspaceActivityLog,
    ForensicAuditLogEntry,
    AuditLogEntry,
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


class UnifiedEnterpriseLoggingTests(TestCase):
    def setUp(self):
        super().setUp()
        self.owner = User.objects.create_user(
            email="enterprise_admin@example.com",
            password="SecurePassword123!",
            first_name="Admin",
            last_name="User",
        )
        self.unauthorized_user = User.objects.create_user(
            email="stranger@example.com",
            password="SecurePassword123!",
            first_name="Stranger",
            last_name="User",
        )
        self.workspace = Workspace.objects.create(
            name="Production Workspace",
            owner=self.owner,
            type=WorkspaceType.SHARED,
        )
        self.membership = Membership.objects.create(
            user=self.owner,
            workspace=self.workspace,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="dummy_key_admin",
        )
        self.auth_headers = {
            "HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(self.owner).access_token}"
        }
        self.unauth_headers = {
            "HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(self.unauthorized_user).access_token}"
        }

    def test_activity_logging_and_query_api(self):
        """Test Tier 1 Managerial Activity Logs on project and secret CRUD, plus API retrieval."""
        ws_id = str(self.workspace.id)

        # 1. Create a project via API
        proj_res = self.client.post(
            "/api/projects/",
            data={"name": "payment-gateway", "description": "Core payment processing", "workspace_id": ws_id},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(proj_res.status_code, 201)
        proj_id = proj_res.json()["data"]["id"]

        # Check that activity log was recorded
        act_proj = WorkspaceActivityLog.objects.filter(workspace=self.workspace, action="project.created").first()
        self.assertIsNotNone(act_proj)
        self.assertEqual(act_proj.target_name, "payment-gateway")
        self.assertEqual(act_proj.actor_email, "enterprise_admin@example.com")

        # 2. Bulk upsert secrets
        upsert_res = self.client.post(
            "/api/secrets/",
            data={
                "project_id": proj_id,
                "environment": "production",
                "secrets": {
                    "STRIPE_API_KEY": "sk_live_secret_value_12345",
                    "WEBHOOK_SECRET": "whsec_secret_value_67890",
                },
            },
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(upsert_res.status_code, 201)

        # Check activity logs for secret creation
        secret_acts = WorkspaceActivityLog.objects.filter(workspace=self.workspace, action="secret.created")
        self.assertEqual(secret_acts.count(), 2)
        for act in secret_acts:
            # CRITICAL: verify raw secret values are NEVER in metadata or target_name
            self.assertNotIn("sk_live_secret_value", str(act.metadata))
            self.assertNotIn("whsec_secret_value", str(act.metadata))

        # 3. Update a secret
        update_res = self.client.patch(
            f"/api/secrets/{proj_id}/STRIPE_API_KEY/?environment=production",
            data={"value": "sk_live_new_value_99999"},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(update_res.status_code, 200)

        update_act = WorkspaceActivityLog.objects.filter(workspace=self.workspace, action="secret.updated").first()
        self.assertIsNotNone(update_act)
        self.assertEqual(update_act.target_name, "STRIPE_API_KEY")
        self.assertNotIn("new_value", str(update_act.metadata))

        # 4. Delete a secret
        del_res = self.client.delete(
            f"/api/secrets/{proj_id}/STRIPE_API_KEY/?environment=production",
            **self.auth_headers,
        )
        self.assertEqual(del_res.status_code, 200)

        del_act = WorkspaceActivityLog.objects.filter(workspace=self.workspace, action="secret.deleted").first()
        self.assertIsNotNone(del_act)
        self.assertEqual(del_act.target_name, "STRIPE_API_KEY")

        # 5. Query activity logs endpoint GET /api/workspaces/{workspace_id}/activity/
        get_res = self.client.get(f"/api/workspaces/{ws_id}/activity/", **self.auth_headers)
        self.assertEqual(get_res.status_code, 200)
        logs = get_res.json()["data"]
        self.assertGreaterEqual(len(logs), 4)

        # Test filter by action
        filt_res = self.client.get(f"/api/workspaces/{ws_id}/activity/?action=project.created", **self.auth_headers)
        self.assertEqual(filt_res.status_code, 200)
        self.assertEqual(len(filt_res.json()["data"]), 1)
        self.assertEqual(filt_res.json()["data"][0]["action"], "project.created")

        # Test unauthorized access (user not in workspace gets 404 Not Found)
        unauth_res = self.client.get(f"/api/workspaces/{ws_id}/activity/", **self.unauth_headers)
        self.assertEqual(unauth_res.status_code, 404)

    def test_forensic_ingest_and_replay_endpoint(self):
        """Test Tier 3 Forensic Audit Log ingestion and 4-step decision replay."""
        ws_id = str(self.workspace.id)

        # 1. Ingest forensic log via POST /api/internal/forensic/logs/
        forensic_payload = [
            {
                "id": "flog_test_decision_001",
                "workspace_id": ws_id,
                "stream_id": "stream_worker_session_42",
                "stream_seq": 1,
                "prev_chain_hash": "genesis_block",
                "chain_hash": "a1b2c3d4e5f67890",
                "entry_hash": "1122334455667788",
                "event": {
                    "type": "proxy_call",
                    "key_name": "STRIPE_SECRET_KEY",
                    "domain": "api.stripe.com",
                    "path": "/v1/charges",
                    "method": "POST",
                    "status_code": 200,
                    "outcome": "permitted",
                    "latency_ms": 14,
                },
                "snapshot": {
                    "workspace": {"id": ws_id, "name": "Production Workspace"},
                    "secrets_count": 5,
                },
                "enforcement": {
                    "decision": "permitted",
                    "decided_by": "workspace_allowlist",
                    "layers_evaluated": [
                        {"layer": "workspace_allowlist", "result": "pass", "reason": "domain match"}
                    ],
                },
                "resolution": {
                    "credential_injected": True,
                    "injection_style": "Bearer",
                    "response_scanned": True,
                    "redaction_triggered": False,
                    "response_status": 200,
                },
            }
        ]

        ingest_res = self.client.post(
            "/api/internal/forensic/logs/",
            data=forensic_payload,
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(ingest_res.status_code, 201)
        self.assertEqual(ingest_res.json()["created_count"], 1)

        # 2. Replay decision via GET /api/forensic/logs/{log_id}/replay/
        replay_res = self.client.get(
            "/api/forensic/logs/flog_test_decision_001/replay/",
            **self.auth_headers,
        )
        self.assertEqual(replay_res.status_code, 200)
        data = replay_res.json()["data"]
        self.assertEqual(data["id"], "flog_test_decision_001")
        self.assertEqual(data["stream_id"], "stream_worker_session_42")
        self.assertEqual(data["event"]["key_name"], "STRIPE_SECRET_KEY")
        self.assertEqual(data["enforcement"]["decision"], "permitted")
        self.assertEqual(data["resolution"]["credential_injected"], True)
        self.assertIn("1_event", data["steps"])
        self.assertIn("4_resolution", data["steps"])
        self.assertTrue(data["verified"])

        # 3. Unauthorized access check (user not in workspace gets 404 Not Found)
        unauth_res = self.client.get(
            "/api/forensic/logs/flog_test_decision_001/replay/",
            **self.unauth_headers,
        )
        self.assertEqual(unauth_res.status_code, 404)

        # 4. Nonexistent log check
        not_found_res = self.client.get(
            "/api/forensic/logs/nonexistent_id/replay/",
            **self.auth_headers,
        )
        self.assertEqual(not_found_res.status_code, 404)

    def test_audit_log_source_field(self):
        """Test Tier 2 AuditLogEntry source field default and filtering."""
        ws_id = str(self.workspace.id)

        # Create audit logs with cloud and cli sources
        AuditLogEntry.objects.create(
            id="log_cloud_1",
            workspace=self.workspace,
            timestamp=timezone.now(),
            target_domain="api.github.com",
            method="GET",
            duration_ms=5,
            source="cloud",
        )
        AuditLogEntry.objects.create(
            id="log_cli_1",
            workspace=self.workspace,
            timestamp=timezone.now(),
            target_domain="api.openai.com",
            method="POST",
            duration_ms=10,
            source="cli",
        )

        # Query all logs
        res_all = self.client.get(f"/api/audit/logs/?workspace_id={ws_id}", **self.auth_headers)
        self.assertEqual(res_all.status_code, 200)
        logs = res_all.json()["data"]
        self.assertEqual(len(logs), 2)
        sources = {l["source"] for l in logs}
        self.assertEqual(sources, {"cloud", "cli"})

        # Query with filter source=cli
        res_cli = self.client.get(f"/api/audit/logs/?workspace_id={ws_id}&source=cli", **self.auth_headers)
        self.assertEqual(res_cli.status_code, 200)
        logs_cli = res_cli.json()["data"]
        self.assertEqual(len(logs_cli), 1)
        self.assertEqual(logs_cli[0]["source"], "cli")

