from __future__ import annotations

import json
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
    AgentRegistration,
    AgentToken,
    IdentityLevel,
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



class WorkloadEnvRevocationAndBillingMirrorTests(TestCase):
    """Phase C: revoked tokens must not receive env secrets; billing detach is
    resolver-confirmed only (server never self-asserts Pro)."""

    def setUp(self):
        super().setUp()
        import hashlib

        self.owner = User.objects.create_user(
            email="env_owner@example.com",
            password="SecurePassword123!",
            first_name="Env",
            last_name="Owner",
        )
        self.auth_headers = {
            "HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(self.owner).access_token}"
        }
        self.ws = Workspace.objects.create(
            name="Env Workspace",
            owner=self.owner,
            type=WorkspaceType.SHARED,
        )
        Membership.objects.create(
            user=self.owner,
            workspace=self.ws,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="dummy",
        )
        self.agent = AgentRegistration.objects.create(
            workspace=self.ws, name="env-bot", created_by=self.owner
        )
        self.raw_token = "agt_env_live_secret_abcdef123456"
        self.token = AgentToken.objects.create(
            registration=self.agent,
            workspace=self.ws,
            token_hash=hashlib.sha256(self.raw_token.encode()).hexdigest(),
            label="env-token",
        )

    def _env_call(self):
        return self.client.post(
            "/api/workloads/env/",
            data={},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.raw_token}",
        )

    def test_revoked_token_rejected_on_env_endpoint(self):
        # Valid token reaches the token-lookup (200 path; no secrets in workspace so empty map)
        resp = self._env_call()
        self.assertEqual(resp.status_code, 200)

        # Revoke the token; env delivery must now be refused (403 from
        # AuthorizationError — "Invalid or revoked workload token").
        self.token.revoked_at = timezone.now()
        self.token.save(update_fields=["revoked_at"])

        resp = self._env_call()
        self.assertEqual(resp.status_code, 403)

    def test_initialize_reserves_id_without_detaching(self):
        init = self.client.post(
            f"/api/workspaces/{self.ws.id}/billing/initialize/",
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(init.status_code, 200)
        billing_id = init.json()["data"]["billing_id"]
        self.assertTrue(billing_id.startswith("ws_bill_"))

        self.ws.refresh_from_db()
        # Reserving an id must NOT detach: tier stays free so the workspace still
        # draws the owner pool (the anti-abuse invariant).
        self.assertEqual(self.ws.billing_id, billing_id)
        self.assertEqual(self.ws.tier, "free")
        self.assertEqual(self.ws.effective_billing_id, self.owner.billing_id)

    def test_reconcile_does_not_self_assert_pro(self):
        # Even if an admin calls reconcile with no resolver confirmation, the
        # workspace must NOT flip to pro. RESOLVER_URL is unreachable here, so the
        # reconcile returns a non-pro status and leaves tier free.
        from django.test import override_settings

        init = self.client.post(
            f"/api/workspaces/{self.ws.id}/billing/initialize/",
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(init.status_code, 200)

        with override_settings(RESOLVER_URL="http://127.0.0.1:1"):
            rec = self.client.post(
                f"/api/workspaces/{self.ws.id}/billing/reconcile/",
                content_type="application/json",
                **self.auth_headers,
            )
        self.assertEqual(rec.status_code, 200)
        data = rec.json()["data"]
        self.assertEqual(data["tier"], "free")

        self.ws.refresh_from_db()
        self.assertEqual(self.ws.tier, "free")


class AuditIngestWorkspaceBindingTests(TestCase):
    """Phase C-4: audit/forensic ingest must be scoped to the caller's own workspaces
    on EVERY auth path (user JWT and agent token), not just the agent-token path."""

    def setUp(self):
        super().setUp()
        self.owner = User.objects.create_user(
            email="binding_owner@example.com",
            password="SecurePassword123!",
            first_name="Binding",
            last_name="Owner",
        )
        self.foreign_ws = Workspace.objects.create(
            name="Foreign Workspace", owner=self.owner, type=WorkspaceType.SHARED
        )
        self.my_ws = Workspace.objects.create(
            name="My Workspace", owner=self.owner, type=WorkspaceType.SHARED
        )
        Membership.objects.create(
            user=self.owner, workspace=self.my_ws,
            role=MembershipRole.OWNER, status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="k",
        )
        self.stranger = User.objects.create_user(
            email="binding_stranger@example.com",
            password="SecurePassword123!",
            first_name="Binding",
            last_name="Stranger",
        )
        self.owner_headers = {"HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(self.owner).access_token}"}
        self.stranger_headers = {"HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(self.stranger).access_token}"}

    def _audit_payload(self, ws_id):
        return [{
            "workspace_id": str(ws_id),
            "timestamp": timezone.now().isoformat(),
            "identity_level": "issued",
            "credential_ref": "k",
            "injection_style": "bearer",
            "target_domain": "api.stripe.com",
            "target_url": "https://api.stripe.com/v1/charges",
            "method": "POST",
            "status_code": 200,
            "duration_ms": 5,
            "resolution_path": "cloud",
            "source": "cloud",
        }]

    def test_user_cannot_ingest_into_unowned_workspace(self):
        # Owner is NOT a member of foreign_ws (no membership row), so ingest claiming it is dropped.
        res = self.client.post(
            "/api/internal/audit/logs/",
            data=self._audit_payload(self.foreign_ws.id),
            content_type="application/json",
            **self.owner_headers,
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["created_count"], 0)
        self.assertFalse(
            AuditLogEntry.objects.filter(workspace_id=self.foreign_ws.id).exists()
        )

    def test_member_can_ingest_into_own_workspace(self):
        res = self.client.post(
            "/api/internal/audit/logs/",
            data=self._audit_payload(self.my_ws.id),
            content_type="application/json",
            **self.owner_headers,
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["created_count"], 1)
        self.assertTrue(AuditLogEntry.objects.filter(workspace_id=self.my_ws.id).exists())

    def test_stranger_with_no_membership_cannot_ingest_anywhere(self):
        res = self.client.post(
            "/api/internal/audit/logs/",
            data=self._audit_payload(self.foreign_ws.id),
            content_type="application/json",
            **self.stranger_headers,
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["created_count"], 0)


class ForensicChainTamperTests(TestCase):
    """Phase C-5: replay verification must catch tampering. The server recomputes
    the content + linkage hashes from stored fields; editing any block flips the
    verified flag to False."""

    def setUp(self):
        super().setUp()
        self.owner = User.objects.create_user(
            email="chain_owner@example.com",
            password="SecurePassword123!",
            first_name="Chain",
            last_name="Owner",
        )
        self.ws = Workspace.objects.create(name="Chain WS", owner=self.owner, type=WorkspaceType.SHARED)
        Membership.objects.create(
            user=self.owner, workspace=self.ws,
            role=MembershipRole.OWNER, status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="k",
        )
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(self.owner).access_token}"}

    def _ingest(self):
        payload = [{
            "id": "flog_chain_tamper_001",
            "workspace_id": str(self.ws.id),
            "stream_id": "stream_tamper",
            "stream_seq": 1,
            "prev_chain_hash": "genesis_block",
            "event": {"type": "proxy_call", "key_name": "STRIPE_KEY", "domain": "api.stripe.com"},
            "snapshot": {"workspace": {"id": str(self.ws.id)}},
            "enforcement": {"decision": "permitted", "decided_by": "allowlist"},
            "resolution": {"credential_injected": True, "response_status": 200},
        }]
        return self.client.post("/api/internal/forensic/logs/", data=payload, content_type="application/json", **self.headers)

    def _replay(self, log_id="flog_chain_tamper_001"):
        return self.client.get(f"/api/forensic/logs/{log_id}/replay/", **self.headers)

    def test_genuine_record_verifies(self):
        res = self._ingest()
        self.assertEqual(res.status_code, 201)
        replay = self._replay()
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.json()["data"]["verified"])

    def test_tampered_content_flips_verified(self):
        self._ingest()
        log = ForensicAuditLogEntry.objects.get(id="flog_chain_tamper_001")
        # Tamper with the stored decision content directly (as a DB-level edit would).
        log.event_json = {"type": "proxy_call", "key_name": "EVIL_KEY", "domain": "evil.example"}
        log.save(update_fields=["event_json"])

        replay = self._replay()
        self.assertEqual(replay.status_code, 200)
        self.assertFalse(replay.json()["data"]["verified"])


class AuditExportPaginationTests(TestCase):
    """Phase C-6: export must be keyset-paginated with a hard cap and explicit fields."""

    def setUp(self):
        super().setUp()
        self.owner = User.objects.create_user(
            email="export_owner@example.com",
            password="SecurePassword123!",
            first_name="Export",
            last_name="Owner",
        )
        self.ws = Workspace.objects.create(name="Export WS", owner=self.owner, type=WorkspaceType.SHARED)
        Membership.objects.create(
            user=self.owner, workspace=self.ws,
            role=MembershipRole.OWNER, status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="k",
        )
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(self.owner).access_token}"}
        # Seed a batch of audit rows with distinct timestamps so keyset pagination
        # order is deterministic.
        from datetime import timedelta
        base_ts = timezone.now()
        for i in range(60):
            AuditLogEntry.objects.create(
                workspace_id=self.ws.id,
                timestamp=base_ts - timedelta(minutes=i),
                identity_level=IdentityLevel.ISSUED,
                credential_ref=f"k{i}",
                injection_style="bearer",
                target_domain="api.stripe.com",
                target_url="https://api.stripe.com/v1/charges",
                method="POST",
                status_code=200,
                duration_ms=5,
                resolution_path="cloud",
                source="cloud",
            )

    def test_export_streams_all_rows_without_duplication(self):
        from django.test import Client
        resp = self.client.get(f"/api/audit/export/?workspace_id={self.ws.id}", **self.headers)
        self.assertEqual(resp.status_code, 200)
        lines = [ln for ln in resp.streaming_content if ln.strip()]
        self.assertEqual(len(lines), 60)
        ids = {json.loads(ln)["id"] for ln in lines}
        self.assertEqual(len(ids), 60)
