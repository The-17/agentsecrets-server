"""End-to-end tests for account migration between servers.

These exercise the real routes and the real service layer against the real
models:

* ``POST /api/migration/token/``  mint a single-use migration token
* ``POST /api/migration/export/`` strip the server Fernet layer, return the
  portable bundle (token-authenticated, no session needed)
* ``POST /api/migration/import/`` adopt the bundle into the authenticated
  account, re-wrapping client ciphertext under the target server key

The point of the suite is the account, not just the secrets: the importing
user must end up able to *unlock* what was migrated. That means the password
hash, the key salt and the wrapped private key travel together, and each
membership keeps the workspace key it was given on the source.
"""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.common.services.encryption import EncryptionService
from apps.migration import views as migration_views
from apps.migration.models import MigrationTokenNonce
from apps.secrets_app.models import Project, Secret
from apps.workspaces.models import (
    AgentRegistration,
    AgentToken,
    Membership,
    MembershipRole,
    MembershipStatus,
    Workspace,
    WorkspaceAllowlist,
    WorkspaceType,
)

PASSWORD = "SecurePassword123!"
CLIENT_CIPHERTEXT = "client-ciphertext-blob"


def auth_headers(user):
    refresh = RefreshToken.for_user(user)
    return {"HTTP_AUTHORIZATION": f"Bearer {refresh.access_token}"}


class MigrationFlowTests(TestCase):
    def setUp(self):
        super().setUp()
        self.owner = User.objects.create_user(
            first_name="Owner",
            last_name="User",
            email="owner@example.com",
            password=PASSWORD,
            key_salt=EncryptionService.encrypt("owner-salt"),
            public_key="owner-public-key",
            encrypted_private_key="owner-wrapped-private-key",
        )
        self.workspace = Workspace.objects.create(
            name="Personal", owner=self.owner, type=WorkspaceType.PERSONAL
        )
        Membership.objects.create(
            user=self.owner,
            workspace=self.workspace,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="workspace-key-wrapped-for-owner",
        )
        self.project = Project.objects.create(workspace=self.workspace, name="api")
        Secret.objects.create(
            project=self.project,
            environment="development",
            key="STRIPE_KEY",
            value=EncryptionService.encrypt(CLIENT_CIPHERTEXT),
            policy={"domains": ["api.stripe.com"]},
        )
        WorkspaceAllowlist.objects.create(
            workspace=self.workspace, domain="api.stripe.com", added_by=self.owner
        )
        self.agent = AgentRegistration.objects.create(
            workspace=self.workspace, name="ci-bot", created_by=self.owner
        )
        self.token = AgentToken.objects.create(
            registration=self.agent,
            workspace=self.workspace,
            token_hash="a" * 64,
            label="GitHub Actions",
            environment="development",
        )

    # ------------------------------------------------------------------ helpers

    def mint_token(self, user=None):
        user = user or self.owner
        res = self.client.post(
            "/api/migration/token/",
            data={},
            content_type="application/json",
            **auth_headers(user),
        )
        self.assertEqual(res.status_code, 200, res.content)
        return res.json()["data"]["token"]

    def export_bundle(self, token=None):
        token = token or self.mint_token()
        res = self.client.post(
            "/api/migration/export/",
            data={"token": token},
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200, res.content)
        return res.json()["data"]

    def import_bundle(self, bundle, user=None):
        return self.client.post(
            "/api/migration/import/",
            data={"bundle": bundle},
            content_type="application/json",
            **auth_headers(user or self.owner),
        )

    # --------------------------------------------------------------- auth gates

    def test_token_route_requires_authentication(self):
        res = self.client.post(
            "/api/migration/token/", data={}, content_type="application/json"
        )
        self.assertEqual(res.status_code, 401)

    def test_export_requires_a_migration_token(self):
        res = self.client.post(
            "/api/migration/export/", data={}, content_type="application/json"
        )
        self.assertEqual(res.status_code, 401)

    def test_import_requires_authentication(self):
        res = self.client.post(
            "/api/migration/import/",
            data={"bundle": {}},
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 401)

    # ------------------------------------------------------------------- token

    def test_token_route_mints_a_scoped_token(self):
        res = self.client.post(
            "/api/migration/token/",
            data={},
            content_type="application/json",
            **auth_headers(self.owner),
        )
        self.assertEqual(res.status_code, 200, res.content)
        data = res.json()["data"]
        self.assertTrue(data["token"])
        self.assertEqual(data["user_email"], "owner@example.com")
        self.assertEqual(data["workspace_count"], 1)

    def test_export_passes_through_a_legacy_plaintext_key_salt(self):
        # Rows written before the salt was encrypted at rest have no Fernet
        # envelope, so export must not hard-fail on them.
        self.owner.key_salt = "legacy-plaintext-salt"
        self.owner.save(update_fields=["key_salt"])

        bundle = self.export_bundle()
        self.assertEqual(bundle["user"]["key_salt"], "legacy-plaintext-salt")

    # ------------------------------------------------------------------ export

    def test_export_strips_server_fernet_and_carries_the_account(self):
        bundle = self.export_bundle()

        # Identity travels with the salt needed to derive the password key.
        self.assertEqual(bundle["user"]["email"], "owner@example.com")
        self.assertEqual(bundle["user"]["password_hash"], self.owner.password)
        self.assertEqual(bundle["user"]["key_salt"], "owner-salt")
        self.assertEqual(bundle["user"]["public_key"], "owner-public-key")
        self.assertEqual(
            bundle["user"]["encrypted_private_key"], "owner-wrapped-private-key"
        )

        self.assertEqual(len(bundle["workspaces"]), 1)
        ws_item = bundle["workspaces"][0]
        self.assertNotIn("slug", ws_item)
        self.assertEqual(ws_item["type"], WorkspaceType.PERSONAL)

        # The client ciphertext is exposed untouched; the server Fernet layer
        # is gone because the destination server re-wraps with its own key.
        project_item = ws_item["projects"][0]
        self.assertNotIn("slug", project_item)
        self.assertEqual(project_item["name"], "api")
        secret_item = project_item["secrets"][0]
        self.assertEqual(secret_item["client_ciphertext"], CLIENT_CIPHERTEXT)
        self.assertEqual(secret_item["key"], "STRIPE_KEY")

        member_item = ws_item["members"][0]
        self.assertEqual(member_item["role"], MembershipRole.OWNER)
        self.assertEqual(
            member_item["encrypted_workspace_key"], "workspace-key-wrapped-for-owner"
        )

        self.assertEqual(len(ws_item["allowlist"]), 1)
        self.assertEqual(ws_item["allowlist"][0]["domain"], "api.stripe.com")

        agent_item = ws_item["agents"][0]
        self.assertEqual(agent_item["id"], self.agent.id)
        self.assertNotIn("is_active", agent_item)
        token_item = agent_item["tokens"][0]
        self.assertEqual(token_item["id"], self.token.id)
        self.assertEqual(token_item["token_hash"], "a" * 64)
        self.assertNotIn("token_prefix", token_item)
        self.assertNotIn("is_active", token_item)
        self.assertIn("revoked_at", token_item)

    def test_export_only_includes_workspaces_the_user_owns(self):
        other = User.objects.create_user(
            first_name="Other",
            last_name="Owner",
            email="other@example.com",
            password=PASSWORD,
        )
        shared = Workspace.objects.create(
            name="Someone Else's Team", owner=other, type=WorkspaceType.SHARED
        )
        Membership.objects.create(
            user=self.owner,
            workspace=shared,
            role=MembershipRole.MEMBER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="wrapped-for-owner",
        )

        bundle = self.export_bundle()
        exported_ids = {item["id"] for item in bundle["workspaces"]}
        self.assertEqual(exported_ids, {str(self.workspace.id)})
        self.assertNotIn(str(shared.id), exported_ids)

    # ------------------------------------------------------------------ import

    def test_import_adopts_credentials_and_makes_secrets_readable(self):
        bundle = self.export_bundle()
        source_password_hash = self.owner.password
        source_agent_id = self.agent.id
        source_token_id = self.token.id
        source_workspace_id = self.workspace.id

        # Simulate the destination server: a fresh account with the same email
        # but its own (different) credentials, and none of the source rows.
        User.objects.all().delete()
        dest = User.objects.create_user(
            first_name="Owner",
            last_name="User",
            email="owner@example.com",
            password="DifferentPassword456!",
            key_salt=EncryptionService.encrypt("dest-salt"),
        )

        res = self.import_bundle(bundle, user=dest)
        self.assertEqual(res.status_code, 200, res.content)
        summary = res.json()["data"]["summary"]
        self.assertEqual(summary["workspaces_imported"], 1)
        self.assertEqual(summary["projects_imported"], 1)
        self.assertEqual(summary["secrets_imported"], 1)
        self.assertEqual(summary["agents_imported"], 1)

        dest.refresh_from_db()
        self.assertEqual(dest.password, source_password_hash)
        self.assertEqual(EncryptionService.decrypt(dest.key_salt), "owner-salt")
        self.assertEqual(dest.public_key, "owner-public-key")
        self.assertEqual(dest.encrypted_private_key, "owner-wrapped-private-key")

        workspace = Workspace.objects.get()
        self.assertEqual(workspace.id, source_workspace_id)
        self.assertEqual(workspace.owner_id, dest.id)
        self.assertEqual(workspace.type, WorkspaceType.PERSONAL)

        membership = Membership.objects.get(workspace=workspace, user=dest)
        self.assertEqual(
            membership.encrypted_workspace_key, "workspace-key-wrapped-for-owner"
        )

        # Re-wrapped under this server's Fernet key; unwrapping yields the
        # client ciphertext the user can already decrypt.
        secret = Secret.objects.get()
        self.assertEqual(EncryptionService.decrypt(secret.value), CLIENT_CIPHERTEXT)
        self.assertEqual(secret.environment, "development")

        agent = AgentRegistration.objects.get()
        self.assertEqual(agent.id, source_agent_id)
        self.assertTrue(agent.id.startswith("areg_"))

        token = AgentToken.objects.get()
        self.assertEqual(token.id, source_token_id)
        self.assertEqual(token.workspace_id, workspace.id)
        self.assertEqual(token.token_hash, "a" * 64)
        self.assertEqual(token.label, "GitHub Actions")

        self.assertEqual(
            WorkspaceAllowlist.objects.get().domain, "api.stripe.com"
        )

    def test_import_rejects_a_bundle_for_a_different_account(self):
        bundle = self.export_bundle()
        bundle["user"]["email"] = "someone-else@example.com"

        res = self.import_bundle(bundle)
        self.assertEqual(res.status_code, 422, res.content)
        self.assertEqual(Workspace.objects.count(), 1)
        self.assertEqual(Membership.objects.filter(user=self.owner).count(), 1)

    def test_import_is_idempotent(self):
        bundle = self.export_bundle()
        User.objects.all().delete()
        dest = User.objects.create_user(
            first_name="Owner",
            last_name="User",
            email="owner@example.com",
            password="DifferentPassword456!",
        )

        first = self.import_bundle(bundle, user=dest)
        second = self.import_bundle(bundle, user=dest)
        self.assertEqual(first.status_code, 200, first.content)
        self.assertEqual(second.status_code, 200, second.content)

        self.assertEqual(Workspace.objects.count(), 1)
        self.assertEqual(Project.objects.count(), 1)
        self.assertEqual(Secret.objects.count(), 1)
        self.assertEqual(AgentRegistration.objects.count(), 1)
        self.assertEqual(AgentToken.objects.count(), 1)
        self.assertEqual(Membership.objects.count(), 1)
        self.assertEqual(WorkspaceAllowlist.objects.count(), 1)

    def test_export_with_the_same_token_twice_is_refused(self):
        token = self.mint_token()

        first = self.client.post(
            "/api/migration/export/",
            data={"token": token},
            content_type="application/json",
        )
        self.assertEqual(first.status_code, 200, first.content)
        self.assertTrue(MigrationTokenNonce.objects.exists())

        # The token is single use, and only the source can verify it, so the
        # source burns it on the first export.
        second = self.client.post(
            "/api/migration/export/",
            data={"token": token},
            content_type="application/json",
        )
        self.assertEqual(second.status_code, 401, second.content)

    def test_import_from_source_url_pulls_the_remote_bundle(self):
        bundle = self.export_bundle()
        token = self.mint_token()

        def fake_post(url, json=None, headers=None, timeout=None):
            response = mock.Mock()
            response.status_code = 200
            response.json.return_value = {"data": bundle}
            return response

        with mock.patch.object(migration_views.requests, "post", side_effect=fake_post):
            res = self.client.post(
                "/api/migration/import/",
                data={"source_url": "https://old-server.example.com", "token": token},
                content_type="application/json",
                **auth_headers(self.owner),
            )
        self.assertEqual(res.status_code, 200, res.content)
        self.assertEqual(res.json()["data"]["summary"]["secrets_imported"], 1)

    def test_import_from_source_surfaces_an_upstream_failure(self):
        token = self.mint_token()

        def failing_post(url, json=None, headers=None, timeout=None):
            response = mock.Mock()
            response.status_code = 500
            response.text = "boom"
            return response

        with mock.patch.object(
            migration_views.requests, "post", side_effect=failing_post
        ):
            res = self.client.post(
                "/api/migration/import/",
                data={"source_url": "https://old-server.example.com", "token": token},
                content_type="application/json",
                **auth_headers(self.owner),
            )
        self.assertEqual(res.status_code, 401, res.content)
