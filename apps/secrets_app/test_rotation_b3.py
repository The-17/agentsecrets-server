from __future__ import annotations

import base64
import hashlib
import json
import time

from django.test import TestCase
from nacl.signing import SigningKey
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.workspaces.models import (
    Workspace,
    Membership,
    MembershipRole,
    MembershipStatus,
    WorkspaceType,
)
from apps.secrets_app.models import Secret


class ProviderBindingTests(TestCase):
    """B3 HR-M2: admin credential binding validated at arm and execute time."""

    ADMIN_CT = "REDACTED_DEK_CT_ADMIN_DSN"
    LEAF_CT = "REDACTED_DEK_CT_LEAF"

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(
            email="b3owner@example.com",
            password="SecurePassword123!",
            first_name="B3",
            last_name="Owner",
        )
        self.workspace = Workspace.objects.create(
            name="B3 Workspace",
            owner=self.user,
            type=WorkspaceType.SHARED,
        )
        Membership.objects.create(
            user=self.user,
            workspace=self.workspace,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="dummy",
        )
        self.auth_headers = {
            "HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(self.user).access_token}"
        }
        proj_res = self.client.post(
            "/api/projects/",
            data={"name": "db", "description": "d", "workspace_id": str(self.workspace.id)},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(proj_res.status_code, 201)
        self.project_id = proj_res.json()["data"]["id"]
        other_res = self.client.post(
            "/api/projects/",
            data={"name": "other", "description": "d", "workspace_id": str(self.workspace.id)},
            content_type="application/json",
            **self.auth_headers,
        )
        self.other_project_id = other_res.json()["data"]["id"]
        for pid, secrets in (
            (self.project_id, {"APP_DB_PASSWORD": self.LEAF_CT, "PGADMIN_DSN": self.ADMIN_CT}),
            (self.other_project_id, {"FOREIGN_DSN": self.ADMIN_CT}),
        ):
            upsert = self.client.post(
                "/api/secrets/",
                data={"project_id": pid, "environment": "production", "secrets": secrets},
                content_type="application/json",
                **self.auth_headers,
            )
            self.assertEqual(upsert.status_code, 201)
        self.signing_key = SigningKey.generate()
        self.verify_hex = self.signing_key.verify_key.encode().hex()

    def _base(self, key="APP_DB_PASSWORD", project_id=None):
        return f"/api/secrets/{project_id or self.project_id}/production/{key}"

    def _signed(self, method, path, body: bytes = b""):
        ts = str(int(time.time()))
        payload = "\n".join([ts, method, path, hashlib.sha256(body).hexdigest()])
        sig = base64.b64encode(self.signing_key.sign(payload.encode()).signature).decode()
        return {
            "HTTP_X_RESOLVER_KEY_ID": "test-key",
            "HTTP_X_RESOLVER_TIMESTAMP": ts,
            "HTTP_X_RESOLVER_SIGNATURE": sig,
        }

    def _arm(self, binding, key="APP_DB_PASSWORD", expected=200):
        binding = {"target_user": "app", **binding}
        res = self.client.put(
            self._base(key) + "/rotation-policy/",
            data={"rotation_type": "value_provider", "period_days": 30,
                  "provider_binding": binding},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(res.status_code, expected)
        return res

    def test_arm_rejects_missing_target_user(self):
        res = self.client.put(
            self._base() + "/rotation-policy/",
            data={"rotation_type": "value_provider", "period_days": 30,
                  "provider_binding": {"adapter": "postgres", "admin_credential_ref": "PGADMIN_DSN"}},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(res.status_code, 422)

    def _execute(self, rotation_id, expected=200):
        body = json.dumps({
            "workspace_id": str(self.workspace.id),
            "project_id": self.project_id,
            "environment": "production",
            "key": "APP_DB_PASSWORD",
            "ciphertext": "REDACTED_DEK_CT_B3_NEW",
            "rotation_id": rotation_id,
            "reason": "routine",
        }).encode()
        with self.settings(RESOLVER_SIGNING_PUBKEY=self.verify_hex):
            res = self.client.post(
                "/api/internal/rotation/value-execute/", data=body,
                content_type="application/json",
                **self._signed("POST", "/api/internal/rotation/value-execute/", body),
            )
        self.assertEqual(res.status_code, expected)
        return res

    def test_arm_valid_binding(self):
        res = self._arm({"adapter": "postgres", "admin_credential_ref": "pgadmin_dsn"})
        policy = res.json()["data"]["policy"]
        self.assertEqual(policy["rotation_type"], "value_provider")
        self.assertEqual(policy["rotation_binding"]["admin_credential_ref"], "PGADMIN_DSN")
        # Phase-1 backfill: no ref supplied -> bundled pin, no hash.
        self.assertEqual(policy["rotation_binding"]["adapter_ref"], "postgres@1.0.0")

    def test_arm_stores_explicit_ref(self):
        res = self._arm({"adapter": "postgres", "admin_credential_ref": "pgadmin_dsn",
                         "adapter_ref": "postgres@1.0.0#sha256:" + "ab" * 32})
        policy = res.json()["data"]["policy"]
        self.assertTrue(policy["rotation_binding"]["adapter_ref"].endswith("#sha256:" + "ab" * 32))

    def test_arm_rejects_bad_refs(self):
        base = {"adapter": "postgres", "admin_credential_ref": "pgadmin_dsn"}
        self._arm({**base, "adapter_ref": "postgres"}, expected=422)
        self._arm({**base, "adapter_ref": "postgres@v1"}, expected=422)
        self._arm({**base, "adapter_ref": "stripe@1.0.0"}, expected=422)
        self._arm({**base, "adapter_ref": "postgres@1.0.0#sha256:xyz"}, expected=422)

    def test_arm_rejects_bad_bindings(self):
        self._arm({"adapter": "stripe"}, expected=422)
        self._arm({"adapter": "postgres"}, expected=422)
        self._arm({"adapter": "postgres", "admin_credential_ref": "NOPE_MISSING"}, expected=422)
        self._arm({"adapter": "postgres", "admin_credential_ref": "APP_DB_PASSWORD"}, expected=422)

    def test_arm_rejects_cross_project_ref(self):
        upsert = self.client.post(
            "/api/secrets/",
            data={"project_id": self.other_project_id, "environment": "production",
                  "secrets": {"ADMIN2": self.ADMIN_CT}},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(upsert.status_code, 201)
        other = self.client.put(
            f"/api/secrets/{self.other_project_id}/production/FOREIGN_DSN/rotation-policy/",
            data={"rotation_type": "value_provider", "period_days": 30,
                  "provider_binding": {"adapter": "postgres", "admin_credential_ref": "ADMIN2",
                                       "target_user": "app"}},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(other.status_code, 200)

        res = self.client.put(
            self._base() + "/rotation-policy/",
            data={"rotation_type": "value_provider", "period_days": 30,
                  "provider_binding": {"adapter": "postgres", "admin_credential_ref": "FOREIGN_DSN",
                                       "target_user": "app"}},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(res.status_code, 422)

    def test_arm_rejects_binding_with_client_type(self):
        res = self.client.put(
            self._base() + "/rotation-policy/",
            data={"rotation_type": "value_client", "period_days": 30,
                  "provider_binding": {"adapter": "postgres", "admin_credential_ref": "PGADMIN_DSN"}},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(res.status_code, 422)

    def test_execute_provider_success(self):
        self._arm({"adapter": "postgres", "admin_credential_ref": "PGADMIN_DSN"})
        result = self._execute("b3-1").json()["data"]
        self.assertIsNotNone(result["current_version_id"])
        self.assertIsNotNone(result["previous_version_id"])

        value = self.client.get(
            self._base() + "/", **self.auth_headers).json()["data"]["value"]
        self.assertEqual(value, "REDACTED_DEK_CT_B3_NEW")

    def test_execute_revalidates_binding(self):
        self._arm({"adapter": "postgres", "admin_credential_ref": "PGADMIN_DSN"})
        Secret.objects.filter(
            project_id=self.project_id, key="PGADMIN_DSN", environment="production"
        ).delete()
        self._execute("b3-2", expected=422)

    def test_execute_rejects_client_armed(self):
        res = self.client.put(
            self._base() + "/rotation-policy/",
            data={"rotation_type": "value_client", "period_days": 30},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(res.status_code, 200)
        self._execute("b3-3", expected=422)
