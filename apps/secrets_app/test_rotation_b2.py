from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone
from nacl.signing import SigningKey
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.workspaces.models import (
    Workspace,
    Membership,
    MembershipRole,
    MembershipStatus,
    WorkspaceType,
    CloudDelegationKey,
)
from apps.secrets_app.models import Secret


class AutonomousRotationTests(TestCase):
    """B2 resolver-autonomous rotation: execute, replay, denylist, cadence."""

    B2CT = "REDACTED_DEK_CT_B2_XYZ"

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(
            email="b2owner@example.com",
            password="SecurePassword123!",
            first_name="B2",
            last_name="Owner",
        )
        self.workspace = Workspace.objects.create(
            name="B2 Workspace",
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
            data={"name": "internal", "description": "d", "workspace_id": str(self.workspace.id)},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(proj_res.status_code, 201)
        self.project_id = proj_res.json()["data"]["id"]
        upsert = self.client.post(
            "/api/secrets/",
            data={
                "project_id": self.project_id,
                "environment": "production",
                "secrets": {"APP_HMAC_KEY": "REDACTED_DEK_CT_ORIG_XYZ"},
            },
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(upsert.status_code, 201)
        self.signing_key = SigningKey.generate()
        self.verify_hex = self.signing_key.verify_key.encode().hex()

    def _base(self, key="APP_HMAC_KEY"):
        return f"/api/secrets/{self.project_id}/production/{key}"

    def _signed(self, method, path, body: bytes = b""):
        ts = str(int(time.time()))
        payload = "\n".join([ts, method, path, hashlib.sha256(body).hexdigest()])
        sig = base64.b64encode(self.signing_key.sign(payload.encode()).signature).decode()
        return {
            "HTTP_X_RESOLVER_KEY_ID": "test-key",
            "HTTP_X_RESOLVER_TIMESTAMP": ts,
            "HTTP_X_RESOLVER_SIGNATURE": sig,
        }

    def _arm_auto(self, key="APP_HMAC_KEY", expected=200):
        res = self.client.put(
            self._base(key) + "/rotation-policy/",
            data={
                "rotation_type": "value_auto",
                "period_days": 30,
                "provider_binding": {"mode": "autonomous", "length_bytes": 32, "encoding": "base64url"},
            },
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(res.status_code, expected)
        return res

    def _execute(self, body, expected=200):
        raw = json.dumps(body).encode()
        with self.settings(RESOLVER_SIGNING_PUBKEY=self.verify_hex):
            res = self.client.post(
                "/api/internal/rotation/value-execute/", data=raw,
                content_type="application/json",
                **self._signed("POST", "/api/internal/rotation/value-execute/", raw),
            )
        self.assertEqual(res.status_code, expected)
        return res.json()["data"] if expected == 200 else res

    def _execute_body(self, rotation_id="b2-1", key="APP_HMAC_KEY"):
        return {
            "workspace_id": str(self.workspace.id),
            "project_id": self.project_id,
            "environment": "production",
            "key": key,
            "ciphertext": self.B2CT,
            "rotation_id": rotation_id,
            "reason": "routine",
        }

    def test_execute_autonomous_full_cycle(self):
        self._arm_auto()
        before = Secret.objects.get(
            project_id=self.project_id, key="APP_HMAC_KEY", environment="production"
        ).next_rotation_at
        result = self._execute(self._execute_body())
        self.assertIsNotNone(result["current_version_id"])
        self.assertIsNotNone(result["previous_version_id"])

        value = self.client.get(
            self._base() + "/", **self.auth_headers).json()["data"]["value"]
        self.assertEqual(value, self.B2CT)

        after = Secret.objects.get(
            project_id=self.project_id, key="APP_HMAC_KEY", environment="production"
        ).next_rotation_at
        self.assertIsNotNone(after)
        self.assertGreater(after, before)

        status = self.client.get(
            self._base() + "/rotation/", **self.auth_headers).json()["data"]
        labels = sorted(v["staging_label"] for v in status["versions"])
        self.assertEqual(labels, ["current", "previous"])
        self.assertNotIn(self.B2CT, json.dumps(status))

    def test_execute_replay_idempotent(self):
        self._arm_auto()
        first = self._execute(self._execute_body(rotation_id="b2-replay"))
        second = self._execute(self._execute_body(rotation_id="b2-replay"))
        self.assertEqual(first["current_version_id"], second["current_version_id"])

    def test_execute_rejects_unarmed_and_unknown(self):
        res = self._execute(self._execute_body(), expected=422)
        self.assertIn("autonomous", res.text.lower())

        res = self.client.put(
            self._base() + "/rotation-policy/",
            data={"rotation_type": "value_client", "period_days": 30},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(res.status_code, 200)
        self._execute(self._execute_body(rotation_id="b2-x"), expected=422)

        unknown = dict(self._execute_body(rotation_id="b2-y"))
        unknown["key"] = "NOPE_MISSING"
        self._execute(unknown, expected=404)

    def test_denylist_at_arm_and_execute(self):
        upsert = self.client.post(
            "/api/secrets/",
            data={
                "project_id": self.project_id,
                "environment": "production",
                "secrets": {"RESOLVER_BOOT_KEY": "REDACTED_DEK_CT_ANCHOR"},
            },
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(upsert.status_code, 201)
        self._arm_auto(key="RESOLVER_BOOT_KEY", expected=422)

        Secret.objects.filter(
            project_id=self.project_id, key="RESOLVER_BOOT_KEY", environment="production"
        ).update(rotation_type="value_auto", rotation_period=timedelta(days=30),
                 next_rotation_at=timezone.now())
        res = self._execute(self._execute_body(rotation_id="b2-z", key="RESOLVER_BOOT_KEY"), expected=422)
        self.assertIn("anchor", res.text.lower())

    def test_workspace_keys_endpoint(self):
        CloudDelegationKey.objects.create(
            workspace=self.workspace,
            resolver_name="default",
            public_key="b" * 64,
            sealed_workspace_key="c2VhbGVk",
            is_active=True,
        )
        with self.settings(RESOLVER_SIGNING_PUBKEY=self.verify_hex):
            res = self.client.get(
                f"/api/internal/rotation/workspace-keys/?workspace_id={self.workspace.id}",
                **self._signed("GET", "/api/internal/rotation/workspace-keys/"),
            )
        self.assertEqual(res.status_code, 200)
        data = res.json()["data"]
        self.assertTrue(data["has_delegation"])
        self.assertEqual(data["sealed_workspace_key"], "c2VhbGVk")

        res = self.client.get(
            f"/api/internal/rotation/workspace-keys/?workspace_id={self.workspace.id}")
        self.assertEqual(res.status_code, 401)

    def test_manual_promote_advances_cadence(self):
        res = self.client.put(
            self._base() + "/rotation-policy/",
            data={"rotation_type": "value_client", "period_days": 30},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(res.status_code, 200)
        before = Secret.objects.get(
            project_id=self.project_id, key="APP_HMAC_KEY", environment="production"
        ).next_rotation_at

        self.client.post(
            self._base() + "/versions/",
            data={"ciphertext": "REDACTED_DEK_CT_MANUAL", "rotation_id": "m1"},
            content_type="application/json",
            **self.auth_headers,
        )
        promo = self.client.post(
            self._base() + "/promote/", data={"reason": "routine"},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(promo.status_code, 200)
        after = Secret.objects.get(
            project_id=self.project_id, key="APP_HMAC_KEY", environment="production"
        ).next_rotation_at
        self.assertGreater(after, before)
