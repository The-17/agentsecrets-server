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
    WorkspaceActivityLog,
    WorkspaceType,
)
from apps.secrets_app.models import Project, Secret, SecretVersion


class SecretRotationTests(TestCase):
    """B1 client-push value rotation: pending, promote, rollback, compromise."""

    ORIG = "REDACTED_DEK_CT_ORIGINAL_XYZ"
    NEW = "REDACTED_DEK_CT_NEW_XYZ"
    NEW2 = "REDACTED_DEK_CT_NEW2_XYZ"

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(
            email="valrot@example.com",
            password="SecurePassword123!",
            first_name="Val",
            last_name="Rot",
        )
        self.workspace = Workspace.objects.create(
            name="Value Rotation WS",
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
            data={"name": "pay", "description": "d", "workspace_id": str(self.workspace.id)},
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
                "secrets": {"API_KEY": self.ORIG},
            },
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(upsert.status_code, 201)
        self.signing_key = SigningKey.generate()
        self.verify_hex = self.signing_key.verify_key.encode().hex()

    def _base(self):
        return f"/api/secrets/{self.project_id}/production/API_KEY"

    def _get_value(self):
        res = self.client.get(self._base() + "/", **self.auth_headers)
        self.assertEqual(res.status_code, 200)
        return res.json()["data"]["value"]

    def _stage(self, ciphertext, rotation_id=None, reason="routine", expected=201):
        body = {"ciphertext": ciphertext, "reason": reason}
        if rotation_id:
            body["rotation_id"] = rotation_id
        res = self.client.post(
            self._base() + "/versions/", data=body,
            content_type="application/json", **self.auth_headers,
        )
        self.assertEqual(res.status_code, expected)
        return res.json()["data"]

    def _signed(self, method, path, body: bytes = b""):
        ts = str(int(time.time()))
        payload = "\n".join([ts, method, path, hashlib.sha256(body).hexdigest()])
        sig = base64.b64encode(self.signing_key.sign(payload.encode()).signature).decode()
        return {
            "HTTP_X_RESOLVER_KEY_ID": "test-key",
            "HTTP_X_RESOLVER_TIMESTAMP": ts,
            "HTTP_X_RESOLVER_SIGNATURE": sig,
        }

    def test_pending_promote_rollback_lifecycle(self):
        staged = self._stage(self.NEW, rotation_id="c1")
        self.assertFalse(staged["replayed"])
        # Hot row untouched while pending.
        self.assertEqual(self._get_value(), self.ORIG)

        status = self.client.get(self._base() + "/rotation/", **self.auth_headers).json()["data"]
        self.assertEqual(len(status["versions"]), 1)
        self.assertEqual(status["versions"][0]["staging_label"], "pending")
        self.assertNotIn(self.NEW, json.dumps(status))

        promo = self.client.post(
            self._base() + "/promote/", data={"reason": "routine"},
            content_type="application/json", **self.auth_headers,
        )
        self.assertEqual(promo.status_code, 200)
        self.assertIsNotNone(promo.json()["data"]["previous_version_id"])
        self.assertEqual(self._get_value(), self.NEW)

        status = self.client.get(self._base() + "/rotation/", **self.auth_headers).json()["data"]
        labels = sorted(v["staging_label"] for v in status["versions"])
        self.assertEqual(labels, ["current", "previous"])

        rollback = self.client.post(
            self._base() + "/rollback/", content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(rollback.status_code, 200)
        self.assertEqual(self._get_value(), self.ORIG)

    def test_pending_conflict_and_replay(self):
        first = self._stage(self.NEW, rotation_id="r1")
        replay = self._stage(self.NEW2, rotation_id="r1", expected=200)
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["version_id"], first["version_id"])

        clash = self.client.post(
            self._base() + "/versions/",
            data={"ciphertext": self.NEW2, "rotation_id": "r2"},
            content_type="application/json", **self.auth_headers,
        )
        self.assertEqual(clash.status_code, 409)

    def test_promote_compare_and_swap(self):
        self._stage(self.NEW, rotation_id="c1")
        self.client.post(self._base() + "/promote/", data={"reason": "routine"},
                         content_type="application/json", **self.auth_headers)
        versions = self.client.get(
            self._base() + "/rotation/", **self.auth_headers).json()["data"]["versions"]
        current_id = next(v["version_id"] for v in versions if v["staging_label"] == "current")

        self._stage(self.NEW2, rotation_id="c2")
        stale = self.client.post(
            self._base() + "/promote/",
            data={"reason": "routine", "expected_current_version_id": "00000000-0000-0000-0000-000000000000"},
            content_type="application/json", **self.auth_headers,
        )
        self.assertEqual(stale.status_code, 409)

        fresh = self.client.post(
            self._base() + "/promote/",
            data={"reason": "routine", "expected_current_version_id": current_id},
            content_type="application/json", **self.auth_headers,
        )
        self.assertEqual(fresh.status_code, 200)
        self.assertEqual(self._get_value(), self.NEW2)

    def test_compromise_shreds_previous_and_refuses_rollback(self):
        self._stage(self.NEW, rotation_id="c1")
        self.client.post(self._base() + "/promote/", data={"reason": "routine"},
                         content_type="application/json", **self.auth_headers)
        self.assertEqual(self._get_value(), self.NEW)

        self._stage(self.NEW2, rotation_id="c2", reason="compromise")
        promo = self.client.post(
            self._base() + "/promote/", data={"reason": "compromise"},
            content_type="application/json", **self.auth_headers,
        )
        self.assertEqual(promo.status_code, 200)
        self.assertIsNone(promo.json()["data"]["previous_version_id"])
        self.assertEqual(self._get_value(), self.NEW2)

        status = self.client.get(self._base() + "/rotation/", **self.auth_headers).json()["data"]
        self.assertEqual([v["staging_label"] for v in status["versions"]], ["current"])

        rollback = self.client.post(
            self._base() + "/rollback/", content_type="application/json",
            **self.auth_headers,
        )
        # No live previous survives a compromise rotation: rollback refuses
        # (BodyValidationError renders 422 in this codebase).
        self.assertIn(rollback.status_code, (400, 404, 422))

    def test_abort_unsticks_pending(self):
        self._stage(self.NEW, rotation_id="c1")
        abort = self.client.delete(
            self._base() + "/versions/pending/", **self.auth_headers)
        self.assertEqual(abort.status_code, 200)
        staged = self._stage(self.NEW2, rotation_id="c2")
        self.assertFalse(staged["replayed"])

    def test_readonly_member_cannot_stage(self):
        member = User.objects.create_user(
            email="valro@example.com", password="SecurePassword123!",
            first_name="R", last_name="O",
        )
        Membership.objects.create(
            user=member, workspace=self.workspace, role=MembershipRole.READ_ONLY,
            status=MembershipStatus.ACTIVE, encrypted_workspace_key="dummy",
        )
        headers = {"HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(member).access_token}"}
        res = self.client.post(
            self._base() + "/versions/", data={"ciphertext": self.NEW},
            content_type="application/json", **headers,
        )
        self.assertEqual(res.status_code, 403)

    def test_policy_arm_disarm_and_value_due(self):
        policy_url = self._base() + "/rotation-policy/"
        res = self.client.put(
            policy_url, data={"rotation_type": "value_client", "period_days": 30},
            content_type="application/json", **self.auth_headers,
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["data"]["policy"]["rotation_period_days"], 30)

        Secret.objects.filter(
            project_id=self.project_id, key="API_KEY", environment="production"
        ).update(next_rotation_at=timezone.now() - timedelta(days=1))

        with self.settings(RESOLVER_SIGNING_PUBKEY=self.verify_hex):
            due = self.client.get(
                f"/api/internal/rotation/value-due/?workspace_id={self.workspace.id}",
                **self._signed("GET", "/api/internal/rotation/value-due/"),
            )
        self.assertEqual(due.status_code, 200)
        items = due.json()["data"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["key"], "API_KEY")
        self.assertNotIn("ciphertext", json.dumps(items))

        res = self.client.put(
            policy_url, data={"enabled": False},
            content_type="application/json", **self.auth_headers,
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["data"]["policy"]["rotation_type"], "none")

    def test_ciphertext_never_in_status_or_audit(self):
        self._stage(self.NEW, rotation_id="c1")
        self.client.post(self._base() + "/promote/", data={"reason": "routine"},
                         content_type="application/json", **self.auth_headers)
        status = self.client.get(self._base() + "/rotation/", **self.auth_headers).json()["data"]
        self.assertNotIn(self.NEW, json.dumps(status))
        self.assertNotIn(self.ORIG, json.dumps(status))

        entries = WorkspaceActivityLog.objects.filter(workspace=self.workspace)
        blob = " ".join(
            json.dumps(e.metadata or {}) + (e.target_id or "") + (e.target_name or "")
            for e in entries
        )
        self.assertNotIn(self.NEW, blob)
