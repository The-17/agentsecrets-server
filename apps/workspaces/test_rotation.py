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
    AgentRegistration,
    AgentToken,
)


class TokenRotationTests(TestCase):
    """Axis A workload-token rotation: rotate, renew, cadence, reuse signals."""

    def setUp(self):
        super().setUp()
        self.owner = User.objects.create_user(
            email="rot_owner@example.com",
            password="SecurePassword123!",
            first_name="Rot",
            last_name="Owner",
        )
        self.workspace = Workspace.objects.create(
            name="Rotation Workspace",
            owner=self.owner,
            type=WorkspaceType.SHARED,
        )
        Membership.objects.create(
            user=self.owner,
            workspace=self.workspace,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="dummy",
        )
        self.auth_headers = {
            "HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(self.owner).access_token}"
        }
        self.agent = AgentRegistration.objects.create(
            workspace=self.workspace, name="worker", created_by=self.owner
        )
        res = self.client.post(
            f"/api/workspaces/{self.workspace.id}/agents/{self.agent.id}/tokens/",
            data={"label": "w1"},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(res.status_code, 201)
        self.raw = res.json()["data"]["token"]
        self.token_id = res.json()["data"]["token_id"]
        self.signing_key = SigningKey.generate()
        self.verify_hex = self.signing_key.verify_key.encode().hex()

    def _verify(self, raw):
        return self.client.post(
            "/api/internal/agents/verify/",
            data={"token": raw},
            content_type="application/json",
        ).json()

    def _signed(self, method, path, body: bytes = b""):
        ts = str(int(time.time()))
        payload = "\n".join([ts, method, path, hashlib.sha256(body).hexdigest()])
        sig = base64.b64encode(self.signing_key.sign(payload.encode()).signature).decode()
        return {
            "HTTP_X_RESOLVER_KEY_ID": "test-key",
            "HTTP_X_RESOLVER_TIMESTAMP": ts,
            "HTTP_X_RESOLVER_SIGNATURE": sig,
        }

    def _rotate_url(self, token_id):
        return (
            f"/api/workspaces/{self.workspace.id}/agents/{self.agent.id}"
            f"/tokens/{token_id}/rotate/"
        )

    def _policy_url(self, token_id):
        return (
            f"/api/workspaces/{self.workspace.id}/agents/{self.agent.id}"
            f"/tokens/{token_id}/rotation-policy/"
        )

    def test_manual_rotate_overlap(self):
        res = self.client.post(
            self._rotate_url(self.token_id),
            data={"reason": "routine", "overlap_hours": 24},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(res.status_code, 201)
        new_raw = res.json()["data"]["token"]
        self.assertTrue(new_raw and new_raw != self.raw)

        old_status = self._verify(self.raw)
        self.assertTrue(old_status["valid"])
        self.assertEqual(old_status["reason"], "superseded_overlap")

        new_status = self._verify(new_raw)
        self.assertTrue(new_status["valid"])
        self.assertIsNone(new_status["reason"])
        self.assertEqual(new_status["rotation"]["rotation_state"], "active")

        AgentToken.objects.filter(id=self.token_id).update(
            overlap_until=timezone.now() - timedelta(hours=1)
        )
        expired = self._verify(self.raw)
        self.assertFalse(expired["valid"])
        self.assertEqual(expired["reason"], "overlap_expired")

    def test_rotate_rejects_non_admin(self):
        member = User.objects.create_user(
            email="rot_member@example.com", password="SecurePassword123!",
            first_name="M", last_name="B",
        )
        Membership.objects.create(
            user=member, workspace=self.workspace, role=MembershipRole.MEMBER,
            status=MembershipStatus.ACTIVE, encrypted_workspace_key="dummy",
        )
        headers = {"HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(member).access_token}"}
        res = self.client.post(
            self._rotate_url(self.token_id),
            data={"reason": "routine"},
            content_type="application/json",
            **headers,
        )
        self.assertEqual(res.status_code, 403)

    def test_mint_successor_idempotent(self):
        url = "/api/internal/agents/mint-successor/"
        first = self.client.post(
            url, data={"token": self.raw, "rotation_id": "cycle-1"},
            content_type="application/json",
        )
        self.assertEqual(first.status_code, 201)
        body = first.json()["data"]
        self.assertTrue(body["token"])
        self.assertFalse(body["replayed"])

        replay = self.client.post(
            url, data={"token": self.raw, "rotation_id": "cycle-1"},
            content_type="application/json",
        )
        self.assertEqual(replay.status_code, 200)
        rbody = replay.json()["data"]
        self.assertTrue(rbody["replayed"])
        self.assertIsNone(rbody["token"])
        self.assertEqual(rbody["token_id"], body["token_id"])

        bare_id = self.client.post(
            url, data={"token": self.token_id},
            content_type="application/json",
        )
        self.assertEqual(bare_id.status_code, 404)

    def test_compromise_zero_overlap_and_reuse_signal(self):
        res = self.client.post(
            self._rotate_url(self.token_id),
            data={"reason": "compromise"},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(res.status_code, 201)
        new_raw = res.json()["data"]["token"]

        old_status = self._verify(self.raw)
        self.assertFalse(old_status["valid"])
        self.assertEqual(old_status["reason"], "Revoked")

        self.assertTrue(self._verify(new_raw)["valid"])
        corroborated = self._verify(self.raw)
        self.assertFalse(corroborated["valid"])
        self.assertEqual(corroborated["reason"], "revoked_reuse_suspected")

    def test_policy_arm_and_due_sweep(self):
        res = self.client.put(
            self._policy_url(self.token_id),
            data={"period_days": 30, "overlap_hours": 12},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["data"]["rotation"]["rotation_period_days"], 30)

        AgentToken.objects.filter(id=self.token_id).update(
            next_rotation_at=timezone.now() - timedelta(days=1)
        )
        with self.settings(RESOLVER_SIGNING_PUBKEY=self.verify_hex):
            due = self.client.get(
                f"/api/internal/rotation/due/?workspace_id={self.workspace.id}",
                **self._signed("GET", "/api/internal/rotation/due/"),
            )
        self.assertEqual(due.status_code, 200)
        items = due.json()["data"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["token_id"], self.token_id)

        with self.settings(RESOLVER_SIGNING_PUBKEY=self.verify_hex):
            bad_sig = dict(self._signed("GET", "/api/internal/rotation/due/"))
            bad_sig["HTTP_X_RESOLVER_SIGNATURE"] = "bogus"
            bad = self.client.get(
                f"/api/internal/rotation/due/?workspace_id={self.workspace.id}",
                **bad_sig,
            )
        self.assertEqual(bad.status_code, 401)

        res = self.client.put(
            self._policy_url(self.token_id),
            data={"enabled": False},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(res.status_code, 200)
        self.assertIsNone(res.json()["data"]["rotation"]["next_rotation_at"])

    def test_family_revoke_signed(self):
        res = self.client.post(
            self._rotate_url(self.token_id),
            data={"reason": "routine", "overlap_hours": 24},
            content_type="application/json",
            **self.auth_headers,
        )
        family = res.json()["data"]["rotation"]["rotation_family_id"]
        self.assertTrue(family)

        body = json.dumps({
            "workspace_id": str(self.workspace.id),
            "family_key": family, "reason": "compromise",
        }).encode()
        with self.settings(RESOLVER_SIGNING_PUBKEY=self.verify_hex):
            revoke = self.client.post(
                "/api/internal/rotation/family-revoke/", data=body,
                content_type="application/json",
                **self._signed("POST", "/api/internal/rotation/family-revoke/", body),
            )
        self.assertEqual(revoke.status_code, 200)
        self.assertGreaterEqual(revoke.json()["data"]["revoked_count"], 2)
        self.assertEqual(self._verify(self.raw)["reason"], "Revoked")

    def test_raw_token_never_audited(self):
        res = self.client.post(
            self._rotate_url(self.token_id),
            data={"reason": "routine"},
            content_type="application/json",
            **self.auth_headers,
        )
        new_raw = res.json()["data"]["token"]
        entries = WorkspaceActivityLog.objects.filter(workspace=self.workspace)
        self.assertTrue(entries.exists())
        blob = " ".join(
            json.dumps(e.metadata or {}) + (e.target_id or "") + (e.target_name or "")
            for e in entries
        )
        self.assertNotIn(self.raw, blob)
        self.assertNotIn(new_raw, blob)
