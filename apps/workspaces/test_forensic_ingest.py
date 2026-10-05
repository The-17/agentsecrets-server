from __future__ import annotations

import base64
import hashlib
import json
import time

from django.test import TestCase
from nacl.signing import SigningKey

from apps.accounts.models import User
from apps.workspaces.models import (
    ForensicAuditLogEntry,
    Membership,
    MembershipRole,
    MembershipStatus,
    Workspace,
    WorkspaceType,
)


class ResolverSignedIngestTests(TestCase):
    """Resolver Ed25519 channel for unattended forensic batches.

    Rotation outcomes carry no user/agent credential; without this channel
    the control plane 401s them and the audit trail silently loses every
    autonomous execution. The signing key already authorizes value-execute
    writes, so this adds no privilege.
    """

    def setUp(self):
        super().setUp()
        self.signing_key = SigningKey.generate()
        self.verify_hex = self.signing_key.verify_key.encode().hex()
        user = User.objects.create_user(
            email="fi@example.com", password="SecurePassword123!",
            first_name="F", last_name="I")
        self.workspace = Workspace.objects.create(
            name="FI", owner=user, type=WorkspaceType.SHARED)
        Membership.objects.create(
            user=user, workspace=self.workspace, role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE, encrypted_workspace_key="d")
        self.ws_id = str(self.workspace.id)

    def _signed(self, body: bytes):
        ts = str(int(time.time()))
        path = "/api/internal/forensic/logs/"
        payload = "\n".join([ts, "POST", path, hashlib.sha256(body).hexdigest()])
        sig = base64.b64encode(self.signing_key.sign(payload.encode()).signature).decode()
        return {
            "HTTP_X_RESOLVER_KEY_ID": "test-key",
            "HTTP_X_RESOLVER_TIMESTAMP": ts,
            "HTTP_X_RESOLVER_SIGNATURE": sig,
        }

    def _post(self, body: bytes, headers: dict):
        with self.settings(RESOLVER_SIGNING_PUBKEY=self.verify_hex):
            return self.client.post(
                "/api/internal/forensic/logs/", data=body,
                content_type="application/json", **headers)

    def test_signed_batch_persists_without_token(self):
        body = json.dumps([{
            "workspace_id": self.ws_id, "type": "value_rotation",
            "outcome": "value_provider_minted", "key": "APP_DB_PASSWORD",
            "rotation_id": "b3:sec_1:2026-09-30", "adapter": "postgres",
        }]).encode()
        res = self._post(body, self._signed(body))
        self.assertEqual(res.status_code, 201)
        self.assertEqual(ForensicAuditLogEntry.objects.count(), 1)

    def test_unsigned_batch_rejected(self):
        body = json.dumps([{"workspace_id": self.ws_id, "type": "x"}]).encode()
        res = self._post(body, {})
        self.assertEqual(res.status_code, 401)
        self.assertEqual(ForensicAuditLogEntry.objects.count(), 0)

    def test_wrong_key_rejected(self):
        body = json.dumps([{"workspace_id": self.ws_id, "type": "x"}]).encode()
        other = SigningKey.generate()
        ts = str(int(time.time()))
        payload = "\n".join([ts, "POST", "/api/internal/forensic/logs/",
                             hashlib.sha256(body).hexdigest()])
        sig = base64.b64encode(other.sign(payload.encode()).signature).decode()
        res = self._post(body, {
            "HTTP_X_RESOLVER_KEY_ID": "test-key",
            "HTTP_X_RESOLVER_TIMESTAMP": ts,
            "HTTP_X_RESOLVER_SIGNATURE": sig,
        })
        self.assertEqual(res.status_code, 401)
        self.assertEqual(ForensicAuditLogEntry.objects.count(), 0)

    def test_stale_timestamp_rejected(self):
        body = json.dumps([{"workspace_id": self.ws_id, "type": "x"}]).encode()
        ts = str(int(time.time()) - 3600)
        payload = "\n".join([ts, "POST", "/api/internal/forensic/logs/",
                             hashlib.sha256(body).hexdigest()])
        sig = base64.b64encode(self.signing_key.sign(payload.encode()).signature).decode()
        res = self._post(body, {
            "HTTP_X_RESOLVER_KEY_ID": "test-key",
            "HTTP_X_RESOLVER_TIMESTAMP": ts,
            "HTTP_X_RESOLVER_SIGNATURE": sig,
        })
        self.assertEqual(res.status_code, 401)
        self.assertEqual(ForensicAuditLogEntry.objects.count(), 0)
