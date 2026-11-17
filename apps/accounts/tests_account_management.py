"""Account management endpoints: profile, avatar, deactivation, deletion."""
from __future__ import annotations

from io import BytesIO

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.workspaces.models import Membership, Workspace, WorkspaceType


class AccountManagementTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="manage@example.com",
            password="Password123!",
            first_name="Old",
            last_name="Name",
        )
        self.token = str(RefreshToken.for_user(self.user).access_token)
        self.auth = {"HTTP_AUTHORIZATION": f"Bearer {self.token}"}

    def test_update_profile(self):
        res = self.client.patch(
            "/api/auth/me/",
            data={"first_name": "New", "last_name": "Person"},
            content_type="application/json",
            **self.auth,
        )
        self.assertEqual(res.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "New")
        self.assertEqual(self.user.last_name, "Person")

    def test_update_profile_rejects_empty_name(self):
        res = self.client.patch(
            "/api/auth/me/",
            data={"first_name": "   "},
            content_type="application/json",
            **self.auth,
        )
        self.assertEqual(res.status_code, 422)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Old")

    def test_upload_avatar_accepts_image_via_cloudinary(self):
        from unittest.mock import patch

        from django.test import override_settings
        from PIL import Image

        buf = BytesIO()
        Image.new("RGB", (400, 300), (10, 120, 90)).save(buf, format="PNG")
        upload = SimpleUploadedFile("me.png", buf.getvalue(), content_type="image/png")
        fake_url = "https://res.cloudinary.com/demo/image/upload/avatars/manage.jpg"
        with override_settings(CLOUDINARY_URL="cloudinary://k:s@demo"):
            with patch("cloudinary.uploader.upload", return_value={"secure_url": fake_url}) as up:
                res = self.client.post(
                    "/api/auth/me/avatar/",
                    data={"file": upload},
                    format="multipart",
                    **self.auth,
                )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["data"]["avatar_url"], fake_url)
        up.assert_called_once()
        kwargs = up.call_args.kwargs
        self.assertEqual(kwargs["public_id"], f"avatars/{self.user.pk}")
        self.assertTrue(kwargs["overwrite"])
        sent = up.call_args.args[0]
        self.assertTrue(sent.startswith("data:image/webp;base64,"))
        self.user.refresh_from_db()
        self.assertEqual(self.user.avatar_url, fake_url)
        # /me/ returns the same URL so the UI can render it.
        me = self.client.get("/api/auth/me/", **self.auth)
        self.assertEqual(me.json()["data"]["avatar"], fake_url)

    def test_upload_avatar_fails_closed_when_cloudinary_unconfigured(self):
        from django.test import override_settings
        from PIL import Image

        buf = BytesIO()
        Image.new("RGB", (10, 10), (1, 2, 3)).save(buf, format="PNG")
        upload = SimpleUploadedFile("me.png", buf.getvalue(), content_type="image/png")
        with override_settings(CLOUDINARY_URL=""):
            res = self.client.post(
                "/api/auth/me/avatar/",
                data={"file": upload},
                format="multipart",
                **self.auth,
            )
        self.assertEqual(res.status_code, 503)
        self.user.refresh_from_db()
        self.assertEqual(self.user.avatar_url, "")

    def test_upload_avatar_rejects_bad_type(self):
        upload = SimpleUploadedFile("evil.png", b"not an image", content_type="image/png")
        res = self.client.post(
            "/api/auth/me/avatar/",
            data={"file": upload},
            format="multipart",
            **self.auth,
        )
        self.assertEqual(res.status_code, 422)
        self.user.refresh_from_db()
        self.assertEqual(self.user.avatar_url, "")

    def test_deactivate_rejects_login(self):
        res = self.client.post("/api/auth/account/deactivate/", **self.auth)
        self.assertEqual(res.status_code, 200)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)
        login = self.client.post(
            "/api/auth/login/",
            data={"email": self.user.email, "password": "Password123!"},
            content_type="application/json",
        )
        self.assertIn(login.status_code, (400, 401, 403))

    def test_delete_requires_matching_email(self):
        res = self.client.delete(
            "/api/auth/account/",
            data={"confirm_email": "wrong@example.com"},
            content_type="application/json",
            **self.auth,
        )
        self.assertEqual(res.status_code, 422)
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())

    def test_delete_removes_account_and_cascades(self):
        ws = Workspace.objects.create(
            name="Personal", owner=self.user, type=WorkspaceType.PERSONAL
        )
        Membership.objects.create(user=self.user, workspace=ws, role="owner")
        res = self.client.delete(
            "/api/auth/account/",
            data={"confirm_email": self.user.email},
            content_type="application/json",
            **self.auth,
        )
        self.assertEqual(res.status_code, 200)
        self.assertFalse(User.objects.filter(pk=self.user.pk).exists())
        self.assertFalse(Workspace.objects.filter(pk=ws.pk).exists())
