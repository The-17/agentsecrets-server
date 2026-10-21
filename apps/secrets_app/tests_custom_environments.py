from __future__ import annotations

from django.test import TestCase
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.secrets_app.environment import STANDARD_ENVIRONMENTS, parse_environment
from apps.common.exceptions import BodyValidationError
from apps.secrets_app.models import Project, Secret
from apps.workspaces.models import (
    Membership,
    MembershipRole,
    MembershipStatus,
    Workspace,
    WorkspaceTier,
    WorkspaceType,
)


class EnvironmentSlugValidationTests(TestCase):
    """One rule, one module. Every call site routes through validate_environment."""

    def test_accepts_valid_slugs(self):
        for raw in ("qa", "preview-pr-12", "uat", "development", "staging", "production"):
            with self.subTest(raw=raw):
                self.assertEqual(parse_environment(raw), raw)

    def test_trims_and_lowercases(self):
        self.assertEqual(parse_environment("QA "), "qa")
        self.assertEqual(parse_environment(" Preview-PR-12 "), "preview-pr-12")

    def test_rejects_invalid_slugs(self):
        cases = {
            "": "Environment name is required",
            "has space": "must match",
            "-lead": "must match",
            "9qa": "must match",
            "q": "must match",
            "a" * 40: "at most 32 characters",
            "café": "must match",
        }
        for raw, fragment in cases.items():
            with self.subTest(raw=raw):
                with self.assertRaises(BodyValidationError) as ctx:
                    parse_environment(raw)
                field, message = ctx.exception.data.popitem()
                self.assertEqual(field, "environment")
                self.assertIn(fragment, message)

    def test_rejects_reserved_names(self):
        for raw in ("root", "admin", "api", "internal", "default"):
            with self.subTest(raw=raw):
                with self.assertRaises(BodyValidationError) as ctx:
                    parse_environment(raw)
                self.assertIn("reserved", ctx.exception.data["environment"])

    def test_standard_names_are_just_valid_slugs(self):
        for name in STANDARD_ENVIRONMENTS:
            self.assertEqual(parse_environment(name), name)


class CustomEnvironmentAPITests(TestCase):
    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(
            email="custom-env@example.com",
            password="SecurePassword123!",
            first_name="Custom",
            last_name="Env",
        )
        self.workspace = Workspace.objects.create(
            name="Custom Env Workspace",
            owner=self.user,
            type=WorkspaceType.SHARED,
            tier=WorkspaceTier.FREE,
        )
        Membership.objects.create(
            user=self.user,
            workspace=self.workspace,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="dummy_key",
        )
        refresh = RefreshToken.for_user(self.user)
        self.auth_headers = {"HTTP_AUTHORIZATION": f"Bearer {refresh.access_token}"}
        self.project = Project.objects.create(name="custom-env-project", workspace=self.workspace)
        self.project_id = str(self.project.id)

    def upsert(self, environment: str, secrets: dict[str, str]):
        return self.client.post(
            "/api/secrets/",
            data={"project_id": self.project_id, "environment": environment, "secrets": secrets},
            content_type="application/json",
            **self.auth_headers,
        )

    def test_free_workspace_round_trip_in_custom_environment(self):
        """No paywall on the control plane. The resolver owns entitlement."""
        created = self.upsert("qa", {"QA_TOKEN": "qa-value"})
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["data"]["environment"], "qa")

        listed = self.client.get(
            f"/api/secrets/{self.project_id}/?environment=qa", **self.auth_headers
        )
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(
            [(s["key"], s["value"]) for s in listed.json()["data"]["secrets"]],
            [("QA_TOKEN", "qa-value")],
        )

        fetched = self.client.get(
            f"/api/secrets/{self.project_id}/QA_TOKEN/?environment=qa", **self.auth_headers
        )
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.json()["data"]["value"], "qa-value")

        env_path = self.client.get(
            f"/api/secrets/{self.project_id}/qa/QA_TOKEN/", **self.auth_headers
        )
        self.assertEqual(env_path.status_code, 200)
        self.assertEqual(env_path.json()["data"]["value"], "qa-value")

        deleted = self.client.delete(
            f"/api/secrets/{self.project_id}/QA_TOKEN/?environment=qa", **self.auth_headers
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertFalse(Secret.objects.filter(project=self.project, environment="qa").exists())

    def test_missing_key_in_custom_environment_matches_standard_path(self):
        self.upsert("qa", {"QA_TOKEN": "qa-value"})
        self.upsert("development", {"DEV_TOKEN": "dev-value"})

        custom_missing = self.client.get(
            f"/api/secrets/{self.project_id}/QA_TOKEN/?environment=development", **self.auth_headers
        )
        standard_missing = self.client.get(
            f"/api/secrets/{self.project_id}/DEV_TOKEN/?environment=qa", **self.auth_headers
        )
        self.assertEqual(custom_missing.status_code, 404)
        self.assertEqual(standard_missing.status_code, 404)
        self.assertEqual(custom_missing.json()["code"], standard_missing.json()["code"])
        self.assertIn("QA_TOKEN", custom_missing.json()["message"])

    def test_invalid_environment_name_is_rejected_consistently(self):
        bad = self.upsert("has space", {"TOKEN": "v"})
        self.assertEqual(bad.status_code, 422)

        reserved = self.client.get(
            f"/api/secrets/{self.project_id}/?environment=root", **self.auth_headers
        )
        self.assertEqual(reserved.status_code, 422)

    def test_inventory_lists_standard_plus_declared_custom(self):
        self.upsert("development", {"DEV_TOKEN": "v"})
        self.upsert("qa", {"QA_TOKEN": "v", "QA_OTHER": "v"})

        res = self.client.get(
            f"/api/projects/{self.project_id}/environments/", **self.auth_headers
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()["data"]

        self.assertEqual(
            [e["name"] for e in data["environments"]],
            ["development", "staging", "production", "qa"],
        )
        by_name = {e["name"]: e for e in data["environments"]}
        self.assertTrue(by_name["development"]["is_standard"])
        self.assertTrue(by_name["staging"]["is_standard"])
        self.assertTrue(by_name["production"]["is_standard"])
        self.assertFalse(by_name["qa"]["is_standard"])
        self.assertEqual(by_name["development"]["secret_count"], 1)
        self.assertEqual(by_name["staging"]["secret_count"], 0)
        self.assertEqual(by_name["qa"]["secret_count"], 2)

        # The count map the dashboard already reads stays keyed and typed as before.
        counts = data["counts"]
        self.assertEqual(counts["development"], {"secret_count": 1})
        self.assertEqual(counts["staging"], {"secret_count": 0})
        self.assertEqual(counts["production"], {"secret_count": 0})
        self.assertEqual(counts["qa"], {"secret_count": 2})

    def test_coverage_and_diff_include_custom_environments(self):
        self.upsert("development", {"SHARED": "v", "DEV_ONLY": "v"})
        self.upsert("qa", {"SHARED": "v", "QA_ONLY": "v"})

        coverage = self.client.get(
            f"/api/projects/{self.project_id}/secrets/coverage/", **self.auth_headers
        )
        self.assertEqual(coverage.status_code, 200)
        keys = {k["key_name"]: k["environments"] for k in coverage.json()["data"]["keys"]}
        self.assertTrue(keys["SHARED"]["development"])
        self.assertTrue(keys["SHARED"]["qa"])
        self.assertFalse(keys["SHARED"]["staging"])
        self.assertNotIn("qa", keys["DEV_ONLY"])
        self.assertIn("production", keys["DEV_ONLY"])
        self.assertFalse(keys["DEV_ONLY"]["production"])

        diff = self.client.get(
            f"/api/projects/{self.project_id}/secrets/diff/?from=development&to=qa",
            **self.auth_headers,
        )
        self.assertEqual(diff.status_code, 200)
        self.assertEqual(diff.json()["data"]["in_both"], ["SHARED"])
        self.assertEqual(diff.json()["data"]["in_from_only"], ["DEV_ONLY"])
        self.assertEqual(diff.json()["data"]["in_to_only"], ["QA_ONLY"])

    def test_custom_environment_is_project_scoped(self):
        other = Project.objects.create(name="other-project", workspace=self.workspace)
        self.upsert("qa", {"QA_TOKEN": "v"})

        res = self.client.get(
            f"/api/projects/{other.id}/environments/", **self.auth_headers
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(
            [e["name"] for e in res.json()["data"]["environments"]],
            ["development", "staging", "production"],
        )

    def test_clean_environment_works_for_custom_environment(self):
        self.upsert("qa", {"QA_TOKEN": "v"})
        res = self.client.delete(
            f"/api/projects/{self.project_id}/environments/qa/clean/", **self.auth_headers
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(Secret.objects.filter(project=self.project, environment="qa").count(), 0)
