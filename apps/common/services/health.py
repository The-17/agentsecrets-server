import sys
import os
import shutil
import uuid
import hashlib
import hmac
import secrets as secrets_module
import logging
import time
from datetime import date
from typing import Tuple, Dict, Any

import django
from django.utils import timezone
from django.conf import settings
from django.db import transaction, connection
from django.core.cache import cache

from apps.accounts.models import User, OneTimePassword
from apps.workspaces.models import (
    Workspace,
    Membership,
    WorkspaceType,
    MembershipRole,
    MembershipStatus,
    WorkspaceAllowlist,
    WorkspaceAllowlistLog,
    AgentRegistration,
    AgentToken,
    AuditLogEntry,
    IdentityLevel,
)
from apps.secrets_app.models import Project, Secret
from apps.telemetry.models import TelemetrySnapshot, DailyMetricsAggregate
from apps.common.services.encryption import EncryptionService

logger = logging.getLogger("apps.common.health")
START_TIME = timezone.now()


class SystemHealthService:
    """
    Comprehensive system health diagnostic pipeline.
    Tests database connectivity, ORM capabilities across all models,
    cache, encryption, and filesystem operations.
    """

    @staticmethod
    def check_database() -> Tuple[bool, bool, Dict[str, Any]]:
        db_read_ready = False
        db_write_ready = False
        db_details = {}
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                db_read_ready = True

                if connection.vendor == "postgresql":
                    cursor.execute("SELECT pg_is_in_recovery(), current_setting('transaction_read_only')")
                    in_recovery, read_only = cursor.fetchone()
                    db_write_ready = not (in_recovery or read_only == "on")
                    db_details = {
                        "in_recovery": in_recovery,
                        "read_only": read_only == "on",
                        "vendor": connection.vendor,
                    }
                else:
                    db_write_ready = True
                    db_details = {"vendor": connection.vendor}
        except Exception as ex:
            db_details = {"error": str(ex)}

        return db_read_ready, db_write_ready, db_details

    @staticmethod
    def check_functional_pipeline() -> Tuple[bool, str | None, Dict[str, Any]]:
        local_checks = {}
        func_ok = False
        func_err = None

        try:
            with transaction.atomic():
                owner = None
                invitee = None
                workspace = None
                invitee_membership = None
                allowlist = None
                project = None
                secret = None
                agent = None
                token = None
                token_hash = None
                test_plaintext = "very-secret-plaintext"

                def run_step(step_name, func):
                    t0 = time.perf_counter()
                    try:
                        func()
                        duration = (time.perf_counter() - t0) * 1000
                        local_checks[step_name] = {
                            "status": "healthy",
                            "duration_ms": round(duration, 2),
                        }
                    except Exception as ex:
                        duration = (time.perf_counter() - t0) * 1000
                        local_checks[step_name] = {
                            "status": "unhealthy",
                            "duration_ms": round(duration, 2),
                            "error": str(ex),
                        }
                        raise ex

                def step_users():
                    nonlocal owner, invitee
                    owner = User(
                        email=f"health-owner-{uuid.uuid4()}@agentsecrets.local",
                        first_name="Health",
                        last_name="Owner",
                    )
                    owner.set_unusable_password()
                    owner.save()

                    invitee = User(
                        email=f"health-invitee-{uuid.uuid4()}@agentsecrets.local",
                        first_name="Health",
                        last_name="Invitee",
                    )
                    invitee.set_unusable_password()
                    invitee.save()

                run_step("user_management", step_users)

                def step_otp():
                    OneTimePassword.objects.create(user=owner, code="123456")

                run_step("otp_service", step_otp)

                def step_jwt():
                    tokens = owner.tokens()
                    if not tokens or "access" not in tokens:
                        raise Exception("JWT generation failed")

                run_step("jwt_auth", step_jwt)

                def step_workspace():
                    nonlocal workspace
                    workspace = Workspace.objects.create(
                        name="Health Workspace",
                        owner=owner,
                        type=WorkspaceType.SHARED,
                    )
                    Membership.objects.create(
                        user=owner,
                        workspace=workspace,
                        role=MembershipRole.OWNER,
                        status=MembershipStatus.ACTIVE,
                        encrypted_workspace_key="dummy-owner-key",
                    )

                run_step("workspace_management", step_workspace)

                def step_membership():
                    nonlocal invitee_membership
                    invitee_membership = Membership.objects.create(
                        user=invitee,
                        workspace=workspace,
                        role=MembershipRole.MEMBER,
                        status=MembershipStatus.ACTIVE,
                        encrypted_workspace_key="dummy-invitee-key",
                    )
                    invitee_membership.role = MembershipRole.ADMIN
                    invitee_membership.save()
                    invitee_membership.role = MembershipRole.MEMBER
                    invitee_membership.save()
                    invitee_membership.delete()

                run_step("workspace_membership", step_membership)

                def step_allowlist():
                    nonlocal allowlist
                    allowlist = WorkspaceAllowlist.objects.create(
                        workspace=workspace,
                        domain="healthcheck.local",
                        added_by=owner,
                    )

                run_step("workspace_allowlist", step_allowlist)

                def step_allowlist_log():
                    WorkspaceAllowlistLog.objects.create(
                        workspace=workspace,
                        domain="healthcheck.local",
                        action="added",
                        performed_by=owner,
                    )
                    allowlist.delete()

                run_step("allowlist_logging", step_allowlist_log)

                def step_project():
                    nonlocal project
                    project = Project.objects.create(
                        workspace=workspace,
                        name="healthcheck-project",
                    )

                run_step("project_management", step_project)

                def step_secret():
                    nonlocal secret
                    encrypted_value = EncryptionService.encrypt(test_plaintext)
                    secret = Secret.objects.create(
                        project=project,
                        environment="development",
                        key="HEALTHCHECK_KEY",
                        value=encrypted_value,
                        policy={"allowed_ips": ["127.0.0.1"]},
                    )

                run_step("secrets_management", step_secret)

                def step_decrypt():
                    fetched_secret = Secret.objects.get(id=secret.id)
                    decrypted = EncryptionService.decrypt(fetched_secret.value)
                    if decrypted != test_plaintext:
                        raise Exception("Encryption/Decryption value mismatch")
                    if fetched_secret.policy.get("allowed_ips") != ["127.0.0.1"]:
                        raise Exception("Policy JSON mismatch")

                run_step("decryption_and_policy", step_decrypt)

                def step_agent():
                    nonlocal agent, token, token_hash
                    agent = AgentRegistration.objects.create(
                        workspace=workspace,
                        project=project,
                        name="Health Agent",
                        capabilities={"read_only": True},
                    )
                    raw_token = secrets_module.token_urlsafe(32)
                    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
                    token = AgentToken.objects.create(
                        registration=agent,
                        workspace=workspace,
                        token_hash=token_hash,
                        label="Health Token",
                    )

                run_step("agent_registration", step_agent)

                def step_token_verify():
                    verified_token = (
                        AgentToken.objects.select_related("registration")
                        .filter(token_hash=token_hash)
                        .first()
                    )
                    if not verified_token or not hmac.compare_digest(
                        verified_token.token_hash, token_hash
                    ):
                        raise Exception("Agent token comparison mismatch")

                run_step("token_verification", step_token_verify)

                def step_audit_log():
                    AuditLogEntry.objects.create(
                        timestamp=timezone.now(),
                        workspace=workspace,
                        project=project,
                        agent_id=str(agent.id),
                        agent_token=token,
                        identity_level=IdentityLevel.ISSUED,
                        credential_ref="HEALTHCHECK_KEY",
                        injection_style="env",
                        target_domain="healthcheck.local",
                        target_url="https://healthcheck.local/resolve",
                        target_path="/resolve",
                        method="POST",
                        duration_ms=15,
                        resolution_path="local",
                        caller_role="agent",
                    )

                run_step("audit_logging", step_audit_log)

                def step_telemetry():
                    TelemetrySnapshot.objects.create(
                        user=owner,
                        cli_version="1.0.0",
                        os="linux",
                        arch="amd64",
                        command_executions={"run": 1},
                        proxy_calls=1,
                    )

                run_step("telemetry_sync", step_telemetry)

                def step_metrics():
                    DailyMetricsAggregate.objects.update_or_create(
                        date=date(2099, 12, 31),
                        defaults={
                            "total_users": 2,
                            "total_projects": 1,
                            "total_secrets": 1,
                        },
                    )

                run_step("metrics_aggregate", step_metrics)

                func_ok = True
                # ALWAYS roll back database changes to keep DB clean
                transaction.set_rollback(True)
        except Exception as e:
            func_ok = False
            func_err = str(e)
            logger.error("Status check functional pipeline failed: %s", type(e).__name__)

        return func_ok, func_err, local_checks

    @staticmethod
    def check_cache() -> Tuple[bool, Dict[str, Any]]:
        cache_ok = False
        cache_details = {}
        try:
            test_key = f"health_check_{uuid.uuid4()}"
            test_val = "ok"
            cache.set(test_key, test_val, timeout=10)
            fetched = cache.get(test_key)
            if fetched == test_val:
                cache_ok = True
            else:
                cache_details["error"] = f"Expected '{test_val}', got '{fetched}'"
            cache.delete(test_key)
        except Exception as e:
            cache_details["error"] = str(e)
        return cache_ok, cache_details

    @staticmethod
    def check_encryption() -> Tuple[bool, Dict[str, Any]]:
        encryption_ok = False
        encryption_details = {}
        try:
            test_str = "AgentSecretsEncryptionVerify"
            enc = EncryptionService.encrypt(test_str)
            dec = EncryptionService.decrypt(enc)
            if dec == test_str:
                encryption_ok = True
            else:
                encryption_details["error"] = "Decrypted output mismatch"
        except Exception as e:
            encryption_details["error"] = str(e)
        return encryption_ok, encryption_details

    @staticmethod
    def check_filesystem() -> Tuple[bool, Dict[str, Any]]:
        fs_ok = False
        fs_details = {}
        try:
            is_vercel = getattr(settings, "IS_VERCEL", False)
            if is_vercel:
                fs_details = {
                    "free_space_gb": "not_applicable",
                    "free_space_percent": "not_applicable",
                    "write_status": "skipped_on_serverless",
                }
                fs_ok = True
            else:
                total, used, free = shutil.disk_usage(settings.BASE_DIR)
                free_gb = free / (1024**3)
                free_percent = (free / total) * 100
                fs_details = {
                    "free_space_gb": round(free_gb, 2),
                    "free_space_percent": round(free_percent, 2),
                }

                if free_percent < 5.0 or free_gb < 1.0:
                    fs_details["warning"] = "Low disk space"

                test_dir = (
                    settings.LOG_DIR
                    if getattr(settings, "ENABLE_FILE_LOGGING", False)
                    else settings.BASE_DIR
                )
                test_file_path = os.path.join(test_dir, f".health_write_test_{uuid.uuid4()}")
                try:
                    with open(test_file_path, "w") as f:
                        f.write("health check")
                    os.remove(test_file_path)
                    fs_ok = True
                    fs_details["write_status"] = "success"
                except Exception as e:
                    fs_details["write_error"] = str(e)
                    fs_details["write_status"] = "failed"
        except Exception as e:
            fs_details["error"] = str(e)
        return fs_ok, fs_details

    @classmethod
    def diagnose_system(cls) -> Tuple[int, Dict[str, Any]]:
        now = timezone.now()
        uptime_seconds = (now - START_TIME).total_seconds()

        db_ok, db_write_ok, db_details = cls.check_database()
        functional_ok = False
        functional_details = {}
        checks = {}

        if db_ok:
            functional_ok, func_err, checks = cls.check_functional_pipeline()
            functional_details["checks"] = checks
            if func_err:
                functional_details["error"] = func_err
        else:
            functional_details["error"] = "Database offline"

        cache_ok, cache_details = cls.check_cache()
        encryption_ok, encryption_details = cls.check_encryption()
        fs_ok, fs_details = cls.check_filesystem()

        overall_healthy = (
            db_ok and db_write_ok and functional_ok and cache_ok and encryption_ok and fs_ok
        )
        status_str = "healthy" if overall_healthy else "unhealthy"

        status_data = {
            "status": status_str,
            "timestamp": now.isoformat(),
            "uptime_seconds": round(uptime_seconds, 1),
            "components": {
                "database": {
                    "status": "healthy" if (db_ok and db_write_ok) else "unhealthy",
                    "read_ok": db_ok,
                    "write_ok": db_write_ok,
                    "details": db_details,
                },
                "functional_checks": {
                    "status": "healthy" if functional_ok else "unhealthy",
                    "details": functional_details,
                },
                "cache": {
                    "status": "healthy" if cache_ok else "unhealthy",
                    "details": cache_details,
                },
                "encryption": {
                    "status": "healthy" if encryption_ok else "unhealthy",
                    "details": encryption_details,
                },
                "filesystem": {
                    "status": "healthy" if fs_ok else "unhealthy",
                    "details": fs_details,
                },
            },
            "system": {
                "python_version": sys.version.split(" ")[0],
                "django_version": django.get_version(),
                "environment": "production" if not settings.DEBUG else "development",
            },
        }

        status_code = 200 if overall_healthy else 503
        return status_code, status_data
