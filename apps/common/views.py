import sys
import os
import shutil
import uuid
import hashlib
import hmac
import secrets as secrets_module
import logging
from datetime import date

# Django
import django
from django.utils import timezone
from django.conf import settings
from django.db import transaction, connection
from django.core.cache import cache

# Third-party
from ninja_extra import api_controller, route

# Local
from apps.accounts.models import User, OneTimePassword
from apps.workspaces.models import (
    Workspace, Membership, WorkspaceType, MembershipRole, MembershipStatus,
    WorkspaceAllowlist, WorkspaceAllowlistLog,
    AgentRegistration, AgentToken, AuditLogEntry, IdentityLevel
)
from apps.secrets_app.models import Project, Secret
from apps.telemetry.models import TelemetrySnapshot, DailyMetricsAggregate
from apps.common.services.encryption import EncryptionService as encryption_service

logger = logging.getLogger("apps.common.status")

# Initialize startup time when the views module is loaded by Django
START_TIME = timezone.now()


@api_controller("/status", tags=["Status"], auth=None)
class StatusController:
    """
    Public health and status endpoint checking all orchestrator capabilities.
    """

    @route.get("/", response={200: dict, 503: dict})
    async def status_root(self, request):
        return await self._get_status_response(request)

    @route.get("/health/", response={200: dict, 503: dict})
    async def status_health(self, request):
        return await self._get_status_response(request)

    async def _get_status_response(self, request):
        # 1. Caching logic to prevent high request volume database load
        fresh = request.GET.get("fresh", "false").lower() == "true"
        if not fresh and request.headers.get("Cache-Control") == "no-cache":
            fresh = True

        if not fresh:
            cached_data = cache.get("status_check_result")
            if cached_data:
                # Return cached healthy response immediately
                return cached_data["code"], cached_data["data"]

        now = timezone.now()
        uptime = now - START_TIME
        uptime_seconds = uptime.total_seconds()

        db_ok = False
        db_write_ok = False
        functional_ok = False
        functional_details = {}
        db_details = {}

        try:
            from asgiref.sync import sync_to_async

            def run_db_and_functional_checks():
                db_read_ready = False
                db_write_ready = False
                local_db_details = {}
                func_ok = False
                func_err = None

                # Database read/write-readiness check
                try:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT 1")
                        db_read_ready = True

                        if connection.vendor == 'postgresql':
                            cursor.execute("SELECT pg_is_in_recovery(), current_setting('transaction_read_only')")
                            in_recovery, read_only = cursor.fetchone()
                            db_write_ready = not (in_recovery or read_only == 'on')
                            local_db_details = {
                                "in_recovery": in_recovery,
                                "read_only": read_only == 'on',
                                "vendor": connection.vendor
                            }
                        else:
                            db_write_ready = True
                            local_db_details = {"vendor": connection.vendor}
                except Exception as ex:
                    local_db_details = {"error": str(ex)}

                # Transactional functional check covering all system capabilities
                if db_read_ready:
                    try:
                        with transaction.atomic():
                            # Step 1: User owner creation (using set_unusable_password to avoid expensive hashing)
                            owner = User(
                                email=f"health-owner-{uuid.uuid4()}@agentsecrets.local",
                                first_name="Health",
                                last_name="Owner"
                            )
                            owner.set_unusable_password()
                            owner.save()

                            # Step 2: User invitee creation
                            invitee = User(
                                email=f"health-invitee-{uuid.uuid4()}@agentsecrets.local",
                                first_name="Health",
                                last_name="Invitee"
                            )
                            invitee.set_unusable_password()
                            invitee.save()

                            # Step 3: One-Time Password (OTP) creation
                            OneTimePassword.objects.create(
                                user=owner,
                                code="123456"
                            )

                            # Step 4: JWT token generation
                            tokens = owner.tokens()
                            if not tokens or "access" not in tokens:
                                raise Exception("JWT generation failed")

                            # Step 5: Workspace creation & Owner membership
                            workspace = Workspace.objects.create(
                                name="Health Workspace",
                                owner=owner,
                                type=WorkspaceType.SHARED
                            )
                            Membership.objects.create(
                                user=owner,
                                workspace=workspace,
                                role=MembershipRole.OWNER,
                                status=MembershipStatus.ACTIVE,
                                encrypted_workspace_key="dummy-owner-key"
                            )

                            # Step 6: Workspace Invite & Membership lifecycle
                            invitee_membership = Membership.objects.create(
                                user=invitee,
                                workspace=workspace,
                                role=MembershipRole.MEMBER,
                                status=MembershipStatus.ACTIVE,
                                encrypted_workspace_key="dummy-invitee-key"
                            )
                            # Promote
                            invitee_membership.role = MembershipRole.ADMIN
                            invitee_membership.save()
                            # Demote
                            invitee_membership.role = MembershipRole.MEMBER
                            invitee_membership.save()
                            # Kick
                            invitee_membership.delete()

                            # Step 7: Workspace Allowlist addition
                            allowlist = WorkspaceAllowlist.objects.create(
                                workspace=workspace,
                                domain="healthcheck.local",
                                added_by=owner
                            )

                            # Step 8: Workspace Allowlist Log auditing
                            WorkspaceAllowlistLog.objects.create(
                                workspace=workspace,
                                domain="healthcheck.local",
                                action="added",
                                performed_by=owner
                            )
                            allowlist.delete()

                            # Step 9: Project management
                            project = Project.objects.create(
                                workspace=workspace,
                                name="healthcheck-project"
                            )

                            # Step 10: Secrets creation & Encryption
                            test_plaintext = "very-secret-plaintext"
                            encrypted_value = encryption_service.encrypt(test_plaintext)
                            secret = Secret.objects.create(
                                project=project,
                                environment="development",
                                key="HEALTHCHECK_KEY",
                                value=encrypted_value,
                                policy={"allowed_ips": ["127.0.0.1"]}
                            )

                            # Step 11: Secrets retrieval & Decryption
                            fetched_secret = Secret.objects.get(id=secret.id)
                            decrypted = encryption_service.decrypt(fetched_secret.value)
                            if decrypted != test_plaintext:
                                raise Exception("Encryption/Decryption value mismatch")
                            if fetched_secret.policy.get("allowed_ips") != ["127.0.0.1"]:
                                raise Exception("Policy JSON mismatch")

                            # Step 12: Agent & Token Registration
                            agent = AgentRegistration.objects.create(
                                workspace=workspace,
                                project=project,
                                name="Health Agent",
                                capabilities={"read_only": True}
                            )
                            raw_token = secrets_module.token_urlsafe(32)
                            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
                            token = AgentToken.objects.create(
                                registration=agent,
                                workspace=workspace,
                                token_hash=token_hash,
                                label="Health Token"
                            )

                            # Step 13: Agent Token Verification (HMAC compare)
                            verified_token = AgentToken.objects.select_related("registration").filter(token_hash=token_hash).first()
                            if not verified_token or not hmac.compare_digest(verified_token.token_hash, token_hash):
                                raise Exception("Agent token comparison mismatch")

                            # Step 14: Audit Logging
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
                                caller_role="agent"
                            )

                            # Step 15: Telemetry snapshot creation
                            TelemetrySnapshot.objects.create(
                                user=owner,
                                cli_version="1.0.0",
                                os="linux",
                                arch="amd64",
                                command_executions={"run": 1},
                                proxy_calls=1
                            )

                            # Step 16: Daily Metrics Aggregate creation
                            # Use far future date to avoid conflict with actual daily metrics
                            DailyMetricsAggregate.objects.create(
                                date=date(2099, 12, 31),
                                total_users=2,
                                total_projects=1,
                                total_secrets=1
                            )

                            # If all steps pass without exception, the functional logic works!
                            func_ok = True

                            # ALWAYS roll back database changes to keep DB clean (must be called INSIDE atomic block)
                            transaction.set_rollback(True)
                    except Exception as e:
                        func_ok = False
                        func_err = str(e)
                        logger.error(f"Status check functional pipeline failed: {e}")

                return db_read_ready, db_write_ready, local_db_details, func_ok, func_err

            db_ok, db_write_ok, db_details, functional_ok, func_error = await sync_to_async(run_db_and_functional_checks)()
            if func_error:
                functional_details["error"] = func_error
        except Exception as e:
            db_details["error"] = str(e)
            functional_details["error"] = f"Failed to execute check runner: {str(e)}"

        # Cache connectivity check
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

        # Encryption functionality check
        encryption_ok = False
        encryption_details = {}
        try:
            test_str = "AgentSecretsEncryptionVerify"
            enc = encryption_service.encrypt(test_str)
            dec = encryption_service.decrypt(enc)
            if dec == test_str:
                encryption_ok = True
            else:
                encryption_details["error"] = "Decrypted output mismatch"
        except Exception as e:
            encryption_details["error"] = str(e)

        # Filesystem capacity and permissions check
        fs_ok = False
        fs_details = {}
        try:
            total, used, free = shutil.disk_usage(settings.BASE_DIR)
            free_gb = free / (1024 ** 3)
            free_percent = (free / total) * 100
            fs_details = {
                "free_space_gb": round(free_gb, 2),
                "free_space_percent": round(free_percent, 2),
            }

            if free_percent < 5.0 or free_gb < 1.0:
                fs_details["warning"] = "Low disk space"

            # Skip write tests in read-only serverless environment (Vercel)
            is_vercel = getattr(settings, 'IS_VERCEL', False)
            if is_vercel:
                fs_details["write_status"] = "skipped_on_serverless"
                fs_ok = True
            else:
                test_dir = settings.LOG_DIR if getattr(settings, 'ENABLE_FILE_LOGGING', False) else settings.BASE_DIR
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

        # Compute overall status
        overall_healthy = db_ok and db_write_ok and functional_ok and cache_ok and encryption_ok and fs_ok
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
                    "details": db_details
                },
                "functional_checks": {
                    "status": "healthy" if functional_ok else "unhealthy",
                    "details": functional_details
                },
                "cache": {
                    "status": "healthy" if cache_ok else "unhealthy",
                    "details": cache_details
                },
                "encryption": {
                    "status": "healthy" if encryption_ok else "unhealthy",
                    "details": encryption_details
                },
                "filesystem": {
                    "status": "healthy" if fs_ok else "unhealthy",
                    "details": fs_details
                }
            },
            "system": {
                "python_version": sys.version.split(" ")[0],
                "django_version": django.get_version(),
                "environment": "production" if not settings.DEBUG else "development"
            }
        }

        # Cache the result if healthy
        if overall_healthy:
            cache.set("status_check_result", {
                "code": 200,
                "data": status_data
            }, timeout=10)

        if overall_healthy:
            return 200, status_data
        else:
            return 503, status_data
