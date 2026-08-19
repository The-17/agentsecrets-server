import hmac
import logging
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, time

from django.conf import settings
from django.core.cache import cache
from django.core.management import call_command
from django.db.models import Count
from django.utils import timezone
from asgiref.sync import sync_to_async
from pydantic import TypeAdapter
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from apps.accounts.models import User
from apps.secrets_app.models import Secret
from apps.workspaces.models import Membership, MembershipStatus
from .models import TelemetrySnapshot
from .schemas import TelemetrySyncSchema

logger = logging.getLogger("apps.telemetry")
_sync_list_adapter = TypeAdapter(List[TelemetrySyncSchema])


class TelemetryService:
    """
    Domain service layer for Telemetry ingestion, deduplication, and scheduled aggregation.
    """

    @staticmethod
    def soft_authenticate(request) -> Optional[User]:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        token = auth_header[7:]
        try:
            jwt_auth = JWTAuthentication()
            validated_token = jwt_auth.get_validated_token(token)
            return jwt_auth.get_user(validated_token)
        except (InvalidToken, TokenError):
            return None
        except Exception:
            return None

    @staticmethod
    def check_rate_limit(request, user: Optional[User]) -> bool:
        if user:
            key = f"rl_telemetry_user_{user.id}"
            limit = 20
        else:
            ip = request.META.get("REMOTE_ADDR", "unknown")
            key = f"rl_telemetry_anon_{ip}"
            limit = 5

        current = cache.get(key, 0)
        if current >= limit:
            return False
        cache.set(key, current + 1, 86400)
        return True

    @staticmethod
    async def process_sync_payload(
        *, request_body: Any, user: Optional[User]
    ) -> Tuple[int, int]:
        if isinstance(request_body, dict) and "snapshots" in request_body:
            payload = request_body["snapshots"]
        elif isinstance(request_body, dict) and "daily" in request_body:
            payload = []
            for date_str, snapshot_data in request_body["daily"].items():
                snapshot_data["date"] = date_str
                payload.append(snapshot_data)
        else:
            payload = request_body if isinstance(request_body, list) else [request_body]

        validated_items = _sync_list_adapter.validate_python(payload)

        email_to_user = {}
        if not user:
            emails = {item.user_email for item in validated_items if item.user_email}
            if emails:
                async for u in User.objects.filter(email__in=emails):
                    email_to_user[u.email] = u

        ws_ids = {item.workspace_id for item in validated_items if item.workspace_id}
        prj_ids = {item.project_id for item in validated_items if item.project_id}

        ws_counts = {}
        if ws_ids:
            ws_qs = (
                Membership.objects.filter(
                    workspace_id__in=ws_ids,
                    status=MembershipStatus.ACTIVE,
                    created_at__date__lte=timezone.now().date(),
                )
                .values("workspace_id")
                .annotate(count=Count("id"))
            )
            async for entry in ws_qs:
                ws_counts[entry["workspace_id"]] = entry["count"]

        prj_counts = {}
        if prj_ids:
            prj_qs = (
                Secret.objects.filter(
                    project_id__in=prj_ids,
                    created_at__date__lte=timezone.now().date(),
                )
                .values("project_id")
                .annotate(count=Count("id"))
            )
            async for entry in prj_qs:
                prj_counts[entry["project_id"]] = entry["count"]

        batch_user_email = next((item.user_email for item in validated_items if item.user_email), None)
        batch_cli_version = next((item.cli_version for item in validated_items if item.cli_version), None)
        batch_os = next((item.os for item in validated_items if item.os), None)
        batch_arch = next((item.arch for item in validated_items if item.arch), None)

        snapshots = []
        for item in validated_items:
            target_date = item.date
            client_ts = item.timestamp

            if target_date:
                client_ts = timezone.make_aware(datetime.combine(target_date, time.min))
            elif not client_ts:
                client_ts = timezone.now()

            ws_id = item.workspace_id
            prj_id = item.project_id

            item_email = item.user_email or batch_user_email
            snapshot_user = user or email_to_user.get(item_email)

            snapshots.append(
                TelemetrySnapshot(
                    user=snapshot_user,
                    cli_version=item.cli_version or batch_cli_version,
                    os=item.os or batch_os,
                    arch=item.arch or batch_arch,
                    command_executions=item.command_executions or {},
                    active_environment=item.active_environment,
                    workspace_type=item.workspace_type,
                    workspace_member_count=ws_counts.get(ws_id, item.workspace_member_count or 0),
                    project_secret_count=prj_counts.get(prj_id, item.project_secret_count or 0),
                    proxy_calls=item.proxy_calls,
                    proxy_blocked=item.proxy_blocked,
                    proxy_redacted=item.proxy_redacted,
                    injection_styles_used=item.injection_styles_used or [],
                    integrations_active=item.integrations_active or [],
                    secrets_resolved=item.secrets_resolved,
                    total_proxy_duration_ms=item.total_proxy_duration_ms,
                    proxy_calls_daemon=item.proxy_calls_daemon,
                    proxy_calls_transient=item.proxy_calls_transient,
                    proxy_calls_mcp=item.proxy_calls_mcp,
                    proxy_calls_direct=item.proxy_calls_direct,
                    developer_commands=item.developer_commands,
                    ssrf_attempts_blocked=item.ssrf_attempts_blocked,
                    allowlist_violations=item.allowlist_violations,
                    response_redactions=item.response_redactions,
                    process_verifications_failed=item.process_verifications_failed,
                    production_write_challenges=item.production_write_challenges,
                    keychain_resolution_ms=item.keychain_resolution_ms,
                    session_refresh_ms=item.session_refresh_ms,
                    interactive_prompts_shown=item.interactive_prompts_shown,
                    interactive_prompts_skipped=item.interactive_prompts_skipped,
                    drift_diffs_detected=item.drift_diffs_detected,
                    log_chain_verifications=item.log_chain_verifications,
                    tampering_detected=item.tampering_detected,
                    is_headless_node=item.is_headless_node,
                    keychain_initialized=item.keychain_initialized,
                    typos=item.typos or {},
                    identity_anonymous_calls=item.identity_anonymous_calls,
                    identity_declared_calls=item.identity_declared_calls,
                    identity_issued_calls=item.identity_issued_calls,
                    capability_violations_blocked=item.capability_violations_blocked,
                    process_verifications_passed=item.process_verifications_passed,
                    errors_auth_count=item.errors_auth_count,
                    errors_keychain_count=item.errors_keychain_count,
                    errors_secrets_count=item.errors_secrets_count,
                    errors_network_count=item.errors_network_count,
                    errors_system_count=item.errors_system_count,
                    errors_unknown_count=item.errors_unknown_count,
                    client_timestamp=client_ts,
                )
            )

        created_count = 0
        updated_count = 0
        for snap in snapshots:
            ts_date = snap.client_timestamp.date() if snap.client_timestamp else None
            existing = None
            if snap.user and ts_date:
                existing = await TelemetrySnapshot.objects.filter(
                    user=snap.user,
                    client_timestamp__date=ts_date,
                ).afirst()

            if existing:
                for field in TelemetrySnapshot._meta.get_fields():
                    if (
                        not hasattr(field, "attname")
                        or field.attname
                        in ("id", "created_at", "updated_at", "user_id", "client_timestamp")
                    ):
                        continue
                    setattr(existing, field.attname, getattr(snap, field.attname))
                await existing.asave()
                updated_count += 1
            else:
                await snap.asave()
                created_count += 1

        logger.debug(
            "Telemetry sync completed: %d created, %d updated", created_count, updated_count
        )
        return created_count, updated_count

    @staticmethod
    def verify_cron_secret(request) -> bool:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False
        token = auth_header[7:]
        expected = getattr(settings, "CRON_SECRET", "dev-secret")
        return hmac.compare_digest(token, expected)

    @staticmethod
    async def execute_cron_metrics() -> None:
        await sync_to_async(call_command)("calculate_metrics")
