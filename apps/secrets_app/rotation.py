from __future__ import annotations

import logging
import uuid
from typing import Any
from django.db import transaction
from django.utils import timezone
from asgiref.sync import sync_to_async

from apps.accounts.models import User
from apps.common.exceptions import (
    NotFoundError,
    AuthorizationError,
    BodyValidationError,
    ConflictError,
)
from apps.common.services.encryption import EncryptionService as encryption_service
from apps.workspaces.models import MembershipRole
from apps.workspaces.services import ActivityLogService
from .models import Secret, SecretVersion
from .selectors import ProjectSelector, SecretSelector

logger = logging.getLogger("apps.secrets_app.rotation")


class SecretRotationService:
    """Domain service for B1 client-push value rotation (ROTATION_PLAN Phase 1).

    Every new value arrives as client DEK-ciphertext; the server applies only
    its own Fernet envelope and stores. Plaintext is never present here, and
    ciphertext never leaves in status/metadata responses (HR-H1).
    """

    DEFAULT_OVERLAP = timezone.timedelta(hours=24)
    REASONS = ("routine", "compromise")
    TYPES = ("value_client", "value_auto", "value_provider")
    RETAIN_PREVIOUS = 1

    @staticmethod
    async def _resolve_secret(
        *, user: User, project_id: uuid.UUID, key: str, environment: str, write: bool = True
    ) -> tuple[Any, Secret]:
        project, role = await ProjectSelector.resolve_secret_project_and_role(
            user=user, project_id=project_id
        )
        if write and role == MembershipRole.READ_ONLY:
            raise AuthorizationError("You don't have permission to modify secrets")
        SecretSelector.validate_env(environment)
        secret = await Secret.objects.filter(
            project=project, key=key.upper(), environment=environment
        ).afirst()
        if not secret:
            raise NotFoundError(f"Secret '{key.upper()}' does not exist in this project")
        return project, secret

    @staticmethod
    def _version_metadata(version: SecretVersion) -> dict[str, Any]:
        return {
            "version_id": str(version.id),
            "staging_label": version.staging_label,
            "rotation_reason": version.rotation_reason,
            "rotation_id": version.rotation_id,
            "overlap_until": version.overlap_until.isoformat() if version.overlap_until else None,
            "revoked_at": version.revoked_at.isoformat() if version.revoked_at else None,
            "created_at": version.created_at.isoformat(),
        }

    @staticmethod
    async def create_pending_version(
        *,
        user: User,
        project_id: uuid.UUID,
        key: str,
        environment: str = "development",
        ciphertext: str,
        rotation_id: str | None = None,
        reason: str = "routine",
    ) -> tuple[dict[str, Any], bool]:
        """Stage a client-encrypted value as pending (two-phase step 1).

        Returns (metadata, replayed). A repeated rotation_id returns the
        existing pending row without minting; a clashing pending raises 409
        (HR-H2: one pending per secret)."""
        if reason not in SecretRotationService.REASONS:
            raise BodyValidationError("reason", "Must be 'routine' or 'compromise'")
        if not ciphertext:
            raise BodyValidationError("ciphertext", "Ciphertext is required")
        project, secret = await SecretRotationService._resolve_secret(
            user=user, project_id=project_id, key=key, environment=environment
        )
        stored = encryption_service.encrypt(ciphertext)

        @sync_to_async
        def _create():
            with transaction.atomic():
                existing = SecretVersion.objects.select_for_update().filter(
                    secret=secret, staging_label="pending"
                ).first()
                if existing is not None:
                    if rotation_id and existing.rotation_id == rotation_id:
                        return existing, True
                    raise ConflictError(
                        "A pending version already exists for this secret; "
                        "promote, roll back, or abort it first"
                    )
                version = SecretVersion.objects.create(
                    secret=secret,
                    ciphertext=stored,
                    staging_label="pending",
                    rotation_reason=reason,
                    rotation_id=rotation_id or None,
                    provider_binding={"mode": "out-of-band"},
                    created_by=user,
                )
                return version, False

        version, replayed = await _create()
        try:
            await ActivityLogService.record(
                workspace_id=project.workspace_id,
                project_id=project.id,
                actor=user,
                actor_email=getattr(user, "email", ""),
                action="secret.rotation_pending",
                target_type="secret",
                target_id=str(secret.id),
                target_name=secret.key,
                metadata={"key": secret.key, "environment": environment, "reason": reason},
                source="api",
            )
        except Exception as exc:
            logger.warning("ROTATION_AUDIT_SKIP: %s", exc)
        return {**SecretRotationService._version_metadata(version), "replayed": replayed}, replayed

    @staticmethod
    async def promote_pending_version(
        *,
        user: User,
        project_id: uuid.UUID,
        key: str,
        environment: str = "development",
        expected_current_version_id: str | None = None,
        reason: str = "routine",
    ) -> dict[str, Any]:
        """Flip pending to current in one transaction (two-phase step 4).

        Routine keeps the old value as previous through the overlap window
        (provider-side overlap: the old credential stays valid AT THE
        PROVIDER until retire). Compromise shreds previous ciphertext
        immediately and keeps no poisoned row (HR-H3/HR-M4).
        CAS: when expected_current_version_id is given, promote only if the
        current row still matches (HR-H4)."""
        if reason not in SecretRotationService.REASONS:
            raise BodyValidationError("reason", "Must be 'routine' or 'compromise'")
        project, secret = await SecretRotationService._resolve_secret(
            user=user, project_id=project_id, key=key, environment=environment
        )

        current_id, previous_id = await sync_to_async(_promote_pending_txn)(
            secret=secret,
            user=user,
            expected_current_version_id=expected_current_version_id,
            reason=reason,
        )
        try:
            await ActivityLogService.record(
                workspace_id=project.workspace_id,
                project_id=project.id,
                actor=user,
                actor_email=getattr(user, "email", ""),
                action="secret.rotation_promoted",
                target_type="secret",
                target_id=str(secret.id),
                target_name=secret.key,
                metadata={"key": secret.key, "environment": environment, "reason": reason},
                source="api",
            )
        except Exception as exc:
            logger.warning("ROTATION_AUDIT_SKIP: %s", exc)
        return {
            "key": secret.key,
            "environment": environment,
            "current_version_id": current_id,
            "previous_version_id": previous_id,
            "reason": reason,
        }

    @staticmethod
    async def rollback_to_previous(
        *,
        user: User,
        project_id: uuid.UUID,
        key: str,
        environment: str = "development",
    ) -> dict[str, Any]:
        """Restore the previous value to current in one transaction.

        Refuses revoked/poisoned or reaped versions (HR-H3): after a
        compromise rotation there is nothing to roll back to."""
        project, secret = await SecretRotationService._resolve_secret(
            user=user, project_id=project_id, key=key, environment=environment
        )

        @sync_to_async
        def _rollback():
            with transaction.atomic():
                current = SecretVersion.objects.select_for_update().filter(
                    secret=secret, staging_label="current"
                ).first()
                if current is None:
                    raise NotFoundError("No current version to roll back from")
                previous = SecretVersion.objects.select_for_update().filter(
                    secret=secret, staging_label="previous", revoked_at__isnull=True
                ).order_by("-created_at").first()
                if previous is None:
                    raise BodyValidationError(
                        "key", "No live previous version: it was poisoned by a "
                        "compromise rotation or reaped after retention"
                    )
                now = timezone.now()
                overlap_eff = secret.rotation_overlap or SecretRotationService.DEFAULT_OVERLAP
                # Relabel the outgoing current FIRST so two `current` rows never
                # coexist under the partial unique index (HR-H2).
                current.staging_label = "previous"
                current.overlap_until = now + overlap_eff
                current.rotation_reason = "routine"
                current.save(update_fields=[
                    "staging_label", "overlap_until", "rotation_reason", "updated_at",
                ])
                previous.staging_label = "current"
                previous.overlap_until = None
                previous.save(update_fields=["staging_label", "overlap_until", "updated_at"])
                secret.value = previous.ciphertext
                _advance_cadence(secret, now)
                secret.save(update_fields=["value", "next_rotation_at", "updated_at"])
                return str(previous.id), str(current.id)

        current_id, previous_id = await _rollback()
        try:
            await ActivityLogService.record(
                workspace_id=project.workspace_id,
                project_id=project.id,
                actor=user,
                actor_email=getattr(user, "email", ""),
                action="secret.rotation_rollback",
                target_type="secret",
                target_id=str(secret.id),
                target_name=secret.key,
                metadata={"key": secret.key, "environment": environment},
                source="api",
            )
        except Exception as exc:
            logger.warning("ROTATION_AUDIT_SKIP: %s", exc)
        return {
            "key": secret.key,
            "environment": environment,
            "current_version_id": current_id,
            "previous_version_id": previous_id,
        }

    @staticmethod
    async def abort_pending_version(
        *,
        user: User,
        project_id: uuid.UUID,
        key: str,
        environment: str = "development",
    ) -> dict[str, Any]:
        """Delete a staged pending version (unsticks crashed rotations; the
        one-pending index would otherwise block the next attempt)."""
        project, secret = await SecretRotationService._resolve_secret(
            user=user, project_id=project_id, key=key, environment=environment
        )
        deleted, _ = await SecretVersion.objects.filter(
            secret=secret, staging_label="pending"
        ).adelete()
        if not deleted:
            raise NotFoundError("No pending version to abort")
        return {"key": secret.key, "environment": environment, "aborted": True}

    @staticmethod
    async def set_rotation_policy(
        *,
        user: User,
        project_id: uuid.UUID,
        key: str,
        environment: str = "development",
        rotation_type: str = "value_client",
        period_days: int | None = None,
        overlap_hours: int | None = None,
        provider_binding: dict[str, Any] | None = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Arm or disarm a value-rotation cadence. Desired-state only:
        execution (including reminders) is Pro-gated in the resolver (HR-M3).
        Arming value_auto on a trust-anchor key is refused (HR-M1)."""
        if rotation_type not in SecretRotationService.TYPES:
            raise BodyValidationError("rotation_type", "Must be value_client, value_auto, or value_provider")
        project, secret = await SecretRotationService._resolve_secret(
            user=user, project_id=project_id, key=key, environment=environment
        )
        now = timezone.now()
        if not enabled or rotation_type == "none" or period_days is None:
            secret.rotation_type = "none"
            secret.rotation_period = None
            secret.next_rotation_at = None
        else:
            if not 1 <= period_days <= 365:
                raise BodyValidationError("period_days", "Must be between 1 and 365")
            if overlap_hours is not None and not 0 <= overlap_hours <= 168:
                raise BodyValidationError("overlap_hours", "Must be between 0 and 168")
            if rotation_type == "value_auto" and not b2_key_allowed(secret.key):
                raise BodyValidationError(
                    "rotation_type",
                    "Key is a rotation trust anchor and can never be an autonomous target (HR-M1)",
                )
            if rotation_type == "value_client" and provider_binding is not None:
                raise BodyValidationError(
                    "provider_binding", "Meaningful only for autonomous/provider rotation"
                )
            if rotation_type == "value_provider":
                if provider_binding is None:
                    raise BodyValidationError("provider_binding", "Required for provider rotation")
                checked = _validate_provider_binding_shape(provider_binding)
                if checked["admin_credential_ref"] == secret.key:
                    raise BodyValidationError("provider_binding", "A secret cannot rotate itself")
                ref_exists = await Secret.objects.filter(
                    project_id=secret.project_id, key=checked["admin_credential_ref"],
                    environment=environment,
                ).aexists()
                if not ref_exists:
                    raise BodyValidationError(
                        "provider_binding",
                        f"Admin credential '{checked['admin_credential_ref']}' does not exist "
                        "in this project/environment",
                    )
                provider_binding = checked
            if provider_binding is not None and not isinstance(provider_binding, dict):
                raise BodyValidationError("provider_binding", "Must be an object")
            secret.rotation_type = rotation_type
            secret.rotation_period = timezone.timedelta(days=period_days)
            secret.next_rotation_at = now + secret.rotation_period
            if overlap_hours is not None:
                secret.rotation_overlap = timezone.timedelta(hours=overlap_hours)
            if provider_binding is not None:
                secret.rotation_binding = provider_binding
        await secret.asave(update_fields=[
            "rotation_type", "rotation_period", "rotation_overlap",
            "rotation_binding", "next_rotation_at", "updated_at",
        ])
        return {
            "key": secret.key,
            "environment": environment,
            "policy": {
                "rotation_type": secret.rotation_type,
                "rotation_period_days": secret.rotation_period.days if secret.rotation_period else None,
                "next_rotation_at": secret.next_rotation_at.isoformat() if secret.next_rotation_at else None,
                "rotation_binding": secret.rotation_binding or {},
            },
        }

    @staticmethod
    async def get_rotation_status(
        *, user: User, project_id: uuid.UUID, key: str, environment: str = "development"
    ) -> dict[str, Any]:
        """Rotation metadata only — ciphertext never leaves in status (HR-H1)."""
        project, secret = await SecretRotationService._resolve_secret(
            user=user, project_id=project_id, key=key, environment=environment, write=False
        )
        versions = [
            SecretRotationService._version_metadata(v)
            async for v in SecretVersion.objects.filter(secret=secret).order_by("-created_at")[:10]
        ]
        return {
            "key": secret.key,
            "environment": environment,
            "policy": {
                "rotation_type": secret.rotation_type,
                "rotation_period_days": secret.rotation_period.days if secret.rotation_period else None,
                "next_rotation_at": secret.next_rotation_at.isoformat() if secret.next_rotation_at else None,
                "rotation_binding": secret.rotation_binding or {},
            },
            "versions": versions,
        }

    @staticmethod
    async def execute_autonomous_rotation(
        *,
        workspace_id: uuid.UUID,
        project_id: uuid.UUID,
        key: str,
        environment: str = "development",
        ciphertext: str,
        rotation_id: str,
        reason: str = "routine",
    ) -> tuple[dict[str, Any], bool]:
        """B2/B3 managed execute: stage a DEK-holder-encrypted value and
        promote it in one atomic transaction. The caller (resolver or its
        isolated executor) is a DEK-holder, so ciphertext-only handling
        preserves zero-knowledge end to end.

        Authorization is the resolver's Ed25519 identity (checked at the view
        layer) plus server-side re-validation: the secret must belong to the
        claimed workspace; value_auto targets must pass the HR-M1 denylist;
        value_provider targets must carry a valid binding whose admin
        credential resolves in the same project/environment (HR-M2).
        Returns (result, replayed)."""
        if reason not in SecretRotationService.REASONS:
            raise BodyValidationError("reason", "Must be 'routine' or 'compromise'")
        if not ciphertext:
            raise BodyValidationError("ciphertext", "Ciphertext is required")
        if not rotation_id:
            raise BodyValidationError("rotation_id", "Idempotency key is required (HR-H4)")

        @sync_to_async
        def _execute():
            with transaction.atomic():
                try:
                    secret = Secret.objects.select_for_update().get(
                        project_id=project_id, key=key.upper(), environment=environment,
                        project__workspace_id=workspace_id,
                    )
                except Secret.DoesNotExist:
                    raise NotFoundError(
                        f"Secret '{key.upper()}' does not exist in this workspace/project"
                    )
                if secret.rotation_type not in ("value_auto", "value_provider"):
                    raise BodyValidationError(
                        "rotation_type", "Secret is not armed for managed rotation"
                    )
                if secret.rotation_type == "value_auto":
                    if not b2_key_allowed(secret.key):
                        raise BodyValidationError(
                            "key", "Key is a rotation trust anchor and can never be an autonomous target (HR-M1)"
                        )
                    version_binding = {"mode": "autonomous"}
                else:
                    version_binding = _validate_provider_binding_sync(
                        secret=secret, binding=secret.rotation_binding, environment=environment
                    )
                existing = SecretVersion.objects.filter(
                    secret=secret, rotation_id=rotation_id
                ).first()
                if existing is not None:
                    if existing.staging_label == "current":
                        return {
                            "key": secret.key,
                            "environment": environment,
                            "current_version_id": str(existing.id),
                            "previous_version_id": None,
                            "reason": existing.rotation_reason,
                        }, True
                    current_id, previous_id = _promote_pending_txn(
                        secret=secret, user=None,
                        expected_current_version_id=None, reason=existing.rotation_reason,
                    )
                    return {
                        "key": secret.key,
                        "environment": environment,
                        "current_version_id": current_id,
                        "previous_version_id": previous_id,
                        "reason": existing.rotation_reason,
                    }, True
                pending = SecretVersion.objects.create(
                    secret=secret,
                    ciphertext=encryption_service.encrypt(ciphertext),
                    staging_label="pending",
                    rotation_reason=reason,
                    rotation_id=rotation_id,
                    provider_binding=version_binding,
                    created_by=None,
                )
                current_id, previous_id = _promote_pending_txn(
                    secret=secret, user=None,
                    expected_current_version_id=None, reason=reason,
                )
                return {
                    "key": secret.key,
                    "environment": environment,
                    "current_version_id": current_id,
                    "previous_version_id": previous_id,
                    "reason": reason,
                }, False

        result, replayed = await _execute()
        try:
            await ActivityLogService.record(
                workspace_id=workspace_id,
                project_id=project_id,
                action="secret.rotation_autonomous",
                target_type="secret",
                target_id=str(project_id),
                target_name=key.upper(),
                metadata={"key": key.upper(), "environment": environment, "reason": reason},
                source="cloud",
            )
        except Exception as exc:
            logger.warning("ROTATION_AUDIT_SKIP: %s", exc)
        return result, replayed


# HR-M2: provider_binding can never be a confused deputy. The admin
# credential reference must resolve to a real secret in the SAME
# project/environment as the rotated secret — checked at arm time and
# re-checked at execution time, server-side in both cases (the forgeable
# server row is never trusted; the check runs against live DB state here).
# Adapter ids are a closed code-defined set; no endpoint or extraction path
# is caller-supplied (HR-C1).
B3_ADAPTERS = ("postgres",)


def _binding_error(field: str, message: str) -> BodyValidationError:
    return BodyValidationError(field, message)


def _validate_provider_binding_shape(binding: Any) -> dict[str, Any]:
    if not isinstance(binding, dict):
        raise _binding_error("provider_binding", "Must be an object")
    adapter = binding.get("adapter")
    if adapter not in B3_ADAPTERS:
        raise _binding_error(
            "provider_binding",
            f"Adapter {adapter!r} is not supported yet (supported: {', '.join(B3_ADAPTERS)})",
        )
    ref = binding.get("admin_credential_ref")
    if not ref or not isinstance(ref, str):
        raise _binding_error("provider_binding", "admin_credential_ref is required")
    return {"mode": "provider", "adapter": adapter, "admin_credential_ref": ref.upper()}


def _validate_provider_binding_sync(*, secret: Secret, binding: Any, environment: str) -> dict[str, Any]:
    """Sync HR-M2 check for the execute path (already inside a transaction)."""
    checked = _validate_provider_binding_shape(binding)
    ref_key = checked["admin_credential_ref"]
    if ref_key == secret.key:
        raise _binding_error("provider_binding", "A secret cannot rotate itself")
    exists = Secret.objects.filter(
        project_id=secret.project_id, key=ref_key, environment=environment
    ).exists()
    if not exists:
        raise _binding_error(
            "provider_binding",
            f"Admin credential '{ref_key}' does not exist in this project/environment",
        )
    return checked


# HR-M1: B2 scope structurally excludes the rotation system's own trust
# anchors. Code-defined, never caller-influenced: a key matching this list
# can never be armed for, or executed as, autonomous rotation.
B2_DENYLIST_EXACT = frozenset({"ENCRYPTION_KEY"})
B2_DENYLIST_SUBSTRINGS = ("RESOLVER_", "CEDK", "DELEGATION", "SIGNING", "PRIVATE")


def b2_key_allowed(key: str) -> bool:
    upper = (key or "").upper()
    if upper in B2_DENYLIST_EXACT:
        return False
    return not any(part in upper for part in B2_DENYLIST_SUBSTRINGS)


def _advance_cadence(secret: Secret, now: Any) -> None:
    """Restart the rotation clock after a successful promote or rollback."""
    if secret.rotation_period:
        secret.next_rotation_at = now + secret.rotation_period


def _promote_pending_txn(
    *,
    secret: Secret,
    user: User | None,
    expected_current_version_id: str | None,
    reason: str,
) -> tuple[str, str | None]:
    """Shared transactional promote core: pending → current, old hot row →
    previous (routine, through overlap) or shredded (compromise), cadence
    advanced. Runs inside transaction.atomic (nests as a savepoint when the
    caller already holds one)."""
    with transaction.atomic():
        try:
            pending = SecretVersion.objects.select_for_update().get(
                secret=secret, staging_label="pending"
            )
        except SecretVersion.DoesNotExist:
            raise NotFoundError("No pending version to promote")
        current = SecretVersion.objects.select_for_update().filter(
            secret=secret, staging_label="current"
        ).first()
        if current is not None and expected_current_version_id is not None:
            if str(current.id) != expected_current_version_id:
                raise ConflictError(
                    "Current version changed since staging; refresh and retry"
                )
        now = timezone.now()
        overlap_eff = secret.rotation_overlap or SecretRotationService.DEFAULT_OVERLAP
        if reason == "compromise":
            SecretVersion.objects.filter(
                secret=secret, staging_label__in=["previous", "current"]
            ).delete()
            previous_id = None
        else:
            if current is not None:
                current.staging_label = "previous"
                current.overlap_until = now + overlap_eff
                current.rotation_reason = reason
                current.save(update_fields=[
                    "staging_label", "overlap_until", "rotation_reason", "updated_at",
                ])
                previous_id = str(current.id)
            else:
                previous = SecretVersion.objects.create(
                    secret=secret,
                    ciphertext=secret.value,
                    staging_label="previous",
                    rotation_reason=reason,
                    overlap_until=now + overlap_eff,
                    created_by=user,
                )
                previous_id = str(previous.id)
            live = list(
                SecretVersion.objects.filter(
                    secret=secret, staging_label="previous", revoked_at__isnull=True
                ).order_by("-created_at").values_list("id", flat=True)
            )
            if len(live) > SecretRotationService.RETAIN_PREVIOUS:
                SecretVersion.objects.filter(id__in=live[SecretRotationService.RETAIN_PREVIOUS:]).delete()
        pending.staging_label = "current"
        pending.rotation_reason = reason
        pending.save(update_fields=["staging_label", "rotation_reason", "updated_at"])
        secret.value = pending.ciphertext
        _advance_cadence(secret, now)
        secret.save(update_fields=["value", "next_rotation_at", "updated_at"])
        return str(pending.id), previous_id
