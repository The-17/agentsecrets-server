from __future__ import annotations

import uuid
from typing import Any
from django.db.models import QuerySet
from apps.common.exceptions import NotFoundError, BodyValidationError
from apps.workspaces.models import Membership, MembershipStatus
from .models import User


class AccountSelector:
    """
    Pure read-only query selector layer for User and Account domains.
    """

    @staticmethod
    async def get_user_by_email(*, email: str) -> User | None:
        return await User.objects.aget_or_none(email=email)

    @staticmethod
    async def get_user_by_id(*, user_id: str | uuid.UUID) -> User | None:
        return await User.objects.aget_or_none(id=user_id)

    @staticmethod
    async def get_public_key(*, email: str) -> str:
        user = await AccountSelector.get_user_by_email(email=email)
        if not user:
            raise NotFoundError(f"User with email {email} not found")
        if not user.public_key:
            raise BodyValidationError("public_key", "User has not set up encryption keys")
        return user.public_key

    @staticmethod
    async def get_user_workspaces_data(*, user: User) -> list[dict[str, Any]]:
        workspaces_data: list[dict[str, Any]] = []
        async for m in Membership.objects.filter(
            user=user, status=MembershipStatus.ACTIVE
        ).select_related("workspace"):
            workspaces_data.append({
                "id": str(m.workspace.id),
                "name": m.workspace.name,
                "type": m.workspace.type,
                "role": m.role,
                "encrypted_workspace_key": m.encrypted_workspace_key,
            })
        return workspaces_data
