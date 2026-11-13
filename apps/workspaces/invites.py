"""Workspace invitations: issue, deliver, accept.

An invitation grants nothing until the invited address accepts it. The token
is single-use and the six-digit code is a second, independent way in for a
terminal. Both are stored hashed, bound to one address and one workspace, and
expire. Acceptance creates a membership with no workspace key: the server
cannot seal one for a user it has not met, so the admin's client does it on its
next refresh. Until then the workspace is visible and locked, which is honest
about what is missing.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from asgiref.sync import sync_to_async
from django.conf import settings
from django.utils import timezone

from apps.accounts.models import User
from apps.common.exceptions import (
    AuthenticationError,
    AuthorizationError,
    BodyValidationError,
    ErrorCode,
    NotFoundError,
    RequestError,
)
from apps.workspaces.models import (
    InviteStatus,
    Membership,
    MembershipRole,
    MembershipStatus,
    WorkspaceInvite,
)

CODE_DIGITS = 6
INVALID_INVITE = "This invitation is invalid, expired, or already used."


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def _display_name(user) -> str:
    name = (user.full_name or "").strip()
    return name or user.email


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _hash_code(code: str, token_hash: str) -> str:
    # Binding the code to the token means a leaked database row cannot be
    # brute-forced back into a working six-digit code on its own.
    return hashlib.sha256(f"{code}:{token_hash}".encode()).hexdigest()


def _generate_code() -> str:
    return f"{secrets.randbelow(10**CODE_DIGITS):0{CODE_DIGITS}d}"


def _normalize_code(value: int | str) -> str:
    raw = str(value).strip()
    if raw.isdigit() and len(raw) < CODE_DIGITS:
        return raw.zfill(CODE_DIGITS)
    return raw


def _accept_url(raw_token: str) -> str:
    base = getattr(settings, "WEBSITE_BASE_URL", "https://agentsecrets.tech").rstrip("/")
    return f"{base}/invite?token={raw_token}"


def _body(*, workspace_name: str, inviter: str, code: str, url: str) -> str:
    return (
        f"{inviter} invited you to the '{workspace_name}' workspace on AgentSecrets.\n\n"
        f"Accept in your browser:\n{url}\n\n"
        f"Or accept in the terminal with this code:\n{code}\n\n"
        f"Use the address this email was sent to. The invitation is single-use "
        f"and expires in {settings.INVITE_TTL_DAYS} days.\n\n"
        f"If you do not have an account yet, create one with this address first: "
        f"{getattr(settings, 'WEBSITE_BASE_URL', 'https://agentsecrets.tech').rstrip('/')}/signup\n"
    )


async def issue(
    *,
    workspace,
    inviter: User,
    email: str,
    role: str,
) -> tuple[WorkspaceInvite, str]:
    """Create and deliver one invitation. Fails closed on delivery failure."""
    from apps.common.email.brevo import send as brevo_send

    email = normalize_email(email)
    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash_token(raw_token)
    code = _generate_code()
    now = timezone.now()

    # One live invitation per address per workspace. Re-inviting replaces the
    # previous token instead of leaving two usable ways in.
    await WorkspaceInvite.objects.filter(
        workspace=workspace,
        email=email,
        status=InviteStatus.PENDING,
    ).aupdate(status=InviteStatus.REVOKED)

    invite = await WorkspaceInvite.objects.acreate(
        workspace=workspace,
        email=email,
        role=role,
        invited_by=inviter,
        token_hash=token_hash,
        code_hash=_hash_code(code, token_hash),
        expires_at=now + timedelta(days=settings.INVITE_TTL_DAYS),
    )

    delivered = await sync_to_async(brevo_send, thread_sensitive=False)(
        to=email,
        subject=f"You're invited to {workspace.name} on AgentSecrets",
        text=_body(
            workspace_name=workspace.name,
            inviter=_display_name(inviter),
            code=code,
            url=_accept_url(raw_token),
        ),
    )
    if not delivered and not settings.DEBUG:
        # No deliverable invitation means no invitation. Leaving the row would
        # put a workspace in the invitee's list that they can never accept.
        await invite.adelete()
        raise RequestError(
            ErrorCode.EMAIL_DELIVERY_UNAVAILABLE,
            "Email delivery is not configured on this server; the invitation "
            "was not sent and no access was granted.",
            503,
        )

    return invite, code


def _expired(invite: WorkspaceInvite) -> bool:
    return invite.expires_at is None or timezone.now() > invite.expires_at


async def preview(*, token: str) -> dict:
    """What a link holder may see before signing in. No secrets, no ids."""
    invite = await WorkspaceInvite.objects.filter(
        token_hash=_hash_token(token), status=InviteStatus.PENDING
    ).select_related("workspace", "invited_by").afirst()
    if invite is None or _expired(invite):
        raise NotFoundError(INVALID_INVITE)
    masked = invite.email
    local, _, domain = invite.email.partition("@")
    if local:
        masked = f"{local[0]}{'*' * max(len(local) - 1, 1)}@{domain}"
    return {
        "workspace_name": invite.workspace.name,
        "invited_by": _display_name(invite.invited_by) if invite.invited_by else "",
        "email": masked,
        "role": invite.role,
        "expires_at": invite.expires_at.isoformat(),
        "has_account": await User.objects.filter(email=invite.email).aexists(),
    }


async def awaiting_key_for(*, user: User) -> list[dict]:
    """Invitations this caller can finish, because they admin the workspace.

    These are the accepted invitations whose workspace key still has to be
    sealed by a client that holds it. That is the admin's terminal, on its
    next refresh.
    """
    admin_workspaces = [
        ws_id
        async for ws_id in Membership.objects.filter(
            user=user,
            status=MembershipStatus.ACTIVE,
            role__in=[MembershipRole.OWNER, MembershipRole.ADMIN],
        ).values_list("workspace_id", flat=True)
    ]
    if not admin_workspaces:
        return []

    items = []
    async for invite in WorkspaceInvite.objects.filter(
        workspace_id__in=admin_workspaces, status=InviteStatus.ACCEPTED
    ).select_related("workspace"):
        items.append(
            {
                "id": str(invite.id),
                "workspace_id": str(invite.workspace_id),
                "workspace_name": invite.workspace.name,
                "email": invite.email,
                "role": invite.role,
            }
        )
    return items


async def pending_for(*, user: User) -> list[dict]:
    """Invitations waiting on this signed-in address."""
    items = []
    async for invite in WorkspaceInvite.objects.filter(
        email=normalize_email(user.email), status=InviteStatus.PENDING
    ).select_related("workspace", "invited_by"):
        if _expired(invite):
            continue
        items.append(
            {
                "id": str(invite.id),
                "workspace_id": str(invite.workspace_id),
                "workspace_name": invite.workspace.name,
                "role": invite.role,
                "invited_by": _display_name(invite.invited_by) if invite.invited_by else "",
                "expires_at": invite.expires_at.isoformat(),
            }
        )
    return items


async def accept(
    *,
    user: User,
    token: str | None = None,
    code: int | str | None = None,
    workspace_id=None,
) -> dict:
    """Accept an invitation as the signed-in user.

    The caller proves control of the invited address by holding the token or
    the code, and by being signed in as that address. Both are required: the
    token alone must not let a different account take the seat.
    """
    if not token and not code:
        raise BodyValidationError("token", "Provide the invitation link or code")

    query = WorkspaceInvite.objects.filter(status=InviteStatus.PENDING)
    if token:
        query = query.filter(token_hash=_hash_token(token))
    else:
        query = query.filter(
            email=normalize_email(user.email),
            workspace_id=workspace_id,
        ) if workspace_id else query.filter(email=normalize_email(user.email))

    invite = await query.select_related("workspace").afirst()
    if invite is None or _expired(invite):
        raise AuthenticationError(INVALID_INVITE)

    if invite.email != normalize_email(user.email):
        # Deliberately the same message: a different address learns nothing
        # about whether the invitation exists.
        raise AuthenticationError(INVALID_INVITE)

    if code:
        if invite.attempts >= settings.EMAIL_CODE_MAX_ATTEMPTS:
            raise RequestError(
                ErrorCode.RATE_LIMITED,
                "Too many incorrect codes for this invitation. Ask an admin to resend it.",
                429,
            )
        if not secrets.compare_digest(
            invite.code_hash, _hash_code(_normalize_code(code), invite.token_hash)
        ):
            invite.attempts += 1
            await invite.asave(update_fields=["attempts"])
            raise AuthenticationError("Incorrect invitation code")

    membership = await Membership.objects.filter(
        user=user, workspace_id=invite.workspace_id
    ).afirst()
    if membership is None:
        await _check_seat(invite, user)
        membership = await Membership.objects.acreate(
            user=user,
            workspace=invite.workspace,
            role=invite.role,
            status=MembershipStatus.ACTIVE,
            # No key yet. The admin client seals one on its next refresh and
            # the workspace unlocks. The server never holds a plaintext key.
            encrypted_workspace_key="",
        )
    elif membership.status == MembershipStatus.INVITED:
        membership.status = MembershipStatus.ACTIVE
        await membership.asave(update_fields=["status", "updated_at"])

    invite.status = InviteStatus.ACCEPTED
    invite.accepted_at = timezone.now()
    invite.accepted_by = user
    await invite.asave(update_fields=["status", "accepted_at", "accepted_by"])

    # Accepting proves control of the address, which is exactly what email
    # verification asks for. Read the flag from a fresh query: request.auth can
    # carry deferred fields, and touching one inside an async view triggers a
    # synchronous refresh.
    verified = await User.objects.filter(pk=user.pk).values_list(
        "is_email_verified", flat=True
    ).afirst()
    if not verified:
        await User.objects.filter(pk=user.pk).aupdate(is_email_verified=True)

    return {
        "workspace_id": str(invite.workspace_id),
        "workspace_name": invite.workspace.name,
        "role": membership.role,
        "key_pending": not bool(membership.encrypted_workspace_key),
    }


async def reserved_seats(workspace_id) -> int:
    """Seats taken now plus seats promised to a pending invitation.

    An invitation reserves a seat even though it creates no Membership row,
    otherwise a free workspace could be invited past its cap and the last
    person to accept would fail for no reason they could see.
    """
    seat_statuses = [MembershipStatus.ACTIVE, MembershipStatus.INVITED]
    members = await Membership.objects.filter(
        workspace_id=workspace_id, status__in=seat_statuses
    ).acount()
    # Materialize the emails first: a lazy queryset used inside another
    # query's exclude() is evaluated synchronously and raises in an async view.
    member_emails = [
        email
        async for email in Membership.objects.filter(
            workspace_id=workspace_id, status__in=seat_statuses
        ).values_list("user__email", flat=True)
    ]
    pending = (
        await WorkspaceInvite.objects.filter(
            workspace_id=workspace_id, status=InviteStatus.PENDING
        )
        .exclude(email__in=member_emails)
        .acount()
    )
    return members + pending


async def check_capacity(*, user: User, workspace) -> None:
    """Refuse a new invitation that would exceed a full free workspace.

    Reconciles billing once on a would-block so a stale local tier cannot
    refuse a workspace the resolver already upgraded.
    """
    from apps.workspaces.services import MemberService, WorkspaceService

    if workspace.tier != "free":
        return
    if await reserved_seats(workspace.id) < MemberService.FREE_MEMBER_LIMIT:
        return
    try:
        reconciled = await WorkspaceService.reconcile_workspace_billing(
            user=user, workspace_id=workspace.id
        )
    except Exception:
        reconciled = {"tier": "free"}
    if (reconciled or {}).get("tier") == "pro":
        return
    raise BodyValidationError("email", MemberService.LIMIT_MESSAGE)


async def _check_seat(invite: WorkspaceInvite, user: User) -> None:
    """Refuse an acceptance that would exceed a full free workspace.

    The accepting invitation already holds its reserved seat, so this only
    refuses the case where the workspace grew past the cap underneath it.
    """
    from apps.workspaces.services import MemberService, WorkspaceService

    if invite.workspace.tier != "free":
        return
    if await reserved_seats(invite.workspace_id) <= MemberService.FREE_MEMBER_LIMIT:
        return
    try:
        reconciled = await WorkspaceService.reconcile_workspace_billing(
            user=user, workspace_id=invite.workspace_id
        )
    except Exception:
        reconciled = {"tier": "free"}
    if (reconciled or {}).get("tier") == "pro":
        return
    raise AuthorizationError(
        f"This workspace is full ({MemberService.FREE_MEMBER_LIMIT} free seats). "
        "Ask the workspace owner to upgrade before accepting."
    )


async def finalize(*, workspace_id, email: str, encrypted_workspace_key: str) -> bool:
    """Seal the key for an already-accepted member and mark the invite ACTIVE.

    Called from the invite path when an admin client supplies a key for an
    address that already accepted. Returns True when an invitation was
    transitioned, so the caller can skip its normal result handling.
    """
    if not encrypted_workspace_key:
        return False
    email = normalize_email(email)
    invite = await WorkspaceInvite.objects.filter(
        workspace_id=workspace_id,
        email=email,
        status=InviteStatus.ACCEPTED,
    ).afirst()
    if invite is None:
        return False

    membership = await Membership.objects.filter(
        workspace_id=workspace_id, user__email=email
    ).afirst()
    if membership is None:
        return False

    membership.encrypted_workspace_key = encrypted_workspace_key
    membership.status = MembershipStatus.ACTIVE
    membership.role = invite.role
    await membership.asave(
        update_fields=["encrypted_workspace_key", "status", "role", "updated_at"]
    )
    invite.status = InviteStatus.ACTIVE
    await invite.asave(update_fields=["status"])
    return True
