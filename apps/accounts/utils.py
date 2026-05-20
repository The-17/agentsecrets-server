import logging
from django.utils import timezone
from apps.accounts.models import User

logger = logging.getLogger("apps.accounts.utils")

async def stamp_user_activity_async(user: User):
    """
    Stamps the user's active date as now (UTC) if not already set, 
    or if it has been more than 15 minutes since the last update.
    Performs updates in a non-blocking, exception-safe manner.
    """
    try:
        now = timezone.now()
        if not user.last_active_at or (now - user.last_active_at).total_seconds() > 900:
            # Atomic update on DB
            await User.objects.filter(id=user.id).aupdate(last_active_at=now)
            # Update in-memory state
            user.last_active_at = now
    except Exception as e:
        # Guarantee failure transparency/non-blocking behavior
        logger.error(f"Failed to stamp user activity async for {user.email}: {e}")

def stamp_user_activity_sync(user: User):
    """
    Sync wrapper for the activity stamping utility.
    """
    try:
        now = timezone.now()
        if not user.last_active_at or (now - user.last_active_at).total_seconds() > 900:
            # Atomic update on DB
            User.objects.filter(id=user.id).update(last_active_at=now)
            # Update in-memory state
            user.last_active_at = now
    except Exception as e:
        logger.error(f"Failed to stamp user activity sync for {user.email}: {e}")
