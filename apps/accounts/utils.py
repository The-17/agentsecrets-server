import logging
from django.utils import timezone
from apps.accounts.models import User

logger = logging.getLogger("apps.accounts.utils")

async def stamp_user_activity_async(user: User):
    """
    Stamps the user's active date as today (UTC) if not already set.
    Performs updates in a non-blocking, exception-safe manner.
    """
    try:
        today = timezone.now().date()
        if user.last_active_date != today:
            # Atomic update on DB
            await User.objects.filter(id=user.id).aupdate(last_active_date=today)
            # Update in-memory state
            user.last_active_date = today
    except Exception as e:
        # Guarantee failure transparency/non-blocking behavior
        logger.error(f"Failed to stamp user activity async for {user.email}: {e}")

def stamp_user_activity_sync(user: User):
    """
    Sync wrapper for the activity stamping utility.
    """
    try:
        today = timezone.now().date()
        if user.last_active_date != today:
            # Atomic update on DB
            User.objects.filter(id=user.id).update(last_active_date=today)
            # Update in-memory state
            user.last_active_date = today
    except Exception as e:
        logger.error(f"Failed to stamp user activity sync for {user.email}: {e}")
