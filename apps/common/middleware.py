import time
import logging

logger = logging.getLogger("django")

class AuditLogMiddleware:
    """
    Middleware to log every request with user identity, status, and duration.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start_time = time.time()
        
        # Process the request
        response = self.get_response(request)
        
        duration = time.time() - start_time
        
        # Identify the user — check both Django Ninja (request.auth) and Django session (request.user)
        user_identity = "Anonymous"
        if hasattr(request, 'auth') and request.auth:
            # Django Ninja sets request.auth to the authenticated user/token
            if hasattr(request.auth, 'email'):
                user_identity = request.auth.email
            else:
                user_identity = str(request.auth)
        elif hasattr(request, 'user') and request.user.is_authenticated:
            user_identity = request.user.email
        
        # Get IP
        ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', '0.0.0.0')).split(',')[0]
        
        # Format: [ACCESS] 200 POST /api/path/ (User: email@test.com) [1.2s] [IP: 1.2.3.4]
        log_message = (
            f"[ACCESS] {response.status_code} {request.method} {request.path} "
            f"(User: {user_identity}) [{duration:.3f}s] [IP: {ip}]"
        )
        
        if response.status_code >= 500:
            logger.error(log_message)
        elif response.status_code >= 400:
            logger.warning(log_message)
        else:
            logger.info(log_message)
            
        return response


from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from apps.accounts.models import User
from apps.accounts.utils import stamp_user_activity_async, stamp_user_activity_sync

def get_user_from_request(request):
    user = None
    if hasattr(request, 'auth') and request.auth:
        if isinstance(request.auth, User):
            user = request.auth
    if not user and hasattr(request, 'user') and request.user and request.user.is_authenticated:
        if isinstance(request.user, User):
            user = request.user
    return user

class ActivityTrackingMiddleware:
    """
    Middleware to capture and stamp active users once per day.
    Runs after views to inspect request.auth / request.user on successful responses.
    """
    def __init__(self, get_response):
        self.get_response = get_response
        if iscoroutinefunction(self.get_response):
            markcoroutinefunction(self)

    async def __acall__(self, request):
        response = await self.get_response(request)
        if response.status_code < 400:
            user = get_user_from_request(request)
            if user:
                await stamp_user_activity_async(user)
        return response

    def __call__(self, request):
        response = self.get_response(request)
        if response.status_code < 400:
            user = get_user_from_request(request)
            if user:
                stamp_user_activity_sync(user)
        return response
