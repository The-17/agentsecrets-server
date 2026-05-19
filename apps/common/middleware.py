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
