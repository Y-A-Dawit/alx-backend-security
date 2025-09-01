from .models import RequestLog
from django.utils.timezone import now

class IPLoggingMiddleware:
    """
    Middleware to log client IP address, timestamp, and request path.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = request.META.get("REMOTE_ADDR")

        if ip:
            RequestLog.objects.create(
                ip_address=ip,
                timestamp=now(),
                path=request.path,
            )

        response = self.get_response(request)
        return response
