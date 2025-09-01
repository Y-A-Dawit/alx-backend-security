from django.http import HttpResponseForbidden
from django.utils.timezone import now
from .models import RequestLog, BlockedIP


class IPLoggingMiddleware:
    """
    Middleware to log requests and block blacklisted IPs.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = request.META.get("REMOTE_ADDR")

        if ip:
            # Block if IP is in blacklist
            if BlockedIP.objects.filter(ip_address=ip).exists():
                return HttpResponseForbidden("Your IP has been blocked.")

            # Otherwise log request
            RequestLog.objects.create(
                ip_address=ip,
                timestamp=now(),
                path=request.path,
            )

        return self.get_response(request)
