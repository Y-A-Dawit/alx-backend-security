# ip_tracking/middleware.py
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.utils.timezone import now
from django_ip_geolocation.backends import IPGeolocationAPI
from .models import RequestLog, BlockedIP

class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.geo_api = IPGeolocationAPI("free")  # "free" mode requires no key

    def __call__(self, request):
        ip = self.get_client_ip(request)

        # Block IPs
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP has been blocked.")

        # Get cached geo info
        cache_key = f"geo_{ip}"
        geo_data = cache.get(cache_key)

        if not geo_data:
            try:
                geo_info = self.geo_api.geolocate(ip)
                geo_data = {
                    "country": geo_info.get("country", None),
                    "city": geo_info.get("city", None),
                }
            except Exception:
                geo_data = {"country": None, "city": None}
            cache.set(cache_key, geo_data, timeout=60*60*24)  # 24 hours

        # Log request
        RequestLog.objects.create(
            ip_address=ip,
            timestamp=now(),
            path=request.path,
            country=geo_data["country"],
            city=geo_data["city"],
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")
