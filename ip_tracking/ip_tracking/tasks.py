from django.db import models
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ["/admin", "/login"]

@shared_task
def detect_suspicious_ips():
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    # Find IPs exceeding 100 requests in the last hour
    request_counts = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values("ip_address")
        .annotate(count=models.Count("id"))
        .filter(count__gt=100)
    )

    for entry in request_counts:
        SuspiciousIP.objects.get_or_create(
            ip_address=entry["ip_address"],
            reason=f"High request volume: {entry['count']} requests in last hour"
        )

    # Flag IPs accessing sensitive paths
    sensitive_requests = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago, path__in=SENSITIVE_PATHS
    ).values("ip_address").distinct()

    for entry in sensitive_requests:
        SuspiciousIP.objects.get_or_create(
            ip_address=entry["ip_address"],
            reason=f"Accessed sensitive path"
        )
