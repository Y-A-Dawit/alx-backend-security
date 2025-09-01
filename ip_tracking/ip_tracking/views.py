from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from ratelimit.decorators import ratelimit

# Apply rate limits
# - key='ip' → limit per IP
# - rate='10/m' → 10 requests per minute (authenticated)
# - method='POST' → limit only applies to POST requests
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def login_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=400)

    # Example authentication (simplified)
    username = request.POST.get("username")
    password = request.POST.get("password")
    user = authenticate(request, username=username, password=password)
    if user:
        login(request, user)
        return JsonResponse({"success": True})
    return JsonResponse({"error": "Invalid credentials"}, status=401)
