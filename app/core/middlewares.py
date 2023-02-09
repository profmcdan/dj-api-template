import json

from django.conf import settings
from django.http import JsonResponse, HttpResponse

from sentry_sdk import capture_exception


class CaptureExceptionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        if exception and not settings.DEBUG:
            capture_exception(exception)
            return JsonResponse(
                {"success": False, "detail": str(exception)}, status=500
            )


class ValidationErrorMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response: HttpResponse = self.get_response(request)

        content_type = response.headers.get("Content-Type")
        if (
            content_type
            and content_type == "application/json"
            and response.status_code == 400
        ):
            data = json.loads(response.content)
            if (
                isinstance(data, dict)
                and not data.get("detail")
                and not data.get("errors")
            ):
                data = {"success": False, "errors": data}
            response.content = json.dumps(data)

        return response
