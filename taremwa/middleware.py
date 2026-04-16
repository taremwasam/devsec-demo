from threading import local


_audit_context = local()


def get_current_audit_actor():
    return getattr(_audit_context, "actor", None)


class AuditActorMiddleware:
    """Store the current authenticated user for downstream audit logging."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        _audit_context.actor = getattr(request, "user", None)
        try:
            return self.get_response(request)
        finally:
            _audit_context.actor = None
