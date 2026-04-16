import logging
from hashlib import sha256

from django.contrib.auth.models import AnonymousUser


audit_logger = logging.getLogger("security.audit")


def _sanitize_value(value):
    if value is None:
        return "-"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (list, tuple, set)):
        return ",".join(str(item) for item in value) or "-"
    text = str(value).strip()
    return text if text else "-"


def _actor_label(actor):
    if not actor or isinstance(actor, AnonymousUser):
        return "anonymous"
    if not getattr(actor, "is_authenticated", False):
        return "anonymous"
    return f"user:{actor.pk}:{actor.username}"


def hash_identifier(value):
    normalized = _sanitize_value(value).lower()
    return sha256(normalized.encode("utf-8")).hexdigest()[:12]


def log_security_event(event, **fields):
    ordered_fields = [("event", event)]
    ordered_fields.extend(sorted(fields.items()))
    message = " ".join(
        f"{key}={_sanitize_value(value)}" for key, value in ordered_fields
    )
    audit_logger.info(message)


def get_actor_label(actor):
    return _actor_label(actor)
