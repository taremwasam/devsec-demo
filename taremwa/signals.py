from django.contrib.auth.models import User
from django.db.models.signals import m2m_changed, post_save, pre_save
from django.dispatch import receiver

from .audit import get_actor_label, log_security_event
from .middleware import get_current_audit_actor
from .models import UserProfile


@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    """Create or update UserProfile when User is saved"""
    if created:
        UserProfile.objects.get_or_create(user=instance)


@receiver(pre_save, sender=User)
def capture_previous_privilege_state(sender, instance, **kwargs):
    """Capture privilege state before a user update for audit comparison."""
    if not instance.pk:
        instance._previous_privilege_state = None
        return

    try:
        previous = sender.objects.get(pk=instance.pk)
    except sender.DoesNotExist:
        previous = None

    instance._previous_privilege_state = previous


@receiver(post_save, sender=User)
def audit_privilege_flag_changes(sender, instance, created, **kwargs):
    """Audit changes to direct privilege flags on User."""
    if created:
        return

    previous = getattr(instance, "_previous_privilege_state", None)
    if previous is None:
        return

    changed_fields = {}
    for field_name in ("is_staff", "is_superuser", "is_active"):
        before = getattr(previous, field_name)
        after = getattr(instance, field_name)
        if before != after:
            changed_fields[field_name] = f"{before}->{after}"

    if not changed_fields:
        return

    actor = get_current_audit_actor()
    log_security_event(
        "privilege.flags_changed",
        actor=get_actor_label(actor),
        target_user_id=instance.pk,
        target_username=instance.username,
        changes=";".join(
            f"{field}:{value}" for field, value in sorted(changed_fields.items())
        ),
    )


@receiver(m2m_changed, sender=User.groups.through)
def audit_group_membership_changes(sender, instance, action, reverse, model, pk_set, **kwargs):
    """Audit role changes represented by Django group membership updates."""
    if action not in {"post_add", "post_remove", "post_clear"}:
        return

    actor = get_current_audit_actor()
    group_names = []
    target_user_id = None
    target_username = None

    if reverse:
        group_names = [instance.name]
        if pk_set:
            user = model.objects.filter(pk__in=pk_set).first()
            if user is not None:
                target_user_id = user.pk
                target_username = user.username
    elif pk_set:
        target_user_id = instance.pk
        target_username = instance.username
        group_names = list(model.objects.filter(pk__in=pk_set).values_list("name", flat=True))
    else:
        target_user_id = instance.pk
        target_username = instance.username

    log_security_event(
        "privilege.groups_changed",
        actor=get_actor_label(actor),
        target_user_id=target_user_id,
        target_username=target_username,
        action=action.replace("post_", ""),
        groups=group_names or "all",
    )


@receiver(m2m_changed, sender=User.user_permissions.through)
def audit_user_permission_changes(sender, instance, action, reverse, model, pk_set, **kwargs):
    """Audit direct per-user permission grants and removals."""
    if action not in {"post_add", "post_remove", "post_clear"}:
        return

    actor = get_current_audit_actor()
    permission_labels = []
    target_user_id = None
    target_username = None

    if reverse:
        permission_labels = [instance.codename]
        if pk_set:
            user = model.objects.filter(pk__in=pk_set).first()
            if user is not None:
                target_user_id = user.pk
                target_username = user.username
    elif pk_set:
        target_user_id = instance.pk
        target_username = instance.username
        permission_labels = list(
            model.objects.filter(pk__in=pk_set).values_list("codename", flat=True)
        )
    else:
        target_user_id = instance.pk
        target_username = instance.username

    log_security_event(
        "privilege.permissions_changed",
        actor=get_actor_label(actor),
        target_user_id=target_user_id,
        target_username=target_username,
        action=action.replace("post_", ""),
        permissions=permission_labels or "all",
    )
