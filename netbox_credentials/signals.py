from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import post_delete
from django.dispatch import receiver

from .models import CredentialAssignment, ImportedSecret

# Models that never carry assignments, so deleting them needs no cleanup query.
_SKIP_APPS = {"netbox_credentials", "contenttypes", "sessions", "admin", "migrations", "django_rq"}
_SKIP_LABELS = {"core.objectchange", "extras.cachedvalue", "auth.permission"}


@receiver(post_delete, dispatch_uid="netbox_credentials_cleanup_assignments")
def cleanup_assignments(sender, instance, **kwargs):
    """
    A generic FK does not cascade, and core models cannot be given a GenericRelation from a
    plugin, so remove assignments pointing at any object that has just been deleted.
    Deleting each row (rather than a raw queryset delete) keeps the change log accurate.
    """
    meta = sender._meta
    if meta.app_label in _SKIP_APPS or meta.label_lower in _SKIP_LABELS or instance.pk is None:
        return
    content_type = ContentType.objects.get_for_model(sender)
    for assignment in CredentialAssignment.objects.filter(
        assigned_object_type=content_type, assigned_object_id=instance.pk
    ):
        assignment.delete()
    ImportedSecret.objects.filter(assigned_object_type=content_type, assigned_object_id=instance.pk).delete()
