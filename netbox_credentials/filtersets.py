import django_filters
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from netbox.filtersets import NetBoxModelFilterSet, PrimaryModelFilterSet
from utilities.filtersets import register_filterset

from .models import Credential, CredentialAssignment

__all__ = (
    "CredentialAssignmentFilterSet",
    "CredentialFilterSet",
)


def _content_type_from_label(value):
    try:
        app_label, model = value.lower().split(".")
        return ContentType.objects.get_by_natural_key(app_label, model)
    except (ValueError, ContentType.DoesNotExist):
        return None


@register_filterset
class CredentialFilterSet(PrimaryModelFilterSet):
    has_secret = django_filters.BooleanFilter(method="filter_has_secret", label=_("Has secret"))
    assigned_object_type = django_filters.CharFilter(
        method="filter_object_type", label=_("Assigned object type (app_label.model)")
    )
    assigned_object_type_id = django_filters.ModelMultipleChoiceFilter(
        field_name="assignments__assigned_object_type",
        queryset=ContentType.objects.all(),
        distinct=True,
        label=_("Assigned object type (ID)"),
    )
    assigned_object_id = django_filters.NumberFilter(
        field_name="assignments__assigned_object_id", distinct=True, label=_("Assigned object (ID)")
    )

    class Meta:
        model = Credential
        # Never filter on secret_ciphertext or key_id.
        fields = ("id", "name", "username", "description", "secret_updated")

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(name__icontains=value) | Q(username__icontains=value) | Q(description__icontains=value)
        )

    def filter_object_type(self, queryset, name, value):
        ct = _content_type_from_label(value)
        if ct is None:
            return queryset.none()
        return queryset.filter(assignments__assigned_object_type=ct).distinct()

    def filter_has_secret(self, queryset, name, value):
        if value is None:
            return queryset
        return queryset.exclude(secret_ciphertext="") if value else queryset.filter(secret_ciphertext="")


@register_filterset
class CredentialAssignmentFilterSet(NetBoxModelFilterSet):
    credential_id = django_filters.ModelMultipleChoiceFilter(
        queryset=Credential.objects.all(), distinct=False, label=_("Credential (ID)")
    )
    credential = django_filters.ModelMultipleChoiceFilter(
        field_name="credential__name",
        queryset=Credential.objects.all(),
        to_field_name="name",
        distinct=False,
        label=_("Credential (name)"),
    )
    assigned_object_type = django_filters.CharFilter(
        method="filter_object_type", label=_("Object type (app_label.model)")
    )
    assigned_object_type_id = django_filters.ModelMultipleChoiceFilter(
        queryset=ContentType.objects.all(), distinct=False, label=_("Object type (ID)")
    )

    class Meta:
        model = CredentialAssignment
        fields = ("id", "assigned_object_id")

    def filter_object_type(self, queryset, name, value):
        ct = _content_type_from_label(value)
        if ct is None:
            return queryset.none()
        return queryset.filter(assigned_object_type=ct)

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(Q(credential__name__icontains=value) | Q(credential__username__icontains=value))
