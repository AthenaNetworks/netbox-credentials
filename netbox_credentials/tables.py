import django_tables2 as tables
from django.utils.translation import gettext_lazy as _
from netbox.tables import NetBoxTable, PrimaryModelTable, columns

from .models import Credential, CredentialAssignment

__all__ = (
    "CredentialAssignmentTable",
    "CredentialTable",
)

# Neither table has a column for the secret or its ciphertext, so CSV/table export can't leak it.


class CredentialTable(PrimaryModelTable):
    name = tables.Column(verbose_name=_("Name"), linkify=True)
    username = tables.Column(verbose_name=_("Username"))
    has_secret = columns.BooleanColumn(verbose_name=_("Secret set"), orderable=False)
    secret_updated = columns.DateTimeColumn(verbose_name=_("Secret updated"))
    assignment_count = columns.LinkedCountColumn(
        viewname="plugins:netbox_credentials:credentialassignment_list",
        url_params={"credential_id": "pk"},
        verbose_name=_("Assignments"),
    )
    tags = columns.TagColumn(url_name="plugins:netbox_credentials:credential_list")

    class Meta(PrimaryModelTable.Meta):
        model = Credential
        fields = (
            "pk",
            "id",
            "name",
            "username",
            "has_secret",
            "secret_updated",
            "assignment_count",
            "description",
            "owner",
            "comments",
            "tags",
            "created",
            "last_updated",
        )
        default_columns = ("pk", "name", "username", "has_secret", "assignment_count", "description")


class CredentialAssignmentTable(NetBoxTable):
    credential = tables.Column(verbose_name=_("Credential"), linkify=True)
    username = tables.Column(accessor="credential__username", verbose_name=_("Username"))
    assigned_object_type = columns.ContentTypeColumn(verbose_name=_("Object type"))
    assigned_object = tables.Column(verbose_name=_("Object"), linkify=True, orderable=False)
    tags = columns.TagColumn(url_name="plugins:netbox_credentials:credentialassignment_list")

    class Meta(NetBoxTable.Meta):
        model = CredentialAssignment
        fields = (
            "pk",
            "id",
            "credential",
            "username",
            "assigned_object_type",
            "assigned_object",
            "tags",
            "created",
            "last_updated",
        )
        default_columns = ("pk", "credential", "username", "assigned_object_type", "assigned_object")
