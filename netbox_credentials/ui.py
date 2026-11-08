from django.utils.translation import gettext_lazy as _
from netbox.ui import attrs, panels

__all__ = (
    "CredentialAssignmentPanel",
    "CredentialPanel",
)


class CredentialPanel(panels.ObjectAttributesPanel):
    title = _("Credential")

    name = attrs.TextAttr("name", label=_("Name"))
    username = attrs.TextAttr("username", label=_("Username"), copy_button=True)
    description = attrs.TextAttr("description", label=_("Description"))
    owner = attrs.RelatedObjectAttr("owner", label=_("Owner"), linkify=True)
    secret_updated = attrs.DateTimeAttr("secret_updated", label=_("Secret updated"), spec="minutes")


class CredentialAssignmentPanel(panels.ObjectAttributesPanel):
    title = _("Assignment")

    credential = attrs.RelatedObjectAttr("credential", label=_("Credential"), linkify=True)
    assigned_object = attrs.GenericForeignKeyAttr("assigned_object", label=_("Object"), linkify=True)
