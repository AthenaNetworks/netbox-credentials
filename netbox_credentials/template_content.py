from django.contrib.contenttypes.models import ContentType
from netbox.plugins import PluginTemplateExtension

from . import webauthn as ceremonies
from .models import Credential, CredentialAssignment

__all__ = ("template_extensions",)


class LinkedCredentialsPanel(PluginTemplateExtension):
    """
    Shows the credentials linked to whatever object is being viewed. `models` is left as None,
    which registers the extension for every model's detail page.
    """

    models = None

    def full_width_page(self):
        obj = self.context.get("object")
        request = self.context.get("request")
        if obj is None or request is None or getattr(obj, "pk", None) is None or not hasattr(obj, "_meta"):
            return ""
        if obj._meta.app_label == "netbox_credentials":
            return ""
        user = request.user

        content_type = ContentType.objects.get_for_model(obj)
        # One query: assignments the user may see, whose credential the user may also see.
        assignments = list(
            CredentialAssignment.objects.restrict(user, "view")
            .filter(
                assigned_object_type=content_type,
                assigned_object_id=obj.pk,
                credential__in=Credential.objects.restrict(user, "view"),
            )
            .select_related("credential")
            .order_by("credential__name", "pk")
        )
        can_assign = user.has_perm("netbox_credentials.add_credentialassignment")
        if not assignments and not can_assign:
            return ""
        return self.render(
            "netbox_credentials/inc/object_credentials.html",
            extra_context={
                "assignments": assignments,
                "content_type": content_type,
                "can_assign": can_assign,
                "secure_context": ceremonies.is_secure_context(request),
            },
        )


template_extensions = [LinkedCredentialsPanel]
