from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import gettext as _
from netbox.api.fields import ContentTypeField
from netbox.api.gfk_fields import GFKSerializerField
from netbox.api.serializers import NetBoxModelSerializer, PrimaryModelSerializer
from rest_framework import serializers
from rest_framework.exceptions import APIException
from rest_framework.permissions import SAFE_METHODS
from rest_framework.request import Request

from .. import crypto
from ..models import Credential, CredentialAssignment

__all__ = (
    "CredentialAssignmentSerializer",
    "CredentialSerializer",
)


class SecretDecryptionFailed(APIException):
    status_code = 500
    default_code = "secret_decryption_failed"


class CredentialSerializer(PrimaryModelSerializer):
    """
    REST callers with view permission get the plaintext secret. No passkey is involved; that is
    deliberate (see the plugin requirements). The plaintext is only added when serializing for a
    real API request. Event rules and webhooks serialize with request=None and never see it.
    """

    secret = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        allow_null=True,
        trim_whitespace=False,
        style={"input_type": "password"},
        help_text=_("Write: sets the secret (blank or null clears it). Read: returned as plaintext."),
    )
    has_secret = serializers.BooleanField(read_only=True)
    assignment_count = serializers.IntegerField(read_only=True, required=False)

    class Meta:
        model = Credential
        fields = (
            "id",
            "url",
            "display_url",
            "display",
            "name",
            "username",
            "secret",
            "has_secret",
            "secret_updated",
            "description",
            "owner",
            "comments",
            "tags",
            "custom_fields",
            "assignment_count",
            "created",
            "last_updated",
        )
        brief_fields = ("id", "url", "display", "name", "username", "description")
        read_only_fields = ("secret_updated",)

    def _include_plaintext(self, instance):
        request = self.context.get("request")
        if self.nested or not isinstance(request, Request):
            return False
        if self._include_fields and "secret" not in self._include_fields:
            return False
        if request.method in SAFE_METHODS:
            # Read endpoints already run on a queryset restricted to what the user may view.
            return True
        # Write responses: only echo the secret back if the caller may also view this object.
        return request.user.has_perm("netbox_credentials.view_credential", instance)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if self._include_plaintext(instance):
            try:
                data["secret"] = crypto.decrypt_secret(instance)
            except crypto.DecryptionError as exc:
                raise SecretDecryptionFailed(f"Credential {instance.pk}: {exc}") from exc
        return data

    # Writes need no special handling: Credential.secret is a write-only property that encrypts on
    # assignment, so the stock create/update paths (and model validation) work unchanged.


class CredentialAssignmentSerializer(NetBoxModelSerializer):
    credential = CredentialSerializer(nested=True)
    assigned_object_type = ContentTypeField(queryset=ContentType.objects.all())
    assigned_object = GFKSerializerField(read_only=True, allow_missing_serializer=True)

    class Meta:
        model = CredentialAssignment
        fields = (
            "id",
            "url",
            "display_url",
            "display",
            "credential",
            "assigned_object_type",
            "assigned_object_id",
            "assigned_object",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        )
        brief_fields = ("id", "url", "display", "credential", "assigned_object_type", "assigned_object_id")

    def validate(self, data):
        object_type = data.get("assigned_object_type", getattr(self.instance, "assigned_object_type", None))
        object_id = data.get("assigned_object_id", getattr(self.instance, "assigned_object_id", None))
        if object_type is not None and object_id is not None:
            model = object_type.model_class()
            if model is None or model._meta.app_label == "netbox_credentials":
                raise serializers.ValidationError({"assigned_object_type": _("Invalid object type.")})
            try:
                object_type.get_object_for_this_type(pk=object_id)
            except ObjectDoesNotExist:
                raise serializers.ValidationError(
                    {"assigned_object_id": _("Object not found: {type} {id}").format(type=object_type, id=object_id)}
                ) from None
        return super().validate(data)
