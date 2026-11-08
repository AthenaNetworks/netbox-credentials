# ObjectType is NetBox's ContentType proxy with a public() filter that hides internal models.
# There is no plugin-API equivalent for "object types a user may pick".
from core.models import ObjectType
from django import forms
from django.contrib.contenttypes.models import ContentType
from django.urls import NoReverseMatch
from django.utils.translation import gettext_lazy as _
from netbox.forms import (
    NetBoxModelFilterSetForm,
    NetBoxModelForm,
    NetBoxModelImportForm,
    PrimaryModelBulkEditForm,
    PrimaryModelFilterSetForm,
    PrimaryModelForm,
    PrimaryModelImportForm,
)
from utilities.forms import GenericObjectFormMixin
from utilities.forms.fields import (
    CommentField,
    ContentTypeMultipleChoiceField,
    CSVContentTypeField,
    CSVModelChoiceField,
    DynamicModelChoiceField,
    DynamicModelMultipleChoiceField,
    GenericObjectChoiceField,
    TagFilterField,
)
from utilities.forms.rendering import FieldSet
from utilities.views import get_action_url

from .models import Credential, CredentialAssignment

__all__ = (
    "CredentialAssignmentFilterForm",
    "CredentialAssignmentForm",
    "CredentialAssignmentImportForm",
    "CredentialBulkEditForm",
    "CredentialFilterForm",
    "CredentialForm",
    "CredentialImportForm",
    "PasskeyRenameForm",
    "assignable_object_types",
)


_assignable_type_ids = None


def assignable_object_types():
    """
    Public object types, minus this plugin's own, that expose a REST list endpoint (the object
    selector searches through it). Computed once per process; the set only changes with code.
    """
    global _assignable_type_ids
    if _assignable_type_ids is None:
        ids = []
        for object_type in ObjectType.objects.public().exclude(app_label="netbox_credentials"):
            model = object_type.model_class()
            if model is None:
                continue
            try:
                get_action_url(model, action="list", rest_api=True)
            except NoReverseMatch:
                continue
            ids.append(object_type.pk)
        _assignable_type_ids = ids
    return ContentType.objects.filter(pk__in=_assignable_type_ids).order_by("app_label", "model")


class SecretInput(forms.PasswordInput):
    """Write-only. Never renders a value back to the browser."""

    def __init__(self, attrs=None):
        super().__init__(attrs={"autocomplete": "new-password", **(attrs or {})}, render_value=False)


class CredentialForm(PrimaryModelForm):
    secret = forms.CharField(
        label=_("Secret"),
        required=False,
        strip=False,
        widget=SecretInput(),
        help_text=_("Write-only. Leave blank to keep the current secret."),
    )
    clear_secret = forms.BooleanField(
        label=_("Clear secret"),
        required=False,
        help_text=_("Remove the stored secret entirely."),
    )
    comments = CommentField(label=_("Notes"))

    fieldsets = (FieldSet("name", "username", "secret", "clear_secret", "description", "tags", name=_("Credential")),)

    class Meta:
        model = Credential
        fields = ("name", "username", "description", "owner", "comments", "tags")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Never pre-fill the secret, even from ?secret= in a URL.
        self.initial.pop("secret", None)
        if not self.instance.pk:
            del self.fields["clear_secret"]
            self.fieldsets = (FieldSet("name", "username", "secret", "description", "tags", name=_("Credential")),)
            self.fields["secret"].help_text = _("Write-only. Stored encrypted.")

    def clean(self):
        super().clean()
        if self.cleaned_data.get("secret") and self.cleaned_data.get("clear_secret"):
            raise forms.ValidationError(_("Set a new secret or clear it, not both."))
        return self.cleaned_data

    def save(self, *args, **kwargs):
        secret = self.cleaned_data.get("secret")
        if secret:
            self.instance.set_secret(secret)
        elif self.cleaned_data.get("clear_secret"):
            self.instance.set_secret(None)
        return super().save(*args, **kwargs)


class CredentialImportForm(PrimaryModelImportForm):
    secret = forms.CharField(label=_("Secret"), required=False, strip=False, help_text=_("Stored encrypted"))

    class Meta:
        model = Credential
        fields = ("name", "username", "secret", "description", "owner", "comments", "tags")

    def save(self, *args, **kwargs):
        secret = self.cleaned_data.get("secret")
        if secret:
            self.instance.set_secret(secret)
        return super().save(*args, **kwargs)


class CredentialBulkEditForm(PrimaryModelBulkEditForm):
    model = Credential
    username = forms.CharField(label=_("Username"), max_length=255, required=False)
    description = forms.CharField(label=_("Description"), max_length=200, required=False)
    comments = CommentField(label=_("Notes"))

    fieldsets = (FieldSet("username", "description"),)
    nullable_fields = ("username", "description", "comments")


class CredentialFilterForm(PrimaryModelFilterSetForm):
    model = Credential
    fieldsets = (
        FieldSet("q", "filter_id", "tag"),
        FieldSet("name", "username", "has_secret", name=_("Attributes")),
        FieldSet("assigned_object_type_id", "assigned_object_id", name=_("Assignment")),
        FieldSet("owner_group_id", "owner_id", name=_("Ownership")),
    )
    name = forms.CharField(label=_("Name"), required=False)
    username = forms.CharField(label=_("Username"), required=False)
    has_secret = forms.NullBooleanField(
        label=_("Has secret"),
        required=False,
        widget=forms.Select(choices=(("", "---------"), ("true", _("Yes")), ("false", _("No")))),
    )
    assigned_object_type_id = ContentTypeMultipleChoiceField(
        queryset=ObjectType.objects.public(), required=False, label=_("Assigned object type")
    )
    assigned_object_id = forms.IntegerField(label=_("Assigned object ID"), required=False)
    tag = TagFilterField(model)


class CredentialAssignmentForm(GenericObjectFormMixin, NetBoxModelForm):
    """
    Pick an object type, then search for the object itself. Uses NetBox's GenericObjectChoiceField:
    changing the type re-renders the "Object" fieldset over HTMX with an API-backed, searchable
    selector for that model (plus the advanced selector modal).

    Prefill from a link with ?assigned_object_content_type=<ct id>&assigned_object_object_id=<pk>.
    """

    credential = DynamicModelChoiceField(label=_("Credential"), queryset=Credential.objects.all(), selector=True)
    assigned_object = GenericObjectChoiceField(
        label=_("Object"),
        content_type_queryset=ContentType.objects.none(),  # narrowed per form in __init__
        selector=True,
        hx_target_id="assigned-object",
    )

    fieldsets = (
        FieldSet("credential", "tags", name=_("Credential")),
        FieldSet("assigned_object", name=_("Assign to"), html_id="assigned-object"),
    )

    class Meta:
        model = CredentialAssignment
        fields = ("credential", "tags")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Offer every public object type that has a REST list endpoint for the selector to search.
        field = self.fields["assigned_object"]
        queryset = assignable_object_types()
        field.content_type_queryset = queryset
        field.content_type_field.queryset = queryset
        field._content_type_cache.clear()
        field.prepare(self, "assigned_object")


class CredentialAssignmentImportForm(NetBoxModelImportForm):
    credential = CSVModelChoiceField(
        label=_("Credential"),
        queryset=Credential.objects.all(),
        to_field_name="pk",
        help_text=_("Credential ID"),
    )
    assigned_object_type = CSVContentTypeField(
        label=_("Object type"),
        queryset=ContentType.objects.all(),
        help_text=_("Object type in app_label.model form, e.g. dcim.device"),
    )

    class Meta:
        model = CredentialAssignment
        fields = ("credential", "assigned_object_type", "assigned_object_id", "tags")


class CredentialAssignmentFilterForm(NetBoxModelFilterSetForm):
    model = CredentialAssignment
    fieldsets = (
        FieldSet("q", "filter_id", "tag"),
        FieldSet("credential_id", "assigned_object_type_id", "assigned_object_id", name=_("Assignment")),
    )
    credential_id = DynamicModelMultipleChoiceField(
        queryset=Credential.objects.all(), required=False, label=_("Credential")
    )
    assigned_object_type_id = ContentTypeMultipleChoiceField(
        queryset=ObjectType.objects.public(), required=False, label=_("Object type")
    )
    assigned_object_id = forms.IntegerField(label=_("Object ID"), required=False)
    tag = TagFilterField(model)


class PasskeyRenameForm(forms.Form):
    name = forms.CharField(label=_("Name"), max_length=64)
