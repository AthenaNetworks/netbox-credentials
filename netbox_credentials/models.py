import uuid

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from netbox.models import NetBoxModel, PrimaryModel

from . import crypto

__all__ = (
    "Credential",
    "CredentialAssignment",
    "ImportedSecret",
    "Passkey",
    "WebAuthnChallenge",
)

# Fields that must never appear in change logs, event payloads or any other serialization.
SECRET_FIELDS = ("secret_ciphertext", "key_id")


class Credential(PrimaryModel):
    """
    A username/secret pair. Only ciphertext is persisted; plaintext is never stored and is
    decrypted solely by crypto.decrypt_secret() from the reveal view and the REST serializer.
    """

    name = models.CharField(verbose_name=_("name"), max_length=200)
    username = models.CharField(verbose_name=_("username"), max_length=255, blank=True)
    secret_ciphertext = models.TextField(blank=True, editable=False)
    key_id = models.CharField(max_length=16, blank=True, editable=False)
    secret_updated = models.DateTimeField(
        verbose_name=_("secret updated"),
        blank=True,
        null=True,
        editable=False,
        help_text=_("When the secret was last set. Recorded so secret changes show in the change log."),
    )

    clone_fields = ("username", "description", "owner")

    class Meta:
        ordering = ("name", "pk")
        verbose_name = _("credential")
        verbose_name_plural = _("credentials")

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_credentials:credential", args=[self.pk])

    @property
    def has_secret(self):
        return bool(self.secret_ciphertext)

    def set_secret(self, plaintext):
        """Encrypt and stage a new secret. An empty value or None clears it."""
        if plaintext:
            self.key_id, self.secret_ciphertext = crypto.encrypt(plaintext)
        else:
            self.key_id, self.secret_ciphertext = "", ""
        self.secret_updated = timezone.now()

    set_secret.alters_data = True

    # Write-only: assigning encrypts, reading raises AttributeError. There is deliberately no
    # getter, so templates (including export templates) cannot pull plaintext off the model.
    secret = property(fset=set_secret, doc="Write-only. Assign plaintext to encrypt it.")

    def serialize_object(self, exclude=None):
        # Keep ciphertext out of ObjectChange snapshots and event payloads.
        exclude = [*(exclude or []), *SECRET_FIELDS]
        return super().serialize_object(exclude=exclude)


class CredentialAssignment(NetBoxModel):
    """Links a Credential to any object through a generic foreign key."""

    credential = models.ForeignKey(
        to=Credential,
        on_delete=models.CASCADE,
        related_name="assignments",
        verbose_name=_("credential"),
    )
    assigned_object_type = models.ForeignKey(
        to="contenttypes.ContentType",
        on_delete=models.CASCADE,
        related_name="+",
        verbose_name=_("object type"),
    )
    assigned_object_id = models.PositiveBigIntegerField(verbose_name=_("object ID"))
    assigned_object = GenericForeignKey(ct_field="assigned_object_type", fk_field="assigned_object_id")

    clone_fields = ("credential", "assigned_object_type")

    class Meta:
        ordering = ("credential", "pk")
        indexes = (models.Index(fields=("assigned_object_type", "assigned_object_id")),)
        constraints = (
            models.UniqueConstraint(
                fields=("credential", "assigned_object_type", "assigned_object_id"),
                name="%(app_label)s_%(class)s_unique_credential_object",
                violation_error_message=_("This credential is already assigned to that object."),
            ),
        )
        verbose_name = _("credential assignment")
        verbose_name_plural = _("credential assignments")

    def __str__(self):
        credential = None
        if self.credential_id:
            try:
                credential = self.credential
            except ObjectDoesNotExist:
                # The GraphQL optimizer can leave the relation cache empty when only `display` is requested.
                credential = Credential.objects.filter(pk=self.credential_id).first()
        target = self.assigned_object if self.assigned_object_type_id else None
        return f"{credential or '?'} -> {target or self.assigned_object_id}"

    def get_absolute_url(self):
        return reverse("plugins:netbox_credentials:credentialassignment", args=[self.pk])

    def clean(self):
        super().clean()
        if not self.assigned_object_type_id:
            return
        model = self.assigned_object_type.model_class()
        if model is None:
            raise ValidationError({"assigned_object_type": _("That object type no longer exists.")})
        if model._meta.app_label == "netbox_credentials":
            raise ValidationError({"assigned_object_type": _("Credentials cannot be assigned to plugin objects.")})
        if self.assigned_object_id and not model._default_manager.filter(pk=self.assigned_object_id).exists():
            raise ValidationError(
                {
                    "assigned_object_id": _("No {model} with ID {id} exists.").format(
                        model=model._meta.verbose_name, id=self.assigned_object_id
                    )
                }
            )


class Passkey(models.Model):
    """A WebAuthn credential a user enrolled in this plugin. Unrelated to NetBox login or SSO."""

    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="credential_passkeys",
    )
    name = models.CharField(verbose_name=_("name"), max_length=64)
    # base64url of the raw credential ID (up to 1023 bytes).
    credential_id = models.CharField(max_length=1400, unique=True)
    public_key = models.BinaryField()
    sign_count = models.PositiveBigIntegerField(default=0)
    transports = models.JSONField(default=list, blank=True)
    aaguid = models.CharField(max_length=36, blank=True)
    backed_up = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("user", "name", "pk")
        verbose_name = _("passkey")
        verbose_name_plural = _("passkeys")

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_credentials:passkey_list")


class WebAuthnChallenge(models.Model):
    """
    A single-use WebAuthn challenge. Bound to one user, one purpose and (for reveals) one
    credential. Deleted on finish whether verification succeeds or fails.
    """

    PURPOSE_REGISTER = "register"
    PURPOSE_REVEAL = "reveal"
    PURPOSE_MANAGE = "manage"
    PURPOSE_CHOICES = (
        (PURPOSE_REGISTER, "Register passkey"),
        (PURPOSE_REVEAL, "Reveal secret"),
        (PURPOSE_MANAGE, "Confirm passkey change"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    purpose = models.CharField(max_length=16, choices=PURPOSE_CHOICES)
    credential = models.ForeignKey(to=Credential, on_delete=models.CASCADE, related_name="+", blank=True, null=True)
    challenge = models.BinaryField()
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField()

    class Meta:
        indexes = (models.Index(fields=("expires",)),)

    def __str__(self):
        return f"{self.purpose} challenge for {self.user}"

    @property
    def is_expired(self):
        return timezone.now() >= self.expires


class ImportedSecret(models.Model):
    """
    Provenance for imported secrets: which source secret ended up in which credential, linked to
    which object. Makes re-imports (and switching to merged credentials) idempotent, and lets the
    importer's --check prove that every source secret has a home. Internal; not shown in the UI.
    """

    source = models.CharField(max_length=50, default="netbox-secrets")
    source_id = models.PositiveBigIntegerField()
    credential = models.ForeignKey(to=Credential, on_delete=models.CASCADE, related_name="import_sources")
    assigned_object_type = models.ForeignKey(to="contenttypes.ContentType", on_delete=models.CASCADE, related_name="+")
    assigned_object_id = models.PositiveBigIntegerField()
    imported = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("source", "source_id")
        constraints = (
            models.UniqueConstraint(fields=("source", "source_id"), name="%(app_label)s_%(class)s_unique_source"),
        )
        verbose_name = _("imported secret")
        verbose_name_plural = _("imported secrets")

    def __str__(self):
        return f"{self.source} #{self.source_id}"
