from typing import TYPE_CHECKING, Annotated

import strawberry
import strawberry_django
from netbox.graphql.types import NetBoxObjectType, PrimaryObjectType, register_type

from .. import models
from .filters import CredentialAssignmentFilter, CredentialFilter

if TYPE_CHECKING:
    from netbox.graphql.types import ContentTypeType

__all__ = (
    "CredentialAssignmentType",
    "CredentialType",
)

# GraphQL is a second read API and only REST is meant to hand out plaintext, so the secret and
# its ciphertext are left off by naming every exposed field explicitly.
CREDENTIAL_FIELDS = (
    "id",
    "name",
    "username",
    "description",
    "comments",
    "secret_updated",
    "owner",
    "assignments",
    "created",
    "last_updated",
)


@register_type(models.Credential, fields=CREDENTIAL_FIELDS, filters=CredentialFilter, pagination=True)
class CredentialType(PrimaryObjectType):
    assignments: list[Annotated["CredentialAssignmentType", strawberry.lazy("netbox_credentials.graphql.types")]]

    @strawberry_django.field
    def has_secret(self) -> bool:
        return bool(self.secret_ciphertext)


@register_type(
    models.CredentialAssignment,
    filters=CredentialAssignmentFilter,
    fields=("id", "credential", "assigned_object_type", "assigned_object_id", "created", "last_updated"),
    pagination=True,
)
class CredentialAssignmentType(NetBoxObjectType):
    # Null when the viewer may see the assignment but not the credential itself.
    credential: CredentialType | None
    assigned_object_type: Annotated["ContentTypeType", strawberry.lazy("netbox.graphql.types")]
