import strawberry_django
from netbox.graphql.filters import NetBoxModelFilter, PrimaryModelFilter, register_filter
from strawberry import ID
from strawberry_django import StrFilterLookup

from .. import models

__all__ = (
    "CredentialAssignmentFilter",
    "CredentialFilter",
)


# No filter on the secret, its ciphertext or key_id.
@register_filter(models.Credential, lookups=True)
class CredentialFilter(PrimaryModelFilter):
    name: StrFilterLookup | None = strawberry_django.filter_field()
    username: StrFilterLookup | None = strawberry_django.filter_field()


@register_filter(models.CredentialAssignment, lookups=True)
class CredentialAssignmentFilter(NetBoxModelFilter):
    credential_id: ID | None = strawberry_django.filter_field()
    assigned_object_type_id: ID | None = strawberry_django.filter_field()
    assigned_object_id: ID | None = strawberry_django.filter_field()
