import strawberry
import strawberry_django

from .types import CredentialAssignmentType, CredentialType


@strawberry.type(name="Query")
class CredentialsQuery:
    credential: CredentialType = strawberry_django.field()
    credential_list: list[CredentialType] = strawberry_django.field()

    credential_assignment: CredentialAssignmentType = strawberry_django.field()
    credential_assignment_list: list[CredentialAssignmentType] = strawberry_django.field()


schema = [CredentialsQuery]
