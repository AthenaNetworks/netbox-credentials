from netbox.search import SearchIndex, register_search

from .models import Credential


@register_search
class CredentialIndex(SearchIndex):
    model = Credential
    # Never index the secret or its ciphertext.
    fields = (
        ("name", 100),
        ("username", 300),
        ("description", 500),
        ("comments", 5000),
    )
    display_attrs = ("username", "description")
