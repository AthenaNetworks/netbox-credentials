from netbox.plugins import PluginConfig

__version__ = "0.1.0"


class NetBoxCredentialsConfig(PluginConfig):
    name = "netbox_credentials"
    verbose_name = "Credentials"
    description = "Encrypted credentials linked to any object, with passkey-gated reveal in the UI"
    version = __version__
    author = "Athena Networks"
    base_url = "credentials"
    min_version = "4.7.0"
    max_version = "4.7.99"
    required_settings = ["master_keys"]
    default_settings = {
        # List of Fernet keys. The first encrypts; all of them decrypt.
        "master_keys": [],
        # WebAuthn relying party. rp_id and origins default to the request's host.
        "rp_id": None,
        "rp_name": "NetBox",
        "origins": None,
        # How long a WebAuthn challenge stays valid, in seconds.
        "challenge_ttl": 120,
        # "required" or "preferred". Required means the authenticator must verify the user (PIN/biometric).
        "user_verification": "required",
    }
    graphql_schema = "graphql.schema.schema"

    def ready(self):
        super().ready()
        from . import crypto, signals  # noqa: F401

        # Fail closed: refuse to start with a missing or broken master key.
        crypto.load_keys()


config = NetBoxCredentialsConfig
