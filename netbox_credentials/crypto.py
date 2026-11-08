"""
The only module that touches raw key material.

Secrets are encrypted with Fernet. The configured `master_keys` list is wrapped in a
MultiFernet: the first key encrypts, every key decrypts, which allows rotation. Each
ciphertext is stored with the short fingerprint (key_id) of the key that produced it so
the rekey command can report how many rows still depend on an old key.

The master keys are deliberately separate from Django's SECRET_KEY.
"""

import hashlib
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

__all__ = (
    "DecryptionError",
    "Keyring",
    "decrypt_secret",
    "encrypt",
    "key_fingerprint",
    "load_keys",
    "primary_key_id",
    "reencrypt",
)

PLUGIN_NAME = "netbox_credentials"


class DecryptionError(Exception):
    """Raised when a stored secret cannot be decrypted. Never swallowed into an empty string."""


@dataclass(frozen=True)
class Keyring:
    multi: MultiFernet
    key_ids: tuple[str, ...]

    @property
    def primary_id(self):
        return self.key_ids[0]


def key_fingerprint(key):
    """Short, non-reversible identifier for a key. Safe to store and display."""
    if isinstance(key, str):
        key = key.encode()
    return hashlib.sha256(key).hexdigest()[:12]


def _configured_keys():
    plugin_config = settings.PLUGINS_CONFIG.get(PLUGIN_NAME, {})
    keys = plugin_config.get("master_keys")
    if isinstance(keys, (str, bytes)):
        keys = [keys]
    return list(keys or [])


def _build_keyring(keys):
    if not keys:
        raise ImproperlyConfigured(
            f"{PLUGIN_NAME}: PLUGINS_CONFIG['{PLUGIN_NAME}']['master_keys'] must list at least one Fernet key."
        )
    fernets = []
    ids = []
    for index, key in enumerate(keys):
        if not key:
            raise ImproperlyConfigured(f"{PLUGIN_NAME}: master_keys[{index}] is empty.")
        try:
            fernets.append(Fernet(key))
        except (ValueError, TypeError) as exc:
            raise ImproperlyConfigured(
                f"{PLUGIN_NAME}: master_keys[{index}] is not a valid Fernet key (32 url-safe base64-encoded bytes)."
            ) from exc
        key_id = key_fingerprint(key)
        if key_id in ids:
            raise ImproperlyConfigured(f"{PLUGIN_NAME}: master_keys[{index}] is listed more than once.")
        ids.append(key_id)
    return Keyring(multi=MultiFernet(fernets), key_ids=tuple(ids))


_keyring_cache = {}


def load_keys():
    """
    Return the Keyring for the current configuration, raising ImproperlyConfigured if it is
    missing or invalid. Cached per key list so tests can override settings.
    """
    keys = _configured_keys()
    cache_key = tuple(k if isinstance(k, str) else k.decode() for k in keys)
    keyring = _keyring_cache.get(cache_key)
    if keyring is None:
        keyring = _build_keyring(keys)
        _keyring_cache.clear()
        _keyring_cache[cache_key] = keyring
    return keyring


def primary_key_id():
    return load_keys().primary_id


def encrypt(plaintext):
    """Encrypt with the primary key. Returns (key_id, ciphertext)."""
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")
    keyring = load_keys()
    token = keyring.multi.encrypt(plaintext.encode("utf-8"))
    return keyring.primary_id, token.decode("ascii")


def _decrypt(key_id, ciphertext):
    keyring = load_keys()
    try:
        return keyring.multi.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError, ValueError) as exc:
        if key_id and key_id not in keyring.key_ids:
            raise DecryptionError(
                f"Secret was encrypted with key {key_id}, which is not in master_keys. Add that key back to decrypt it."
            ) from exc
        raise DecryptionError("Secret could not be decrypted: the ciphertext is corrupt or the key is wrong.") from exc


def decrypt_secret(credential):
    """
    Return the plaintext secret for a Credential, or None when no secret is stored.
    Raises DecryptionError rather than ever returning an empty string on failure.
    """
    if not credential.secret_ciphertext:
        return None
    return _decrypt(credential.key_id, credential.secret_ciphertext)


def reencrypt(key_id, ciphertext):
    """Re-encrypt a ciphertext under the primary key. Returns (key_id, ciphertext)."""
    keyring = load_keys()
    try:
        token = keyring.multi.rotate(ciphertext.encode("ascii"))
    except InvalidToken as exc:
        raise DecryptionError(f"Cannot re-encrypt: no configured key decrypts a secret tagged {key_id}.") from exc
    return keyring.primary_id, token.decode("ascii")
