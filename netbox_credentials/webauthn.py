"""
WebAuthn registration and assertion ceremonies plus the single-use challenge store.

Every reveal gets its own challenge, bound to the user and the credential being revealed.
Challenges live in the database so consuming one is atomic: a DELETE that removes exactly
one row is the only way to get a challenge back, so a challenge can never be used twice.
"""

import hashlib
import json
import logging
from datetime import timedelta
from urllib.parse import urlsplit

import webauthn as pywebauthn
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, generate_challenge
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .models import Passkey, WebAuthnChallenge

__all__ = (
    "CeremonyError",
    "begin_authentication",
    "begin_registration",
    "finish_authentication",
    "finish_registration",
)

logger = logging.getLogger("netbox_credentials.webauthn")

PLUGIN_NAME = "netbox_credentials"


class CeremonyError(Exception):
    """A WebAuthn ceremony failed. The message is safe to show the user."""


def _config(name):
    return settings.PLUGINS_CONFIG.get(PLUGIN_NAME, {}).get(name)


def _rp_id(request):
    return _config("rp_id") or request.get_host().split(":")[0]


def _origins(request):
    configured = _config("origins")
    if configured:
        return [configured] if isinstance(configured, str) else list(configured)
    return [f"{request.scheme}://{request.get_host()}"]


def _user_verification():
    value = (_config("user_verification") or "required").lower()
    return UserVerificationRequirement.PREFERRED if value == "preferred" else UserVerificationRequirement.REQUIRED


def _uv_required():
    return _user_verification() == UserVerificationRequirement.REQUIRED


def _user_handle(user):
    # Opaque, stable per user, and contains nothing identifying.
    return hashlib.sha256(f"{PLUGIN_NAME}:user:{user.pk}".encode()).digest()


def _transports(values):
    result = []
    for value in values or []:
        try:
            result.append(AuthenticatorTransport(value))
        except ValueError:
            continue
    return result


def _descriptors(passkeys):
    return [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(pk.credential_id), transports=_transports(pk.transports))
        for pk in passkeys
    ]


def _new_challenge(user, purpose, credential=None):
    ttl = int(_config("challenge_ttl") or 120)
    now = timezone.now()
    # Housekeeping: expired challenges anywhere, and any outstanding one for the same purpose and target.
    WebAuthnChallenge.objects.filter(expires__lte=now).delete()
    WebAuthnChallenge.objects.filter(user=user, purpose=purpose, credential=credential).delete()
    challenge = generate_challenge()
    return WebAuthnChallenge.objects.create(
        user=user,
        purpose=purpose,
        credential=credential,
        challenge=challenge,
        expires=now + timedelta(seconds=ttl),
    ), ttl


def _consume_challenge(challenge_id, user, purpose, credential=None):
    """
    Atomically take a challenge out of the store. It is deleted here whatever happens next,
    so a failed verification cannot be retried with the same challenge.
    """
    try:
        with transaction.atomic():
            row = WebAuthnChallenge.objects.select_for_update().get(pk=challenge_id)
            row.delete()
    except (WebAuthnChallenge.DoesNotExist, ValueError, TypeError) as exc:
        raise CeremonyError("This request has expired or was already used. Try again.") from exc
    if row.user_id != user.pk or row.purpose != purpose:
        raise CeremonyError("This request does not belong to you. Try again.")
    if credential is not None and row.credential_id != credential.pk:
        raise CeremonyError("This request was issued for a different credential. Try again.")
    if row.is_expired:
        raise CeremonyError("This request has expired. Try again.")
    return bytes(row.challenge)


def _parse_json(payload):
    if isinstance(payload, (str, bytes)):
        try:
            payload = json.loads(payload)
        except ValueError as exc:
            raise CeremonyError("The browser sent a malformed response.") from exc
    if not isinstance(payload, dict):
        raise CeremonyError("The browser sent a malformed response.")
    return payload


#
# Registration
#


def begin_registration(request, step_up_challenge_id=None, step_up_assertion=None):
    """
    Issue passkey creation options. A user who already has a passkey must first prove
    possession of one, so a hijacked session cannot quietly enrol an attacker's passkey.
    """
    user = request.user
    if Passkey.objects.filter(user=user).exists():
        if not step_up_challenge_id or not step_up_assertion:
            raise CeremonyError("Confirm with an existing passkey before adding another.")
        finish_authentication(
            request, step_up_challenge_id, step_up_assertion, purpose=WebAuthnChallenge.PURPOSE_MANAGE
        )
    row, ttl = _new_challenge(user, WebAuthnChallenge.PURPOSE_REGISTER)
    options = pywebauthn.generate_registration_options(
        rp_id=_rp_id(request),
        rp_name=_config("rp_name") or "NetBox",
        user_id=_user_handle(user),
        user_name=user.get_username(),
        user_display_name=user.get_full_name() or user.get_username(),
        challenge=bytes(row.challenge),
        timeout=ttl * 1000,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=_user_verification(),
        ),
        exclude_credentials=_descriptors(Passkey.objects.filter(user=user)),
    )
    return {"challenge_id": str(row.pk), "options": json.loads(pywebauthn.options_to_json(options))}


def finish_registration(request, challenge_id, credential_json, name):
    user = request.user
    challenge = _consume_challenge(challenge_id, user, WebAuthnChallenge.PURPOSE_REGISTER)
    credential_json = _parse_json(credential_json)
    try:
        verified = pywebauthn.verify_registration_response(
            credential=credential_json,
            expected_challenge=challenge,
            expected_rp_id=_rp_id(request),
            expected_origin=_origins(request),
            require_user_verification=_uv_required(),
        )
    except WebAuthnException as exc:
        logger.warning("Passkey registration failed for %s: %s", user, exc)
        raise CeremonyError(f"Passkey registration failed: {exc}") from exc

    credential_id = bytes_to_base64url(verified.credential_id)
    if Passkey.objects.filter(credential_id=credential_id).exists():
        raise CeremonyError("That passkey is already registered.")
    transports = credential_json.get("response", {}).get("transports") or []
    passkey = Passkey.objects.create(
        user=user,
        name=(name or "").strip()[:64] or "Passkey",
        credential_id=credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        transports=[t for t in transports if isinstance(t, str)],
        aaguid=str(verified.aaguid or ""),
        backed_up=bool(verified.credential_backed_up),
    )
    logger.info("User %s registered passkey %s (%s)", user, passkey.pk, passkey.name)
    return passkey


#
# Authentication: every reveal, and the step-up before adding or removing a passkey
#


def begin_authentication(request, credential=None, purpose=WebAuthnChallenge.PURPOSE_REVEAL):
    user = request.user
    passkeys = list(Passkey.objects.filter(user=user))
    if not passkeys:
        raise CeremonyError("You have no passkeys. Register one on the My passkeys page first.")
    if purpose == WebAuthnChallenge.PURPOSE_REVEAL and credential is None:
        raise ValueError("A reveal challenge must be bound to a credential")
    row, ttl = _new_challenge(user, purpose, credential=credential)
    options = pywebauthn.generate_authentication_options(
        rp_id=_rp_id(request),
        challenge=bytes(row.challenge),
        timeout=ttl * 1000,
        allow_credentials=_descriptors(passkeys),
        user_verification=_user_verification(),
    )
    return {"challenge_id": str(row.pk), "options": json.loads(pywebauthn.options_to_json(options))}


def finish_authentication(
    request, challenge_id, credential_json, credential=None, purpose=WebAuthnChallenge.PURPOSE_REVEAL
):
    """Verify an assertion. For reveals it must be bound to `credential`. Returns the Passkey that signed it."""
    user = request.user
    if purpose == WebAuthnChallenge.PURPOSE_REVEAL and credential is None:
        raise ValueError("A reveal must name the credential being revealed")
    challenge = _consume_challenge(challenge_id, user, purpose, credential=credential)
    credential_json = _parse_json(credential_json)

    raw_id = credential_json.get("rawId") or credential_json.get("id")
    if not isinstance(raw_id, str):
        raise CeremonyError("The browser sent a malformed response.")
    with transaction.atomic():
        passkey = Passkey.objects.select_for_update().filter(user=user, credential_id=raw_id).first()
        if passkey is None:
            raise CeremonyError("That passkey is not registered to your account.")
        try:
            verified = pywebauthn.verify_authentication_response(
                credential=credential_json,
                expected_challenge=challenge,
                expected_rp_id=_rp_id(request),
                expected_origin=_origins(request),
                credential_public_key=bytes(passkey.public_key),
                credential_current_sign_count=passkey.sign_count,
                require_user_verification=_uv_required(),
            )
        except WebAuthnException as exc:
            # Includes a sign count that did not increase, which signals a cloned authenticator.
            logger.warning("Passkey assertion failed for %s (passkey %s): %s", user, passkey.pk, exc)
            raise CeremonyError(f"Passkey verification failed: {exc}") from exc
        passkey.sign_count = verified.new_sign_count
        passkey.backed_up = bool(verified.credential_backed_up)
        passkey.last_used = timezone.now()
        passkey.save(update_fields=("sign_count", "backed_up", "last_used"))
    return passkey


def is_secure_context(request):
    """Used by templates to warn when WebAuthn will not work (no secure context)."""
    origin = _origins(request)[0]
    parts = urlsplit(origin)
    return parts.scheme == "https" or parts.hostname in ("localhost", "127.0.0.1", "::1")
