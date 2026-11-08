"""
A minimal software WebAuthn authenticator (ES256, "none" attestation) so tests can run the real
registration and assertion ceremonies end to end against py_webauthn.
"""

import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.encode_cbor import encode_cbor

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40


class SoftAuthenticator:
    def __init__(self, rp_id="testserver", origin="http://testserver", user_verified=True):
        self.rp_id = rp_id
        self.origin = origin
        self.user_verified = user_verified
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0

    @property
    def credential_id_b64(self):
        return bytes_to_base64url(self.credential_id)

    def _flags(self, extra=0):
        return FLAG_UP | (FLAG_UV if self.user_verified else 0) | extra

    def _cose_public_key(self):
        numbers = self.private_key.public_key().public_numbers()
        return encode_cbor(
            {
                1: 2,  # kty: EC2
                3: -7,  # alg: ES256
                -1: 1,  # crv: P-256
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )

    def _client_data(self, kind, challenge_b64, origin=None):
        return json.dumps(
            {
                "type": kind,
                "challenge": challenge_b64,
                "origin": origin or self.origin,
                "crossOrigin": False,
            }
        ).encode()

    def create(self, options):
        """Respond to registration options (the JSON dict the server sends)."""
        rp_hash = hashlib.sha256(self.rp_id.encode()).digest()
        attested = bytes(16) + struct.pack(">H", len(self.credential_id)) + self.credential_id + self._cose_public_key()
        auth_data = rp_hash + bytes([self._flags(FLAG_AT)]) + struct.pack(">I", self.sign_count) + attested
        attestation = encode_cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = self._client_data("webauthn.create", options["challenge"])
        return {
            "id": self.credential_id_b64,
            "rawId": self.credential_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "attestationObject": bytes_to_base64url(attestation),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
        }

    def get(self, options, origin=None, sign_count=None):
        """Respond to authentication options. Increments the signature counter like real hardware."""
        allowed = [c["id"] for c in options.get("allowCredentials", [])]
        if allowed and self.credential_id_b64 not in allowed:
            raise ValueError("Credential not in allowCredentials")
        self.sign_count = self.sign_count + 1 if sign_count is None else sign_count
        rp_hash = hashlib.sha256(self.rp_id.encode()).digest()
        auth_data = rp_hash + bytes([self._flags()]) + struct.pack(">I", self.sign_count)
        client_data = self._client_data("webauthn.get", options["challenge"], origin=origin)
        signature = self.private_key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "id": self.credential_id_b64,
            "rawId": self.credential_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(signature),
            },
            "clientExtensionResults": {},
        }


def challenge_bytes(options):
    return base64url_to_bytes(options["challenge"])
