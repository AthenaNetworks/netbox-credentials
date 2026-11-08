import json
from datetime import timedelta

from django.urls import reverse
from django.utils import timezone
from users.models import User
from utilities.testing import TestCase

from netbox_credentials.models import Credential, Passkey, WebAuthnChallenge

from .authenticator import SoftAuthenticator


class CeremonyTestMixin:
    def post_json(self, name, body=None, **kwargs):
        response = self.client.post(
            reverse(f"plugins:netbox_credentials:{name}", kwargs=kwargs or None),
            data=json.dumps(body or {}),
            content_type="application/json",
        )
        return response, (response.json() if response["Content-Type"].startswith("application/json") else None)

    def enrol(self, authenticator, step_up_with=None, name="Test key"):
        body = {}
        if step_up_with is not None:
            _, begin = self.post_json("passkey_stepup_begin")
            body = {"challenge_id": begin["challenge_id"], "credential": step_up_with.get(begin["options"])}
        response, begin = self.post_json("passkey_register_begin", body)
        self.assertEqual(response.status_code, 200, begin)
        response, data = self.post_json(
            "passkey_register_finish",
            {"challenge_id": begin["challenge_id"], "credential": authenticator.create(begin["options"]), "name": name},
        )
        self.assertEqual(response.status_code, 200, data)
        return Passkey.objects.get(pk=data["id"])

    def reveal(self, credential, authenticator, **get_kwargs):
        response, begin = self.post_json("credential_reveal_begin", pk=credential.pk)
        if response.status_code != 200:
            return response, begin
        assertion = authenticator.get(begin["options"], **get_kwargs)
        return self.post_json(
            "credential_reveal_finish",
            {"challenge_id": begin["challenge_id"], "credential": assertion},
            pk=credential.pk,
        )


class PasskeyEnrolmentTestCase(CeremonyTestMixin, TestCase):
    def test_first_passkey_enrols_without_step_up(self):
        passkey = self.enrol(SoftAuthenticator(), name="Laptop")
        self.assertEqual(passkey.user, self.user)
        self.assertEqual(passkey.name, "Laptop")

    def test_second_passkey_requires_step_up(self):
        first = SoftAuthenticator()
        self.enrol(first)
        response, data = self.post_json("passkey_register_begin")
        self.assertEqual(response.status_code, 403)
        self.assertIn("existing passkey", data["error"])
        self.enrol(SoftAuthenticator(), step_up_with=first)
        self.assertEqual(Passkey.objects.filter(user=self.user).count(), 2)

    def test_step_up_with_someone_elses_passkey_fails(self):
        mine = SoftAuthenticator()
        self.enrol(mine)
        stranger = SoftAuthenticator()
        _, begin = self.post_json("passkey_stepup_begin")
        # Forge an assertion from an unregistered authenticator by allowing any credential.
        begin["options"]["allowCredentials"] = []
        response, data = self.post_json(
            "passkey_register_begin",
            {"challenge_id": begin["challenge_id"], "credential": stranger.get(begin["options"])},
        )
        self.assertEqual(response.status_code, 403)

    def test_delete_requires_assertion(self):
        auth = SoftAuthenticator()
        passkey = self.enrol(auth)
        response, _ = self.post_json("passkey_delete", {}, pk=passkey.pk)
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Passkey.objects.filter(pk=passkey.pk).exists())
        _, begin = self.post_json("passkey_stepup_begin")
        response, _ = self.post_json(
            "passkey_delete",
            {"challenge_id": begin["challenge_id"], "credential": auth.get(begin["options"])},
            pk=passkey.pk,
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Passkey.objects.filter(pk=passkey.pk).exists())

    def test_cannot_delete_other_users_passkey(self):
        other = User.objects.create_user(username="other")
        passkey = Passkey.objects.create(user=other, name="x", credential_id="abc", public_key=b"x")
        response, _ = self.post_json("passkey_delete", {}, pk=passkey.pk)
        self.assertEqual(response.status_code, 404)

    def test_wrong_origin_rejected(self):
        auth = SoftAuthenticator(origin="https://evil.example")
        _, begin = self.post_json("passkey_register_begin")
        response, data = self.post_json(
            "passkey_register_finish",
            {"challenge_id": begin["challenge_id"], "credential": auth.create(begin["options"])},
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Passkey.objects.exists())

    def test_get_not_allowed(self):
        response = self.client.get(reverse("plugins:netbox_credentials:passkey_register_begin"))
        self.assertEqual(response.status_code, 405)

    def test_passkey_page(self):
        response = self.client.get(reverse("plugins:netbox_credentials:passkey_list"))
        self.assertHttpStatus(response, 200)


class RevealTestCase(CeremonyTestMixin, TestCase):
    @classmethod
    def setUpTestData(cls):
        credential = Credential(name="Core router", username="admin")
        credential.set_secret("<b>tr0ub4dor&3</b>")
        credential.save()
        Credential(name="Other").save()

    def setUp(self):
        super().setUp()
        self.credential = Credential.objects.get(name="Core router")
        self.auth = SoftAuthenticator()

    def test_reveal_requires_view_permission(self):
        self.enrol(self.auth)
        response, _ = self.post_json("credential_reveal_begin", pk=self.credential.pk)
        self.assertEqual(response.status_code, 404)

    def test_reveal_requires_a_passkey(self):
        self.add_permissions("netbox_credentials.view_credential")
        response, data = self.post_json("credential_reveal_begin", pk=self.credential.pk)
        self.assertEqual(response.status_code, 409)
        self.assertIn("no passkeys", data["error"])

    def test_successful_reveal_returns_escaped_plaintext_fragment(self):
        self.add_permissions("netbox_credentials.view_credential")
        self.enrol(self.auth)
        response, data = self.reveal(self.credential, self.auth)
        self.assertEqual(response.status_code, 200, data)
        self.assertIn("&lt;b&gt;tr0ub4dor&amp;3&lt;/b&gt;", data["html"])
        self.assertIn("no-store", response["Cache-Control"])
        passkey = Passkey.objects.get(user=self.user)
        self.assertEqual(passkey.sign_count, 1)
        self.assertIsNotNone(passkey.last_used)

    def test_every_reveal_needs_a_new_assertion(self):
        self.add_permissions("netbox_credentials.view_credential")
        self.enrol(self.auth)
        _, begin = self.post_json("credential_reveal_begin", pk=self.credential.pk)
        assertion = self.auth.get(begin["options"])
        body = {"challenge_id": begin["challenge_id"], "credential": assertion}
        first, _ = self.post_json("credential_reveal_finish", body, pk=self.credential.pk)
        self.assertEqual(first.status_code, 200)
        # Replaying the exact same request fails: the challenge was consumed.
        replay, data = self.post_json("credential_reveal_finish", body, pk=self.credential.pk)
        self.assertEqual(replay.status_code, 403)
        self.assertNotIn("tr0ub4dor", data["html"])

    def test_challenge_bound_to_credential(self):
        self.add_permissions("netbox_credentials.view_credential")
        self.enrol(self.auth)
        other = Credential.objects.get(name="Other")
        _, begin = self.post_json("credential_reveal_begin", pk=other.pk)
        response, data = self.post_json(
            "credential_reveal_finish",
            {"challenge_id": begin["challenge_id"], "credential": self.auth.get(begin["options"])},
            pk=self.credential.pk,
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("different credential", data["html"])

    def test_challenge_bound_to_user(self):
        self.add_permissions("netbox_credentials.view_credential")
        self.enrol(self.auth)
        _, begin = self.post_json("credential_reveal_begin", pk=self.credential.pk)
        WebAuthnChallenge.objects.filter(pk=begin["challenge_id"]).update(
            user=User.objects.create_user(username="someone-else")
        )
        response, _ = self.post_json(
            "credential_reveal_finish",
            {"challenge_id": begin["challenge_id"], "credential": self.auth.get(begin["options"])},
            pk=self.credential.pk,
        )
        self.assertEqual(response.status_code, 403)

    def test_expired_challenge_rejected_and_consumed(self):
        self.add_permissions("netbox_credentials.view_credential")
        self.enrol(self.auth)
        _, begin = self.post_json("credential_reveal_begin", pk=self.credential.pk)
        WebAuthnChallenge.objects.filter(pk=begin["challenge_id"]).update(expires=timezone.now() - timedelta(seconds=1))
        response, data = self.post_json(
            "credential_reveal_finish",
            {"challenge_id": begin["challenge_id"], "credential": self.auth.get(begin["options"])},
            pk=self.credential.pk,
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("expired", data["html"])
        self.assertFalse(WebAuthnChallenge.objects.filter(pk=begin["challenge_id"]).exists())

    def test_failed_verification_still_consumes_challenge(self):
        self.add_permissions("netbox_credentials.view_credential")
        self.enrol(self.auth)
        _, begin = self.post_json("credential_reveal_begin", pk=self.credential.pk)
        bad = self.auth.get(begin["options"], origin="https://evil.example")
        response, _ = self.post_json(
            "credential_reveal_finish",
            {"challenge_id": begin["challenge_id"], "credential": bad},
            pk=self.credential.pk,
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(WebAuthnChallenge.objects.filter(pk=begin["challenge_id"]).exists())

    def test_sign_count_regression_rejected(self):
        self.add_permissions("netbox_credentials.view_credential")
        self.enrol(self.auth)
        ok, _ = self.reveal(self.credential, self.auth, sign_count=10)
        self.assertEqual(ok.status_code, 200)
        cloned, data = self.reveal(self.credential, self.auth, sign_count=5)
        self.assertEqual(cloned.status_code, 403)
        self.assertNotIn("tr0ub4dor", data["html"])

    def test_user_verification_required(self):
        self.add_permissions("netbox_credentials.view_credential")
        self.enrol(self.auth)
        self.auth.user_verified = False
        response, _ = self.reveal(self.credential, self.auth)
        self.assertEqual(response.status_code, 403)

    def test_permission_rechecked_on_finish(self):
        self.add_permissions("netbox_credentials.view_credential")
        self.enrol(self.auth)
        _, begin = self.post_json("credential_reveal_begin", pk=self.credential.pk)
        self.remove_permissions("netbox_credentials.view_credential")
        response, _ = self.post_json(
            "credential_reveal_finish",
            {"challenge_id": begin["challenge_id"], "credential": self.auth.get(begin["options"])},
            pk=self.credential.pk,
        )
        self.assertEqual(response.status_code, 404)

    def test_someone_elses_passkey_cannot_reveal(self):
        self.add_permissions("netbox_credentials.view_credential")
        self.enrol(self.auth)
        other_user = User.objects.create_user(username="mallory")
        theirs = SoftAuthenticator()
        Passkey.objects.create(
            user=other_user, name="theirs", credential_id=theirs.credential_id_b64, public_key=b"unused"
        )
        _, begin = self.post_json("credential_reveal_begin", pk=self.credential.pk)
        begin["options"]["allowCredentials"] = []
        response, data = self.post_json(
            "credential_reveal_finish",
            {"challenge_id": begin["challenge_id"], "credential": theirs.get(begin["options"])},
            pk=self.credential.pk,
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("not registered to your account", data["html"])
