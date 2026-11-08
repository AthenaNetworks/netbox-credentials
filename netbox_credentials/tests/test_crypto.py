from core.models import ObjectChange
from cryptography.fernet import Fernet
from dcim.models import Site
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.test import TestCase, override_settings
from extras.events import serialize_for_event
from utilities.testing import TestCase as NetBoxTestCase

from netbox_credentials import crypto
from netbox_credentials.models import Credential, CredentialAssignment


def plugin_config(**overrides):
    config = {**settings.PLUGINS_CONFIG["netbox_credentials"], **overrides}
    return {**settings.PLUGINS_CONFIG, "netbox_credentials": config}


class CryptoTestCase(TestCase):
    def test_round_trip(self):
        key_id, token = crypto.encrypt("pa55")
        self.assertEqual(key_id, crypto.primary_key_id())
        self.assertNotIn("pa55", token)
        credential = Credential(secret_ciphertext=token, key_id=key_id)
        self.assertEqual(crypto.decrypt_secret(credential), "pa55")

    def test_empty_is_none_not_empty_string(self):
        self.assertIsNone(crypto.decrypt_secret(Credential()))

    def test_missing_keys_fail_closed(self):
        with override_settings(PLUGINS_CONFIG=plugin_config(master_keys=[])):
            with self.assertRaises(ImproperlyConfigured):
                crypto.load_keys()

    def test_invalid_key_fails_closed(self):
        with override_settings(PLUGINS_CONFIG=plugin_config(master_keys=["not-a-key"])):
            with self.assertRaises(ImproperlyConfigured):
                crypto.load_keys()

    def test_wrong_key_raises_clear_error(self):
        key_id, token = crypto.encrypt("pa55")
        other = Fernet.generate_key().decode()
        with override_settings(PLUGINS_CONFIG=plugin_config(master_keys=[other])):
            with self.assertRaisesMessage(crypto.DecryptionError, key_id):
                crypto.decrypt_secret(Credential(secret_ciphertext=token, key_id=key_id))

    def test_rotation_and_rekey(self):
        old_keys = settings.PLUGINS_CONFIG["netbox_credentials"]["master_keys"]
        credential = Credential(name="Rotate")
        credential.set_secret("rotate-me")
        credential.save()
        old_id = credential.key_id

        new_key = Fernet.generate_key().decode()
        with override_settings(PLUGINS_CONFIG=plugin_config(master_keys=[new_key, *old_keys])):
            # Old rows still decrypt while the old key is listed.
            self.assertEqual(crypto.decrypt_secret(credential), "rotate-me")
            call_command("credentials_rekey", stdout=open("/dev/null", "w"))
            credential.refresh_from_db()
            self.assertNotEqual(credential.key_id, old_id)
            self.assertEqual(credential.key_id, crypto.key_fingerprint(new_key))

        # After rekey the old key can go.
        with override_settings(PLUGINS_CONFIG=plugin_config(master_keys=[new_key])):
            self.assertEqual(crypto.decrypt_secret(credential), "rotate-me")


class LeakTestCase(NetBoxTestCase):
    """Change logging and events must never carry the secret or its ciphertext."""

    def test_changelog_has_no_secret_material(self):
        self.add_permissions("netbox_credentials.add_credential", "netbox_credentials.change_credential")
        self.client.post("/plugins/credentials/credentials/add/", {"name": "Logged", "secret": "first-secret"})
        credential = Credential.objects.get(name="Logged")
        self.client.post(
            f"/plugins/credentials/credentials/{credential.pk}/edit/",
            {"name": "Logged", "secret": "second-secret"},
        )
        credential.refresh_from_db()
        changes = ObjectChange.objects.filter(
            changed_object_type=ContentType.objects.get_for_model(Credential), changed_object_id=credential.pk
        )
        self.assertEqual(changes.count(), 2)
        for change in changes:
            blob = f"{change.prechange_data} {change.postchange_data}"
            for needle in ("first-secret", "second-secret", "secret_ciphertext", "key_id", credential.key_id):
                self.assertNotIn(needle, blob)
        # A secret-only change is still visible in the log through secret_updated.
        edit = changes.get(action="update")
        self.assertNotEqual(edit.prechange_data["secret_updated"], edit.postchange_data["secret_updated"])

    def test_event_payload_has_no_secret(self):
        credential = Credential(name="Event")
        credential.set_secret("event-secret")
        credential.save()
        payload = serialize_for_event(credential)
        self.assertNotIn("secret", payload)
        self.assertNotIn("event-secret", str(payload))
        self.assertNotIn(credential.secret_ciphertext, str(payload))

    def test_secret_property_is_write_only(self):
        credential = Credential(name="WO", secret="write-only")
        self.assertTrue(credential.has_secret)
        with self.assertRaises(AttributeError):
            _ = credential.secret

    def test_deleting_object_removes_assignments(self):
        site = Site.objects.create(name="Doomed", slug="doomed")
        credential = Credential.objects.create(name="Survivor")
        CredentialAssignment.objects.create(
            credential=credential,
            assigned_object_type=ContentType.objects.get_for_model(Site),
            assigned_object_id=site.pk,
        )
        site.delete()
        self.assertFalse(CredentialAssignment.objects.exists())
        self.assertTrue(Credential.objects.filter(pk=credential.pk).exists())

    def test_cannot_assign_to_missing_object(self):
        from django.core.exceptions import ValidationError

        assignment = CredentialAssignment(
            credential=Credential.objects.create(name="X"),
            assigned_object_type=ContentType.objects.get_for_model(Site),
            assigned_object_id=999999,
        )
        with self.assertRaises(ValidationError):
            assignment.full_clean()
