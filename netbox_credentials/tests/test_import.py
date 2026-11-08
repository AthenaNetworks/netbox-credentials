import io
import tempfile
from unittest import mock

from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from django.core.management import CommandError, call_command
from utilities.testing import TestCase

from netbox_credentials import crypto
from netbox_credentials.models import Credential, CredentialAssignment

PEM = "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"


class FakeResponse:
    def __init__(self, data, status=200):
        self._data, self.status_code = data, status

    def json(self):
        return self._data

    def raise_for_status(self):
        pass


class ImportNetboxSecretsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        site = Site.objects.create(name="S", slug="s")
        dtype = DeviceType.objects.create(
            manufacturer=Manufacturer.objects.create(name="M", slug="m"), model="T", slug="t"
        )
        role = DeviceRole.objects.create(name="R", slug="r")
        cls.fw = Device.objects.create(name="fw1", site=site, device_type=dtype, role=role)
        cls.db = Device.objects.create(name="db1", site=site, device_type=dtype, role=role)
        cls.sw = Device.objects.create(name="sw1", site=site, device_type=dtype, role=role)

    def _secret(self, pk, device, name, plaintext, role="Device Login", comments=""):
        return {
            "id": pk,
            "name": name,
            "plaintext": plaintext,
            "comments": comments,
            "description": "",
            "role": {"name": role},
            "assigned_object_type": "dcim.device",
            "assigned_object_id": device.pk,
            "assigned_object": {"name": device.name, "display": device.name},
        }

    def run_import(self, secrets, *extra, next_url=None):
        session = mock.MagicMock()
        session.headers = {}
        session.post.return_value = FakeResponse({"session_key": "c2s="})
        pages = [
            FakeResponse({"results": secrets[:1], "next": next_url}),
            FakeResponse({"results": secrets[1:], "next": None}),
        ]
        session.get.side_effect = pages if next_url else [FakeResponse({"results": secrets, "next": None})]
        out = io.StringIO()
        with tempfile.NamedTemporaryFile("w", suffix=".tok") as tok, tempfile.NamedTemporaryFile("w") as key:
            tok.write("nbt_abc.def")
            tok.flush()
            key.write(PEM)
            key.flush()
            with mock.patch("requests.Session", return_value=session):
                call_command(
                    "credentials_import_netbox_secrets",
                    "--url",
                    "https://src",
                    "--token-file",
                    tok.name,
                    "--private-key-file",
                    key.name,
                    *extra,
                    stdout=out,
                )
        return out.getvalue(), session

    def test_dry_run_saves_nothing(self):
        out, _ = self.run_import([self._secret(1, self.fw, "admin", "pw-1")])
        self.assertIn("DRY RUN", out)
        self.assertFalse(Credential.objects.exists())
        self.assertNotIn("pw-1", out)

    def test_commit_maps_and_verifies(self):
        secrets = [
            self._secret(1, self.fw, "admin", "pw-1", comments="note"),
            self._secret(2, self.db, "app-key", "pw-2", role="App Secret"),
        ]
        out, session = self.run_import(secrets, "--commit")
        self.assertNotIn("pw-1", out)
        self.assertTrue(session.post.call_args.kwargs["json"]["preserve_key"])
        login = Credential.objects.get(name="fw1 admin")
        self.assertEqual(login.username, "admin")
        self.assertEqual(login.comments, "note")
        self.assertEqual(crypto.decrypt_secret(login), "pw-1")
        self.assertTrue(login.tags.filter(slug="netbox-secrets").exists())
        app = Credential.objects.get(name="db1 app-key")
        self.assertEqual(app.username, "")
        assignment = CredentialAssignment.objects.get(credential=login)
        self.assertEqual(assignment.assigned_object, self.fw)
        self.assertRegex(out, r"verified\s+2")

    def test_rerun_is_idempotent_and_updates_changes(self):
        self.run_import([self._secret(1, self.fw, "admin", "pw-1")], "--commit")
        out, _ = self.run_import([self._secret(1, self.fw, "admin", "pw-1")], "--commit")
        self.assertRegex(out, r"unchanged\s+1")
        out, _ = self.run_import([self._secret(1, self.fw, "admin", "rotated")], "--commit")
        self.assertRegex(out, r"updated\s+1")
        self.assertEqual(Credential.objects.count(), 1)
        self.assertEqual(crypto.decrypt_secret(Credential.objects.get()), "rotated")
        self.assertEqual(CredentialAssignment.objects.count(), 1)

    def test_name_mismatch_is_skipped(self):
        secret = self._secret(1, self.fw, "admin", "pw-1")
        secret["assigned_object"] = {"name": "someone-else"}
        out, _ = self.run_import([secret], "--commit")
        self.assertIn("is 'fw1' here but 'someone-else' in the source", out)
        self.assertFalse(Credential.objects.exists())

    def test_missing_plaintext_aborts(self):
        with self.assertRaisesMessage(CommandError, "without plaintext"):
            self.run_import([self._secret(1, self.fw, "admin", None)], "--commit")
        self.assertFalse(Credential.objects.exists())

    def test_pagination_stays_on_source_url(self):
        secrets = [self._secret(1, self.fw, "a", "x"), self._secret(2, self.db, "b", "y")]
        _, session = self.run_import(
            secrets, next_url="https://public.example.com/api/plugins/secrets/secrets/?limit=1&offset=1"
        )
        self.assertEqual(
            session.get.call_args_list[1].args[0], "https://src/api/plugins/secrets/secrets/?limit=1&offset=1"
        )


class MergeAndCheckTestCase(ImportNetboxSecretsTestCase):
    """--merge, switching modes, --prune and --check. Inherits the base fixtures and helpers."""

    def shared_set(self, password="shared-pw"):
        return [
            self._secret(1, self.fw, "root", password),
            self._secret(2, self.db, "root", password),
            self._secret(3, self.sw, "root", "different"),
        ]

    def test_merge_groups_identical_secrets(self):
        out, _ = self.run_import(self.shared_set(), "--merge", "--commit")
        self.assertRegex(out, r"credentials created\s+2")
        shared = Credential.objects.get(name="root (shared)")
        self.assertEqual(crypto.decrypt_secret(shared), "shared-pw")
        self.assertEqual({a.assigned_object for a in shared.assignments.all()}, {self.fw, self.db})
        single = Credential.objects.get(name="sw1 root")
        self.assertEqual(crypto.decrypt_secret(single), "different")
        self.assertRegex(out, r"verified\s+3")

    def test_switching_to_merge_moves_links_and_prune_removes_leftovers(self):
        self.run_import(self.shared_set(), "--commit")
        self.assertEqual(Credential.objects.count(), 3)
        out, _ = self.run_import(self.shared_set(), "--merge", "--commit")
        self.assertRegex(out, r"secrets moved\s+1")
        self.assertRegex(out, r"orphans left\s+1")
        # The credential that kept a group member is reused; the other per-device one is now empty.
        orphan = Credential.objects.exclude(assignments__isnull=False).get()
        self.assertFalse(orphan.assignments.exists())
        # A reused per-device credential takes the shared name.
        self.assertTrue(Credential.objects.filter(name="root (shared)").exists())
        out, _ = self.run_import(self.shared_set(), "--merge", "--prune", "--commit")
        self.assertRegex(out, r"pruned\s+1")
        self.assertEqual(Credential.objects.count(), 2)
        self.assertEqual(CredentialAssignment.objects.count(), 3)

    def test_rotation_splits_a_merged_group(self):
        self.run_import(self.shared_set(), "--merge", "--commit")
        rotated = self.shared_set()
        rotated[1]["plaintext"] = "rotated-on-db1"
        out, _ = self.run_import(rotated, "--merge", "--commit")
        self.assertRegex(out, r"verified\s+3")
        fw_cred = CredentialAssignment.objects.get(assigned_object_id=self.fw.pk).credential
        db_cred = CredentialAssignment.objects.get(assigned_object_id=self.db.pk).credential
        self.assertNotEqual(fw_cred.pk, db_cred.pk)
        self.assertEqual(crypto.decrypt_secret(fw_cred), "shared-pw")
        self.assertEqual(crypto.decrypt_secret(db_cred), "rotated-on-db1")

    def test_check_passes_after_import_and_writes_nothing(self):
        self.run_import(self.shared_set(), "--merge", "--commit")
        before = (Credential.objects.count(), CredentialAssignment.objects.count())
        out, _ = self.run_import(self.shared_set(), "--check")
        self.assertIn("3 accounted for, 0 not", out)
        self.assertEqual(before, (Credential.objects.count(), CredentialAssignment.objects.count()))

    def test_check_fails_on_missing_or_changed(self):
        self.run_import(self.shared_set(), "--merge", "--commit")
        changed = self.shared_set()
        changed[2]["plaintext"] = "changed-at-source"
        changed.append(self._secret(4, self.sw, "admin", "never-imported"))
        with self.assertRaises(CommandError):
            self.run_import(changed, "--check")

    def test_check_flags_unlinked_object(self):
        self.run_import(self.shared_set(), "--merge", "--commit")
        CredentialAssignment.objects.get(assigned_object_id=self.db.pk).delete()
        with self.assertRaises(CommandError):
            self.run_import(self.shared_set(), "--check")

    def test_user_rename_is_kept(self):
        self.run_import(self.shared_set(), "--merge", "--commit")
        Credential.objects.filter(name="root (shared)").update(name="Fleet root")
        self.run_import(self.shared_set(), "--merge", "--commit")
        self.assertTrue(Credential.objects.filter(name="Fleet root").exists())
        self.assertFalse(Credential.objects.filter(name="root (shared)").exists())
