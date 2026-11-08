from dcim.models import Site
from django.contrib.contenttypes.models import ContentType
from django.test import override_settings
from django.urls import reverse
from utilities.testing import TestCase, ViewTestCases

from netbox_credentials import crypto
from netbox_credentials.models import Credential, CredentialAssignment


class PluginURLMixin:
    """NetBox's stock view tests build URL names without the plugins: namespace."""

    def _get_base_url(self):
        return f"plugins:netbox_credentials:{self.model._meta.model_name}_{{}}"


class CredentialViewTestCase(PluginURLMixin, ViewTestCases.PrimaryObjectViewTestCase):
    model = Credential
    validation_excluded_fields = ["secret"]

    @classmethod
    def setUpTestData(cls):
        for i in range(1, 4):
            credential = Credential(name=f"Credential {i}", username=f"user{i}")
            credential.set_secret(f"secret-{i}")
            credential.save()

        cls.form_data = {
            "name": "Credential X",
            "username": "admin",
            "secret": "hunter2",
            "description": "A description",
            "comments": "Some notes",
            "tags": [],
        }
        cls.csv_data = (
            "name,username,secret,description",
            "Credential 4,user4,pw4,Fourth",
            "Credential 5,user5,pw5,Fifth",
            "Credential 6,user6,,Sixth",
        )
        cls.csv_update_data = (
            "id,username,description",
            f"{Credential.objects.get(name='Credential 1').pk},changed1,New description 1",
            f"{Credential.objects.get(name='Credential 2').pk},changed2,New description 2",
            f"{Credential.objects.get(name='Credential 3').pk},changed3,New description 3",
        )
        cls.bulk_edit_data = {"description": "Bulk description"}


class CredentialFormTestCase(TestCase):
    """Secret handling in the UI forms and pages."""

    @classmethod
    def setUpTestData(cls):
        credential = Credential(name="Router", username="admin")
        credential.set_secret("s3cret-value")
        credential.save()

    def setUp(self):
        super().setUp()
        self.add_permissions(
            "netbox_credentials.view_credential",
            "netbox_credentials.change_credential",
            "netbox_credentials.view_credentialassignment",
        )
        self.credential = Credential.objects.get(name="Router")

    def test_edit_form_never_renders_secret(self):
        response = self.client.get(reverse("plugins:netbox_credentials:credential_edit", args=[self.credential.pk]))
        self.assertHttpStatus(response, 200)
        self.assertNotIn("s3cret-value", response.content.decode())
        self.assertNotIn(self.credential.secret_ciphertext, response.content.decode())

    def test_detail_page_never_renders_secret(self):
        response = self.client.get(self.credential.get_absolute_url())
        self.assertHttpStatus(response, 200)
        body = response.content.decode()
        self.assertNotIn("s3cret-value", body)
        self.assertNotIn(self.credential.secret_ciphertext, body)

    def test_blank_secret_on_edit_keeps_existing(self):
        before = self.credential.secret_ciphertext
        response = self.client.post(
            reverse("plugins:netbox_credentials:credential_edit", args=[self.credential.pk]),
            {"name": "Router", "username": "root", "secret": ""},
        )
        self.assertHttpStatus(response, 302)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.username, "root")
        self.assertEqual(self.credential.secret_ciphertext, before)
        self.assertEqual(crypto.decrypt_secret(self.credential), "s3cret-value")

    def test_new_secret_on_edit_replaces(self):
        self.client.post(
            reverse("plugins:netbox_credentials:credential_edit", args=[self.credential.pk]),
            {"name": "Router", "username": "admin", "secret": "rotated"},
        )
        self.credential.refresh_from_db()
        self.assertEqual(crypto.decrypt_secret(self.credential), "rotated")

    def test_clear_secret(self):
        self.client.post(
            reverse("plugins:netbox_credentials:credential_edit", args=[self.credential.pk]),
            {"name": "Router", "username": "admin", "clear_secret": "on"},
        )
        self.credential.refresh_from_db()
        self.assertFalse(self.credential.has_secret)
        self.assertIsNone(crypto.decrypt_secret(self.credential))

    def test_csv_export_has_no_secret(self):
        response = self.client.get(reverse("plugins:netbox_credentials:credential_list") + "?export=table&columns=all")
        self.assertHttpStatus(response, 200)
        body = response.content.decode()
        self.assertNotIn("s3cret-value", body)
        self.assertNotIn(self.credential.secret_ciphertext, body)


class CredentialAssignmentViewTestCase(
    PluginURLMixin,
    ViewTestCases.GetObjectViewTestCase,
    ViewTestCases.GetObjectChangelogViewTestCase,
    ViewTestCases.CreateObjectViewTestCase,
    ViewTestCases.DeleteObjectViewTestCase,
    ViewTestCases.ListObjectsViewTestCase,
    ViewTestCases.BulkImportObjectsViewTestCase,
    ViewTestCases.BulkDeleteObjectsViewTestCase,
):
    model = CredentialAssignment

    @classmethod
    def setUpTestData(cls):
        sites = [Site.objects.create(name=f"Site {i}", slug=f"site-{i}") for i in range(1, 5)]
        credentials = [Credential.objects.create(name=f"Credential {i}") for i in range(1, 3)]
        site_type = ContentType.objects.get_for_model(Site)
        for site in sites[:3]:
            CredentialAssignment.objects.create(
                credential=credentials[0], assigned_object_type=site_type, assigned_object_id=site.pk
            )

        cls.form_data = {
            "credential": credentials[1].pk,
            "assigned_object_content_type": site_type.pk,
            "assigned_object_object_id": sites[3].pk,
            "tags": [],
        }
        cls.csv_data = (
            "credential,assigned_object_type,assigned_object_id",
            f"{credentials[1].pk},dcim.site,{sites[0].pk}",
            f"{credentials[1].pk},dcim.site,{sites[1].pk}",
            f"{credentials[1].pk},dcim.site,{sites[2].pk}",
        )
        cls.csv_update_data = (
            "id,credential",
            *(f"{a.pk},{credentials[1].pk}" for a in CredentialAssignment.objects.all()),
        )


@override_settings(EXEMPT_VIEW_PERMISSIONS=[])
class ObjectPanelTestCase(TestCase):
    """The linked-credentials panel on other objects' pages."""

    @classmethod
    def setUpTestData(cls):
        site = Site.objects.create(name="Panel Site", slug="panel-site")
        Site.objects.create(name="Empty Site", slug="empty-site")
        credential = Credential(name="Panel Credential", username="panel-user")
        credential.set_secret("panel-secret")
        credential.save()
        CredentialAssignment.objects.create(
            credential=credential,
            assigned_object_type=ContentType.objects.get_for_model(Site),
            assigned_object_id=site.pk,
        )

    def test_panel_lists_linked_credentials(self):
        self.add_permissions(
            "dcim.view_site", "netbox_credentials.view_credential", "netbox_credentials.view_credentialassignment"
        )
        # localhost is a secure context, so the reveal button is offered.
        response = self.client.get(Site.objects.get(slug="panel-site").get_absolute_url(), HTTP_HOST="localhost")
        body = response.content.decode()
        self.assertHttpStatus(response, 200)
        self.assertIn("Panel Credential", body)
        self.assertIn("panel-user", body)
        self.assertIn("data-nbc-reveal", body)
        self.assertNotIn("panel-secret", body)

    def test_panel_hidden_without_permission(self):
        self.add_permissions("dcim.view_site", "netbox_credentials.view_credentialassignment")
        response = self.client.get(Site.objects.get(slug="panel-site").get_absolute_url())
        self.assertHttpStatus(response, 200)
        self.assertNotIn("Panel Credential", response.content.decode())

    def test_no_panel_on_unlinked_object(self):
        self.add_permissions(
            "dcim.view_site", "netbox_credentials.view_credential", "netbox_credentials.view_credentialassignment"
        )
        response = self.client.get(Site.objects.get(slug="empty-site").get_absolute_url())
        self.assertHttpStatus(response, 200)
        self.assertNotIn("nbc-secret-", response.content.decode())
        self.assertNotIn("Assign credential", response.content.decode())

    def test_small_assign_link_when_permitted(self):
        self.add_permissions("dcim.view_site", "netbox_credentials.add_credentialassignment")
        response = self.client.get(Site.objects.get(slug="empty-site").get_absolute_url())
        self.assertIn("Assign credential", response.content.decode())


class AssignmentFormTestCase(TestCase):
    """The type-then-search object selector on the assignment form."""

    @classmethod
    def setUpTestData(cls):
        cls.site = Site.objects.create(name="Picker Site", slug="picker-site")
        cls.credential = Credential.objects.create(name="Picker")

    def setUp(self):
        super().setUp()
        self.add_permissions(
            "netbox_credentials.add_credentialassignment", "netbox_credentials.view_credential", "dcim.view_site"
        )
        self.url = reverse("plugins:netbox_credentials:credentialassignment_add")
        self.site_type = ContentType.objects.get_for_model(Site)

    def test_object_selector_disabled_until_type_chosen(self):
        body = self.client.get(self.url).content.decode()
        self.assertIn('name="assigned_object_content_type"', body)
        self.assertIn('name="assigned_object_object_id"', body)
        self.assertNotIn('data-url="/api/dcim/sites/"', body)

    def test_choosing_type_gives_searchable_selector(self):
        # What the HTMX re-render requests when the type dropdown changes.
        response = self.client.get(self.url, {"assigned_object_content_type": self.site_type.pk})
        body = response.content.decode()
        self.assertHttpStatus(response, 200)
        self.assertIn('data-url="/api/dcim/sites/"', body)
        self.assertIn('id="assigned-object"', body)

    def test_prefilled_from_object_page_link(self):
        response = self.client.get(
            self.url,
            {"assigned_object_content_type": self.site_type.pk, "assigned_object_object_id": self.site.pk},
        )
        body = response.content.decode()
        self.assertIn("Picker Site", body)
        self.assertIn('data-url="/api/dcim/sites/"', body)

    def test_types_without_api_or_internal_are_not_offered(self):
        from netbox_credentials.forms import assignable_object_types

        labels = {f"{ct.app_label}.{ct.model}" for ct in assignable_object_types()}
        self.assertIn("dcim.device", labels)
        self.assertIn("ipam.ipaddress", labels)
        self.assertIn("virtualization.virtualmachine", labels)
        self.assertNotIn("core.configrevision", labels)
        self.assertNotIn("netbox_credentials.credential", labels)
        self.assertNotIn("netbox_credentials.passkey", labels)

    def test_submit_creates_assignment(self):
        response = self.client.post(
            self.url,
            {
                "credential": self.credential.pk,
                "assigned_object_content_type": self.site_type.pk,
                "assigned_object_object_id": self.site.pk,
            },
        )
        self.assertHttpStatus(response, 302)
        assignment = CredentialAssignment.objects.get(credential=self.credential)
        self.assertEqual(assignment.assigned_object, self.site)

    def test_type_without_object_is_rejected(self):
        response = self.client.post(
            self.url, {"credential": self.credential.pk, "assigned_object_content_type": self.site_type.pk}
        )
        self.assertHttpStatus(response, 200)
        self.assertIn("Please select a site", response.content.decode())
        self.assertFalse(CredentialAssignment.objects.exists())

    def test_disallowed_type_is_rejected(self):
        response = self.client.post(
            self.url,
            {
                "credential": self.credential.pk,
                "assigned_object_content_type": ContentType.objects.get_for_model(Credential).pk,
                "assigned_object_object_id": self.credential.pk,
            },
        )
        self.assertHttpStatus(response, 200)
        self.assertFalse(CredentialAssignment.objects.exists())

    def test_credential_page_offers_assign_to_object(self):
        self.add_permissions("netbox_credentials.view_credentialassignment")
        body = self.client.get(self.credential.get_absolute_url()).content.decode()
        self.assertIn(f"{self.url}?credential={self.credential.pk}", body)
