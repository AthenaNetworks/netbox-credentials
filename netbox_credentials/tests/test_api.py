from dcim.models import Site
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from rest_framework import status
from utilities.testing import APITestCase, APIViewTestCases

from netbox_credentials import crypto
from netbox_credentials.models import Credential, CredentialAssignment


class CredentialAPITestCase(APIViewTestCases.APIViewTestCase):
    model = Credential
    view_namespace = "plugins-api:netbox_credentials"
    brief_fields = ["description", "display", "id", "name", "url", "username"]
    validation_excluded_fields = ["secret"]
    bulk_update_data = {"description": "Bulk description"}
    # GraphQL deliberately has no secret field; the stock GraphQL tests cover the rest.

    @classmethod
    def setUpTestData(cls):
        for i in range(1, 4):
            credential = Credential(name=f"Credential {i}", username=f"user{i}")
            credential.set_secret(f"secret-{i}")
            credential.save()
        cls.create_data = [
            {"name": "Credential 4", "username": "user4", "secret": "pw4"},
            {"name": "Credential 5", "username": "user5", "secret": "pw5"},
            {"name": "Credential 6", "username": "user6"},
        ]


class CredentialAssignmentAPITestCase(APIViewTestCases.APIViewTestCase):
    model = CredentialAssignment
    view_namespace = "plugins-api:netbox_credentials"
    brief_fields = ["assigned_object_id", "assigned_object_type", "credential", "display", "id", "url"]
    bulk_update_data = {}

    @classmethod
    def setUpTestData(cls):
        sites = [Site.objects.create(name=f"Site {i}", slug=f"site-{i}") for i in range(1, 7)]
        credential = Credential.objects.create(name="Shared")
        cls.other = Credential.objects.create(name="Other")
        for site in sites[:3]:
            CredentialAssignment.objects.create(
                credential=credential,
                assigned_object_type=ContentType.objects.get_for_model(Site),
                assigned_object_id=site.pk,
            )
        cls.create_data = [
            {"credential": cls.other.pk, "assigned_object_type": "dcim.site", "assigned_object_id": site.pk}
            for site in sites[3:]
        ]

    def test_bulk_update_objects(self):
        # Nothing on an assignment is meaningfully bulk-editable.
        pass


class SecretOverAPITestCase(APITestCase):
    """Requirement 3: REST reads return plaintext to anyone with view permission, no passkey."""

    model = Credential
    view_namespace = "plugins-api:netbox_credentials"

    @classmethod
    def setUpTestData(cls):
        cls.credential = Credential(name="API", username="api-user")
        cls.credential.set_secret("api-plaintext")
        cls.credential.save()

    def _url(self, pk=None):
        if pk:
            return reverse("plugins-api:netbox_credentials-api:credential-detail", kwargs={"pk": pk})
        return reverse("plugins-api:netbox_credentials-api:credential-list")

    def test_get_returns_plaintext_with_view_permission(self):
        self.add_permissions("netbox_credentials.view_credential")
        response = self.client.get(self._url(self.credential.pk), **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)
        self.assertEqual(response.data["secret"], "api-plaintext")
        self.assertNotIn("secret_ciphertext", response.data)
        self.assertNotIn("key_id", response.data)

    def test_list_returns_plaintext(self):
        self.add_permissions("netbox_credentials.view_credential")
        response = self.client.get(self._url(), **self.header)
        self.assertEqual(response.data["results"][0]["secret"], "api-plaintext")

    def test_brief_omits_secret(self):
        self.add_permissions("netbox_credentials.view_credential")
        response = self.client.get(self._url() + "?brief=1", **self.header)
        self.assertNotIn("secret", response.data["results"][0])

    def test_no_view_permission_no_secret(self):
        response = self.client.get(self._url(self.credential.pk), **self.header)
        self.assertHttpStatus(response, status.HTTP_403_FORBIDDEN)

    def test_constrained_permission_hides_other_objects(self):
        other = Credential(name="Hidden")
        other.set_secret("hidden-plaintext")
        other.save()
        self.add_permissions("netbox_credentials.view_credential")
        from users.models import ObjectPermission

        ObjectPermission.objects.filter(users=self.user).update(constraints={"name": "API"})
        response = self.client.get(self._url(other.pk), **self.header)
        self.assertHttpStatus(response, status.HTTP_404_NOT_FOUND)
        response = self.client.get(self._url(), **self.header)
        self.assertNotIn("hidden-plaintext", str(response.data))

    def test_create_encrypts(self):
        self.add_permissions("netbox_credentials.add_credential", "netbox_credentials.view_credential")
        response = self.client.post(self._url(), {"name": "New", "secret": "fresh"}, format="json", **self.header)
        self.assertHttpStatus(response, status.HTTP_201_CREATED)
        self.assertEqual(response.data["secret"], "fresh")
        created = Credential.objects.get(name="New")
        self.assertNotIn("fresh", created.secret_ciphertext)
        self.assertEqual(crypto.decrypt_secret(created), "fresh")

    def test_write_without_view_does_not_echo_secret(self):
        self.add_permissions("netbox_credentials.change_credential")
        response = self.client.patch(self._url(self.credential.pk), {"description": "x"}, format="json", **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)
        self.assertNotIn("secret", response.data)

    def test_patch_without_secret_keeps_it(self):
        self.add_permissions("netbox_credentials.change_credential", "netbox_credentials.view_credential")
        self.client.patch(self._url(self.credential.pk), {"username": "new"}, format="json", **self.header)
        self.credential.refresh_from_db()
        self.assertEqual(crypto.decrypt_secret(self.credential), "api-plaintext")

    def test_patch_null_secret_clears(self):
        self.add_permissions("netbox_credentials.change_credential", "netbox_credentials.view_credential")
        response = self.client.patch(self._url(self.credential.pk), {"secret": None}, format="json", **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)
        self.assertIsNone(response.data["secret"])
        self.credential.refresh_from_db()
        self.assertFalse(self.credential.has_secret)

    def test_graphql_cannot_query_secret(self):
        self.add_permissions("netbox_credentials.view_credential")
        query = "{ credential_list { name secret } }"
        response = self.client.post(reverse("graphql"), data={"query": query}, format="json", **self.header)
        self.assertIn("errors", response.json())
        self.assertNotIn("api-plaintext", response.content.decode())
        query = "{ credential_list { name has_secret } }"
        response = self.client.post(reverse("graphql"), data={"query": query}, format="json", **self.header)
        data = response.json()
        self.assertNotIn("errors", data)
        self.assertTrue(data["data"]["credential_list"][0]["has_secret"])
