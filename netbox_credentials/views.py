import json
import logging

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.db.models import Count
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect

# Tag and custom-field panels are not re-exported under netbox.ui; extras.ui.panels is where
# core views get them, and there is no public alternative.
from extras.ui.panels import CustomFieldsPanel, TagsPanel
from netbox.object_actions import AddObject, BulkDelete, BulkExport, BulkImport
from netbox.ui import actions, layout
from netbox.ui.panels import CommentsPanel, ObjectsTablePanel, TemplatePanel
from netbox.views import generic
from utilities.views import register_model_view

from . import crypto, filtersets, forms, tables
from . import webauthn as ceremonies
from .models import Credential, CredentialAssignment, Passkey, WebAuthnChallenge
from .ui import CredentialAssignmentPanel, CredentialPanel

logger = logging.getLogger("netbox_credentials.reveal")


#
# Credentials
#


@register_model_view(Credential, "list", path="", detail=False)
class CredentialListView(generic.ObjectListView):
    queryset = Credential.objects.annotate(assignment_count=Count("assignments"))
    table = tables.CredentialTable
    filterset = filtersets.CredentialFilterSet
    filterset_form = forms.CredentialFilterForm


@register_model_view(Credential)
class CredentialView(generic.ObjectView):
    queryset = Credential.objects.all()
    layout = layout.SimpleLayout(
        left_panels=[
            CredentialPanel(),
            TemplatePanel("netbox_credentials/inc/secret_panel.html", title=_("Secret")),
            TagsPanel(),
        ],
        right_panels=[
            CommentsPanel(title=_("Notes")),
            CustomFieldsPanel(),
        ],
        bottom_panels=[
            ObjectsTablePanel(
                model="netbox_credentials.credentialassignment",
                title=_("Assigned to"),
                filters={"credential_id": lambda ctx: ctx["object"].pk},
                exclude_columns=["credential", "username"],
                actions=[
                    actions.AddObject(
                        "netbox_credentials.CredentialAssignment",
                        url_params={"credential": lambda ctx: ctx["object"].pk},
                        label=_("Assign to object"),
                    ),
                ],
            ),
        ],
    )

    def get_extra_context(self, request, instance):
        return {
            "secure_context": ceremonies.is_secure_context(request),
            "has_passkey": (request.user.is_authenticated and Passkey.objects.filter(user=request.user).exists()),
        }


@register_model_view(Credential, "add", detail=False)
@register_model_view(Credential, "edit")
class CredentialEditView(generic.ObjectEditView):
    queryset = Credential.objects.all()
    form = forms.CredentialForm


@register_model_view(Credential, "delete")
class CredentialDeleteView(generic.ObjectDeleteView):
    queryset = Credential.objects.all()


@register_model_view(Credential, "bulk_import", path="import", detail=False)
class CredentialBulkImportView(generic.BulkImportView):
    queryset = Credential.objects.all()
    model_form = forms.CredentialImportForm


@register_model_view(Credential, "bulk_edit", path="edit", detail=False)
class CredentialBulkEditView(generic.BulkEditView):
    queryset = Credential.objects.all()
    filterset = filtersets.CredentialFilterSet
    table = tables.CredentialTable
    form = forms.CredentialBulkEditForm


@register_model_view(Credential, "bulk_delete", path="delete", detail=False)
class CredentialBulkDeleteView(generic.BulkDeleteView):
    queryset = Credential.objects.all()
    filterset = filtersets.CredentialFilterSet
    table = tables.CredentialTable


#
# Credential assignments
#


@register_model_view(CredentialAssignment, "list", path="", detail=False)
class CredentialAssignmentListView(generic.ObjectListView):
    queryset = CredentialAssignment.objects.select_related("credential", "assigned_object_type")
    table = tables.CredentialAssignmentTable
    filterset = filtersets.CredentialAssignmentFilterSet
    filterset_form = forms.CredentialAssignmentFilterForm
    # Assignments have no bulk edit view.
    actions = (AddObject, BulkImport, BulkExport, BulkDelete)


@register_model_view(CredentialAssignment)
class CredentialAssignmentView(generic.ObjectView):
    queryset = CredentialAssignment.objects.all()
    layout = layout.SimpleLayout(
        left_panels=[CredentialAssignmentPanel(), TagsPanel()],
        right_panels=[CustomFieldsPanel()],
    )


@register_model_view(CredentialAssignment, "add", detail=False)
@register_model_view(CredentialAssignment, "edit")
class CredentialAssignmentEditView(generic.ObjectEditView):
    queryset = CredentialAssignment.objects.all()
    form = forms.CredentialAssignmentForm


@register_model_view(CredentialAssignment, "delete")
class CredentialAssignmentDeleteView(generic.ObjectDeleteView):
    queryset = CredentialAssignment.objects.all()


@register_model_view(CredentialAssignment, "bulk_import", path="import", detail=False)
class CredentialAssignmentBulkImportView(generic.BulkImportView):
    queryset = CredentialAssignment.objects.all()
    model_form = forms.CredentialAssignmentImportForm


@register_model_view(CredentialAssignment, "bulk_delete", path="delete", detail=False)
class CredentialAssignmentBulkDeleteView(generic.BulkDeleteView):
    queryset = CredentialAssignment.objects.all()
    filterset = filtersets.CredentialAssignmentFilterSet
    table = tables.CredentialAssignmentTable


#
# Helpers for the JSON/XHR endpoints
#


def _read_json(request):
    try:
        data = json.loads(request.body or b"{}")
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _no_store(response):
    response["Cache-Control"] = "no-store, private"
    response["Pragma"] = "no-cache"
    return response


def _json_error(message, status=400):
    return _no_store(JsonResponse({"error": str(message)}, status=status))


@method_decorator([csrf_protect, never_cache], name="dispatch")
class _CeremonyView(LoginRequiredMixin, View):
    """POST-only, CSRF-protected, never cached. Used by every WebAuthn endpoint."""

    http_method_names = ["post"]
    raise_exception = True


#
# Reveal: a fresh passkey assertion for every read
#


def _viewable_credential(request, pk):
    # restrict() applies the user's object permissions, including any constraints.
    return get_object_or_404(Credential.objects.restrict(request.user, "view"), pk=pk)


class RevealBeginView(_CeremonyView):
    def post(self, request, pk):
        credential = _viewable_credential(request, pk)
        try:
            data = ceremonies.begin_authentication(request, credential=credential)
        except ceremonies.CeremonyError as exc:
            return _json_error(exc, status=409)
        return _no_store(JsonResponse(data))


class RevealFinishView(_CeremonyView):
    def post(self, request, pk):
        data = _read_json(request)
        if data is None:
            return HttpResponseBadRequest("Malformed request")

        def fragment(status, **context):
            html = render_to_string("netbox_credentials/inc/reveal_result.html", context, request=request)
            return _no_store(JsonResponse({"html": html}, status=status))

        # Check permission again: it may have changed since the ceremony began.
        credential = _viewable_credential(request, pk)
        try:
            passkey = ceremonies.finish_authentication(
                request, data.get("challenge_id"), data.get("credential"), credential=credential
            )
        except ceremonies.CeremonyError as exc:
            return fragment(403, error=str(exc))

        try:
            secret = crypto.decrypt_secret(credential)
        except crypto.DecryptionError as exc:
            logger.error("Decryption failed for credential %s: %s", credential.pk, exc)
            return fragment(500, error=str(exc))

        logger.info(
            "User %s revealed credential %s (%s) using passkey %s",
            request.user,
            credential.pk,
            credential.name,
            passkey.pk,
        )
        return fragment(200, credential=credential, secret=secret, no_secret=secret is None)


#
# Passkeys: self-service enrolment and removal
#


class PasskeyListView(LoginRequiredMixin, View):
    def get(self, request):
        return render(
            request,
            "netbox_credentials/passkey_list.html",
            {
                "passkeys": Passkey.objects.filter(user=request.user),
                "secure_context": ceremonies.is_secure_context(request),
            },
        )


class PasskeyStepUpBeginView(_CeremonyView):
    """Assertion options used to confirm adding or removing a passkey."""

    def post(self, request):
        try:
            data = ceremonies.begin_authentication(request, purpose=WebAuthnChallenge.PURPOSE_MANAGE)
        except ceremonies.CeremonyError as exc:
            return _json_error(exc, status=409)
        return _no_store(JsonResponse(data))


class PasskeyRegisterBeginView(_CeremonyView):
    def post(self, request):
        data = _read_json(request) or {}
        try:
            options = ceremonies.begin_registration(
                request,
                step_up_challenge_id=data.get("challenge_id"),
                step_up_assertion=data.get("credential"),
            )
        except ceremonies.CeremonyError as exc:
            return _json_error(exc, status=403)
        return _no_store(JsonResponse(options))


class PasskeyRegisterFinishView(_CeremonyView):
    def post(self, request):
        data = _read_json(request)
        if data is None:
            return _json_error("Malformed request")
        try:
            passkey = ceremonies.finish_registration(
                request, data.get("challenge_id"), data.get("credential"), data.get("name")
            )
        except ceremonies.CeremonyError as exc:
            return _json_error(exc, status=400)
        messages.success(request, _("Passkey {name} registered.").format(name=passkey.name))
        return _no_store(JsonResponse({"id": passkey.pk, "name": passkey.name}))


class PasskeyDeleteView(_CeremonyView):
    """Remove one of your own passkeys. Needs an assertion from any of your passkeys."""

    def post(self, request, pk):
        passkey = get_object_or_404(Passkey, pk=pk, user=request.user)
        data = _read_json(request)
        if data is None:
            return _json_error("Malformed request")
        try:
            ceremonies.finish_authentication(
                request, data.get("challenge_id"), data.get("credential"), purpose=WebAuthnChallenge.PURPOSE_MANAGE
            )
        except ceremonies.CeremonyError as exc:
            return _json_error(exc, status=403)
        name = passkey.name
        passkey.delete()
        logging.getLogger("netbox_credentials.webauthn").info("User %s removed passkey %s", request.user, pk)
        messages.success(request, _("Passkey {name} removed.").format(name=name))
        return _no_store(JsonResponse({"deleted": pk}))


class PasskeyRenameView(LoginRequiredMixin, View):
    http_method_names = ["post"]

    def post(self, request, pk):
        passkey = get_object_or_404(Passkey, pk=pk, user=request.user)
        form = forms.PasskeyRenameForm(request.POST)
        if form.is_valid():
            passkey.name = form.cleaned_data["name"]
            passkey.save(update_fields=("name",))
        return redirect("plugins:netbox_credentials:passkey_list")


#
# Passkeys: superuser reset for users who lost theirs
#


class SuperuserRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    raise_exception = True

    def test_func(self):
        return self.request.user.is_superuser


class PasskeyAdminListView(SuperuserRequiredMixin, View):
    def get(self, request):
        return render(
            request,
            "netbox_credentials/passkey_admin_list.html",
            {
                "passkeys": Passkey.objects.select_related("user").order_by("user__username", "name"),
            },
        )


class PasskeyAdminDeleteView(SuperuserRequiredMixin, View):
    http_method_names = ["post"]

    def post(self, request, pk):
        passkey = get_object_or_404(Passkey, pk=pk)
        owner, name = passkey.user, passkey.name
        passkey.delete()
        logging.getLogger("netbox_credentials.webauthn").warning(
            "Superuser %s removed passkey %s (%s) belonging to %s", request.user, pk, name, owner
        )
        messages.success(request, _("Removed passkey {name} from {user}.").format(name=name, user=owner))
        return redirect("plugins:netbox_credentials:passkey_admin_list")
