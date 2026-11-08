from django.urls import include, path
from utilities.urls import get_model_urls

from . import views

app_name = "netbox_credentials"

urlpatterns = (
    # Credentials
    path("credentials/", include(get_model_urls("netbox_credentials", "credential", detail=False))),
    path("credentials/<int:pk>/", include(get_model_urls("netbox_credentials", "credential"))),
    path("credentials/<int:pk>/reveal/begin/", views.RevealBeginView.as_view(), name="credential_reveal_begin"),
    path("credentials/<int:pk>/reveal/finish/", views.RevealFinishView.as_view(), name="credential_reveal_finish"),
    # Assignments
    path(
        "assignments/",
        include(get_model_urls("netbox_credentials", "credentialassignment", detail=False)),
    ),
    path("assignments/<int:pk>/", include(get_model_urls("netbox_credentials", "credentialassignment"))),
    # Passkeys
    path("passkeys/", views.PasskeyListView.as_view(), name="passkey_list"),
    path("passkeys/step-up/", views.PasskeyStepUpBeginView.as_view(), name="passkey_stepup_begin"),
    path("passkeys/register/begin/", views.PasskeyRegisterBeginView.as_view(), name="passkey_register_begin"),
    path("passkeys/register/finish/", views.PasskeyRegisterFinishView.as_view(), name="passkey_register_finish"),
    path("passkeys/<int:pk>/delete/", views.PasskeyDeleteView.as_view(), name="passkey_delete"),
    path("passkeys/<int:pk>/rename/", views.PasskeyRenameView.as_view(), name="passkey_rename"),
    path("passkeys/all/", views.PasskeyAdminListView.as_view(), name="passkey_admin_list"),
    path("passkeys/all/<int:pk>/delete/", views.PasskeyAdminDeleteView.as_view(), name="passkey_admin_delete"),
)
