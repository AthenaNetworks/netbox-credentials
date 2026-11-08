from django.utils.translation import gettext_lazy as _
from netbox.plugins import PluginMenu, PluginMenuButton, PluginMenuItem

menu = PluginMenu(
    label=_("Credentials"),
    icon_class="mdi mdi-key-chain",
    groups=(
        (
            _("Credentials"),
            (
                PluginMenuItem(
                    link="plugins:netbox_credentials:credential_list",
                    link_text=_("Credentials"),
                    permissions=["netbox_credentials.view_credential"],
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_credentials:credential_add",
                            title=_("Add"),
                            icon_class="mdi mdi-plus-thick",
                            permissions=["netbox_credentials.add_credential"],
                        ),
                        PluginMenuButton(
                            link="plugins:netbox_credentials:credential_bulk_import",
                            title=_("Import"),
                            icon_class="mdi mdi-upload",
                            permissions=["netbox_credentials.add_credential"],
                        ),
                    ),
                ),
                PluginMenuItem(
                    link="plugins:netbox_credentials:credentialassignment_list",
                    link_text=_("Assignments"),
                    permissions=["netbox_credentials.view_credentialassignment"],
                ),
            ),
        ),
        (
            _("Security"),
            (
                PluginMenuItem(
                    link="plugins:netbox_credentials:passkey_list",
                    link_text=_("My passkeys"),
                    auth_required=True,
                ),
            ),
        ),
    ),
)
