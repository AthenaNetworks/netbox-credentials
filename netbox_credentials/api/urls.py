from netbox.api.routers import NetBoxRouter

from . import views

app_name = "netbox_credentials-api"

router = NetBoxRouter()
router.register("credentials", views.CredentialViewSet)
router.register("assignments", views.CredentialAssignmentViewSet)

urlpatterns = router.urls
