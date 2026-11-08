from django.db.models import Count
from netbox.api.viewsets import NetBoxModelViewSet

from .. import filtersets
from ..models import Credential, CredentialAssignment
from .serializers import CredentialAssignmentSerializer, CredentialSerializer


class CredentialViewSet(NetBoxModelViewSet):
    queryset = Credential.objects.annotate(assignment_count=Count("assignments"))
    serializer_class = CredentialSerializer
    filterset_class = filtersets.CredentialFilterSet


class CredentialAssignmentViewSet(NetBoxModelViewSet):
    queryset = CredentialAssignment.objects.select_related("credential", "assigned_object_type")
    serializer_class = CredentialAssignmentSerializer
    filterset_class = filtersets.CredentialAssignmentFilterSet
