from rest_framework import generics
from rest_framework.response import Response
from rest_framework.views import APIView

from security.models import Alert, SecurityEvent
from security.serializers import AlertSerializer, SecurityEventSerializer


class SecurityEventListCreateView(generics.ListCreateAPIView):
    queryset = SecurityEvent.objects.all()
    serializer_class = SecurityEventSerializer


class AlertListView(generics.ListAPIView):
    serializer_class = AlertSerializer

    def get_queryset(self):
        queryset = Alert.objects.all()
        alert_type = self.request.query_params.get("alert_type")
        severity = self.request.query_params.get("severity")
        ip_address = self.request.query_params.get("ip_address")

        if alert_type:
            queryset = queryset.filter(alert_type=alert_type)
        if severity:
            queryset = queryset.filter(severity=severity)
        if ip_address:
            queryset = queryset.filter(ip_address=ip_address)

        return queryset


class AlertSummaryView(APIView):
    def get(self, request):
        return Response({})
