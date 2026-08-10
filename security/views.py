from rest_framework import generics
from rest_framework.response import Response
from rest_framework.views import APIView

from security.models import Alert, SecurityEvent
from security.serializers import AlertSerializer, SecurityEventSerializer
from security.services import analyze_security_event


class SecurityEventListCreateView(generics.ListCreateAPIView):
    queryset = SecurityEvent.objects.all()
    serializer_class = SecurityEventSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        event = serializer.save()
        generated_alerts = analyze_security_event(event)
        headers = self.get_success_headers(serializer.data)

        data = {
            "event": SecurityEventSerializer(event, context=self.get_serializer_context()).data,
            "generated_alerts": AlertSerializer(generated_alerts, many=True).data,
        }
        return Response(data, status=201, headers=headers)


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
        return Response(
            {
                "total_alerts": Alert.objects.count(),
                "low_severity": Alert.objects.filter(severity=Alert.Severity.LOW).count(),
                "medium_severity": Alert.objects.filter(severity=Alert.Severity.MEDIUM).count(),
                "high_severity": Alert.objects.filter(severity=Alert.Severity.HIGH).count(),
                "critical_severity": Alert.objects.filter(severity=Alert.Severity.CRITICAL).count(),
                "brute_force": Alert.objects.filter(alert_type=Alert.AlertType.BRUTE_FORCE).count(),
                "multiple_accounts": Alert.objects.filter(
                    alert_type=Alert.AlertType.MULTIPLE_ACCOUNTS
                ).count(),
                "suspicious_activity": Alert.objects.filter(
                    alert_type=Alert.AlertType.SUSPICIOUS_ACTIVITY
                ).count(),
            }
        )
