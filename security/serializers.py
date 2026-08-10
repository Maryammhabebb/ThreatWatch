from rest_framework import serializers

from security.models import Alert, SecurityEvent


class SecurityEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityEvent
        fields = ["id", "ip_address", "username", "event_type", "timestamp", "created_at"]
        read_only_fields = ["id", "created_at"]


class AlertSerializer(serializers.ModelSerializer):
    related_event_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        read_only=True,
        source="related_events",
    )

    class Meta:
        model = Alert
        fields = [
            "id",
            "alert_type",
            "severity",
            "ip_address",
            "username",
            "description",
            "risk_score",
            "detected_at",
            "related_event_ids",
        ]
        read_only_fields = fields
