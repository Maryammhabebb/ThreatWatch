import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone

from security.models import Alert, SecurityEvent


@pytest.mark.django_db
def test_security_event_creation():
    event = SecurityEvent.objects.create(
        ip_address="192.168.1.10",
        username="admin",
        event_type=SecurityEvent.EventType.LOGIN_SUCCESS,
        timestamp=timezone.now(),
    )

    assert event.id is not None
    assert event.created_at is not None
    assert str(event) == "LOGIN_SUCCESS for admin from 192.168.1.10"


@pytest.mark.django_db
def test_security_event_rejects_invalid_event_type():
    event = SecurityEvent(
        ip_address="192.168.1.10",
        username="admin",
        event_type="INVALID",
        timestamp=timezone.now(),
    )

    with pytest.raises(ValidationError):
        event.full_clean()


@pytest.mark.django_db
def test_alert_creation():
    event = SecurityEvent.objects.create(
        ip_address="10.0.0.15",
        username="admin",
        event_type=SecurityEvent.EventType.LOGIN_FAILED,
        timestamp=timezone.now(),
    )
    alert = Alert.objects.create(
        alert_type=Alert.AlertType.BRUTE_FORCE,
        severity=Alert.Severity.HIGH,
        ip_address=event.ip_address,
        username=event.username,
        description="Repeated failed login attempts detected.",
        risk_score=70,
    )
    alert.related_events.add(event)

    assert alert.id is not None
    assert alert.related_events.count() == 1
    assert str(alert) == "HIGH BRUTE_FORCE alert for 10.0.0.15"
