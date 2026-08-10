from datetime import timedelta

import pytest
from django.utils import timezone

from security.detection import analyze_event, severity_for_score
from security.models import Alert, SecurityEvent


def create_event(
    *,
    ip_address: str = "192.168.1.10",
    username: str = "admin",
    event_type: str = SecurityEvent.EventType.LOGIN_FAILED,
    timestamp=None,
) -> SecurityEvent:
    return SecurityEvent.objects.create(
        ip_address=ip_address,
        username=username,
        event_type=event_type,
        timestamp=timestamp or timezone.now(),
    )


@pytest.mark.django_db
def test_fewer_than_five_failed_logins_do_not_trigger_brute_force():
    base_time = timezone.now()
    for minute in range(4):
        event = create_event(timestamp=base_time + timedelta(minutes=minute))

    alerts = analyze_event(event)

    assert alerts == []
    assert Alert.objects.count() == 0


@pytest.mark.django_db
def test_five_failed_logins_within_five_minutes_trigger_brute_force():
    base_time = timezone.now()
    for minute in range(5):
        event = create_event(timestamp=base_time + timedelta(minutes=minute))

    alerts = analyze_event(event)

    assert len(alerts) == 1
    assert alerts[0].alert_type == Alert.AlertType.BRUTE_FORCE
    assert alerts[0].severity == Alert.Severity.CRITICAL
    assert alerts[0].risk_score == 100
    assert alerts[0].related_events.count() == 5


@pytest.mark.django_db
def test_failed_logins_outside_window_do_not_trigger_brute_force():
    base_time = timezone.now()
    create_event(timestamp=base_time - timedelta(minutes=20))
    for minute in range(4):
        event = create_event(timestamp=base_time + timedelta(minutes=minute))

    alerts = analyze_event(event)

    assert alerts == []
    assert Alert.objects.count() == 0


@pytest.mark.django_db
def test_three_usernames_from_same_ip_trigger_multiple_accounts():
    base_time = timezone.now()
    for minute, username in enumerate(["admin", "alice", "bob"]):
        event = create_event(username=username, timestamp=base_time + timedelta(minutes=minute))

    alerts = analyze_event(event)

    assert len(alerts) == 1
    assert alerts[0].alert_type == Alert.AlertType.MULTIPLE_ACCOUNTS
    assert alerts[0].severity == Alert.Severity.MEDIUM
    assert alerts[0].risk_score == 50


@pytest.mark.django_db
def test_ten_events_from_same_ip_trigger_suspicious_activity():
    base_time = timezone.now()
    for second in range(10):
        event = create_event(
            event_type=SecurityEvent.EventType.LOGIN_SUCCESS,
            timestamp=base_time + timedelta(seconds=second),
        )

    alerts = analyze_event(event)

    assert len(alerts) == 1
    assert alerts[0].alert_type == Alert.AlertType.SUSPICIOUS_ACTIVITY
    assert alerts[0].severity == Alert.Severity.MEDIUM


@pytest.mark.django_db
def test_different_ip_addresses_do_not_trigger_same_rule():
    base_time = timezone.now()
    for index in range(10):
        event = create_event(
            ip_address=f"10.0.0.{index + 1}",
            timestamp=base_time + timedelta(seconds=index),
        )

    alerts = analyze_event(event)

    assert alerts == []
    assert Alert.objects.count() == 0


@pytest.mark.django_db
def test_duplicate_alerts_are_prevented():
    base_time = timezone.now()
    for minute in range(5):
        event = create_event(timestamp=base_time + timedelta(minutes=minute))

    first_alerts = analyze_event(event)
    extra_event = create_event(timestamp=base_time + timedelta(minutes=5))
    second_alerts = analyze_event(extra_event)

    assert len(first_alerts) == 1
    assert second_alerts == []
    assert Alert.objects.count() == 1


def test_severity_for_score():
    assert severity_for_score(10) == Alert.Severity.LOW
    assert severity_for_score(30) == Alert.Severity.MEDIUM
    assert severity_for_score(60) == Alert.Severity.HIGH
    assert severity_for_score(90) == Alert.Severity.CRITICAL
