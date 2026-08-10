from datetime import timedelta

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from security.models import Alert, SecurityEvent


@pytest.fixture
def api_client():
    return APIClient()


def event_payload(**overrides):
    payload = {
        "ip_address": "192.168.1.10",
        "username": "admin",
        "event_type": "LOGIN_SUCCESS",
        "timestamp": timezone.now().isoformat().replace("+00:00", "Z"),
    }
    payload.update(overrides)
    return payload


@pytest.mark.django_db
def test_post_event_creates_event(api_client):
    response = api_client.post("/api/events/", event_payload(), format="json")

    assert response.status_code == 201
    assert response.data["event"]["ip_address"] == "192.168.1.10"
    assert response.data["generated_alerts"] == []
    assert SecurityEvent.objects.count() == 1


@pytest.mark.django_db
def test_post_event_returns_generated_alert(api_client):
    base_time = timezone.now()

    response = None
    for minute in range(5):
        response = api_client.post(
            "/api/events/",
            event_payload(
                event_type="LOGIN_FAILED",
                timestamp=(base_time + timedelta(minutes=minute)).isoformat().replace("+00:00", "Z"),
            ),
            format="json",
        )

    assert response.status_code == 201
    assert response.data["generated_alerts"][0]["alert_type"] == Alert.AlertType.BRUTE_FORCE
    assert Alert.objects.count() == 1


@pytest.mark.django_db
def test_get_events_returns_events(api_client):
    SecurityEvent.objects.create(
        ip_address="192.168.1.10",
        username="admin",
        event_type=SecurityEvent.EventType.LOGIN_SUCCESS,
        timestamp=timezone.now(),
    )

    response = api_client.get("/api/events/")

    assert response.status_code == 200
    assert response.data["count"] == 1
    assert response.data["results"][0]["username"] == "admin"


@pytest.mark.django_db
def test_get_alerts_returns_alerts_and_supports_filters(api_client):
    Alert.objects.create(
        alert_type=Alert.AlertType.BRUTE_FORCE,
        severity=Alert.Severity.HIGH,
        ip_address="10.0.0.15",
        username="admin",
        description="Repeated failed logins.",
        risk_score=70,
    )
    Alert.objects.create(
        alert_type=Alert.AlertType.SUSPICIOUS_ACTIVITY,
        severity=Alert.Severity.MEDIUM,
        ip_address="10.0.0.20",
        username="service",
        description="High event volume.",
        risk_score=30,
    )

    response = api_client.get("/api/alerts/", {"severity": "HIGH", "ip_address": "10.0.0.15"})

    assert response.status_code == 200
    assert response.data["count"] == 1
    assert response.data["results"][0]["alert_type"] == Alert.AlertType.BRUTE_FORCE


@pytest.mark.django_db
def test_alert_summary_returns_counts(api_client):
    Alert.objects.create(
        alert_type=Alert.AlertType.BRUTE_FORCE,
        severity=Alert.Severity.HIGH,
        ip_address="10.0.0.15",
        username="admin",
        description="Repeated failed logins.",
        risk_score=70,
    )
    Alert.objects.create(
        alert_type=Alert.AlertType.MULTIPLE_ACCOUNTS,
        severity=Alert.Severity.MEDIUM,
        ip_address="10.0.0.15",
        username="bob",
        description="Multiple accounts targeted.",
        risk_score=50,
    )

    response = api_client.get("/api/alerts/summary/")

    assert response.status_code == 200
    assert response.data["total_alerts"] == 2
    assert response.data["high_severity"] == 1
    assert response.data["medium_severity"] == 1
    assert response.data["brute_force"] == 1
    assert response.data["multiple_accounts"] == 1


@pytest.mark.django_db
def test_invalid_event_input(api_client):
    response = api_client.post("/api/events/", {}, format="json")

    assert response.status_code == 400
    assert "ip_address" in response.data
    assert "username" in response.data
    assert "event_type" in response.data
    assert "timestamp" in response.data


@pytest.mark.django_db
def test_invalid_event_type(api_client):
    response = api_client.post(
        "/api/events/",
        event_payload(event_type="UNKNOWN_EVENT"),
        format="json",
    )

    assert response.status_code == 400
    assert "event_type" in response.data


@pytest.mark.django_db
def test_invalid_ip_address(api_client):
    response = api_client.post(
        "/api/events/",
        event_payload(ip_address="not-an-ip"),
        format="json",
    )

    assert response.status_code == 400
    assert "ip_address" in response.data


@pytest.mark.django_db
def test_invalid_timestamp(api_client):
    response = api_client.post(
        "/api/events/",
        event_payload(timestamp="not-a-timestamp"),
        format="json",
    )

    assert response.status_code == 400
    assert "timestamp" in response.data


@pytest.mark.django_db
def test_empty_username_is_rejected(api_client):
    response = api_client.post(
        "/api/events/",
        event_payload(username=""),
        format="json",
    )

    assert response.status_code == 400
    assert "username" in response.data
