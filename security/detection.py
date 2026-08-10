from dataclasses import dataclass
from datetime import timedelta

from django.db.models import QuerySet
from django.utils import timezone

from security.models import Alert, SecurityEvent


BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=5)
MULTIPLE_ACCOUNTS_THRESHOLD = 3
MULTIPLE_ACCOUNTS_WINDOW = timedelta(minutes=10)
SUSPICIOUS_ACTIVITY_THRESHOLD = 10
SUSPICIOUS_ACTIVITY_WINDOW = timedelta(minutes=10)
ALERT_COOLDOWN = timedelta(minutes=10)

REPEATED_FAILED_LOGIN_SCORE = 10
MULTIPLE_ACCOUNT_SCORE = 20
BRUTE_FORCE_SCORE = 50
SUSPICIOUS_ACTIVITY_SCORE = 30


@dataclass(frozen=True)
class DetectionResult:
    alert_type: str
    description: str
    risk_score: int
    username: str
    related_events: QuerySet[SecurityEvent]


def analyze_event(event: SecurityEvent) -> list[Alert]:
    """Run deterministic detection rules for one stored security event."""
    created_alerts = []

    for result in _detect_threats(event):
        if _has_recent_duplicate(result.alert_type, event.ip_address):
            continue

        alert = Alert.objects.create(
            alert_type=result.alert_type,
            severity=severity_for_score(result.risk_score),
            ip_address=event.ip_address,
            username=result.username,
            description=result.description,
            risk_score=result.risk_score,
        )
        alert.related_events.set(result.related_events)
        created_alerts.append(alert)

    return created_alerts


def severity_for_score(score: int) -> str:
    if score >= 90:
        return Alert.Severity.CRITICAL
    if score >= 60:
        return Alert.Severity.HIGH
    if score >= 30:
        return Alert.Severity.MEDIUM
    return Alert.Severity.LOW


def _detect_threats(event: SecurityEvent) -> list[DetectionResult]:
    return [
        result
        for result in [
            _detect_brute_force(event),
            _detect_multiple_accounts(event),
            _detect_suspicious_activity(event),
        ]
        if result is not None
    ]


def _detect_brute_force(event: SecurityEvent) -> DetectionResult | None:
    if event.event_type != SecurityEvent.EventType.LOGIN_FAILED:
        return None

    events = _events_in_window(event, BRUTE_FORCE_WINDOW).filter(
        event_type=SecurityEvent.EventType.LOGIN_FAILED
    )
    failed_count = events.count()

    if failed_count < BRUTE_FORCE_THRESHOLD:
        return None

    risk_score = BRUTE_FORCE_SCORE + (failed_count * REPEATED_FAILED_LOGIN_SCORE)
    return DetectionResult(
        alert_type=Alert.AlertType.BRUTE_FORCE,
        description=(
            f"{failed_count} failed login attempts from {event.ip_address} "
            f"within {BRUTE_FORCE_WINDOW.seconds // 60} minutes."
        ),
        risk_score=risk_score,
        username=event.username,
        related_events=events,
    )


def _detect_multiple_accounts(event: SecurityEvent) -> DetectionResult | None:
    if event.event_type != SecurityEvent.EventType.LOGIN_FAILED:
        return None

    events = _events_in_window(event, MULTIPLE_ACCOUNTS_WINDOW).filter(
        event_type=SecurityEvent.EventType.LOGIN_FAILED
    )
    username_count = events.values("username").distinct().count()

    if username_count < MULTIPLE_ACCOUNTS_THRESHOLD:
        return None

    failed_count = events.count()
    risk_score = MULTIPLE_ACCOUNT_SCORE + (failed_count * REPEATED_FAILED_LOGIN_SCORE)
    return DetectionResult(
        alert_type=Alert.AlertType.MULTIPLE_ACCOUNTS,
        description=(
            f"Failed login attempts targeted {username_count} usernames from "
            f"{event.ip_address} within {MULTIPLE_ACCOUNTS_WINDOW.seconds // 60} minutes."
        ),
        risk_score=risk_score,
        username=event.username,
        related_events=events,
    )


def _detect_suspicious_activity(event: SecurityEvent) -> DetectionResult | None:
    events = _events_in_window(event, SUSPICIOUS_ACTIVITY_WINDOW)
    event_count = events.count()

    if event_count < SUSPICIOUS_ACTIVITY_THRESHOLD:
        return None

    return DetectionResult(
        alert_type=Alert.AlertType.SUSPICIOUS_ACTIVITY,
        description=(
            f"{event_count} security events from {event.ip_address} within "
            f"{SUSPICIOUS_ACTIVITY_WINDOW.seconds // 60} minutes."
        ),
        risk_score=SUSPICIOUS_ACTIVITY_SCORE,
        username=event.username,
        related_events=events,
    )


def _events_in_window(event: SecurityEvent, window: timedelta) -> QuerySet[SecurityEvent]:
    window_start = event.timestamp - window
    return SecurityEvent.objects.filter(
        ip_address=event.ip_address,
        timestamp__gte=window_start,
        timestamp__lte=event.timestamp,
    )


def _has_recent_duplicate(alert_type: str, ip_address: str) -> bool:
    cooldown_start = timezone.now() - ALERT_COOLDOWN
    return Alert.objects.filter(
        alert_type=alert_type,
        ip_address=ip_address,
        detected_at__gte=cooldown_start,
    ).exists()
