from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from security.models import Alert, SecurityEvent
from security.services import analyze_security_event


class Command(BaseCommand):
    help = "Create demonstration security events and alerts for ThreatWatch."

    def handle(self, *args, **options):
        base_time = timezone.now().replace(microsecond=0)
        scenarios = [
            *self._normal_activity(base_time),
            *self._brute_force_attack(base_time + timedelta(minutes=20)),
            *self._multiple_account_attack(base_time + timedelta(minutes=40)),
            *self._suspicious_activity(base_time + timedelta(minutes=60)),
        ]

        created_events = 0
        created_alerts = 0

        for event_data in scenarios:
            event = SecurityEvent.objects.create(**event_data)
            alerts = analyze_security_event(event)
            created_events += 1
            created_alerts += len(alerts)

        self.stdout.write(
            self.style.SUCCESS(
                f"Created {created_events} demo events and {created_alerts} alerts. "
                f"Total alerts: {Alert.objects.count()}."
            )
        )

    def _normal_activity(self, start):
        return [
            {
                "ip_address": "192.168.1.10",
                "username": "alice",
                "event_type": SecurityEvent.EventType.LOGIN_SUCCESS,
                "timestamp": start,
            },
            {
                "ip_address": "192.168.1.10",
                "username": "alice",
                "event_type": SecurityEvent.EventType.LOGOUT,
                "timestamp": start + timedelta(minutes=15),
            },
            {
                "ip_address": "10.0.0.15",
                "username": "bob",
                "event_type": SecurityEvent.EventType.PASSWORD_RESET,
                "timestamp": start + timedelta(minutes=30),
            },
        ]

    def _brute_force_attack(self, start):
        return [
            {
                "ip_address": "10.0.0.20",
                "username": "admin",
                "event_type": SecurityEvent.EventType.LOGIN_FAILED,
                "timestamp": start + timedelta(minutes=minute),
            }
            for minute in range(5)
        ]

    def _multiple_account_attack(self, start):
        usernames = ["admin", "alice", "bob"]
        return [
            {
                "ip_address": "10.0.0.30",
                "username": username,
                "event_type": SecurityEvent.EventType.LOGIN_FAILED,
                "timestamp": start + timedelta(minutes=index),
            }
            for index, username in enumerate(usernames)
        ]

    def _suspicious_activity(self, start):
        event_types = [
            SecurityEvent.EventType.LOGIN_SUCCESS,
            SecurityEvent.EventType.LOGOUT,
            SecurityEvent.EventType.LOGIN_SUCCESS,
            SecurityEvent.EventType.PASSWORD_RESET,
            SecurityEvent.EventType.LOGIN_SUCCESS,
            SecurityEvent.EventType.LOGOUT,
            SecurityEvent.EventType.LOGIN_SUCCESS,
            SecurityEvent.EventType.LOGOUT,
            SecurityEvent.EventType.ACCOUNT_LOCKED,
            SecurityEvent.EventType.LOGIN_SUCCESS,
        ]
        return [
            {
                "ip_address": "192.168.1.50",
                "username": "service_account",
                "event_type": event_type,
                "timestamp": start + timedelta(seconds=index * 20),
            }
            for index, event_type in enumerate(event_types)
        ]
