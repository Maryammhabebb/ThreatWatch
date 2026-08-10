from django.core.validators import MinValueValidator
from django.db import models
from django.utils import timezone


class SecurityEvent(models.Model):
    class EventType(models.TextChoices):
        LOGIN_SUCCESS = "LOGIN_SUCCESS", "Login success"
        LOGIN_FAILED = "LOGIN_FAILED", "Login failed"
        LOGOUT = "LOGOUT", "Logout"
        PASSWORD_RESET = "PASSWORD_RESET", "Password reset"
        ACCOUNT_LOCKED = "ACCOUNT_LOCKED", "Account locked"

    ip_address = models.GenericIPAddressField()
    username = models.CharField(max_length=150)
    event_type = models.CharField(max_length=32, choices=EventType.choices)
    timestamp = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp", "-created_at"]
        indexes = [
            models.Index(fields=["ip_address", "event_type", "timestamp"]),
            models.Index(fields=["ip_address", "timestamp"]),
        ]

    def __str__(self) -> str:
        return f"{self.event_type} for {self.username} from {self.ip_address}"

    def save(self, *args, **kwargs):
        if self.timestamp and timezone.is_naive(self.timestamp):
            self.timestamp = timezone.make_aware(self.timestamp, timezone.get_current_timezone())
        super().save(*args, **kwargs)


class Alert(models.Model):
    class AlertType(models.TextChoices):
        BRUTE_FORCE = "BRUTE_FORCE", "Brute force"
        MULTIPLE_ACCOUNTS = "MULTIPLE_ACCOUNTS", "Multiple accounts"
        SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY", "Suspicious activity"

    class Severity(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    alert_type = models.CharField(max_length=32, choices=AlertType.choices)
    severity = models.CharField(max_length=16, choices=Severity.choices)
    ip_address = models.GenericIPAddressField()
    username = models.CharField(max_length=150, blank=True)
    description = models.TextField()
    risk_score = models.PositiveIntegerField(validators=[MinValueValidator(0)])
    detected_at = models.DateTimeField(default=timezone.now)
    related_events = models.ManyToManyField(SecurityEvent, blank=True, related_name="alerts")

    class Meta:
        ordering = ["-detected_at"]
        indexes = [
            models.Index(fields=["alert_type", "ip_address", "detected_at"]),
            models.Index(fields=["severity"]),
        ]

    def __str__(self) -> str:
        return f"{self.severity} {self.alert_type} alert for {self.ip_address}"
