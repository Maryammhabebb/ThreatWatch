from django.contrib import admin

from security.models import Alert, SecurityEvent


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ("event_type", "username", "ip_address", "timestamp", "created_at")
    list_filter = ("event_type", "created_at")
    search_fields = ("username", "ip_address")


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("alert_type", "severity", "ip_address", "username", "risk_score", "detected_at")
    list_filter = ("alert_type", "severity", "detected_at")
    search_fields = ("username", "ip_address", "description")
