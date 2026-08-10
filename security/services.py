from security.detection import analyze_event
from security.models import Alert, SecurityEvent


def analyze_security_event(event: SecurityEvent) -> list[Alert]:
    return analyze_event(event)
