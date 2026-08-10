CLAUDE.md
# ThreatWatch — Security Event Monitoring API

## 1. Project Goal

Build a small but polished cybersecurity-focused backend application called **ThreatWatch**.

ThreatWatch is a Django REST API that receives authentication/security events, stores them, analyzes them using deterministic rule-based detection, and generates security alerts when suspicious behavior is detected.

The project is intended as a portfolio project for a Software Engineering Internship application at a cybersecurity company.

The developer already has Python experience but is learning Django/Django REST Framework through this project.

The project must therefore be:
- Clean
- Simple enough to understand completely
- Technically credible
- Well tested
- Well documented
- Relevant to cybersecurity
- Relevant to backend/software engineering
- Finishable in approximately one day

Do NOT turn this into a large SIEM, SOC platform, ML project, frontend application, or production-scale security platform.

---

# 2. Required Technology Stack

Use:

- Python 3
- Django
- Django REST Framework
- SQLite
- Pytest
- pytest-django
- Git

Optional:
- Django Admin if useful for development/debugging

Do NOT introduce additional major frameworks or infrastructure unless absolutely necessary.

Do NOT use:
- React
- Vue
- Angular
- Docker
- PostgreSQL
- Redis
- Celery
- Kafka
- Elasticsearch
- Machine Learning
- LLMs
- external cybersecurity APIs

The goal is to keep the project small and understandable.

---

# 3. Core Concept

The application receives security events such as:

- LOGIN_SUCCESS
- LOGIN_FAILED
- LOGOUT
- PASSWORD_RESET
- ACCOUNT_LOCKED

Each event contains:

- IP address
- username
- event type
- timestamp

Example:

POST /api/events/

```json
{
    "ip_address": "192.168.1.10",
    "username": "admin",
    "event_type": "LOGIN_FAILED",
    "timestamp": "2026-08-10T15:30:00Z"
}

The event is stored in the database.

After storing the event, ThreatWatch analyzes recent events and determines whether suspicious behavior has occurred.

If suspicious behavior is detected, an Alert is created.

4. Data Models

Create two main models.

SecurityEvent

Fields:

id
ip_address
username
event_type
timestamp
created_at

Recommended Django field types:

GenericIPAddressField for IP address
CharField for username
CharField with choices for event_type
DateTimeField for timestamp
DateTimeField(auto_now_add=True) for created_at

Valid event types:

LOGIN_SUCCESS
LOGIN_FAILED
LOGOUT
PASSWORD_RESET
ACCOUNT_LOCKED

The timestamp should use timezone-aware datetimes.

Do not store passwords, tokens, credentials, or other secrets.

Alert

Fields:

id
alert_type
severity
ip_address
username
description
risk_score
detected_at
related event information if useful

Alert types:

BRUTE_FORCE
MULTIPLE_ACCOUNTS
SUSPICIOUS_ACTIVITY

Severity levels:

LOW
MEDIUM
HIGH
CRITICAL

Use sensible Django choices/enums.

5. Detection Rules

Implement deterministic rule-based detection.

Keep the rules simple and explainable.

Rule 1 — Brute Force

Trigger a BRUTE_FORCE alert when:

The same IP address
Has at least 5 LOGIN_FAILED events
Within a rolling 5-minute window

Example:

10:00 failed login
10:01 failed login
10:02 failed login
10:03 failed login
10:04 failed login

=> Brute force detected.

The rule should use database queries rather than loading the entire database into Python.

Rule 2 — Multiple Account Targeting

Trigger a MULTIPLE_ACCOUNTS alert when:

The same IP address
Attempts to log into at least 3 different usernames
Through LOGIN_FAILED events
Within a rolling 10-minute window

Example:

10:00 -> admin
10:02 -> alice
10:05 -> bob

from the same IP.

=> Multiple-account attack detected.

Rule 3 — Suspicious Activity

Create a SUSPICIOUS_ACTIVITY alert when an IP generates at least 10 security events within 10 minutes.

This is a deliberately simple heuristic.

Do not attempt to make this a real IDS.

6. Risk Scoring

Implement a simple deterministic risk scoring system.

Suggested scores:

Repeated failed login attempt: +10
Multiple account targeting:   +20
Brute force detected:         +50
Suspicious activity:          +30

Severity should be derived from the resulting score:

0-29    LOW
30-59   MEDIUM
60-89   HIGH
90+     CRITICAL

Keep the implementation simple.

The exact implementation may differ slightly if a cleaner design is found, but the behavior must remain understandable.

7. Duplicate Alert Prevention

Do not generate unlimited duplicate alerts every time a new event arrives.

For example, if an IP has already triggered a brute-force alert for the same recent attack window, do not create another identical alert for every subsequent failed login.

Implement a simple duplicate-prevention strategy.

Possible approach:

Look for an existing alert of the same type
For the same IP
Detected recently
Avoid creating another duplicate alert within a reasonable cooldown period

Keep this logic simple.

8. API Endpoints

Use Django REST Framework.

Required endpoints:

Create Event
POST /api/events/

Creates a SecurityEvent and runs detection.

Example request:

{
    "ip_address": "192.168.1.10",
    "username": "admin",
    "event_type": "LOGIN_FAILED",
    "timestamp": "2026-08-10T15:30:00Z"
}

Return the created event.

If an alert was generated, return useful information about the generated alert as well.

List Events
GET /api/events/

Returns security events.

Support basic pagination if it is straightforward with DRF.

List Alerts
GET /api/alerts/

Returns generated security alerts.

Allow useful filtering if simple to implement, such as:

?severity=HIGH
?alert_type=BRUTE_FORCE
?ip_address=192.168.1.10

Do not build a complicated filtering system.

Alert Summary
GET /api/alerts/summary/

Return a simple JSON summary.

Example:

{
    "total_alerts": 12,
    "high_severity": 4,
    "medium_severity": 5,
    "low_severity": 3,
    "critical_severity": 0,
    "brute_force": 6,
    "multiple_accounts": 4,
    "suspicious_activity": 2
}

The exact fields may be improved if there is a cleaner design.

9. Project Structure

Use a clean Django structure.

A reasonable structure is:

ThreatWatch/
│
├── manage.py
├── requirements.txt
├── README.md
├── .gitignore
├── CLAUDE.md
│
├── threatwatch/
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   ├── asgi.py
│   └── wsgi.py
│
└── security/
    ├── __init__.py
    ├── admin.py
    ├── apps.py
    ├── models.py
    ├── serializers.py
    ├── urls.py
    ├── views.py
    ├── services.py
    ├── detection.py
    ├── tests/
    │   ├── __init__.py
    │   ├── test_models.py
    │   ├── test_detection.py
    │   └── test_api.py
    └── migrations/

You may adjust the structure if Django best practices suggest a better small-scale organization.

Keep business logic OUT of the API views when possible.

The detection rules should live in a dedicated module/service rather than being embedded inside serializers or views.

10. Architecture

Use a simple separation of responsibilities.

Suggested flow:

HTTP Request
     |
     v
DRF View
     |
     v
Serializer
     |
     v
SecurityEvent saved
     |
     v
Detection Service
     |
     +----> Brute Force Rule
     |
     +----> Multiple Accounts Rule
     |
     +----> Suspicious Activity Rule
     |
     v
Alert created if necessary
     |
     v
HTTP Response

Do NOT introduce unnecessary architectural patterns.

This is a small project.

Prioritize readability over abstraction.

11. Validation

The API must validate:

Required fields
Valid IP addresses
Valid event types
Valid timestamps
Username is not empty

Return proper HTTP status codes.

For invalid input, return a useful DRF validation response.

Do not expose internal stack traces to API clients.

12. Testing

Testing is important.

Use:

pytest
pytest-django
DRF APIClient where appropriate

Write tests for:

Model tests

At minimum:

SecurityEvent creation
Valid event types
Alert creation
Detection tests

Test:

Fewer than 5 failed logins does NOT trigger brute force.
5 failed logins from the same IP within 5 minutes triggers brute force.
Failed logins outside the 5-minute window do not trigger brute force.
3 different usernames from the same IP within 10 minutes triggers multiple-account detection.
10 events from the same IP within 10 minutes triggers suspicious activity.
Different IP addresses do not incorrectly trigger the same rule.
Duplicate alerts are prevented.
API tests

Test:

POST /api/events/
GET /api/events/
GET /api/alerts/
GET /api/alerts/summary/
Invalid event input
Invalid event type
Invalid IP address

Tests should be meaningful, not written just to increase coverage.

Aim for strong coverage of the core detection logic.

13. Seed / Demo Data

Create an easy way to populate demonstration data.

Prefer a Django management command such as:

python manage.py seed_demo

It should create realistic example events that demonstrate:

Normal login activity
A brute-force attack
Multiple-account targeting
Suspicious high-volume activity

The demo data should make it easy to show the project during an interview.

Do not use real people's IP addresses or usernames.

Use example/private IP addresses such as:

192.168.1.10
10.0.0.15
10.0.0.20
14. README

Create a professional README.md.

It should include:

Project Overview

What ThreatWatch does and why it exists.

Features

List the main features.

Architecture

Include a simple Mermaid diagram if appropriate.

Example:

Detection Rules

Clearly explain every rule and threshold.

Risk Scoring

Explain the scoring system.

API Endpoints

Document every endpoint with example requests/responses.

Installation

Example:

git clone <repository-url>
cd ThreatWatch

python -m venv venv

# macOS/Linux
source venv/bin/activate

# Windows
venv\Scripts\activate

pip install -r requirements.txt

python manage.py migrate
python manage.py seed_demo
python manage.py runserver
Running Tests
pytest
Example Usage

Show curl examples.

For example:

curl -X POST http://127.0.0.1:8000/api/events/ \
-H "Content-Type: application/json" \
-d '{
  "ip_address": "192.168.1.10",
  "username": "admin",
  "event_type": "LOGIN_FAILED",
  "timestamp": "2026-08-10T15:30:00Z"
}'
Future Improvements

Mention realistic future improvements, but DO NOT implement them.

Examples:

Authentication and role-based access
PostgreSQL
Redis-based rate limiting
Background event processing
Real-time alert streaming
More sophisticated detection rules
Integration with SIEM systems
IP reputation services
15. Code Quality

Follow these rules:

Use clear names.
Keep functions small.
Add type hints where useful.
Write docstrings for important business logic.
Avoid unnecessary comments.
Do not duplicate detection logic.
Keep views thin.
Keep detection rules testable.
Follow Django conventions.
Follow PEP 8 where practical.

Do not create unnecessary abstractions.

Avoid code such as:

AbstractSecurityEventFactory
SecurityDetectionStrategyFactory
AlertManagerFactory

unless genuinely necessary.

This project should be understandable to a junior software engineer.

16. Security Practices

Even though this is a demonstration project, follow sensible security practices.

Never store passwords.
Never store authentication tokens.
Never hardcode secrets.
Use environment variables for sensitive configuration if any are introduced.
Validate all incoming data.
Do not trust client-provided values blindly.
Use Django's built-in security mechanisms.
Do not expose Django DEBUG errors in production configuration.
Do not include real sensitive data in demo data.
17. Scope Control

This is extremely important.

The project should be completed in approximately one day.

DO NOT add:

Frontend
React
Authentication system
User registration
JWT
Docker
Kubernetes
Cloud deployment
Machine learning
LLMs
External threat intelligence APIs
Real-time WebSockets
Complex permissions
Microservices
Message queues
Complex dashboards
SIEM integrations

Unless explicitly requested later.

The goal is a polished backend project, not a large application.

18. Development Process

Build the project incrementally.

Recommended order:

Phase 1 — Setup
Create virtual environment
Install dependencies
Create Django project
Create security app
Configure SQLite
Configure DRF
Verify server starts
Phase 2 — Models
SecurityEvent
Alert
Migrations
Admin registration if useful
Phase 3 — Serializers/API
Event serializer
Alert serializer
Event endpoint
Event list endpoint
Alert list endpoint
Phase 4 — Detection Engine

Implement:

Brute-force detection
Multiple-account detection
Suspicious activity detection
Risk scoring
Severity classification
Duplicate prevention
Phase 5 — Summary Endpoint

Implement:

/api/alerts/summary/
Phase 6 — Tests

Implement comprehensive tests for detection logic and API behavior.

Phase 7 — Demo Data

Implement:

python manage.py seed_demo
Phase 8 — README

Document the finished system.

Phase 9 — Final Verification

Run:

pytest

Then run the Django server and manually verify the main API endpoints.

Fix all failing tests before considering the project complete.

19. Important Instruction About Implementation

Do not simply generate a large amount of code immediately.

First inspect the environment and repository.

Then implement the project incrementally.

After each major phase:

Run the relevant tests/checks.
Fix errors.
Continue.

Do not silently change the requirements.

If a requirement is ambiguous, choose the simplest implementation consistent with this specification.

20. Final Acceptance Criteria

The project is considered complete only when ALL of the following are true:

Django project runs successfully.
SQLite database works.
SecurityEvent model works.
Alert model works.
POST /api/events/ works.
GET /api/events/ works.
GET /api/alerts/ works.
GET /api/alerts/summary/ works.
Brute-force detection works.
Multiple-account detection works.
Suspicious activity detection works.
Risk scoring works.
Severity classification works.
Duplicate alerts are prevented.
Invalid API input is handled correctly.
Demo data can be generated.
Pytest suite passes.
README is complete.
No unnecessary technologies were introduced.
No secrets or sensitive data are included.
Code is clean enough for a portfolio project.

Before finishing, provide a concise final report containing:

What was implemented.
Project structure.
How to run it.
How to run tests.
Test results.
API endpoints.
Detection rules.
Any assumptions made.
Any remaining optional improvements.

Do not claim a feature is implemented unless it actually exists and has been tested.