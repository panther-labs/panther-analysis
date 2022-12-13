from fnmatch import fnmatch

from panther_base_helpers import okta_alert_context

DETECTION_EVENTS = [
    "app.oauth2.client_id_rate_limit_warning",
    "application.integration.rate_limit_exceeded",
    "system.client.concurrency_rate_limit.notification",
    "system.operation.rate_limit.*",
    "system.org.rate_limit.*",
]


def rule(event):
    eventtype = event.get("eventtype", "")
    for detection_event in DETECTION_EVENTS:
        if fnmatch(eventtype, detection_event):
            return True
    return False


def title(event):
    return f"Okta Rate Limit Event: [{event.get('eventtype','')}]"


def alert_context(event):
    return okta_alert_context(event)
