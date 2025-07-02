from fnmatch import fnmatch

from panther_okta_helpers import okta_alert_context

DETECTION_EVENTS = [
    "app.oauth2.client_id_rate_limit_warning",
    "application.integration.rate_limit_exceeded",
    "system.client.rate_limit.*",
    "system.client.concurrency_rate_limit.*",
    "system.operation.rate_limit.*",
    "system.org.rate_limit.*",
    "core.concurrency.org.limit.violation",
]


def rule(event):
    eventtype = event.get("eventtype", "")
    for detection_event in DETECTION_EVENTS:
        if fnmatch(eventtype, detection_event) and "violation" in eventtype:
            return True
    return False


def title(event):
    actor = event.deep_get("actor", "alternateId")
    if actor == "unknown":
        actor = event.deep_get("actor", "displayName", default="<id-not-found>")
    return (
        f"Okta Rate Limit Event: [{event.get('eventtype','')}] "
        f"by [{actor}/{event.deep_get('actor', 'type', default='<type-not-found>')}] "
    )


def dedup(event):
    return event.deep_get("actor", "id")


def alert_context(event):
    return okta_alert_context(event)
