from fnmatch import fnmatch

from panther_base_helpers import okta_alert_context

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
    return (
        f"Okta Rate Limit Event: [{event.get('eventtype','')}] "
        f"by [{event.deep_get('actor', 'alternateId', default='<id-not-found>')}]"
    )


def dedup(event):
    return event.deep_get("actor", "alternateId", default="<id-not-found>")


def alert_context(event):
    return okta_alert_context(event)
