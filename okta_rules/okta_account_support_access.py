OKTA_SUPPORT_ACCESS_EVENTS = [
    "user.session.impersonation.grant",
    "user.session.impersonation.initiate",
]


def rule(event):
    return event.get("eventType") in OKTA_SUPPORT_ACCESS_EVENTS


def title(event):
    return f"Okta Support Access Granted by {event.udm('actor_user')}"


def alert_context(event):
    context = {
        "user": event.udm("actor_user"),
        "ip": event.udm("source_ip"),
        "event": event.get("eventType"),
    }
    return context
