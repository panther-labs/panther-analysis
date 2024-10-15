from panther_base_helpers import okta_alert_context

APP_LIFECYCLE_EVENTS = (
    "application.lifecycle.update",
    "application.lifecycle.create",
    "application.lifecycle.activate",
)


def rule(event):
    if event.get("eventType") not in APP_LIFECYCLE_EVENTS:
        return False

    return "Org2Org" in event.deep_walk("target", "displayName", default="", return_val="first")


def title(event):
    action = event.get("eventType").split(".")[-1]
    target = event.deep_walk(
        "target", "alternateId", default="<alternateId-not-found>", return_val="first"
    )
    return (
        f"{event.deep_get('actor', 'displayName', default='<displayName-not-found>')} "
        f"<{event.deep_get('actor', 'alternateId', default='alternateId-not-found')}> "
        f"{action}d Org2Org app [{target}]"
    )


def severity(event):
    if "create" in event.get("eventType"):
        return "HIGH"
    return "MEDIUM"


def alert_context(event):
    return okta_alert_context(event)
