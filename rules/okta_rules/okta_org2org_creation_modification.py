from panther_base_helpers import deep_get, deep_walk, okta_alert_context

APP_LIFECYCLE_EVENTS = (
    "application.lifecycle.update",
    "application.lifecycle.create",
    "application.lifecycle.activate",
)


def rule(event):
    if event.get("eventType") not in APP_LIFECYCLE_EVENTS:
        return False

    return "Org2Org" in deep_walk(event, "target", "displayName", default="", return_val="first")


def title(event):
    action = event.get("eventType").split(".")[2]
    target = deep_walk(
        event, "target", "alternateId", default="<alternateId-not-found>", return_val="first"
    )
    return (
        f"{deep_get(event, 'actor', 'displayName', default='<displayName-not-found>')} "
        f"<{deep_get(event, 'actor', 'alternateId', default='alternateId-not-found')}> "
        f"{action}d Org2Org app [{target}]"
    )


def severity(event):
    if "create" in event.get("eventType"):
        return "HIGH"
    return "MEDIUM"


def alert_context(event):
    return okta_alert_context(event)
