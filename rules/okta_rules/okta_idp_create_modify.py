from panther_okta_helpers import okta_alert_context


def rule(event):
    return "system.idp.lifecycle" in event.get("eventType")


def title(event):
    action = event.get("eventType").split(".")[-1]
    target = event.deep_walk(
        "target", "displayName", default="<displayName-not-found>", return_val="first"
    )
    return (
        f"{event.deep_get('actor', 'displayName', default='<displayName-not-found>')} "
        f"<{event.deep_get('actor', 'alternateId', default='alternateId-not-found')}> "
        f"{action}d Identity Provider [{target}]"
    )


def severity(event):
    if "create" in event.get("eventType"):
        return "HIGH"
    return "MEDIUM"


def alert_context(event):
    return okta_alert_context(event)
