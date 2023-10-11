from panther_base_helpers import deep_get, deep_walk, okta_alert_context


def rule(event):
    return "system.idp.lifecycle" in event.get("eventType")


def title(event):
    action = event.get("eventType").split(".")[3]
    target = deep_walk(
        event, "target", "displayName", default="<displayName-not-found>", return_val="first"
    )
    return (
        f"{deep_get(event, 'actor', 'displayName', default='<displayName-not-found>')} "
        f"<{deep_get(event, 'actor', 'alternateId', default='alternateId-not-found')}> "
        f"{action}d Identity Provider [{target}]"
    )


def severity(event):
    if "create" in event.get("eventType"):
        return "HIGH"
    return "MEDIUM"


def alert_context(event):
    return okta_alert_context(event)
