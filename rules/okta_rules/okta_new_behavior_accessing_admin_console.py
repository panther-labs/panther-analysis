from panther_base_helpers import deep_get, deep_walk, okta_alert_context


def rule(event):
    if event.get("eventtype") != "policy.evaluate_sign_on":
        return False

    if "Okta Admin Console" not in deep_walk(event, "target", "displayName", default=""):
        return False

    behaviors = deep_get(event, "debugContext", "debugData", "behaviors")
    if behaviors:
        return "New Device=POSITIVE" in behaviors and "New IP=POSITIVE" in behaviors

    return (
        deep_get(
            event, "debugContext", "debugData", "logOnlySecurityData", "behaviors", "New Device"
        )
        == "POSITIVE"
        and deep_get(
            event, "debugContext", "debugData", "logOnlySecurityData", "behaviors", "New IP"
        )
        == "POSITIVE"
    )


def title(event):
    return (
        f"{deep_get(event, 'actor', 'displayName', default='<displayName-not-found>')} "
        f"<{deep_get(event, 'actor', 'alternateId', default='alternateId-not-found')}> "
        f"accessed Okta Admin Console using new behaviors: "
        f"New IP: {deep_get(event, 'client', 'ipAddress', default='<ipAddress-not-found>')} "
        f"New Device: {deep_get(event, 'device', 'name', default='<deviceName-not-found>')}"
    )


def alert_context(event):
    return okta_alert_context(event)
