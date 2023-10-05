from panther_base_helpers import deep_get, get_val_from_list, okta_alert_context


def rule(event):
    if event.get("eventtype") != "policy.evaluate_sign_on":
        return False

    target_app_names = get_val_from_list(
        event.get("target", [{}]), "displayName", "type", "AppInstance"
    )

    if "Okta Admin Console" not in target_app_names:
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
        f"A user {deep_get(event, 'actor', 'alternateId')} accessed "
        f"Okta Admin Console using new behaviors: "
        f"New IP: {deep_get(event, 'client', 'ipAddress')} "
        f"New Device: {deep_get(event, 'device', 'name')}"
    )


def alert_context(event):
    return okta_alert_context(event)
