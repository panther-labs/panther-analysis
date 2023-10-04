from panther_base_helpers import okta_alert_context, deep_get, get_val_from_list


def rule(event):
    if event.get("eventtype") != "policy.evaluate_sign_on":
        return False
    
    TARGET_APP_NAMES = get_val_from_list(
        event.get("target", [{}]), "displayName", "type", "AppInstance"
    )

    if "Okta Admin Console" not in TARGET_APP_NAMES:
        return False

    behaviors = deep_get(event, "debugContext", "debugData", "behaviors")
    if behaviors:
        return (
            "New Device=POSITIVE" in behaviors
            and "New IP=POSITIVE" in behaviors
            )

    return (
        deep_get(event, "debugContext", "debugData", "logOnlySecurityData", "behaviors", "New Device") == "POSITIVE"
        and deep_get(event, "debugContext", "debugData", "logOnlySecurityData", "behaviors", "New IP") == "POSITIVE"
    )


def title(event):
    return (
        f"A user {deep_get(event, 'actor', 'alternateId')} accessed Okta Admin Console using new behaviors: "
        f"New IP: {deep_get(event, 'client', 'ipAddress')} "
        f"New Device: {deep_get(event, 'device', 'name')}"
    )


def alert_context(event):
    return okta_alert_context(event)
