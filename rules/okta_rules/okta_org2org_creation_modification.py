from panther_base_helpers import get_val_from_list, okta_alert_context

APP_LIFECYCLE_EVENTS = (
    "application.lifecycle.update",
    "application.lifecycle.create",
    "application.lifecycle.activate",
)


def rule(event):
    if event.get("eventType") not in APP_LIFECYCLE_EVENTS:
        return False

    target_app_names = get_val_from_list(
        event.get("target", [{}]), "displayName", "type", "AppInstance"
    )

    for app_name in target_app_names:
        if "Org2Org" in app_name:
            return True
    return False


def title(event):
    action = event.get("eventType").split(".")[2]
    return (
        f"Okta: [{event.get('actor',{}).get('alternateId','<id-not-found>')}] "
        f"{action} Org2Org application"
    )


def severity(event):
    if "create" in event.get("eventType"):
        return "HIGH"
    return "MEDIUM"


def alert_context(event):
    return okta_alert_context(event)
