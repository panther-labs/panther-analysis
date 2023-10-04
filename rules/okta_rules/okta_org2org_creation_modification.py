from panther_base_helpers import deep_get, okta_alert_context, get_val_from_list

APP_LIFECYCLE_EVENTS = ('application.lifecycle.update', 'application.lifecycle.create', 'application.lifecycle.activate')

def rule(event):
    if event.get("eventType") not in APP_LIFECYCLE_EVENTS:
        return False

    TARGET_APP_NAMES = get_val_from_list(
        event.get("target", [{}]), "displayName", "type", "AppInstance"
    )

    for app_name in TARGET_APP_NAMES:
        if 'Org2Org' in app_name:
            return True


def title(event):
    action = event.get('eventType').split('.')[2]
    return (
        f"Okta: [{event.get('actor',{}).get('alternateId','<id-not-found>')}] "
        f"{action} Org2Org application"
    )


def severity(event):
    if 'create' in event.get("eventType"):
        return 'HIGH'
    return 'MEDIUM'


def alert_context(event):
    return okta_alert_context(event)
