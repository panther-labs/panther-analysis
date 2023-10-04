from panther_base_helpers import deep_get, okta_alert_context


def rule(event):
    return 'system.idp.lifecycle' in event.get("eventType")


def title(event):
    action = event.get('eventType').split('.')[3]
    return (
        f"Okta: [{event.get('actor',{}).get('alternateId','<id-not-found>')}] "
        f"{action} Identity Provider"
    )


def severity(event):
    if 'create' in event.get("eventType"):
        return 'HIGH'
    return 'MEDIUM'


def alert_context(event):
    return okta_alert_context(event)
