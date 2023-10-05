from panther_base_helpers import deep_get, okta_alert_context


def rule(event):
    return event.get(
        "eventType"
    ) == "application.lifecycle.update" and "Pushing user passwords" in deep_get(
        event, "outcome", "reason"
    )


def title(event):
    return (
        f"Okta: [{event.get('actor',{}).get('alternateId','<id-not-found>')}] "
        f"extracted cleartext user passwords via SCIM"
    )


def alert_context(event):
    return okta_alert_context(event)
