from panther_base_helpers import deep_get, okta_alert_context


def rule(event):
    return (event.get("eventType") == "user.authentication.auth_via_mfa"
        and deep_get(event, "outcome", "result") == "FAILURE"
        and deep_get(event, "outcome", "reason") == "FastPass declined phishing attempt")


def title(event):
    return (
        f"Okta: [{event.get('actor',{}).get('alternateId','<id-not-found>')}] "
        f"phishing attempt blocked by FastPass."
    )


def alert_context(event):
    return okta_alert_context(event)
