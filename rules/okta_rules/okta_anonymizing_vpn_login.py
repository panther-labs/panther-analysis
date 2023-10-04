from panther_base_helpers import deep_get, okta_alert_context


def rule(event):
    return (
        event.get("eventType") == "user.session.start"
        and deep_get(event, "securityContext", "isProxy") == True
        )


def title(event):
    return (
        f"Okta: [{event.get('actor',{}).get('alternateId','<id-not-found>')}] "
        f"sign-in attempt from anonymizing VPN: "
        f"{deep_get(event, 'securityContext', 'domain')}"
    )


def alert_context(event):
    return okta_alert_context(event)
