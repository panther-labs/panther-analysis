from panther_base_helpers import okta_alert_context


def rule(event):
    return event.get("eventType") == 'user.authentication.auth_via_IDP'


def title(event):

    return (
        f"Okta: [{event.get('actor',{}).get('alternateId','<id-not-found>')}] "
        f"sign-in via 3rd-party Identity Provider"
    )


def alert_context(event):
    return okta_alert_context(event)
