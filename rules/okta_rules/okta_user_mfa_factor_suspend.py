from panther_base_helpers import okta_alert_context


def rule(event):
    return event.get("eventtype") == "user.mfa.factor.suspend"


def title(event):
    return (
        "Okta MFA Factor Suspended for "
        f"[{event.get('target',[{}])[0].get('alternateId', '<id-not-found>')}] "
        f"by [{event.get('actor',{}).get('alternateId','<id-not-found>')}]"
    )


def alert_context(event):
    return okta_alert_context(event)
