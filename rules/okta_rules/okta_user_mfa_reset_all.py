from panther_base_helpers import okta_alert_context


def rule(event):
    return event.get("eventtype") == "user.mfa.factor.reset_all"


def title(event):
    return (
        "Okta: All MFA factors were reset for "
        f"[{event.get('target',[{}])[0].get('alternateId', '<id-not-found>')}] "
        f"by [{event.get('actor',{}).get('alternateId','<id-not-found>')}]"
    )


def alert_context(event):
    return okta_alert_context(event)
