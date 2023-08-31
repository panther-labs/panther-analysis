from panther_base_helpers import okta_alert_context


def rule(event):
    return (
        event.get("eventtype") == "user.mfa.factor.suspend"
        and event.deep_get("outcome", "result") == "SUCCESS"
    )


def title(event):
    return (
        "Okta: Authentication Factor for "
        f"[{event.get('target',[{}])[0].get('alternateId', '<id-not-found>')}] "
        f"has been suspended."
    )


def alert_context(event):
    return okta_alert_context(event)
