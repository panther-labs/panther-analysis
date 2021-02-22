from panther_base_helpers import deep_get, okta_alert_context


def rule(event):
    return (
        deep_get(event, "outcome", "result") == "FAILURE"
        and event.get("eventType") == "user.session.start"
    )


def title(event):
    return "Suspected brute force Okta logins to account {} due to [{}]".format(
        deep_get(event, "actor", "alternateId", default="<UNKNOWN_ACCOUNT>"),
        deep_get(event, "outcome", "reason", default="<UNKNOWN_REASON>"),
    )


def alert_context(event):
    return okta_alert_context(event)
