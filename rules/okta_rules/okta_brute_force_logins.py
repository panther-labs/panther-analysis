from panther_base_helpers import okta_alert_context


def rule(event):
    return (
        event.deep_get("outcome", "result") == "FAILURE"
        and event.get("eventType") == "user.session.start"
    )


def title(event):
    return (
        f"Suspected brute force Okta logins to account "
        f"{event.deep_get('actor', 'alternateId', default='<UNKNOWN_ACCOUNT>')}, due to "
        f"[{event.deep_get('outcome', 'reason', default='<UNKNOWN_REASON>')}]"
    )


def alert_context(event):
    return okta_alert_context(event)
