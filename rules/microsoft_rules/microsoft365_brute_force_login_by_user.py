from panther_base_helpers import m365_alert_context


def rule(event):
    return event.get("Operation", "") == "UserLoginFailed"


def title(event):
    return (
        f"Microsoft365: [{event.get('UserId', '<user-not-found>')}] "
        "may be undergoing a Brute Force Attack."
    )


def alert_context(event):
    return m365_alert_context(event)
