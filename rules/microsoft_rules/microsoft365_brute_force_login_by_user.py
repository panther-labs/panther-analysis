from panther_base_helpers import m365_alert_context


def rule(event):
    return event.get("Operation", "") == "UserLoginFailed"


def title(event):
    return "Microsoft365 Brute Force Login Attempt " f"[{event.get('UserId')}]"


def alert_context(event):
    return m365_alert_context(event)
