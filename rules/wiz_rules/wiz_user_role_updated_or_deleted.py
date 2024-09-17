from panther_wiz_helpers import wiz_alert_context, wiz_success

SUSPICIOUS_ACTIONS = ["DeleteUserRole", "UpdateUserRole"]


def rule(event):
    if not wiz_success(event):
        return False
    return event.get("action", "ACTION_NOT_FOUND") in SUSPICIOUS_ACTIONS


def title(event):
    return (
        f"[Wiz]: [{event.get('action', 'ACTION_NOT_FOUND')}] action "
        f"performed by user [{event.deep_get('user', 'name', default='USER_NAME_NOT_FOUND')}]"
    )


def dedup(event):
    return event.get("id")


def alert_context(event):
    return wiz_alert_context(event)


def severity(event):
    action = event.get("action", "ACTION_NOT_FOUND")
    if "Delete" in action:
        return "High"
    return "Default"