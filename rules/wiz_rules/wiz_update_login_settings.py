from panther_wiz_helpers import wiz_alert_context, wiz_success


def rule(event):
    if not wiz_success(event):
        return False
    return event.get("action", "ACTION_NOT_FOUND") == "UpdateLoginSettings"


def title(event):
    return (
        f"[Wiz]: [{event.get('action', 'ACTION_NOT_FOUND')}] action "
        f"performed by user [{event.deep_get('user', 'name', default='USER_NAME_NOT_FOUND')}]"
    )


def dedup(event):
    return event.get("id")


def alert_context(event):
    return wiz_alert_context(event)
