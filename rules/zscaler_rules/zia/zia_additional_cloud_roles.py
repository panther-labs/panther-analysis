from panther_zscaler_helpers import zia_alert_context, zia_success


def rule(event):
    if not zia_success(event):
        return False
    event_data = event.get("event", {})
    return (
        event_data.get("action", "ACTION_NOT_FOUND") == "CREATE"
        and event_data.get("category", "CATEGORY_NOT_FOUND") == "ROLE_MANAGEMENT"
    )


def title(event):
    return (
        f"[Zscaler.ZIA]: Additional cloud role was created by admin with id "
        f"[{event.deep_get('event', 'adminid', default='<ADMIN_ID_NOT_FOUND>')}]"
    )


def alert_context(event):
    return zia_alert_context(event)
