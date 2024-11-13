from panther_zscaler_helpers import zia_alert_context, zia_success
from pygments.lexer import default


def rule(event):
    if not zia_success(event):
        return False
    action = event.deep_get("event", "action", default="ACTION_NOT_FOUND")
    category = event.deep_get("event", "category", default="CATEGORY_NOT_FOUND")
    if action == "DELETE" and category == "NSS":
        return True
    return False


def title(event):
    cloud_connection_url = event.deep_get(
        "event",
        "preaction",
        "cloudNssSiemConfiguration",
        "connectionURL",
        default="<CLOUD_CONNECTION_URL_NOT_FOUND>",
    )
    return (
        f"[Zscaler.ZIA]: Log streaming for location [{cloud_connection_url}] "
        f"was deleted by admin with id "
        f"[{event.deep_get('event', 'adminid', default='<ADMIN_ID_NOT_FOUND>')}]"
    )


def alert_context(event):
    return zia_alert_context(event)
