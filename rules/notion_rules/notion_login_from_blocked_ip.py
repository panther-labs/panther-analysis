from global_filter_notion import filter_include_event
from panther_notion_helpers import notion_alert_context


def rule(event):
    # Users can specify inline-filters to permit rules based on IPs
    if not filter_include_event(event):
        return False
    return event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>") == "user.login"


def title(event):
    user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
    ip = event.deep_get("event", "ip_address", default="<UNKNOWN IP>")
    return f"Notion User [{user}] attempted to login from a blocked IP: [{ip}]."


def alert_context(event):
    return notion_alert_context(event)
