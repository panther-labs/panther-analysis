from global_filter_notion import filter_include_event
from panther_notion_helpers import notion_alert_context


def rule(event):
    if not filter_include_event(event):
        return False
    return event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>") == "page.exported"


def title(event):
    user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
    return f"Notion User [{user}] exported multiple pages."


def alert_context(event):
    return notion_alert_context(event)
