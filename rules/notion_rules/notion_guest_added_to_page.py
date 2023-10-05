from global_filter_notion import filter_include_event
from panther_notion_helpers import notion_alert_context

# These event types correspond to users adding or editing the default role on a public page
event_types = ("page.permissions.guest_role_added", "page.permissions.guest_role_updated")


def rule(event):
    if not filter_include_event(event):
        return False
    return event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>") in event_types


def alert_context(event):
    return notion_alert_context(event)
