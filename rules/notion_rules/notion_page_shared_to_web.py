from global_filter_notion import filter_include_event
from panther_notion_helpers import notion_alert_context

# These event types correspond to users adding or editing the default role on a public page
event_types = (
    "page.permissions.shared_to_public_role_added",
    "page.permissions.shared_to_public_role_updated",
)


def rule(event):
    if not filter_include_event(event):
        return False
    return event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>") in event_types


def title(event):
    user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
    page_name = event.deep_get("event", "details", "page_name", default="<NO_PAGE_NAME_FOUND>")
    return f"Notion User [{user}] changed the status of page [{page_name}] to public."


def alert_context(event):
    context = notion_alert_context(event)
    page_name = event.deep_get("event", "details", "page_name", default="<NO_PAGE_NAME_FOUND>")
    context["page_name"] = page_name
    return context
