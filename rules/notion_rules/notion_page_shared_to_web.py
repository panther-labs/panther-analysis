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
    page_id = event.deep_get("event", "details", "target", "page_id", default="<NO_PAGE_ID_FOUND>")
    return f"Notion User [{user}] changed the status of page [{page_id}] to public."

def alert_context(event):
    context = notion_alert_context(event)
    page_id = event.deep_get("event", "details", "target", "page_id", default="<NO_PAGE_ID_FOUND>")
    context['page_id'] = page_id
    return context
