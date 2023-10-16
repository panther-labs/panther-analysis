from global_filter_notion import filter_include_event
from panther_notion_helpers import notion_alert_context
from panther_base_helpers import deep_get

# These event types correspond to users adding or editing the default role on a public page
event_types = ("page.permissions.guest_role_added", "page.permissions.guest_role_updated")


def rule(event):
    if not filter_include_event(event):
        return False
    return event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>") in event_types


def title(event):
    user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
    guest = event.deep_get(
        "event", "details", "entity", "person", "email", default="<NO_USER_FOUND>"
    )
    page_id = event.deep_get("event", "details", "target", "page_id", default="<NO_PAGE_ID_FOUND>")
    event_type = event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>")
    action = {
        "page.permissions.guest_role_added": "added a guest",
        "page.permissions.guest_role_updated": "changed the guest permissions of",
    }.get(event_type, "changed the guest permissions of")
    return f"Notion User [{user}] {action} [{guest}] on page [{page_id}]."


def alert_context(event):
    context = notion_alert_context(event)
    page_id = event.deep_get("event", "details", "target", "page_id", default="<NO_PAGE_ID_FOUND>")
    context["page_id"] = page_id
    details = event.deep_get("event", "details", default={})
    context["guest"] = deep_get(details, "entity", "person", "email", default="<NO_USER_FOUND>")
    context["new_permission"] = deep_get(details, "new_permission", default="<UNKNOWN PERMISSION>")
    context["old_permission"] = deep_get(details, "old_permission", default="<UNKNOWN PERMISSION>")
    return context
