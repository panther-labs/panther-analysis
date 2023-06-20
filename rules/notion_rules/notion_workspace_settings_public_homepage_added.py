from global_filter_notion import filter_include_event
from panther_base_helpers import deep_get
from panther_notion_helpers import notion_alert_context


def rule(event):
    if not filter_include_event(event):
        return False

    event_type = deep_get(event, "type", default="<NO_EVENT_TYPE_FOUND>")
    return event_type == "workspace.settings.public_homepage_added"


def title(event):
    actor = deep_get(event, "actor", "person", "email", default="<NO_EMAIL_FOUND>")
    workspace_id = deep_get(event, "workspace_id", default="<NO_WORKSPACE_ID_FOUND>")
    db_id = deep_get(
        event,
        "workspace.settings.public_homepage_added",
        "new_public_page",
        "database_id",
        default="<NO_DATABASE_ID_FOUND>",
    )
    return f"Notion User [{actor}] added a new public page [{db_id}] in workspace [{workspace_id}]"


def alert_context(event):
    return notion_alert_context(event)
