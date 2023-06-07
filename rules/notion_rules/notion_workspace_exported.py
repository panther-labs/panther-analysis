from global_filter_notion import filter_include_event
from panther_base_helpers import deep_get
from panther_notion_helpers import notion_alert_context


def rule(event):
    if not filter_include_event(event):
        return False
    return deep_get(event, "type", default="<NO_EVENT_TYPE_FOUND>") == "workspace.content_exported"


def title(event):
    user = deep_get(event, "actor", "person", "email", default="<NO_USER_FOUND>")
    workspace_id = deep_get(event, "workspace_id", default="<NO_WORKSPACE_ID_FOUND>")
    return f"Notion User [{user}] exported a workspace with workspace id [{workspace_id}]."


def alert_context(event):
    return notion_alert_context(event)
