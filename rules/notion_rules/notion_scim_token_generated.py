from global_filter_notion import filter_include_event
from panther_notion_helpers import notion_alert_context


def rule(event):
    if not filter_include_event(event):
        return False
    event_type = event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>")
    return event_type == "workspace.scim_token_generated"


def title(event):
    user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
    workspace_id = event.get("workspace_id", "<NO_WORKSPACE_ID_FOUND>")
    token_id = event.deep_get("event", "workspace", "scim_token_generated", default="{}")
    return (
        f"Notion User [{user}] generated a SCIM token "
        f"[{token_id}] for workspace id [{workspace_id}]."
    )


def alert_context(event):
    return notion_alert_context(event)
