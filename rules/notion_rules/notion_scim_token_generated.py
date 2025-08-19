from panther_notion_helpers import notion_alert_context


def rule(event):

    event_type = event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>")
    return event_type == "workspace.scim_token_generated"


def title(event):
    user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
    workspace_id = event.deep_get("event", "workspace_id", default="<NO_WORKSPACE_ID_FOUND>")
    return f"Notion User [{user}] generated a SCIM token for workspace id [{workspace_id}]."


def alert_context(event):
    return notion_alert_context(event)
