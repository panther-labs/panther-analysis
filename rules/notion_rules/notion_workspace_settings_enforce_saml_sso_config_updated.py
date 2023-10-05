from global_filter_notion import filter_include_event
from panther_base_helpers import deep_get
from panther_notion_helpers import notion_alert_context


def rule(event):
    if not filter_include_event(event):
        return False
    return (
        event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>")
        == "workspace.settings.enforce_saml_sso_config_updated"
    )


def title(event):
    user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
    workspace_id = event.deep_get("event", "workspace_id", default="<NO_WORKSPACE_ID_FOUND>")
    state = deep_get(
        event,
        "event",
        "state",
        default="<NO_STATE_FOUND>",
    )

    if state == "enabled":
        return (
            f"Notion User [{user}] updated settings to enable SAML SSO config "
            f"for workspace id {workspace_id}"
        )

    return (
        f"Notion User [{user}] updated settings to disable SAML SSO config "
        f"for workspace id {workspace_id}"
    )


def severity(event):
    state = deep_get(
        event,
        "event",
        "workspace.settings.enforce_saml_sso_config_updated",
        "state",
        default="<NO_STATE_FOUND>",
    )

    if state == "enabled":
        return "INFO"

    return "HIGH"


def alert_context(event):
    return notion_alert_context(event)
