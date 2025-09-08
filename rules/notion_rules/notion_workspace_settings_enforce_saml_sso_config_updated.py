from panther_notion_helpers import notion_alert_context


def rule(event):

    return (
        event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>")
        == "workspace.settings.enforce_saml_sso_config_updated"
    )


def title(event):
    user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
    workspace_id = event.deep_get("event", "workspace_id", default="<NO_WORKSPACE_ID_FOUND>")
    state = event.deep_get(
        "event",
        "workspace.settings.enforce_saml_sso_config_updated",
        "state",
        default="<NO_STATE_FOUND>",
    )

    if state == "enabled":
        return (
            f"Notion User [{user}] updated settings to enable SAML SSO config "
            f"from workspace id {workspace_id}"
        )

    return (
        f"Notion User [{user}] updated settings to disable SAML SSO config "
        f"from workspace id {workspace_id}"
    )


def severity(event):
    state = event.deep_get(
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
