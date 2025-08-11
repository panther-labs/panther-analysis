from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event


def rule(event):

    description = event.deep_get("data", "description", default="<NO_DESCRIPTION_FOUND>")
    enabled = event.deep_get("data", "details", "response", "body", "enabled")
    return all(
        [
            description == "Update a Multi-factor Authentication Factor",
            enabled is True,
            is_auth0_config_event(event),
        ]
    )


def title(event):
    user = event.deep_get(
        "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    path = event.deep_get("data", "details", "request", "path", default="<NO_PATH_FOUND>")
    p_source_label = event.get("p_source_label", "<NO_P_SOURCE_LABEL_FOUND>")
    return (
        f"Auth0 User [{user}] enabled mfa factor settings for [{path}] "
        f"in your organization’s tenant [{p_source_label}]."
    )


def alert_context(event):
    return auth0_alert_context(event)
