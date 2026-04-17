from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event


def rule(event):

    data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
    request_path = event.deep_get(
        "data", "details", "request", "path", default="<NO_REQUEST_PATH_FOUND>"
    )
    request_body = event.deep_get(
        "data", "details", "request", "body", "AfterAuthentication", default=[]
    )
    return all(
        [
            data_description == "Updates risk assessment configs",
            request_path == "/api/v2/risk-assessment/config",
            request_body is False,
            is_auth0_config_event(event),
        ]
    )


def title(event):
    user = event.deep_get(
        "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    p_source_label = event.get("p_source_label", "<NO_P_SOURCE_LABEL_FOUND>")
    return (
        f"Auth0 User [{user}] disabled mfa risk assessment settings for your "
        f"organization’s tenant [{p_source_label}]."
    )


def alert_context(event):
    return auth0_alert_context(event)
