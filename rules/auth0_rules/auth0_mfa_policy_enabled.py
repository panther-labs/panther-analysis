from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event


def rule(event):

    data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
    request_path = event.deep_get(
        "data", "details", "request", "path", default="<NO_REQUEST_PATH_FOUND>"
    )
    return all(
        [
            data_description == "Set the Multi-factor Authentication policies",
            request_path == "/api/v2/guardian/policies",
            is_auth0_config_event(event),
        ]
    )


def title(event):
    user_email = event.deep_get(
        "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    request_body = event.deep_get("data", "details", "request", "body", default=[])

    if "all-applications" in request_body:
        setting_change = "Always Require"
    if "confidence-score" in request_body:
        setting_change = "Use Adaptive MFA"
    else:
        setting_change = "Unknown"

    return (
        f"Auth0 user [{user_email}] set the "
        f"mfa policies in your organization to [{setting_change}]."
    )


def alert_context(event):
    return auth0_alert_context(event)
