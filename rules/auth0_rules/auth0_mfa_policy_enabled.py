from global_filter_auth0 import filter_include_event
from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event
from panther_base_helpers import deep_get


def rule(event):

    if not filter_include_event(event):
        return False
    data_description = deep_get(event, "data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
    request_path = deep_get(
        event, "data", "details", "request", "path", default="<NO_REQUEST_PATH_FOUND>"
    )
    return all(
        [
            data_description == "Set the Multi-factor Authentication policies",
            request_path == "/api/v2/guardian/policies",
            is_auth0_config_event(event),
        ]
    )


def title(event):

    user_email = deep_get(
        event, "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    request_body = deep_get(event, "data", "details", "request", "body", default=[])

    if "all-applications" in request_body:
        setting_change = "Always Require"
    if "confidence-score" in request_body:
        setting_change = "Use Adaptive MFA"

    return (
        f"Auth0 user {user_email} set the "
        f"mfa policies in your organization to {setting_change}."
    )


def alert_context(event):

    return auth0_alert_context(event)
