from global_filter_auth0 import filter_include_event
from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event
from panther_base_helpers import deep_get


def rule(event):
    if not filter_include_event(event):
        return False
    data_description = deep_get(event, "data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
    return all(
        [
            data_description == "Create a role",
            is_auth0_config_event(event),
        ]
    )


def title(event):
    user = deep_get(
        event, "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    request_body_name = deep_get(
        event, "data", "details", "request", "body", "name", default="<NO_REQUEST_NAME_FOUND>"
    )
    request_body_description = deep_get(event, "data", "details", "request", "body", default="<NO_REQUEST_BODY_FOUND>")

    if "admin" in request_body_description or "admin" in request_body_name:
        role_type = "admin"
    else:
        role_type = "custom"

    p_source_label = deep_get(event, "p_source_label", default="<NO_P_SOURCE_LABEL_FOUND>")
    return (
        f"Auth0 User [{user}] created a "
        f"role [{request_body_name}] with [{role_type}] "
        f"permissions in your tenant [{p_source_label}]."
    )


def severity(event):
    request_body_name = deep_get(
        event, "data", "details", "request", "body", "name", default="<NO_REQUEST_NAME_FOUND>"
    )
    request_body_description = deep_get(
        event, "data", "details", "request", "body", "description", default=[-1]
    )
    if "admin" in request_body_description or "admin" in request_body_name:
        return "MEDIUM"
    return "LOW"


def alert_context(event):
    return auth0_alert_context(event)
