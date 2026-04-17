from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event


def rule(event):

    data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
    return all(
        [
            data_description == "Create a role",
            is_auth0_config_event(event),
        ]
    )


def title(event):
    user = event.deep_get(
        "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    request_body_name = event.deep_get(
        "data", "details", "request", "body", "name", default="<NO_REQUEST_NAME_FOUND>"
    )
    request_body_description = event.deep_get(
        "data", "details", "request", "body", default="<NO_REQUEST_BODY_FOUND>"
    )

    if "admin" in request_body_description or "admin" in request_body_name:
        role_type = "admin"
    else:
        role_type = "custom"

    p_source_label = event.get("p_source_label", "<NO_P_SOURCE_LABEL_FOUND>")
    return (
        f"Auth0 User [{user}] created a "
        f"role [{request_body_name}] with [{role_type}] "
        f"permissions in your tenant [{p_source_label}]."
    )


def severity(event):
    request_body_name = event.deep_get(
        "data", "details", "request", "body", "name", default="<NO_REQUEST_NAME_FOUND>"
    )
    request_body_description = event.deep_get(
        "data", "details", "request", "body", "description", default=""
    )
    if "admin" in request_body_description or "admin" in request_body_name:
        return "MEDIUM"
    return "LOW"


def alert_context(event):
    return auth0_alert_context(event)
