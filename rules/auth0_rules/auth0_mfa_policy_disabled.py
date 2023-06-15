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
    request_body = deep_get(event, "data", "details", "request", "body", default=[])
    return all(
        [
            data_description == "Set the Multi-factor Authentication policies",
            request_path == "/api/v2/guardian/policies",
            request_body == [],
            is_auth0_config_event(event),
        ]
    )


def title(event):
    user = deep_get(
        event, "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    p_source_label = deep_get(event, "p_source_label", default="<NO_P_SOURCE_LABEL_FOUND>")
    return (
        f"Auth0 User [{user}] set mfa requirement settings to 'Never' for your "
        f"organization's tenant [{p_source_label}]."
    )


def alert_context(event):
    return auth0_alert_context(event)
