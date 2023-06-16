from global_filter_auth0 import filter_include_event
from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event
from panther_base_helpers import deep_get

def rule(event):
    if not filter_include_event(event):
        return False
    description = deep_get(event,"data","description", default="<NO_DESCRIPTION_FOUND>")
    enabled = deep_get(event,"data","details","response","body","enabled")

    return all(
        [
            description == "Update a Multi-factor Authentication Factor",
            enabled is True,
            is_auth0_config_event(event),
        ]
    )

def title(event):
    user = deep_get(
        event, "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    path = deep_get(event, "data", "details", "request", "path", default="<NO_PATH_FOUND>")
    p_source_label = deep_get(event, "p_source_label", default="<NO_P_SOURCE_LABEL_FOUND>")
    return (
        f"Auth0 User [{user}] enabled mfa factor settings for [[{path}] "
        f"in your organization’s tenant [{p_source_label}]."
    ) 

def alert_context(event):
    return auth0_alert_context(event)