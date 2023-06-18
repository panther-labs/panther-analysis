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
            data_description == "Update trigger bindings",
            request_path == "/api/v2/actions/triggers/post-login/bindings",
            is_auth0_config_event(event),
        ]
    )


def title(event):
    user = deep_get(
        event, "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    p_source_label = deep_get(event, "p_source_label", default="<NO_P_SOURCE_LABEL_FOUND>")
    request_bindings = deep_get(event, "data", "details", "request", "body", "bindings", default=[])
    response_bindings = deep_get(
        event, "data", "details", "response", "body", "bindings", default=[]
    )

    actions_added_list = []
    for binding in request_bindings:
        if "display_name" in binding:
            # check to see if actions were added to the flow
            actions_added_list.append(binding.get("display_name", ""))

    # otherwise, actions were removed from the action flow and we want
    # to grab what's still present in the flow
    actions_remaining_list = []
    for binding in response_bindings:
        if binding.get("display_name", ""):
            actions_remaining_list.append(binding.get("display_name", ""))

    if actions_added_list:
        return (
            f"Auth0 User {user} added action(s) {actions_added_list} to a post-login action flow "
            f"for your organization’s tenant {p_source_label}."
        )

    if actions_remaining_list:
        return (
            f"Auth0 User {user} removed action(s) "
            f"to a post-login action flow for your organization’s tenant {p_source_label}, "
            f"remaining actions include {actions_remaining_list}."
        )

    # no actions remain in the flow
    return (
        f"Auth0 User {user} removed all actions "
        f"from a post-login action flow for your organization’s tenant {p_source_label}."
    )


def alert_context(event):
    return auth0_alert_context(event)
