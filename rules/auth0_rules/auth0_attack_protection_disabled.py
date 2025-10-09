from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event


def rule(event):

    data_type = event.deep_get("data", "type", default="<NO_DATA_TYPE_FOUND>")

    data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")

    request_path = event.deep_get(
        "data", "details", "request", "path", default="<NO_REQUEST_PATH_FOUND>"
    )

    response_body_enabled = event.deep_get(
        "data", "details", "response", "body", "enabled", default="<NO_ENABLED_INFO_FOUND>"
    )

    response_body_shields = event.deep_get(
        "data", "details", "response", "body", "shields", default="<NO_SHIELD_INFO_FOUND>"
    )

    response_status_code = event.deep_get(
        "data", "details", "response", "statusCode", default="<NO_RESPONSE_CODE_FOUND>"
    )

    return all(
        [
            data_type == "sapi",
            (
                (
                    "Suspicious IP Throttling" in data_description
                    and request_path == "/v2/attack-protection/suspicious-ip-throttling"
                )
                or (
                    "Brute-force" in data_description
                    and request_path == "/v2/attack-protection/brute-force-protection"
                )
                or (
                    "Breached Password Detection" in data_description
                    and request_path == "/v2/attack-protection/breached-password-detection"
                )
            ),
            (
                (response_body_enabled is False or response_body_enabled == "disabled")
                or (
                    (response_body_enabled is True or response_body_enabled == "enabled")
                    and response_body_shields != "block"
                )
            ),
            response_status_code == 200,
            is_auth0_config_event(event),
        ]
    )


def title(event):
    user = event.deep_get(
        "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")

    response_body_enabled = event.deep_get(
        "data", "details", "response", "body", "enabled", default="<NO_ENABLED_INFO_FOUND>"
    )

    response_body_shields = event.deep_get(
        "data", "details", "response", "body", "shields", default="<NO_SHIELD_INFO_FOUND>"
    )
    p_source_label = event.get("p_source_label", "<NO_P_SOURCE_LABEL_FOUND>")
    return (
        f"Auth0 User [{user}] updated shields to [{response_body_shields}]"
        f"or set attack protection monitoring to [{response_body_enabled}]"
        f"with message [{data_description}] in"
        f"your organization's tenant [{p_source_label}]."
    )


def alert_context(event):
    return auth0_alert_context(event)
