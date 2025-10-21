from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event


def rule(event):

    data_type = event.deep_get("data", "type", default="<NO_DATA_TYPE_FOUND>")

    data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")

    bot_p_policy = event.deep_get(
        "data",
        "details",
        "response",
        "body",
        "passwordless_policy",
        default="<NO_PASSWORDLESS_POLICY_FOUND>",
    )

    bot_reset_policy = event.deep_get(
        "data",
        "details",
        "response",
        "body",
        "password_reset_policy",
        default="<NO_PASSWORD_RESET_POLICY_FOUND>",
    )

    bot_policy = event.deep_get(
        "data", "details", "response", "body", "policy", default="<NO_BOT_POLICY_FOUND>"
    )

    response_status_code = event.deep_get(
        "data", "details", "response", "statusCode", default="<NO_RESPONSE_CODE_FOUND>"
    )
    return all(
        [
            data_type == "sapi",
            (
                data_description == "Create or update the anomaly detection captcha"
                and (bot_p_policy == "off" or bot_reset_policy == "off" or bot_policy == "off")
            ),
            response_status_code == 200,
            is_auth0_config_event(event),
        ]
    )


def title(event):
    user = event.deep_get(
        "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    p_source_label = event.get("p_source_label", "<NO_P_SOURCE_LABEL_FOUND>")
    return (
        f"Auth0 User [{user}] disabled bot detection in "
        f"your organization's tenant [{p_source_label}]."
    )


def alert_context(event):
    return auth0_alert_context(event)
