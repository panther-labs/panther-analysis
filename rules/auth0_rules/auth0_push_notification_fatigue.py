from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event


def rule(event):

    data_type = event.deep_get("data", "type", default="<NO_DATA_TYPE_FOUND>")

    return all(
        [
            data_type == "gd_send_pn",
            is_auth0_config_event(event),
        ]
    )


def title(event):
    user = event.deep_get(
        "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    return (
        f"Auth0 User [{user}] has received an excessive number of MFA push notifications,"
        f"possible MFA fatigue detected"
    )


def alert_context(event):
    return auth0_alert_context(event)
