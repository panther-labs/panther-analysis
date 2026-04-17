from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event


def rule(event):

    data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")

    return all(
        [
            is_auth0_config_event(event),
            data_description == "Delete tenant member",
        ]
    )


def alert_context(event):
    return auth0_alert_context(event)
