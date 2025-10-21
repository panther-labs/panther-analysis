from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event


def rule(event):

    data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
    roles = event.deep_get("data", "details", "request", "body", "roles", default="<NO_ROLE_FOUND>")

    return all(
        [
            is_auth0_config_event(event),
            data_description == "Create tenant invitations for a given client",
            "owner" in roles,
        ]
    )


def alert_context(event):
    return auth0_alert_context(event)
